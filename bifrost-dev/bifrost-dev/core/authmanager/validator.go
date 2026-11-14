package authmanager

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/scopepolicy"
)

// ValidateRequest performs authoritative validation of an in-flight tool or HTTP request.
// It verifies existence, non-revocation, approval status, temporal validity, tenant isolation,
// and full target/resource/action boundaries.
func (m *Manager) ValidateRequest(req ValidationRequest) (*AuthorizationGrant, error) {
	var grant *AuthorizationGrant
	var err error

	// 1. Resolve authoritative grant from server-side store
	if strings.TrimSpace(req.GrantID) != "" {
		grant, err = m.GetGrant(req.GrantID)
	} else if strings.TrimSpace(req.AssessmentID) != "" {
		grant, err = m.GetGrantByAssessment(req.AssessmentID)
	}

	if err != nil || grant == nil {
		m.RecordDecision(false, req.GrantID, "missing or unknown authorization grant")
		return nil, fmt.Errorf("authorization denied: request lacks a valid server-side authorization grant")
	}

	// 2. Reject revoked grants
	if grant.IsRevoked {
		reason := fmt.Sprintf("grant %s is revoked (reason: %s)", grant.GrantID, grant.RevocationReason)
		m.RecordDecision(false, grant.GrantID, reason)
		return nil, fmt.Errorf("authorization denied: %s", reason)
	}

	// 3. Reject unapproved grants (pending, dns_verified_pending_approval, rejected)
	if grant.ApprovalStatus != StatusApproved {
		reason := fmt.Sprintf("assessment %s is not approved (current status: %s)", grant.AssessmentID, grant.ApprovalStatus)
		m.RecordDecision(false, grant.GrantID, reason)
		return nil, fmt.Errorf("authorization denied: %s", reason)
	}

	// 4. Reject expired grants
	now := time.Now().UTC()
	if now.Before(grant.StartTime) || now.After(grant.ExpiryTime) {
		reason := fmt.Sprintf("grant %s expired at %s (current time: %s)", grant.GrantID, grant.ExpiryTime.Format(time.RFC3339), now.Format(time.RFC3339))
		m.RecordDecision(false, grant.GrantID, reason)
		return nil, fmt.Errorf("authorization denied: %s", reason)
	}

	// 5. Tenant Isolation: User and Organization identity bound checks
	if strings.TrimSpace(req.UserID) != "" && req.UserID != grant.UserID {
		reason := fmt.Sprintf("tenant mismatch: grant belongs to user %q, cannot be used by user %q", grant.UserID, req.UserID)
		m.RecordDecision(false, grant.GrantID, reason)
		return nil, fmt.Errorf("authorization denied: %s", reason)
	}
	if strings.TrimSpace(req.OrgID) != "" && req.OrgID != grant.OrgID {
		reason := fmt.Sprintf("tenant mismatch: grant belongs to organization %q, cannot be used by organization %q", grant.OrgID, req.OrgID)
		m.RecordDecision(false, grant.GrantID, reason)
		return nil, fmt.Errorf("authorization denied: %s", reason)
	}

	// 6. Target URL Parsing & Scheme Enforcement
	rawTarget := strings.TrimSpace(req.TargetURL)
	if rawTarget == "" {
		reason := "missing target URL in request"
		m.RecordDecision(false, grant.GrantID, reason)
		return nil, fmt.Errorf("authorization denied: %s", reason)
	}

	u, parseErr := url.Parse(rawTarget)
	if parseErr != nil {
		reason := fmt.Sprintf("unparseable target URL %q: %v", rawTarget, parseErr)
		m.RecordDecision(false, grant.GrantID, reason)
		return nil, fmt.Errorf("authorization denied: %s", reason)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		reason := fmt.Sprintf("unauthorized scheme %q; only http and https are permitted", scheme)
		m.RecordDecision(false, grant.GrantID, reason)
		return nil, fmt.Errorf("authorization denied: %s", reason)
	}

	host := u.Hostname()
	port := 80
	if scheme == "https" {
		port = 443
	}
	if portStr := u.Port(); portStr != "" {
		if pVal, err := strconv.Atoi(portStr); err == nil {
			port = pVal
		}
	}

	// 7. Assessment Mode Target Restrictions
	if grant.AssessmentType == AssessmentTypeManagedLab {
		// Rule: In managed practice lab mode, users CANNOT replace or supply an arbitrary target.
		// If someone attempts to use netflix.com or an arbitrary host, reject!
		if !strings.EqualFold(host, grant.AuthorizedHost) || port != grant.AuthorizedPort {
			reason := fmt.Sprintf("managed lab grant %s is strictly locked to registered target %s; arbitrary target %q is rejected",
				grant.GrantID, grant.ResolvedTarget, rawTarget)
			m.RecordDecision(false, grant.GrantID, reason)
			return nil, fmt.Errorf("authorization denied: %s", reason)
		}
	} else {
		// External mode: check against authorized host and allowed CIDRs
		if !strings.EqualFold(host, grant.AuthorizedHost) {
			// Check if host is an allowed IP
			ipAddr, ipErr := netip.ParseAddr(host)
			if ipErr != nil {
				reason := fmt.Sprintf("host %q does not match authorized host %q in grant %s", host, grant.AuthorizedHost, grant.GrantID)
				m.RecordDecision(false, grant.GrantID, reason)
				return nil, fmt.Errorf("authorization denied: %s", reason)
			}
			ipAddr = ipAddr.Unmap()
			inRange := false
			for _, cidr := range grant.AllowedCIDRs {
				if prefix, pErr := netip.ParsePrefix(cidr); pErr == nil && prefix.Contains(ipAddr) {
					inRange = true
					break
				}
			}
			if !inRange {
				reason := fmt.Sprintf("target host %q is not authorized in grant %s", host, grant.GrantID)
				m.RecordDecision(false, grant.GrantID, reason)
				return nil, fmt.Errorf("authorization denied: %s", reason)
			}
		}
	}

	// 8. Port Enforcement
	portAllowed := false
	for _, p := range grant.AllowedPorts {
		if p == port {
			portAllowed = true
			break
		}
	}
	if !portAllowed {
		reason := fmt.Sprintf("port %d is not authorized in grant (allowed: %v)", port, grant.AllowedPorts)
		m.RecordDecision(false, grant.GrantID, reason)
		return nil, fmt.Errorf("authorization denied: %s", reason)
	}

	// 9. Resource Path Enforcement with Canonical Normalization
	normPath, normErr := scopepolicy.NormalizePath(u.Path)
	if normErr != nil {
		reason := fmt.Sprintf("path normalization failed for %q: %v", u.Path, normErr)
		m.RecordDecision(false, grant.GrantID, reason)
		return nil, fmt.Errorf("authorization denied: %s", reason)
	}

	// Check blocked paths
	for _, blocked := range grant.BlockedPaths {
		normBlocked, _ := scopepolicy.NormalizePath(blocked)
		if matchesPathPrefix(normPath, normBlocked) {
			reason := fmt.Sprintf("path %q matches prohibited resource %q in grant", normPath, blocked)
			m.RecordDecision(false, grant.GrantID, reason)
			return nil, fmt.Errorf("authorization denied: %s", reason)
		}
	}

	// Check allowed paths
	if len(grant.AllowedPaths) > 0 {
		pathAllowed := false
		for _, allow := range grant.AllowedPaths {
			normAllowed, _ := scopepolicy.NormalizePath(allow)
			if matchesPathPrefix(normPath, normAllowed) {
				pathAllowed = true
				break
			}
		}
		if !pathAllowed {
			reason := fmt.Sprintf("path %q is not within approved resource scope %v", normPath, grant.AllowedPaths)
			m.RecordDecision(false, grant.GrantID, reason)
			return nil, fmt.Errorf("authorization denied: %s", reason)
		}
	}

	// 10. Action Method Enforcement
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = "GET"
	}
	methodAllowed := false
	for _, mth := range grant.AllowedMethods {
		if strings.EqualFold(mth, method) {
			methodAllowed = true
			break
		}
	}
	if !methodAllowed {
		reason := fmt.Sprintf("HTTP method %q is not authorized in grant (allowed: %v)", method, grant.AllowedMethods)
		m.RecordDecision(false, grant.GrantID, reason)
		return nil, fmt.Errorf("authorization denied: %s", reason)
	}

	m.RecordDecision(true, grant.GrantID, "authorized")
	return grant, nil
}

// matchesPathPrefix checks if p equals prefix or is a sub-path of prefix.
func matchesPathPrefix(p, prefix string) bool {
	p = strings.TrimSuffix(p, "/")
	prefix = strings.TrimSuffix(prefix, "/")

	if p == prefix {
		return true
	}
	if strings.HasPrefix(p, prefix+"/") {
		return true
	}
	return false
}
