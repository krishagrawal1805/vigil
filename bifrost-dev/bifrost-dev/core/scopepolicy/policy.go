package scopepolicy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// Policy defines the multi-layer authorization rules.
type Policy struct {
	// 1. Target-level
	AllowedCIDRs []string `json:"allowed_cidrs"` // e.g. ["172.28.0.100/32", "127.0.0.1/32"]
	AllowedPorts []int    `json:"allowed_ports"` // e.g. [3000, 8080, 80, 443]
	AllowedHosts []string `json:"allowed_hosts"` // e.g. ["172.28.0.100", "localhost"]
	BlockedCIDRs []string `json:"blocked_cidrs"` // e.g. ["169.254.169.254/32", "10.0.0.0/8"]

	// 2. Resource-level
	AllowedPaths []string `json:"allowed_paths"` // e.g. ["/public/", "/products/"]
	BlockedPaths []string `json:"blocked_paths"` // e.g. ["/admin/", "/payments/", "/users/private/"]

	// 3. Action-level
	AllowedMethods         []string `json:"allowed_methods"`          // e.g. ["GET", "HEAD"]
	BlockedMethods         []string `json:"blocked_methods"`          // e.g. ["DELETE", "POST", "PUT", "PATCH"]
	ReadOnlyMode           bool     `json:"read_only_mode"`           // true enforces only read-only verbs
	RequireApprovalMethods []string `json:"require_approval_methods"` // e.g. ["DELETE"]
}

// DefaultLabPolicy returns the fine-grained scope policy for our lab.
func DefaultLabPolicy() Policy {
	return Policy{
		AllowedCIDRs: []string{"172.28.0.100/32", "127.0.0.1/32"},
		AllowedPorts: []int{3000, 8080, 80, 443},
		AllowedHosts: []string{"172.28.0.100", "127.0.0.1", "localhost"},
		BlockedCIDRs: []string{"169.254.169.254/32"},

		AllowedPaths: []string{"/public/", "/products/"},
		BlockedPaths: []string{"/admin/", "/payments/", "/users/private/"},

		AllowedMethods:         []string{"GET", "HEAD"},
		BlockedMethods:         []string{"DELETE", "POST", "PUT", "PATCH"},
		ReadOnlyMode:           true,
		RequireApprovalMethods: []string{"DELETE"},
	}
}

// FineGrainedScopeEnforcer evaluates target, resource, and action authorization.
type FineGrainedScopeEnforcer struct {
	policy          Policy
	allowedPrefixes []netip.Prefix
	blockedPrefixes []netip.Prefix
	allowedPorts    map[int]struct{}
	allowedHosts    map[string]struct{}
	allowedMethods  map[string]struct{}
	blockedMethods  map[string]struct{}
	resolver        *net.Resolver
}

// NewFineGrainedScopeEnforcer initializes and compiles the enforcer.
func NewFineGrainedScopeEnforcer(p Policy) (*FineGrainedScopeEnforcer, error) {
	if len(p.AllowedCIDRs) == 0 {
		return nil, fmt.Errorf("policy error: allowed_cidrs is mandatory")
	}
	if len(p.AllowedPorts) == 0 {
		return nil, fmt.Errorf("policy error: allowed_ports is mandatory")
	}

	e := &FineGrainedScopeEnforcer{
		policy:         p,
		allowedPorts:   make(map[int]struct{}),
		allowedHosts:   make(map[string]struct{}),
		allowedMethods: make(map[string]struct{}),
		blockedMethods: make(map[string]struct{}),
		resolver:       &net.Resolver{PreferGo: true},
	}

	for _, cidr := range p.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed CIDR %q: %w", cidr, err)
		}
		e.allowedPrefixes = append(e.allowedPrefixes, prefix)
	}

	for _, cidr := range p.BlockedCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid blocked CIDR %q: %w", cidr, err)
		}
		e.blockedPrefixes = append(e.blockedPrefixes, prefix)
	}

	for _, port := range p.AllowedPorts {
		e.allowedPorts[port] = struct{}{}
	}

	for _, h := range p.AllowedHosts {
		e.allowedHosts[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}

	for _, m := range p.AllowedMethods {
		e.allowedMethods[strings.ToUpper(strings.TrimSpace(m))] = struct{}{}
	}

	for _, m := range p.BlockedMethods {
		e.blockedMethods[strings.ToUpper(strings.TrimSpace(m))] = struct{}{}
	}

	return e, nil
}

// CheckRequest evaluates all three policy layers on a pending HTTP request.
// Returns nil if allowed, or a descriptive error detailing which policy layer denied access.
func (e *FineGrainedScopeEnforcer) CheckRequest(method string, rawURL string) error {
	// 1. Action-level validation
	if err := e.CheckAction(method); err != nil {
		return err
	}

	// Parse URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("target validation failed: unparseable URL %q: %w", rawURL, err)
	}

	// 2. Target-level validation (Scheme, Host, Port, IP CIDR)
	if err := e.CheckTarget(parsedURL); err != nil {
		return err
	}

	// 3. Resource-level validation (Path Normalization, Allowed/Blocked Paths)
	if err := e.CheckResource(parsedURL.Path); err != nil {
		return err
	}

	return nil
}

// CheckAction validates the HTTP method against action-level policy.
func (e *FineGrainedScopeEnforcer) CheckAction(method string) error {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}

	// Explicit blocked methods
	if _, blocked := e.blockedMethods[method]; blocked {
		return fmt.Errorf("action policy denied: HTTP method %q is explicitly blocked", method)
	}

	// Read-only mode check
	if e.policy.ReadOnlyMode {
		switch method {
		case "GET", "HEAD", "OPTIONS":
			// permitted read-only
		default:
			return fmt.Errorf("action policy denied: method %q is prohibited in read-only mode", method)
		}
	}

	// Allowed methods allowlist (if specified)
	if len(e.allowedMethods) > 0 {
		if _, allowed := e.allowedMethods[method]; !allowed {
			return fmt.Errorf("action policy denied: HTTP method %q is not in allowed methods", method)
		}
	}

	return nil
}

// CheckTarget validates the scheme, host, port, and IP address against target-level policy.
func (e *FineGrainedScopeEnforcer) CheckTarget(u *url.URL) error {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("target policy denied: unauthorized protocol scheme %q; only http and https are permitted", scheme)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("target policy denied: missing host in URL")
	}

	port := 80
	if scheme == "https" {
		port = 443
	}
	if portStr := u.Port(); portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("target policy denied: invalid port %q: %w", portStr, err)
		}
		port = p
	}

	// Port check
	if _, ok := e.allowedPorts[port]; !ok {
		return fmt.Errorf("target policy denied: port %d is not authorized (allowed: %v)", port, e.policy.AllowedPorts)
	}

	// Direct IP check
	if ipAddr, err := netip.ParseAddr(host); err == nil {
		ipAddr = ipAddr.Unmap()
		return e.checkIP(ipAddr)
	}

	// Hostname check
	lowerHost := strings.ToLower(host)
	if len(e.allowedHosts) > 0 {
		if _, ok := e.allowedHosts[lowerHost]; !ok {
			return fmt.Errorf("target policy denied: host %q is not in allowed hosts whitelist", lowerHost)
		}
	}

	// Resolve hostname and check all resolved IPs
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ips, err := e.resolver.LookupIPAddr(ctx, lowerHost)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("target policy denied: failed to resolve host %q: %v", lowerHost, err)
	}

	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip.IP.String())
		if err != nil {
			return fmt.Errorf("target policy denied: invalid resolved IP: %w", err)
		}
		addr = addr.Unmap()
		if err := e.checkIP(addr); err != nil {
			return fmt.Errorf("target policy denied: DNS resolution for host %q returned unauthorized IP %s: %w", lowerHost, addr, err)
		}
	}

	return nil
}

// checkIP validates an IP address against blocked and allowed CIDR prefixes.
func (e *FineGrainedScopeEnforcer) checkIP(addr netip.Addr) error {
	for _, blocked := range e.blockedPrefixes {
		if blocked.Contains(addr) {
			return fmt.Errorf("IP %s falls into prohibited CIDR %s", addr, blocked)
		}
	}

	for _, allowed := range e.allowedPrefixes {
		if allowed.Contains(addr) {
			return nil
		}
	}

	return fmt.Errorf("IP %s is not in any allowed CIDR range", addr)
}

// NormalizePath performs strict canonical path normalization:
// 1. Iteratively unescapes percent-encoding to counter double-encoding.
// 2. Converts backslashes to forward slashes.
// 3. Strips matrix/path parameters (e.g. /public/..;/admin -> /public/../admin).
// 4. Applies path.Clean to resolve .., ., and consecutive slashes.
// 5. Ensures path begins with a leading slash.
func NormalizePath(rawPath string) (string, error) {
	if rawPath == "" {
		return "/", nil
	}

	// 1. Iterative URL decoding (max 3 rounds to avoid infinite loops)
	curr := rawPath
	for i := 0; i < 3; i++ {
		unescaped, err := url.PathUnescape(curr)
		if err != nil || unescaped == curr {
			break
		}
		curr = unescaped
	}

	// 2. Convert backslashes
	curr = strings.ReplaceAll(curr, "\\", "/")

	// 3. Strip matrix parameters (;param=val)
	segments := strings.Split(curr, "/")
	cleanSegments := make([]string, 0, len(segments))
	for _, seg := range segments {
		if semi := strings.Index(seg, ";"); semi != -1 {
			seg = seg[:semi]
		}
		cleanSegments = append(cleanSegments, seg)
	}
	curr = strings.Join(cleanSegments, "/")

	// 4. Clean using standard path.Clean
	hadTrailingSlash := strings.HasSuffix(curr, "/")
	cleaned := path.Clean(curr)

	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}

	// Preserve directory boundary if original had trailing slash (except root)
	if hadTrailingSlash && cleaned != "/" && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}

	return cleaned, nil
}

// CheckResource validates a URL path against allowed and blocked resource policies.
func (e *FineGrainedScopeEnforcer) CheckResource(rawPath string) error {
	normPath, err := NormalizePath(rawPath)
	if err != nil {
		return fmt.Errorf("resource policy denied: failed to normalize path: %w", err)
	}

	// 1. Check against BlockedPaths (Highest priority: default-deny on forbidden resources)
	for _, blocked := range e.policy.BlockedPaths {
		normBlocked, _ := NormalizePath(blocked)
		if matchesPathPrefix(normPath, normBlocked) {
			return fmt.Errorf("resource policy denied: path %q matches blocked resource %q", normPath, blocked)
		}
	}

	// 2. Check against AllowedPaths (If defined, path must match at least one allowed prefix)
	if len(e.policy.AllowedPaths) > 0 {
		allowed := false
		for _, allow := range e.policy.AllowedPaths {
			normAllowed, _ := NormalizePath(allow)
			if matchesPathPrefix(normPath, normAllowed) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("resource policy denied: path %q is not in allowed paths %v", normPath, e.policy.AllowedPaths)
		}
	}

	return nil
}

// matchesPathPrefix checks if p is equal to prefix or is a sub-path under prefix.
// Handles directory boundaries (e.g. /products matches /products/ and /products/1, but NOT /products_other).
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

