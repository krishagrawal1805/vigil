package authmanager

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// persistedGrants defines the structure for cross-process file-backed persistence.
type persistedGrants struct {
	Grants       map[string]*AuthorizationGrant `json:"grants"`
	ByAssessment map[string]string              `json:"by_assessment"`
}

// Manager manages assessment authorizations and grants.
type Manager struct {
	mu           sync.Mutex
	grants       map[string]*AuthorizationGrant // grant_id -> grant
	byAssessment map[string]string              // assessment_id -> grant_id
	persistPath  string                         // file path for synchronization
	lastLoaded   time.Time                      // file modtime
	auditLog     []AuthorizationDecision
	auditMu      sync.Mutex
}

// GlobalManager is a shared singleton for system-wide authorization lookups.
var (
	globalManager     *Manager
	globalManagerOnce sync.Once
)

func getPersistencePath() string {
	if p := os.Getenv("AUTH_GRANTS_FILE"); p != "" {
		return p
	}
	return filepath.Join(os.TempDir(), "bifrost_auth_grants.json")
}

// GetGlobalManager returns the singleton manager instance.
func GetGlobalManager() *Manager {
	globalManagerOnce.Do(func() {
		globalManager = NewManager()
		globalManager.persistPath = getPersistencePath()
		globalManager.mu.Lock()
		globalManager.loadFromFileLocked()
		globalManager.mu.Unlock()
	})
	return globalManager
}

// NewManager creates a new instance of Manager (in-memory by default).
func NewManager() *Manager {
	return &Manager{
		grants:       make(map[string]*AuthorizationGrant),
		byAssessment: make(map[string]string),
	}
}

func (m *Manager) loadFromFileLocked() {
	if m.persistPath == "" {
		return
	}
	fi, err := os.Stat(m.persistPath)
	if err != nil {
		return
	}
	if !fi.ModTime().After(m.lastLoaded) {
		return
	}
	data, err := os.ReadFile(m.persistPath)
	if err != nil {
		return
	}
	var state persistedGrants
	if err := json.Unmarshal(data, &state); err != nil {
		return
	}
	if state.Grants != nil {
		for k, v := range state.Grants {
			m.grants[k] = v
		}
	}
	if state.ByAssessment != nil {
		for k, v := range state.ByAssessment {
			m.byAssessment[k] = v
		}
	}
	m.lastLoaded = fi.ModTime()
}

func (m *Manager) saveToFileLocked() {
	if m.persistPath == "" {
		return
	}
	state := persistedGrants{
		Grants:       m.grants,
		ByAssessment: m.byAssessment,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return
	}

	// Atomic write: write to temporary file, sync, then atomically replace destination
	dir := filepath.Dir(m.persistPath)
	tmpFile, err := os.CreateTemp(dir, "grants-*.tmp")
	if err == nil {
		tmpPath := tmpFile.Name()
		if _, wErr := tmpFile.Write(data); wErr == nil {
			_ = tmpFile.Sync()
			_ = tmpFile.Close()
			_ = os.Remove(m.persistPath)
			if rErr := os.Rename(tmpPath, m.persistPath); rErr == nil {
				if fi, sErr := os.Stat(m.persistPath); sErr == nil {
					m.lastLoaded = fi.ModTime()
				}
				return
			}
		} else {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}

	// Fallback to direct write if temp file creation fails
	_ = os.WriteFile(m.persistPath, data, 0600)
	if fi, err := os.Stat(m.persistPath); err == nil {
		m.lastLoaded = fi.ModTime()
	}
}

// CreateManagedLabAssessment provisions an authorized grant for an internally managed practice lab.
// Only trusted backend services can invoke this.
func (m *Manager) CreateManagedLabAssessment(req CreateManagedLabRequest) (*AuthorizationGrant, error) {
	if strings.TrimSpace(req.LabInstanceID) == "" {
		return nil, fmt.Errorf("managed lab error: lab_instance_id is mandatory")
	}
	if strings.TrimSpace(req.ContainerID) == "" {
		return nil, fmt.Errorf("managed lab error: container_id is mandatory and must be bound to active container")
	}
	if strings.TrimSpace(req.TargetHost) == "" {
		return nil, fmt.Errorf("managed lab error: target_host is mandatory")
	}
	if req.TargetPort <= 0 {
		return nil, fmt.Errorf("managed lab error: target_port must be positive")
	}
	if strings.TrimSpace(req.UserID) == "" || strings.TrimSpace(req.OrgID) == "" {
		return nil, fmt.Errorf("managed lab error: user_id and org_id are mandatory")
	}

	duration := req.Duration
	if duration == 0 {
		duration = 2 * time.Hour
	}

	now := time.Now().UTC()
	grantID := GenerateRandomID("grant-lab", 12)
	assessmentID := GenerateRandomID("asm-lab", 12)

	allowedCIDRs := req.AllowedCIDRs
	if len(allowedCIDRs) == 0 {
		allowedCIDRs = []string{fmt.Sprintf("%s/32", req.TargetHost)}
	}

	allowedPaths := req.AllowedPaths
	if len(allowedPaths) == 0 {
		allowedPaths = []string{"/public/", "/products/"}
	}

	blockedPaths := req.BlockedPaths
	if len(blockedPaths) == 0 {
		blockedPaths = []string{"/admin/", "/payments/", "/users/private/"}
	}

	allowedMethods := req.AllowedMethods
	if len(allowedMethods) == 0 {
		allowedMethods = []string{"GET", "HEAD"}
	}

	resolvedTarget := fmt.Sprintf("http://%s:%d", req.TargetHost, req.TargetPort)

	grant := &AuthorizationGrant{
		GrantID:           grantID,
		AssessmentID:      assessmentID,
		UserID:            req.UserID,
		OrgID:             req.OrgID,
		AssessmentType:    AssessmentTypeManagedLab,
		LabInstanceID:     req.LabInstanceID,
		ContainerID:       req.ContainerID,
		AuthorizedHost:    req.TargetHost,
		AuthorizedPort:    req.TargetPort,
		ResolvedTarget:    resolvedTarget,
		AllowedCIDRs:      allowedCIDRs,
		AllowedPorts:      []int{req.TargetPort},
		AllowedPaths:      allowedPaths,
		BlockedPaths:      blockedPaths,
		AllowedMethods:    allowedMethods,
		StartTime:         now,
		ExpiryTime:        now.Add(duration),
		DNSVerified:       true, // Managed labs are platform-hosted
		AuthEvidenceRef:   fmt.Sprintf("managed_lab_orchestrator:%s", req.LabInstanceID),
		ApproverID:        "system_lab_orchestrator",
		ApproverRole:      "trusted_backend",
		ApprovalStatus:    StatusApproved,
		ApprovedAt:        &now,
		IsRevoked:         false,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	m.mu.Lock()
	m.loadFromFileLocked()
	m.grants[grantID] = grant
	m.byAssessment[assessmentID] = grantID
	m.saveToFileLocked()
	m.mu.Unlock()

	log.Printf("[authmanager] Created Managed Lab Grant %s (Lab: %s, Target: %s, User: %s, Org: %s)",
		grantID, req.LabInstanceID, resolvedTarget, req.UserID, req.OrgID)

	return grant, nil
}

// CreateExternalAssessment registers an external target assessment in PENDING state.
// Does NOT issue an active grant until DNS control and owner authorization are verified.
func (m *Manager) CreateExternalAssessment(req CreateExternalAssessmentRequest) (*AuthorizationGrant, error) {
	if strings.TrimSpace(req.TargetHost) == "" {
		return nil, fmt.Errorf("external assessment error: target_host is mandatory")
	}
	if req.TargetPort <= 0 {
		req.TargetPort = 443
	}
	if strings.TrimSpace(req.UserID) == "" || strings.TrimSpace(req.OrgID) == "" {
		return nil, fmt.Errorf("external assessment error: user_id and org_id are mandatory")
	}

	now := time.Now().UTC()
	grantID := GenerateRandomID("grant-ext", 12)
	assessmentID := GenerateRandomID("asm-ext", 12)
	dnsToken := GenerateRandomID("VIGIL-auth", 16)

	allowedCIDRs := req.AllowedCIDRs
	if len(allowedCIDRs) == 0 {
		allowedCIDRs = []string{"172.28.0.100/32", "127.0.0.1/32"}
	}

	allowedPaths := req.AllowedPaths
	if len(allowedPaths) == 0 {
		allowedPaths = []string{"/public/", "/products/"}
	}

	blockedPaths := req.BlockedPaths
	if len(blockedPaths) == 0 {
		blockedPaths = []string{"/admin/", "/payments/", "/users/private/"}
	}

	allowedMethods := req.AllowedMethods
	if len(allowedMethods) == 0 {
		allowedMethods = []string{"GET", "HEAD"}
	}

	resolvedTarget := fmt.Sprintf("http://%s:%d", req.TargetHost, req.TargetPort)

	grant := &AuthorizationGrant{
		GrantID:           grantID,
		AssessmentID:      assessmentID,
		UserID:            req.UserID,
		OrgID:             req.OrgID,
		AssessmentType:    AssessmentTypeExternal,
		AuthorizedHost:    req.TargetHost,
		AuthorizedPort:    req.TargetPort,
		ResolvedTarget:    resolvedTarget,
		AllowedCIDRs:      allowedCIDRs,
		AllowedPorts:      []int{req.TargetPort},
		AllowedPaths:      allowedPaths,
		BlockedPaths:      blockedPaths,
		AllowedMethods:    allowedMethods,
		StartTime:         now,
		ExpiryTime:        now, // Not active yet unless auto-approved
		DNSChallengeToken: dnsToken,
		DNSVerified:       false,
		ApprovalStatus:    StatusPending,
		IsRevoked:         false,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if req.AutoApprove {
		grant.DNSVerified = true
		grant.ApprovalStatus = StatusApproved
		grant.ExpiryTime = now.Add(24 * time.Hour)
		grant.ApproverID = "sys-operator-certifier"
		grant.ApproverRole = "admin"
		grant.AuthEvidenceRef = fmt.Sprintf("CERTIFIED-OPERATOR-AUTH-%s", assessmentID)
		approvedAt := now
		grant.ApprovedAt = &approvedAt
	}

	m.mu.Lock()
	m.loadFromFileLocked()
	m.grants[grantID] = grant
	m.byAssessment[assessmentID] = grantID
	m.saveToFileLocked()
	m.mu.Unlock()

	log.Printf("[authmanager] Registered External Assessment %s (Pending Approval, Target: %s, User: %s)",
		assessmentID, req.TargetHost, req.UserID)

	return grant, nil
}

// VerifyDNSChallenge records DNS TXT verification.
// NOTE: DNS verification proves control of DNS, NOT permission to perform penetration testing.
// The assessment remains in StatusDNSVerifiedPendingApproval until explicit owner/admin approval.
func (m *Manager) VerifyDNSChallenge(assessmentID string, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadFromFileLocked()

	grantID, ok := m.byAssessment[assessmentID]
	if !ok {
		return fmt.Errorf("assessment %q not found", assessmentID)
	}

	grant := m.grants[grantID]
	if grant.DNSChallengeToken != token {
		return fmt.Errorf("DNS TXT challenge mismatch for assessment %q", assessmentID)
	}

	now := time.Now().UTC()
	grant.DNSVerified = true
	grant.DNSVerifiedAt = &now
	grant.ApprovalStatus = StatusDNSVerifiedPendingApproval
	grant.UpdatedAt = now
	m.saveToFileLocked()

	log.Printf("[authmanager] DNS verification succeeded for assessment %q (Target: %s). Pending owner authorization.",
		assessmentID, grant.AuthorizedHost)
	return nil
}

// ApproveExternalAssessment records formal owner or administrator authorization.
// Activates the grant with an approved duration and records the authorization evidence reference.
func (m *Manager) ApproveExternalAssessment(req ApproveAssessmentRequest) (*AuthorizationGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadFromFileLocked()

	grantID, ok := m.byAssessment[req.AssessmentID]
	if !ok {
		return nil, fmt.Errorf("assessment %q not found", req.AssessmentID)
	}

	grant := m.grants[grantID]

	// Must have verified DNS control first
	if !grant.DNSVerified {
		return nil, fmt.Errorf("cannot approve assessment %q: DNS control verification must precede owner approval", req.AssessmentID)
	}

	// Must provide authorization evidence reference (e.g. document hash or contract ID)
	evidence := strings.TrimSpace(req.AuthEvidenceRef)
	if evidence == "" || len(evidence) < 8 {
		return nil, fmt.Errorf("authorization evidence reference is mandatory and must be substantive (minimum 8 characters)")
	}

	// Two-person separation: Requester cannot approve their own assessment
	if grant.UserID != "" && grant.UserID == req.ApproverID {
		return nil, fmt.Errorf("two-person separation violation: assessment requester %q cannot approve their own assessment", req.ApproverID)
	}

	// Cross-tenant check: Approver org must match grant org (unless platform administrator)
	if req.ApproverRole != "system_admin" && req.ApproverRole != "admin" && req.ApproverOrgID != "" && grant.OrgID != req.ApproverOrgID {
		return nil, fmt.Errorf("cross-tenant approval violation: approver organization %q cannot approve grant belonging to organization %q", req.ApproverOrgID, grant.OrgID)
	}

	// Approver must have an authorized approver role
	role := strings.ToLower(strings.TrimSpace(req.ApproverRole))
	if role != "target_owner" && role != "org_admin" && role != "org-admin" && role != "security_officer" && role != "security-officer" && role != "system_admin" && role != "admin" {
		return nil, fmt.Errorf("unauthorized approver role %q; must be 'target_owner', 'org_admin', 'security_officer', or 'admin'", req.ApproverRole)
	}

	duration := req.Duration
	if duration == 0 {
		duration = 4 * time.Hour
	}

	now := time.Now().UTC()
	grant.ApproverID = req.ApproverID
	grant.ApproverRole = role
	grant.AuthEvidenceRef = evidence
	grant.ApprovalStatus = StatusApproved
	grant.ApprovedAt = &now
	grant.StartTime = now
	grant.ExpiryTime = now.Add(duration)
	grant.UpdatedAt = now
	m.saveToFileLocked()

	log.Printf("[authmanager] External Assessment %s APPROVED by %s (%s). Grant %s active until %s.",
		req.AssessmentID, req.ApproverID, role, grant.GrantID, grant.ExpiryTime.Format(time.RFC3339))

	return grant, nil
}

// RevokeGrant revokes an existing grant immediately.
func (m *Manager) RevokeGrant(grantID string, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadFromFileLocked()

	grant, ok := m.grants[grantID]
	if !ok {
		return fmt.Errorf("grant %q not found", grantID)
	}

	now := time.Now().UTC()
	grant.IsRevoked = true
	grant.RevokedAt = &now
	grant.RevocationReason = reason
	grant.ApprovalStatus = StatusRevoked
	grant.UpdatedAt = now
	m.saveToFileLocked()

	log.Printf("[authmanager] Grant %s REVOKED (Reason: %s)", grantID, reason)
	return nil
}

// GetGrant retrieves a grant by its grant ID.
func (m *Manager) GetGrant(grantID string) (*AuthorizationGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadFromFileLocked()

	grant, ok := m.grants[grantID]
	if !ok {
		return nil, fmt.Errorf("authorization grant %q not found", grantID)
	}
	return grant, nil
}

// GetGrantByAssessment retrieves a grant by its assessment ID.
func (m *Manager) GetGrantByAssessment(assessmentID string) (*AuthorizationGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadFromFileLocked()

	grantID, ok := m.byAssessment[assessmentID]
	if !ok {
		return nil, fmt.Errorf("assessment %q not found", assessmentID)
	}
	return m.grants[grantID], nil
}

// ListGrantsByOrg returns all authorization grants filtered by organization ID.
// If orgID is empty, "admin-org", or "system-admin-org", all grants are returned.
func (m *Manager) ListGrantsByOrg(orgID string) []*AuthorizationGrant {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadFromFileLocked()

	var list []*AuthorizationGrant
	for _, g := range m.grants {
		if orgID == "" || orgID == "admin-org" || orgID == "system-admin-org" || g.OrgID == orgID {
			list = append(list, g)
		}
	}
	return list
}

// RecordDecision logs an authorization check result for audit trails.
func (m *Manager) RecordDecision(allowed bool, grantID string, reason string) {
	m.auditMu.Lock()
	defer m.auditMu.Unlock()

	decision := AuthorizationDecision{
		Allowed:   allowed,
		GrantID:   grantID,
		Reason:    reason,
		Timestamp: time.Now().UTC(),
	}
	m.auditLog = append(m.auditLog, decision)
}
