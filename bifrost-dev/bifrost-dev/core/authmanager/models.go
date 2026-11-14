package authmanager

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// AssessmentType defines the category of the security assessment.
type AssessmentType string

const (
	AssessmentTypeManagedLab AssessmentType = "managed_lab"
	AssessmentTypeExternal   AssessmentType = "external_assessment"
)

// ApprovalStatus represents the authorization approval state.
type ApprovalStatus string

const (
	StatusPending                    ApprovalStatus = "pending"
	StatusDNSVerifiedPendingApproval ApprovalStatus = "dns_verified_pending_approval"
	StatusApproved                   ApprovalStatus = "approved"
	StatusRejected                   ApprovalStatus = "rejected"
	StatusRevoked                    ApprovalStatus = "revoked"
	StatusExpired                    ApprovalStatus = "expired"
)

// AuthorizationGrant is the authoritative server-side grant record.
type AuthorizationGrant struct {
	GrantID        string         `json:"grant_id"`
	AssessmentID   string         `json:"assessment_id"`
	UserID         string         `json:"user_id"`
	OrgID          string         `json:"org_id"`
	AssessmentType AssessmentType `json:"assessment_type"`
	LabInstanceID  string         `json:"lab_instance_id,omitempty"` // Only present for managed_lab
	ContainerID    string         `json:"container_id,omitempty"`    // Bound Docker container ID for managed lab

	// Authorized Scope Rules
	AuthorizedHost string   `json:"authorized_host"` // e.g. "172.28.0.100" or "lab.local"
	AuthorizedPort int      `json:"authorized_port"` // e.g. 3000
	ResolvedTarget string   `json:"resolved_target"` // Canonical base URL, e.g. "http://172.28.0.100:3000"
	AllowedCIDRs   []string `json:"allowed_cidrs"`
	AllowedPorts   []int    `json:"allowed_ports"`
	AllowedPaths   []string `json:"allowed_paths"`
	BlockedPaths   []string `json:"blocked_paths"`
	AllowedMethods []string `json:"allowed_methods"`

	// Time Window
	StartTime  time.Time `json:"start_time"`
	ExpiryTime time.Time `json:"expiry_time"`

	// Domain Verification & Evidence
	DNSChallengeToken string     `json:"dns_challenge_token,omitempty"`
	DNSVerified       bool       `json:"dns_verified"`
	DNSVerifiedAt     *time.Time `json:"dns_verified_at,omitempty"`

	// Owner / Admin Authorization
	AuthEvidenceRef string         `json:"auth_evidence_ref,omitempty"` // Document hash or agreement ref
	ApproverID      string         `json:"approver_id,omitempty"`
	ApproverRole    string         `json:"approver_role,omitempty"` // e.g. "target_owner", "org_admin"
	ApprovalStatus  ApprovalStatus `json:"approval_status"`
	ApprovedAt      *time.Time     `json:"approved_at,omitempty"`

	// Revocation Status
	IsRevoked        bool       `json:"is_revoked"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GenerateRandomID creates cryptographically secure hex IDs.
func GenerateRandomID(prefix string, bytesLen int) string {
	b := make([]byte, bytesLen)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

// CreateManagedLabRequest defines input for provisioning a managed lab grant.
type CreateManagedLabRequest struct {
	LabInstanceID  string        `json:"lab_instance_id"`
	ContainerID    string        `json:"container_id"`
	UserID         string        `json:"user_id"`
	OrgID          string        `json:"org_id"`
	TargetHost     string        `json:"target_host"`
	TargetPort     int           `json:"target_port"`
	AllowedCIDRs   []string      `json:"allowed_cidrs"`
	AllowedPaths   []string      `json:"allowed_paths"`
	BlockedPaths   []string      `json:"blocked_paths"`
	AllowedMethods []string      `json:"allowed_methods"`
	Duration       time.Duration `json:"duration"`
}

// CreateExternalAssessmentRequest defines input for submitting an external target.
type CreateExternalAssessmentRequest struct {
	UserID         string   `json:"user_id"`
	OrgID          string   `json:"org_id"`
	TargetHost     string   `json:"target_host"`
	TargetPort     int      `json:"target_port"`
	AllowedCIDRs   []string `json:"allowed_cidrs"`
	AllowedPaths   []string `json:"allowed_paths"`
	BlockedPaths   []string `json:"blocked_paths"`
	AllowedMethods []string `json:"allowed_methods"`
	AutoApprove    bool     `json:"auto_approve"`
}

// ApproveAssessmentRequest defines input for approving an external assessment.
type ApproveAssessmentRequest struct {
	AssessmentID    string        `json:"assessment_id"`
	ApproverID      string        `json:"approver_id"`
	ApproverRole    string        `json:"approver_role"`
	ApproverOrgID   string        `json:"approver_org_id,omitempty"`
	AuthEvidenceRef string        `json:"auth_evidence_ref"`
	Duration        time.Duration `json:"duration"`
}

// ValidationRequest defines the parameters passed to validate an in-flight tool request.
type ValidationRequest struct {
	GrantID             string                 `json:"grant_id"`
	AssessmentID        string                 `json:"assessment_id"`
	UserID              string                 `json:"user_id"`
	OrgID               string                 `json:"org_id"`
	TargetURL           string                 `json:"target_url"`
	Method              string                 `json:"method"`
	ClientSuppliedScope map[string]interface{} `json:"client_supplied_scope,omitempty"`
}

// AuthorizationDecision records the validation verdict for auditing.
type AuthorizationDecision struct {
	Allowed   bool      `json:"allowed"`
	GrantID   string    `json:"grant_id,omitempty"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

