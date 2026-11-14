package assessment

import (
	"time"
)

// AssessmentState defines the lifecycle state of an autonomous security assessment.
type AssessmentState string

const (
	StateQueued    AssessmentState = "queued"
	StateStarting  AssessmentState = "starting"
	StateRunning   AssessmentState = "running"
	StateCompleted AssessmentState = "completed"
	StateFailed    AssessmentState = "failed"
	StateCancelled AssessmentState = "cancelled"
	StateBlocked   AssessmentState = "blocked"
)

// Finding represents a validated or potential security finding detected during assessment.
type Finding struct {
	ID                 string    `json:"id"`
	AssessmentID       string    `json:"assessment_id"`
	RunID              string    `json:"run_id"`
	Target             string    `json:"target"`
	Title              string    `json:"title"`
	Severity           string    `json:"severity"` // "Critical", "High", "Medium", "Low", "Informational"
	Category           string    `json:"category"`
	CWE                string    `json:"cwe"`
	AffectedURL        string    `json:"affected_url"`
	Method             string    `json:"method"`
	Parameter          string    `json:"parameter,omitempty"`
	Evidence           string    `json:"evidence"`
	VerificationStatus string    `json:"verification"` // "Confirmed", "Potential"
	Confidence         string    `json:"confidence"`   // "High", "Medium", "Low"
	Description        string    `json:"description"`
	Recommendation     string    `json:"recommendation"`
	RemediationTime    string    `json:"remediation_time"`
	DiscoveredAt               any       `json:"discovered_at"`
	AffectedInstances          any       `json:"affected_instances,omitempty"`
	CorroboratedToolInvocation string    `json:"corroborated_tool_invocation,omitempty"`
	ValidatorDecisionID        string    `json:"validator_decision_id,omitempty"`
	EvidenceRecordID           string    `json:"evidence_record_id,omitempty"`
	HypothesisID               string    `json:"hypothesis_id,omitempty"`
	NegativeControl            string    `json:"negative_control,omitempty"`
	Counterevidence            string    `json:"counterevidence,omitempty"`
	CanonicalURL               string    `json:"canonical_url,omitempty"`
}

// ToolExecutionSummary aggregates execution counts and outcomes for a tool.
type ToolExecutionSummary struct {
	Tool        string `json:"tool"`
	Invocations int    `json:"invocations"`
	Status      string `json:"status"` // "success", "blocked", "failed"
}

// ToolInvocationRecord records an individual security capability tool execution with genuine telemetry.
type ToolInvocationRecord struct {
	InvocationID    string `json:"invocation_id"`
	TaskID          string `json:"task_id,omitempty"`
	AssessmentID    string `json:"assessment_id,omitempty"`
	RunID           string `json:"run_id,omitempty"`
	Tool            string `json:"tool"`
	Target          string `json:"target"`
	Method          string `json:"method,omitempty"`
	ExecutionStatus string `json:"execution_status"` // "SUCCESS", "FAILED", "BLOCKED", "ERROR"
	SecurityOutcome string `json:"security_outcome"` // "CONFIRMED", "RULED_OUT", "INCONCLUSIVE", "NOT_EVALUATED"
	IsError         bool   `json:"is_error"`
	Confirmed       bool   `json:"confirmed"`
	Details         string `json:"details,omitempty"`
	Timestamp       string `json:"timestamp"`
}

// BlockedScopeViolation records an unauthorized or out-of-scope request blocked by ScopeEnforcer.
type BlockedScopeViolation struct {
	TargetURL string `json:"target_url"`
	Reason    string `json:"reason"`
	Timestamp string `json:"timestamp"`
}

// AssessmentRun captures the complete state and results of an autonomous penetration testing mission.
type AssessmentRun struct {
	RunID               string                  `json:"run_id"`
	AssessmentID        string                  `json:"assessment_id"`
	GrantID             string                  `json:"grant_id"`
	UserID              string                  `json:"user_id"`
	OrgID               string                  `json:"org_id"`
	TargetURL           string                  `json:"target"`
	Status              AssessmentState         `json:"status"`
	StartTime           time.Time               `json:"start_time"`
	EndTime             *time.Time              `json:"end_time,omitempty"`
	DurationSeconds     int                     `json:"duration_seconds"`
	AgentModel          string                  `json:"agent_model"`
	Mode                string                  `json:"mode,omitempty"`
	Concurrency         int                     `json:"concurrency,omitempty"`
	TurnsExecuted       int                     `json:"turns_executed"`
	Scope               map[string]any          `json:"scope"`
	ToolsExecuted       []ToolExecutionSummary  `json:"tools_executed"`
	DiscoveredEndpoints []string                `json:"discovered_endpoints,omitempty"`
	ToolInvocations     []ToolInvocationRecord  `json:"tool_invocations,omitempty"`
	Hypotheses          []any                   `json:"hypotheses,omitempty"`
	BlockedRequests     []BlockedScopeViolation `json:"blocked_requests"`
	Findings            []Finding               `json:"findings"`
	FinalReport        string                  `json:"final_report,omitempty"`
	ErrorMessage       string                  `json:"error_message,omitempty"`
	CancellationReason string                  `json:"cancellation_reason,omitempty"`
	PID                int                     `json:"pid,omitempty"`
	CreatedAt          time.Time               `json:"created_at"`
	UpdatedAt          time.Time               `json:"updated_at"`
}

