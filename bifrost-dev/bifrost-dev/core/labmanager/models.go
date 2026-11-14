package labmanager

import (
	"time"

	"github.com/maximhq/bifrost/core/authmanager"
)

// LabStatus represents the lifecycle state of a managed practice lab.
type LabStatus string

const (
	LabStatusStarting LabStatus = "starting"
	LabStatusRunning  LabStatus = "running"
	LabStatusStopped  LabStatus = "stopped"
	LabStatusFailed   LabStatus = "failed"
)

// LabSession records the state and telemetry of a managed practice lab.
type LabSession struct {
	LabInstanceID    string    `json:"lab_instance_id"`
	ContainerID      string    `json:"container_id"`
	TargetHost       string    `json:"target_host"`
	TargetPort       int       `json:"target_port"`
	TargetURL        string    `json:"target_url"`
	BrowserURL       string    `json:"browser_url"`
	BrowserTargetURL string    `json:"browser_target_url,omitempty"`
	GrantID          string    `json:"grant_id"`
	AssessmentID     string    `json:"assessment_id"`
	UserID           string    `json:"user_id"`
	OrgID            string    `json:"org_id"`
	Status           LabStatus `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	ErrorMessage     string    `json:"error_message,omitempty"`
}

// StartLabRequest defines parameters to start a new managed practice lab.
type StartLabRequest struct {
	UserID         string        `json:"user_id"`
	OrgID          string        `json:"org_id"`
	Duration       time.Duration `json:"duration"`
	AllowedPaths   []string      `json:"allowed_paths,omitempty"`
	BlockedPaths   []string      `json:"blocked_paths,omitempty"`
	AllowedMethods []string      `json:"allowed_methods,omitempty"`
}

// StartLabResponse returns details of the newly created lab session.
type StartLabResponse struct {
	LabSession *LabSession                   `json:"lab_session"`
	Grant      *authmanager.AuthorizationGrant `json:"grant"`
}

// StopLabRequest defines parameters to shut down a practice lab.
type StopLabRequest struct {
	LabInstanceID string `json:"lab_instance_id"`
	Reason        string `json:"reason,omitempty"`
}

// StopLabResponse returns confirmation of shutdown.
type StopLabResponse struct {
	LabInstanceID string `json:"lab_instance_id"`
	ContainerID   string `json:"container_id"`
	GrantID       string `json:"grant_id"`
	Status        string `json:"status"`
	Message       string `json:"message"`
}

// CallerIdentity represents the authenticated identity context of an API caller.
type CallerIdentity struct {
	UserID string `json:"user_id"`
	OrgID  string `json:"org_id"`
	Role   string `json:"role"` // "admin", "org-admin", "user"
}


