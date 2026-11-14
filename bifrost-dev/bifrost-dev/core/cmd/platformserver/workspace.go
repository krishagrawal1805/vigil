package main

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/authmanager"
)

// Workspace represents an isolated security testing environment or engagement.
type Workspace struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	OrgID       string    `json:"org_id"`
	TargetHosts []string  `json:"target_hosts"`
	CreatedAt   time.Time `json:"created_at"`
}

// WorkspaceStore manages engagement workspaces per organization.
type WorkspaceStore struct {
	mu         sync.RWMutex
	workspaces map[string]*Workspace
}

var (
	globalWorkspaceStore     *WorkspaceStore
	globalWorkspaceStoreOnce sync.Once
)

// GetGlobalWorkspaceStore returns the singleton workspace store.
func GetGlobalWorkspaceStore() *WorkspaceStore {
	globalWorkspaceStoreOnce.Do(func() {
		globalWorkspaceStore = &WorkspaceStore{
			workspaces: make(map[string]*Workspace),
		}
		globalWorkspaceStore.seedDefaultWorkspaces()
	})
	return globalWorkspaceStore
}

func (s *WorkspaceStore) seedDefaultWorkspaces() {
	ws := &Workspace{
		ID:          "ws-primary-engagement",
		Name:        "Primary Enterprise Assessment Workspace",
		Description: "Authorized testing scope for local practice lab and verified enterprise targets",
		OrgID:       "org-cyber-defense",
		TargetHosts: []string{"127.0.0.1", "localhost"},
		CreatedAt:   time.Now().UTC(),
	}
	s.workspaces[ws.ID] = ws
}

// ListWorkspaces returns workspaces filtered by the caller's organization.
func (s *WorkspaceStore) ListWorkspaces(orgID string, isAdmin bool) []*Workspace {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]*Workspace, 0)
	for _, ws := range s.workspaces {
		if isAdmin || ws.OrgID == orgID {
			result = append(result, ws)
		}
	}
	if len(result) == 0 && orgID != "" {
		ws := &Workspace{
			ID:          authmanager.GenerateRandomID("ws", 6),
			Name:        fmt.Sprintf("Default Workspace (%s)", orgID),
			Description: "Default tenant engagement workspace for authorized penetration testing",
			OrgID:       orgID,
			TargetHosts: []string{"127.0.0.1", "localhost"},
			CreatedAt:   time.Now().UTC(),
		}
		s.workspaces[ws.ID] = ws
		result = append(result, ws)
	}
	return result
}

// CreateWorkspace creates a new tenant-isolated workspace.
func (s *WorkspaceStore) CreateWorkspace(name, description, orgID string, targetHosts []string) (*Workspace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("workspace name is required")
	}

	ws := &Workspace{
		ID:          authmanager.GenerateRandomID("ws", 6),
		Name:        name,
		Description: description,
		OrgID:       orgID,
		TargetHosts: targetHosts,
		CreatedAt:   time.Now().UTC(),
	}

	s.workspaces[ws.ID] = ws
	return ws, nil
}

// GetWorkspace retrieves a workspace by ID.
func (s *WorkspaceStore) GetWorkspace(workspaceID string) (*Workspace, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ws, ok := s.workspaces[workspaceID]
	if !ok {
		return nil, fmt.Errorf("workspace %q not found", workspaceID)
	}
	return ws, nil
}

