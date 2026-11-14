package labmanager

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// TenantSessionStore manages authenticated session identities for multi-tenant users.
type TenantSessionStore struct {
	mu     sync.RWMutex
	tokens map[string]CallerIdentity // token -> identity
}

var (
	globalTenantSessionStore     *TenantSessionStore
	globalTenantSessionStoreOnce sync.Once
)

// IsTestModeEnabled checks whether test mode is explicitly enabled.
func IsTestModeEnabled() bool {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("BIFROST_TEST_MODE")))
	return mode == "true" || mode == "1" || mode == "yes"
}

// CheckProductionSafety ensures that test mode cannot be active in a production environment.
func CheckProductionSafety() error {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("BIFROST_ENV")))
	if env == "production" && IsTestModeEnabled() {
		return fmt.Errorf("CRITICAL SECURITY CONFIGURATION ERROR: BIFROST_TEST_MODE cannot be enabled in production environment (BIFROST_ENV=production)")
	}
	return nil
}

func loadTestCredentials(s *TenantSessionStore) {
	s.tokens["token-alice"] = CallerIdentity{
		UserID: "user-alice",
		OrgID:  "org-cyber-range",
		Role:   "user",
	}
	s.tokens["token-bob"] = CallerIdentity{
		UserID: "user-bob",
		OrgID:  "org-cyber-range",
		Role:   "user",
	}
	s.tokens["token-carol-admin"] = CallerIdentity{
		UserID: "admin-carol",
		OrgID:  "org-cyber-range",
		Role:   "org-admin",
	}
	s.tokens["token-mallory"] = CallerIdentity{
		UserID: "attacker-mallory",
		OrgID:  "org-attacker",
		Role:   "user",
	}
}

// GetGlobalTenantSessionStore returns the singleton session store.
// In normal mode (BIFROST_TEST_MODE not set or false), no hardcoded test credentials are loaded.
func GetGlobalTenantSessionStore() *TenantSessionStore {
	globalTenantSessionStoreOnce.Do(func() {
		if err := CheckProductionSafety(); err != nil {
			panic(err)
		}
		globalTenantSessionStore = &TenantSessionStore{
			tokens: make(map[string]CallerIdentity),
		}
		if IsTestModeEnabled() {
			loadTestCredentials(globalTenantSessionStore)
		}
	})
	return globalTenantSessionStore
}

// EnableTestCredentialsForTesting explicitly populates test credentials if permitted.
func (s *TenantSessionStore) EnableTestCredentialsForTesting() error {
	if err := CheckProductionSafety(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	loadTestCredentials(s)
	return nil
}

// ClearTokens removes all tokens from the store.
func (s *TenantSessionStore) ClearTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = make(map[string]CallerIdentity)
}

// RegisterToken binds a session token to a verified CallerIdentity.
func (s *TenantSessionStore) RegisterToken(token string, id CallerIdentity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = id
}

// ResolveToken returns the CallerIdentity associated with a token.
func (s *TenantSessionStore) ResolveToken(token string) (CallerIdentity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.tokens[token]
	return id, ok
}
