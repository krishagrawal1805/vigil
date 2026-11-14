package labmanager

import (
	"os"
	"testing"
)

func TestSessionStore_NormalMode(t *testing.T) {
	// Ensure test mode is OFF
	_ = os.Unsetenv("BIFROST_TEST_MODE")
	_ = os.Unsetenv("BIFROST_ENV")

	store := &TenantSessionStore{
		tokens: make(map[string]CallerIdentity),
	}

	testTokens := []string{
		"token-alice",
		"token-bob",
		"token-carol-admin",
		"token-mallory",
		"token-unregistered-evil",
	}

	for _, tok := range testTokens {
		if id, ok := store.ResolveToken(tok); ok {
			t.Fatalf("CRITICAL SECURITY FAILURE: Token %q resolved in normal mode: %+v", tok, id)
		}
	}
}

func TestSessionStore_ProductionSafety(t *testing.T) {
	_ = os.Setenv("BIFROST_ENV", "production")
	_ = os.Setenv("BIFROST_TEST_MODE", "true")
	defer func() {
		_ = os.Unsetenv("BIFROST_ENV")
		_ = os.Unsetenv("BIFROST_TEST_MODE")
	}()

	err := CheckProductionSafety()
	if err == nil {
		t.Fatalf("CRITICAL SECURITY FAILURE: Expected CheckProductionSafety to fail when BIFROST_TEST_MODE=true in production!")
	}

	store := &TenantSessionStore{
		tokens: make(map[string]CallerIdentity),
	}
	err = store.EnableTestCredentialsForTesting()
	if err == nil {
		t.Fatalf("CRITICAL SECURITY FAILURE: EnableTestCredentialsForTesting should fail in production!")
	}
}

func TestSessionStore_TestModeAllowed(t *testing.T) {
	_ = os.Setenv("BIFROST_ENV", "development")
	_ = os.Setenv("BIFROST_TEST_MODE", "true")
	defer func() {
		_ = os.Unsetenv("BIFROST_ENV")
		_ = os.Unsetenv("BIFROST_TEST_MODE")
	}()

	store := &TenantSessionStore{
		tokens: make(map[string]CallerIdentity),
	}
	err := store.EnableTestCredentialsForTesting()
	if err != nil {
		t.Fatalf("Expected EnableTestCredentialsForTesting to succeed in dev test mode: %v", err)
	}

	alice, ok := store.ResolveToken("token-alice")
	if !ok || alice.UserID != "user-alice" || alice.OrgID != "org-cyber-range" {
		t.Fatalf("Failed to resolve token-alice in test mode: %+v", alice)
	}

	mallory, ok := store.ResolveToken("token-mallory")
	if !ok || mallory.UserID != "attacker-mallory" || mallory.OrgID != "org-attacker" {
		t.Fatalf("Failed to resolve token-mallory in test mode: %+v", mallory)
	}
}

func TestSessionStore_CustomRegistration(t *testing.T) {
	store := &TenantSessionStore{
		tokens: make(map[string]CallerIdentity),
	}

	store.RegisterToken("custom-token-123", CallerIdentity{
		UserID: "custom-user",
		OrgID:  "custom-org",
		Role:   "user",
	})

	id, ok := store.ResolveToken("custom-token-123")
	if !ok || id.UserID != "custom-user" || id.OrgID != "custom-org" {
		t.Fatalf("Custom token did not resolve correctly: %+v", id)
	}

	store.ClearTokens()
	if _, ok := store.ResolveToken("custom-token-123"); ok {
		t.Fatalf("Token resolved after ClearTokens()")
	}
}

