package main

import (
	"strings"
	"testing"
)

func TestPBKDF2_600000IterationsDefault(t *testing.T) {
	store := GetGlobalUserStore()

	user, err := store.RegisterUser("secure-pentester-600k", "pentester@defense.org", "MyStrongPass2026!", "org-defense", "pentester", false)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if user.Iterations != CurrentPBKDF2Iterations {
		t.Fatalf("Expected %d iterations for new user, got %d", CurrentPBKDF2Iterations, user.Iterations)
	}
	if user.Iterations != 600000 {
		t.Fatalf("Expected exactly 600,000 iterations, got %d", user.Iterations)
	}

	// Authenticate and verify iterations remain 600k
	authUser, token, err := store.Authenticate("secure-pentester-600k", "MyStrongPass2026!")
	if err != nil || token == "" {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if authUser.Iterations != 600000 {
		t.Fatalf("Expected 600,000 iterations after auth, got %d", authUser.Iterations)
	}
}

func TestPBKDF2_TransparentHashMigration(t *testing.T) {
	store := GetGlobalUserStore()

	// 1. Register a user
	username := "legacy-user-100k"
	rawPassword := "LegacyPassword2026!"
	_, err := store.RegisterUser(username, "legacy@defense.org", rawPassword, "org-defense", "pentester", false)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Downgrade hash and iterations to simulate pre-migration account
	store.SetUserIterationsForTesting(username, LegacyPBKDF2Iterations, rawPassword)

	// Verify user is in legacy state
	u, _ := store.GetUserByUsername(username)
	if u.Iterations != 100000 {
		t.Fatalf("Expected legacy user to have 100000 iterations, got %d", u.Iterations)
	}
	originalLegacyHash := u.PasswordHash

	// 2. User logs in with legitimate password -> triggers transparent upgrade
	authUser, token, err := store.Authenticate(username, rawPassword)
	if err != nil {
		t.Fatalf("Legacy user authentication failed during migration: %v", err)
	}
	if token == "" {
		t.Fatalf("Expected non-empty JWT token for migrated user")
	}

	// 3. Verify user's hash was transparently upgraded to 600,000 iterations
	if authUser.Iterations != CurrentPBKDF2Iterations {
		t.Fatalf("Expected upgraded user iterations %d, got %d", CurrentPBKDF2Iterations, authUser.Iterations)
	}
	if authUser.PasswordHash == originalLegacyHash {
		t.Fatalf("Expected PasswordHash to be recomputed with new salt and iterations")
	}

	// 4. Verify subsequent logins authenticate against the upgraded 600,000-iteration hash
	uAfter, _ := store.GetUserByUsername(username)
	if uAfter.Iterations != 600000 {
		t.Fatalf("Expected stored user iterations to persist as 600000, got %d", uAfter.Iterations)
	}

	authUser2, _, err := store.Authenticate(username, rawPassword)
	if err != nil || authUser2.Iterations != 600000 {
		t.Fatalf("Subsequent auth after migration failed: %v", err)
	}
}

func TestBootstrapAdmin_Workflow(t *testing.T) {
	store := GetGlobalUserStore()

	// Manually initialize bootstrap token as in production
	store.mu.Lock()
	store.bootstrapToken = "test-bootstrap-token-secure-xyz"
	store.mu.Unlock()

	// 1. Invalid token should fail
	_, err := store.BootstrapAdmin("wrong-token", "prod-admin", "AdminPass2026!", "admin@enterprise.org")
	if err == nil {
		t.Fatalf("Expected error with wrong bootstrap token")
	}

	// 2. Valid token creates admin with 600,000 iterations
	adminUser, err := store.BootstrapAdmin("test-bootstrap-token-secure-xyz", "prod-admin", "AdminPass2026!", "admin@enterprise.org")
	if err != nil {
		t.Fatalf("BootstrapAdmin failed: %v", err)
	}
	if adminUser.Username != "prod-admin" || adminUser.Role != RoleAdmin {
		t.Fatalf("Unexpected admin user: %+v", adminUser)
	}
	if adminUser.Iterations != 600000 {
		t.Fatalf("Expected 600,000 iterations for bootstrapped admin, got %d", adminUser.Iterations)
	}

	// 3. Second attempt with same token must fail (single-use token consumed)
	_, err = store.BootstrapAdmin("test-bootstrap-token-secure-xyz", "prod-admin-2", "AdminPass2026!", "admin2@enterprise.org")
	if err == nil || !strings.Contains(err.Error(), "already provisioned") {
		t.Fatalf("Expected token reuse to be blocked, got: %v", err)
	}
}
