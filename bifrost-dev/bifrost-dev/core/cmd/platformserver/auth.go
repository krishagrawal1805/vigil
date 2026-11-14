package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/maximhq/bifrost/core/authmanager"
	"github.com/maximhq/bifrost/core/labmanager"
	"golang.org/x/crypto/pbkdf2"
)

// Role definitions
const (
	RoleAdmin           = "admin"
	RoleOrgAdmin        = "org-admin"
	RoleSecurityOfficer = "security_officer"
	RolePentester       = "pentester"
	RoleAuditor         = "auditor"
)

// Protected organizations that public users cannot self-assign
var ProtectedOrgs = map[string]bool{
	"org-cyber-defense": true,
	"system-admin-org":  true,
}

// User represents an authenticated identity in the independent platform.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Name         string    `json:"name,omitempty"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Salt         string    `json:"-"`
	Iterations   int       `json:"iterations,omitempty"`
	OrgID        string    `json:"org_id"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

// persistentUserRecord handles atomic on-disk storage of user credentials.
// It explicitly stores PasswordHash and Salt to survive service restarts while keeping them hidden from HTTP JSON output.
type persistentUserRecord struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Name         string    `json:"name,omitempty"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash"`
	Salt         string    `json:"salt"`
	Iterations   int       `json:"iterations,omitempty"`
	OrgID        string    `json:"org_id"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

// UserClaims represents JWT claims for platform authentication.
type UserClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	OrgID    string `json:"org_id"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// UserStore manages users and sessions with thread safety and persistent revocation.
type UserStore struct {
	mu             sync.RWMutex
	usersByID      map[string]*User
	usersByName    map[string]*User
	revokedTokens  map[string]time.Time // token -> revocation time
	revocationsDir string
	jwtSecret      []byte
	bootstrapToken string
}

const (
	CurrentPBKDF2Iterations = 600000 // OWASP-recommended standard
	LegacyPBKDF2Iterations  = 100000 // Legacy backward compatibility
)

var (
	globalUserStore     *UserStore
	globalUserStoreOnce sync.Once
)

// GetGlobalUserStore returns the singleton user store.
func GetGlobalUserStore() *UserStore {
	globalUserStoreOnce.Do(func() {
		secret := os.Getenv("PLATFORM_JWT_SECRET")
		if secret == "" {
			secret = "enterprise-autonomous-pentest-platform-secret-key-2026"
		}
		dataDir := os.Getenv("PLATFORM_DATA_DIR")
		revDir := filepath.Join(os.TempDir(), "platform_sessions")
		if dataDir != "" {
			revDir = filepath.Join(dataDir, "sessions")
		}
		_ = os.MkdirAll(revDir, 0755)

		globalUserStore = &UserStore{
			usersByID:      make(map[string]*User),
			usersByName:    make(map[string]*User),
			revokedTokens:  make(map[string]time.Time),
			revocationsDir: revDir,
			jwtSecret:      []byte(secret),
		}
		globalUserStore.loadPersistentRevocations()
		globalUserStore.loadPersistentUsers()
		globalUserStore.seedDefaultUsers()
	})
	return globalUserStore
}

// hashPasswordWithIterations generates PBKDF2-HMAC-SHA256 hash using the specified iteration count.
func hashPasswordWithIterations(password, salt string, iterations int) string {
	if iterations <= 0 {
		iterations = CurrentPBKDF2Iterations
	}
	derivedKey := pbkdf2.Key([]byte(password), []byte(salt), iterations, 32, sha256.New)
	return hex.EncodeToString(derivedKey)
}

// hashPassword creates a cryptographic PBKDF2-HMAC-SHA256 password hash using current 600,000 iterations.
func hashPassword(password, salt string) string {
	return hashPasswordWithIterations(password, salt, CurrentPBKDF2Iterations)
}

// generateSalt returns a 16-byte cryptographically secure random salt hex string.
func generateSalt() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// loadPersistentRevocations restores revoked tokens from disk.
func (s *UserStore) loadPersistentRevocations() {
	path := filepath.Join(s.revocationsDir, "revoked_tokens.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var stored map[string]string
	if err := json.Unmarshal(data, &stored); err != nil {
		return
	}
	now := time.Now().UTC()
	for tok, expStr := range stored {
		if t, err := time.Parse(time.RFC3339, expStr); err == nil {
			// Retain if revocation occurred within last 7 days
			if now.Sub(t) < 7*24*time.Hour {
				s.revokedTokens[tok] = t
			}
		}
	}
	log.Printf("[platform-auth] Loaded %d persistent token revocations from disk", len(s.revokedTokens))
}

// savePersistentRevocations writes revoked tokens to disk atomically.
func (s *UserStore) savePersistentRevocations() {
	path := filepath.Join(s.revocationsDir, "revoked_tokens.json")
	stored := make(map[string]string, len(s.revokedTokens))
	for tok, t := range s.revokedTokens {
		stored[tok] = t.Format(time.RFC3339)
	}
	data, err := json.MarshalIndent(stored, "", "  ")
	if err == nil {
		_ = os.WriteFile(path, data, 0600)
	}
}

// loadPersistentUsers restores registered user accounts from disk.
func (s *UserStore) loadPersistentUsers() {
	path := filepath.Join(s.revocationsDir, "users.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var records []persistentUserRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return
	}
	for _, r := range records {
		if r.ID != "" && r.Username != "" {
			u := &User{
				ID:           r.ID,
				Username:     r.Username,
				Name:         r.Name,
				Email:        r.Email,
				PasswordHash: r.PasswordHash,
				Salt:         r.Salt,
				Iterations:   r.Iterations,
				OrgID:        r.OrgID,
				Role:         r.Role,
				CreatedAt:    r.CreatedAt,
			}
			s.usersByID[u.ID] = u
			s.usersByName[strings.ToLower(u.Username)] = u
		}
	}
	log.Printf("[platform-auth] Loaded %d persistent users from disk", len(records))
}

// savePersistentUsers writes user accounts to disk atomically with persistent hashes and salts.
func (s *UserStore) savePersistentUsers() {
	path := filepath.Join(s.revocationsDir, "users.json")
	records := make([]persistentUserRecord, 0, len(s.usersByID))
	for _, u := range s.usersByID {
		records = append(records, persistentUserRecord{
			ID:           u.ID,
			Username:     u.Username,
			Name:         u.Name,
			Email:        u.Email,
			PasswordHash: u.PasswordHash,
			Salt:         u.Salt,
			Iterations:   u.Iterations,
			OrgID:        u.OrgID,
			Role:         u.Role,
			CreatedAt:    u.CreatedAt,
		})
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err == nil {
		_ = os.WriteFile(path, data, 0600)
	}
}

// seedDefaultUsers initializes pre-configured organizational users for enterprise testing,
// or triggers secure initial administrator bootstrap in production mode.
func (s *UserStore) seedDefaultUsers() {
	allowDemo := true // Always seed platform accounts for demo & assessment access

	if !allowDemo {
		log.Printf("[platform-auth] Production environment detected: hardcoded demo credentials disabled")
		s.ensureProductionAdmin()
		return
	}

	defaults := []struct {
		id       string
		username string
		email    string
		password string
		orgID    string
		role     string
	}{
		{
			id:       "usr-admin-01",
			username: "admin",
			email:    "admin@cyberdefense.internal",
			password: "AdminPassword2026!",
			orgID:    "org-cyber-defense",
			role:     RoleAdmin,
		},
		{
			id:       "usr-pentester-krish",
			username: "krish",
			email:    "krish@cyberdefense.internal",
			password: "AdminPassword2026!",
			orgID:    "org-krish",
			role:     RolePentester,
		},
		{
			id:       "usr-secofficer-01",
			username: "security-officer",
			email:    "secofficer@cyberdefense.internal",
			password: "SecOfficerPassword2026!",
			orgID:    "org-cyber-defense",
			role:     RoleSecurityOfficer,
		},
		{
			id:       "usr-pentester-01",
			username: "pentester-alice",
			email:    "alice@cyberdefense.internal",
			password: "PentesterPassword2026!",
			orgID:    "org-cyber-defense",
			role:     RolePentester,
		},
		{
			id:       "usr-pentester-02",
			username: "charlie",
			email:    "charlie@cyberdefense.internal",
			password: "CharlieSecret2026!",
			orgID:    "org-cyber-defense",
			role:     RolePentester,
		},
		{
			id:       "usr-auditor-01",
			username: "auditor-bob",
			email:    "bob@cyberdefense.internal",
			password: "AuditorPassword2026!",
			orgID:    "org-cyber-defense",
			role:     RoleAuditor,
		},
	}

	for _, d := range defaults {
		salt := generateSalt()
		u := &User{
			ID:           d.id,
			Username:     d.username,
			Email:        d.email,
			PasswordHash: hashPasswordWithIterations(d.password, salt, CurrentPBKDF2Iterations),
			Salt:         salt,
			Iterations:   CurrentPBKDF2Iterations,
			OrgID:        d.orgID,
			Role:         d.role,
			CreatedAt:    time.Now().UTC(),
		}
		s.usersByID[u.ID] = u
		s.usersByName[strings.ToLower(u.Username)] = u
	}
	s.savePersistentUsers()
	log.Printf("[platform-auth] Seeded %d development demo accounts (600k PBKDF2-HMAC-SHA256 iterations)", len(defaults))
}

// ensureProductionAdmin guarantees that production deployments have an administrator setup mechanism.
func (s *UserStore) ensureProductionAdmin() {
	for _, u := range s.usersByID {
		if u.Role == RoleAdmin {
			return
		}
	}

	initialPass := os.Getenv("PLATFORM_INITIAL_ADMIN_PASSWORD")
	if initialPass != "" {
		salt := generateSalt()
		adminUser := &User{
			ID:           "usr-admin-prod-01",
			Username:     "admin",
			Email:        "admin@enterprise.internal",
			PasswordHash: hashPasswordWithIterations(initialPass, salt, CurrentPBKDF2Iterations),
			Salt:         salt,
			Iterations:   CurrentPBKDF2Iterations,
			OrgID:        "org-cyber-defense",
			Role:         RoleAdmin,
			CreatedAt:    time.Now().UTC(),
		}
		s.usersByID[adminUser.ID] = adminUser
		s.usersByName["admin"] = adminUser
		log.Printf("[platform-auth] Initial production administrator provisioned from environment credentials")
		return
	}

	initialToken := os.Getenv("PLATFORM_INITIAL_ADMIN_TOKEN")
	if initialToken == "" {
		initialToken = authmanager.GenerateRandomID("boot-admin", 16)
	}
	s.bootstrapToken = initialToken
	bootstrapFile := filepath.Join(s.revocationsDir, "initial_admin_bootstrap_token.txt")
	_ = os.WriteFile(bootstrapFile, []byte(initialToken), 0600)
	log.Printf("================================================================================")
	log.Printf("[SECURITY WARNING] No production administrator found!")
	log.Printf("[SECURITY NOTICE] One-time bootstrap token generated (redacted in logs; read from disk or env)")
	log.Printf("[SECURITY NOTICE] Saved to %s. Use POST /api/v1/auth/bootstrap-admin to initialize.", bootstrapFile)
	log.Printf("================================================================================")
}

// BootstrapAdmin registers the initial production administrator using the one-time bootstrap token.
func (s *UserStore) BootstrapAdmin(token, username, password, email string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.bootstrapToken == "" {
		return nil, fmt.Errorf("bootstrap token not active or administrator already provisioned")
	}

	if subtle.ConstantTimeCompare([]byte(token), []byte(s.bootstrapToken)) != 1 {
		return nil, fmt.Errorf("invalid bootstrap token")
	}

	if len(password) < 12 {
		return nil, fmt.Errorf("production administrator password must be at least 12 characters")
	}

	salt := generateSalt()
	uid := authmanager.GenerateRandomID("usr-admin", 6)
	adminUser := &User{
		ID:           uid,
		Username:     username,
		Email:        email,
		PasswordHash: hashPasswordWithIterations(password, salt, CurrentPBKDF2Iterations),
		Salt:         salt,
		Iterations:   CurrentPBKDF2Iterations,
		OrgID:        "org-cyber-defense",
		Role:         RoleAdmin,
		CreatedAt:    time.Now().UTC(),
	}

	s.usersByID[adminUser.ID] = adminUser
	s.usersByName[strings.ToLower(username)] = adminUser
	s.bootstrapToken = "" // Burn the one-time token immediately
	s.savePersistentUsers()

	bootstrapFile := filepath.Join(s.revocationsDir, "initial_admin_bootstrap_token.txt")
	_ = os.Remove(bootstrapFile)

	log.Printf("[platform-auth] Production administrator %q provisioned successfully via one-time bootstrap token", username)
	return adminUser, nil
}

// RegisterUser creates a new user account with PBKDF2-HMAC-SHA256 password hashing.
// isPublic enforces that privileged roles and protected organizations cannot be self-claimed.
func (s *UserStore) RegisterUser(username, email, password, orgID, role string, isPublic bool) (*User, error) {
	return s.RegisterUserWithName("", username, email, password, orgID, role, isPublic)
}

// RegisterUserWithName registers a user while supporting display name alongside unique username.
func (s *UserStore) RegisterUserWithName(name, username, email, password, orgID, role string, isPublic bool) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name = strings.TrimSpace(name)
	username = strings.TrimSpace(username)
	email = strings.TrimSpace(email)
	orgID = strings.TrimSpace(orgID)
	role = strings.TrimSpace(strings.ToLower(role))

	// If username was not provided but name was, auto-generate a valid unique username from name
	if username == "" && name != "" {
		cleaned := strings.ToLower(regexp.MustCompile(`[^a-zA-Z0-9_-]`).ReplaceAllString(name, ""))
		if cleaned == "" {
			cleaned = "operator"
		}
		candidate := cleaned
		counter := 1
		for {
			if _, exists := s.usersByName[candidate]; !exists {
				username = candidate
				break
			}
			candidate = fmt.Sprintf("%s_%d", cleaned, counter)
			counter++
		}
	}

	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}

	if isPublic {
		// Strict Security Control: Prevent privilege escalation via public registration
		if role == RoleAdmin || role == RoleOrgAdmin || role == RoleSecurityOfficer {
			return nil, fmt.Errorf("forbidden: privileged roles (%s) cannot be claimed via public registration; administrator provisioning required", role)
		}
		// Strict Security Control: Prevent joining protected organizations without admin invite
		if ProtectedOrgs[orgID] {
			return nil, fmt.Errorf("forbidden: cannot self-assign to protected organization %q", orgID)
		}
		if orgID == "" {
			orgID = fmt.Sprintf("org-%s", strings.ToLower(username))
		}
		if role == "" {
			role = RolePentester
		}
	} else {
		if orgID == "" {
			orgID = "org-default"
		}
		if role == "" {
			role = RolePentester
		}
	}

	// Validate allowed roles
	validRoles := map[string]bool{
		RoleAdmin:           true,
		RoleOrgAdmin:        true,
		RoleSecurityOfficer: true,
		RolePentester:       true,
		RoleAuditor:         true,
	}
	if !validRoles[role] {
		return nil, fmt.Errorf("invalid role %q; must be one of: admin, org-admin, security_officer, pentester, auditor", role)
	}

	lowerName := strings.ToLower(username)
	if existing, exists := s.usersByName[lowerName]; exists {
		// Auto-recovery for accounts that lost their password hash due to previous un-hashed persistence bug
		if existing.PasswordHash == "" {
			salt := generateSalt()
			existing.PasswordHash = hashPasswordWithIterations(password, salt, CurrentPBKDF2Iterations)
			existing.Salt = salt
			existing.Iterations = CurrentPBKDF2Iterations
			if name != "" {
				existing.Name = name
			}
			if email != "" {
				existing.Email = email
			}
			s.savePersistentUsers()
			log.Printf("[platform-auth] Successfully recovered/claimed un-hashed account %q with new credentials", existing.Username)
			return existing, nil
		}
		return nil, fmt.Errorf("username %q is already taken. Display names can be shared, but sign-in usernames must be unique. Please choose a different username (e.g. %s_1) or sign in.", username, username)
	}

	salt := generateSalt()
	uid := authmanager.GenerateRandomID("usr", 6)
	user := &User{
		ID:           uid,
		Username:     username,
		Name:         name,
		Email:        email,
		PasswordHash: hashPasswordWithIterations(password, salt, CurrentPBKDF2Iterations),
		Salt:         salt,
		Iterations:   CurrentPBKDF2Iterations,
		OrgID:        orgID,
		Role:         role,
		CreatedAt:    time.Now().UTC(),
	}

	s.usersByID[user.ID] = user
	s.usersByName[lowerName] = user
	s.savePersistentUsers()

	return user, nil
}

// Authenticate validates user credentials using PBKDF2-HMAC-SHA256 and returns signed JWT token.
// Preserves existing accounts through safe hash migration from legacy 100k to 600k iterations.
func (s *UserStore) Authenticate(username, password string) (*User, string, error) {
	s.mu.RLock()
	user, exists := s.usersByName[strings.ToLower(strings.TrimSpace(username))]
	s.mu.RUnlock()

	if !exists {
		return nil, "", fmt.Errorf("invalid username or password")
	}

	// Auto-recovery: If an account has an empty password hash (e.g. from previous persistence serialization bug),
	// allow setting/authenticating with the supplied valid password (>= 8 chars).
	if user.PasswordHash == "" && len(password) >= 8 {
		newSalt := generateSalt()
		newHash := hashPasswordWithIterations(password, newSalt, CurrentPBKDF2Iterations)
		s.mu.Lock()
		user.Salt = newSalt
		user.PasswordHash = newHash
		user.Iterations = CurrentPBKDF2Iterations
		s.mu.Unlock()
		s.savePersistentUsers()
		log.Printf("[platform-auth] Auto-recovered un-hashed account %q upon login", user.Username)
	}

	iters := user.Iterations
	if iters <= 0 {
		iters = LegacyPBKDF2Iterations // Legacy accounts without recorded iterations used 100,000
	}

	expectedHash := hashPasswordWithIterations(password, user.Salt, iters)
	matched := subtle.ConstantTimeCompare([]byte(user.PasswordHash), []byte(expectedHash)) == 1

	// Fallback check against 600k if legacy check didn't match
	if !matched && iters != CurrentPBKDF2Iterations {
		expectedCurrent := hashPasswordWithIterations(password, user.Salt, CurrentPBKDF2Iterations)
		if subtle.ConstantTimeCompare([]byte(user.PasswordHash), []byte(expectedCurrent)) == 1 {
			matched = true
			iters = CurrentPBKDF2Iterations
		}
	}

	if !matched {
		return nil, "", fmt.Errorf("invalid username or password")
	}

	// Safe Hash Migration: Transparently upgrade legacy 100k iteration hash to 600k iterations upon successful login
	if iters < CurrentPBKDF2Iterations {
		newSalt := generateSalt()
		newHash := hashPasswordWithIterations(password, newSalt, CurrentPBKDF2Iterations)
		s.mu.Lock()
		user.Salt = newSalt
		user.PasswordHash = newHash
		user.Iterations = CurrentPBKDF2Iterations
		s.mu.Unlock()
		s.savePersistentUsers()
		log.Printf("[platform-auth] Safely migrated user %q password hash from %d to %d PBKDF2 iterations", user.Username, iters, CurrentPBKDF2Iterations)
	}

	// Generate JWT Token
	claims := UserClaims{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		OrgID:    user.OrgID,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(24 * time.Hour)),
			Issuer:    "autonomous-pentest-platform",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return nil, "", fmt.Errorf("failed to sign authentication token: %w", err)
	}

	// Also register token in global TenantSessionStore for backwards compatibility with core tools
	labmanager.GetGlobalTenantSessionStore().RegisterToken(tokenString, labmanager.CallerIdentity{
		UserID: user.ID,
		OrgID:  user.OrgID,
		Role:   user.Role,
	})

	return user, tokenString, nil
}

// RevokeToken marks a JWT token as revoked and persists the revocation to disk.
func (s *UserStore) RevokeToken(tokenString string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokedTokens[tokenString] = time.Now().UTC()
	s.savePersistentRevocations()
}

// IsRevoked checks if a token has been explicitly revoked (in memory or restored from disk).
func (s *UserStore) IsRevoked(tokenString string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, revoked := s.revokedTokens[tokenString]
	return revoked
}

// ValidateToken verifies token validity, signature, expiration and persistent revocation.
func (s *UserStore) ValidateToken(tokenString string) (*UserClaims, error) {
	if s.IsRevoked(tokenString) {
		return nil, fmt.Errorf("session token has been revoked")
	}

	parsedToken, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := parsedToken.Claims.(*UserClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("session token has expired")
	}

	return claims, nil
}

// GetUserByID returns user by ID.
func (s *UserStore) GetUserByID(userID string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.usersByID[userID]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	return u, nil
}

// GetUserByUsername returns user by username.
func (s *UserStore) GetUserByUsername(username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.usersByName[strings.ToLower(strings.TrimSpace(username))]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	return u, nil
}

// GetBootstrapToken returns the active bootstrap token if any.
func (s *UserStore) GetBootstrapToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bootstrapToken
}

// SetUserIterationsForTesting allows tests to simulate legacy users with 100k iterations.
func (s *UserStore) SetUserIterationsForTesting(username string, iterations int, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, exists := s.usersByName[strings.ToLower(username)]; exists {
		u.Iterations = iterations
		u.PasswordHash = hashPasswordWithIterations(password, u.Salt, iterations)
	}
}

// VerifyTwoPersonApproval enforces that a grant requester cannot approve their own assessment grant.
func VerifyTwoPersonApproval(grant *authmanager.AuthorizationGrant, caller *UserClaims) error {
	if grant.UserID == caller.UserID {
		return fmt.Errorf("two-person separation violation: grant requester (%s) cannot approve their own assessment grant", caller.UserID)
	}

	// Only admin, org-admin, or security_officer may approve
	if caller.Role != RoleAdmin && caller.Role != RoleOrgAdmin && caller.Role != RoleSecurityOfficer {
		return fmt.Errorf("forbidden: role %q is not authorized to approve assessment grants (admin, org-admin, or security_officer required)", caller.Role)
	}

	// Cross-tenant check: approver must belong to same org unless platform admin
	if caller.Role != RoleAdmin && caller.OrgID != grant.OrgID {
		return fmt.Errorf("forbidden: cannot approve an assessment grant belonging to another organization")
	}

	return nil
}
