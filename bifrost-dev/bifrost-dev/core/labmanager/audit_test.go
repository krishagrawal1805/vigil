package labmanager

import (
	"os"
	"strings"
	"testing"
)

func TestCryptographicAuditLogger_IntegrityAndTamperDetection(t *testing.T) {
	// Initialize a dedicated logger instance
	logger := &AuditLogger{
		events:          make([]AuditEvent, 0),
		signingKey:      []byte("super-secret-test-key-32bytes!!"),
		lastHash:        GenesisHash,
		sequenceCounter: 0,
	}

	// 1. Verify empty chain is valid
	valid, idx, err := logger.VerifyChain()
	if !valid || err != nil {
		t.Fatalf("Empty audit chain should be valid, got: %v (idx %d)", err, idx)
	}

	// 2. Append 5 sequential audit events
	e1 := logger.Log("USER_LOGIN", "usr-alice", "org-alpha", "Alice logged in successfully")
	e2 := logger.Log("GRANT_REQUESTED", "usr-alice", "org-alpha", "Requested grant for target app.example.com")
	_ = logger.Log("DNS_VERIFIED", "usr-alice", "org-alpha", "DNS TXT challenge verified")
	_ = logger.Log("ASSESSMENT_APPROVED", "usr-bob", "org-alpha", "Approved by security officer Bob")
	e5 := logger.Log("ASSESSMENT_STARTED", "usr-alice", "org-alpha", "Multi-agent assessment run started")

	if e1.Sequence != 1 || e5.Sequence != 5 {
		t.Fatalf("Expected sequence 1..5, got %d..%d", e1.Sequence, e5.Sequence)
	}
	if e1.PrevHash != GenesisHash {
		t.Fatalf("Expected GenesisHash for first event, got %s", e1.PrevHash)
	}
	if e2.PrevHash != e1.Signature {
		t.Fatalf("Expected e2.PrevHash == e1.Signature, got %s vs %s", e2.PrevHash, e1.Signature)
	}

	// 3. Verify clean chain passes
	valid, idx, err = logger.VerifyChain()
	if !valid || err != nil {
		t.Fatalf("Clean audit chain verification failed: %v", err)
	}

	// 4. Test Payload Tampering at event index 2 (Sequence 3)
	originalDetails := logger.events[2].Details
	_ = logger.TamperWithEventForTesting(2, "FORGED: Malicious modification of DNS verification payload")

	valid, tamperedIdx, err := logger.VerifyChain()
	if valid {
		t.Fatalf("Expected VerifyChain to detect payload tampering, but returned valid!")
	}
	if tamperedIdx != 2 {
		t.Fatalf("Expected tampering detected at index 2, got %d", tamperedIdx)
	}
	if !strings.Contains(err.Error(), "payload tampering detected at sequence 3") {
		t.Fatalf("Expected error mentioning sequence 3 tampering, got: %v", err)
	}

	// 5. Restore original details and verify chain is valid again
	_ = logger.RestoreTamperedEventForTesting(2, originalDetails)
	valid, _, err = logger.VerifyChain()
	if !valid || err != nil {
		t.Fatalf("Restored audit chain should be valid, got: %v", err)
	}

	// 6. Test Event Deletion / Omission
	// Remove event index 1 (Sequence 2)
	removed := logger.events[1]
	logger.events = append(logger.events[:1], logger.events[2:]...)

	valid, breakIdx, err := logger.VerifyChain()
	if valid {
		t.Fatalf("Expected VerifyChain to detect event omission/break, but returned valid!")
	}
	if breakIdx != 1 {
		t.Fatalf("Expected chain break detected at index 1, got %d", breakIdx)
	}
	if !strings.Contains(err.Error(), "audit chain broken") {
		t.Fatalf("Expected error mentioning audit chain broken, got: %v", err)
	}

	// Put event back
	logger.events = append([]AuditEvent{logger.events[0], removed}, logger.events[1:]...)
	valid, _, err = logger.VerifyChain()
	if !valid || err != nil {
		t.Fatalf("Reassembled audit chain should be valid, got: %v", err)
	}
}

func TestCryptographicAuditLogger_SecureKeyManagement(t *testing.T) {
	// Set custom audit key in env
	testKey := "production-grade-hmac-sha256-key"
	_ = os.Setenv("PLATFORM_AUDIT_KEY", testKey)
	defer os.Unsetenv("PLATFORM_AUDIT_KEY")

	rawKey := os.Getenv("PLATFORM_AUDIT_KEY")
	if rawKey != testKey {
		t.Fatalf("Expected PLATFORM_AUDIT_KEY=%s, got %s", testKey, rawKey)
	}
}

func TestCryptographicAuditLogger_PersistenceAndRestoration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit_persist_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testKey := []byte("persistent-test-hmac-signing-key")

	// 1. First logger instance creates and persists events
	l1 := &AuditLogger{
		events:          make([]AuditEvent, 0),
		signingKey:      testKey,
		lastHash:        GenesisHash,
		sequenceCounter: 0,
		storageDir:      tempDir,
	}

	l1.Log("USER_LOGIN", "usr-1", "org-test", "Initial login")
	l1.Log("GRANT_CREATED", "usr-1", "org-test", "Grant minted")
	l1.Log("ASSESSMENT_STARTED", "usr-1", "org-test", "Run initiated")

	if l1.sequenceCounter != 3 {
		t.Fatalf("Expected sequenceCounter 3, got %d", l1.sequenceCounter)
	}

	// 2. Second logger instance starts up pointing to the same directory
	l2 := &AuditLogger{
		events:          make([]AuditEvent, 0),
		signingKey:      testKey,
		lastHash:        GenesisHash,
		sequenceCounter: 0,
		storageDir:      tempDir,
	}
	l2.loadPersistentAuditChain()

	if len(l2.events) != 3 {
		t.Fatalf("Expected 3 restored events, got %d", len(l2.events))
	}
	if l2.sequenceCounter != 3 {
		t.Fatalf("Expected restored sequenceCounter 3, got %d", l2.sequenceCounter)
	}
	if l2.lastHash != l1.lastHash {
		t.Fatalf("Expected restored lastHash %s, got %s", l1.lastHash, l2.lastHash)
	}

	// 3. Chain verification on restored logger passes
	valid, idx, err := l2.VerifyChain()
	if !valid || err != nil {
		t.Fatalf("Restored chain failed verification: %v (idx %d)", err, idx)
	}

	// 4. Logging a 4th event continues chain smoothly
	e4 := l2.Log("ASSESSMENT_COMPLETED", "usr-1", "org-test", "Completed with 0 critical findings")
	if e4.Sequence != 4 {
		t.Fatalf("Expected sequence 4 for next event, got %d", e4.Sequence)
	}
	if e4.PrevHash != l1.lastHash {
		t.Fatalf("Expected e4.PrevHash == l1.lastHash, got %s vs %s", e4.PrevHash, l1.lastHash)
	}

	valid, _, err = l2.VerifyChain()
	if !valid || err != nil {
		t.Fatalf("Extended chain verification failed: %v", err)
	}
}
