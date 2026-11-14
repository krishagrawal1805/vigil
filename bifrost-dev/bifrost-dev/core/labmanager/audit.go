package labmanager

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// AuditEvent represents an immutable, cryptographically chained security event.
type AuditEvent struct {
	Sequence  int64     `json:"sequence"`
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	UserID    string    `json:"user_id"`
	OrgID     string    `json:"org_id"`
	Details   string    `json:"details"`
	PrevHash  string    `json:"prev_hash"`
	Signature string    `json:"signature"`
}

// AuditLogger manages thread-safe, cryptographically signed audit logging.
type AuditLogger struct {
	mu              sync.Mutex
	events          []AuditEvent
	signingKey      []byte
	lastHash        string
	sequenceCounter int64
	storageDir      string
}

var (
	globalAuditLogger     *AuditLogger
	globalAuditLoggerOnce sync.Once
)

// computeSignature computes an HMAC-SHA256 signature over event metadata and previous hash.
func computeSignature(key []byte, seq int64, ts time.Time, eventType, userID, orgID, details, prevHash string) string {
	mac := hmac.New(sha256.New, key)
	payload := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s",
		seq,
		ts.UTC().Format(time.RFC3339Nano),
		eventType,
		userID,
		orgID,
		details,
		prevHash,
	)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// loadPersistentAuditChain restores recorded audit events from disk and verifies the chain.
func (l *AuditLogger) loadPersistentAuditChain() {
	if l.storageDir == "" {
		return
	}
	path := filepath.Join(l.storageDir, "audit_chain.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var stored []AuditEvent
	if err := json.Unmarshal(data, &stored); err != nil {
		log.Printf("[labmanager] Warning: failed to parse persisted audit chain: %v", err)
		return
	}
	if len(stored) == 0 {
		return
	}

	// Verify cryptographic integrity of stored chain
	expectedPrev := GenesisHash
	for _, evt := range stored {
		if evt.PrevHash != expectedPrev {
			log.Printf("[labmanager] SECURITY WARNING: Persisted audit chain broken at sequence %d: expected %s, found %s",
				evt.Sequence, expectedPrev, evt.PrevHash)
			return
		}
		expectedSig := computeSignature(l.signingKey, evt.Sequence, evt.Timestamp, evt.EventType, evt.UserID, evt.OrgID, evt.Details, evt.PrevHash)
		if subtle.ConstantTimeCompare([]byte(evt.Signature), []byte(expectedSig)) != 1 {
			log.Printf("[labmanager] SECURITY WARNING: Persisted audit chain signature mismatch at sequence %d", evt.Sequence)
			return
		}
		expectedPrev = evt.Signature
	}

	l.events = stored
	l.lastHash = stored[len(stored)-1].Signature
	l.sequenceCounter = stored[len(stored)-1].Sequence
	log.Printf("[labmanager] Restored %d cryptographically verified audit events from disk (Latest Sequence: %d)",
		len(stored), l.sequenceCounter)
}

// savePersistentAuditChain writes audit events to disk with restricted permissions (0600).
func (l *AuditLogger) savePersistentAuditChain() {
	if l.storageDir == "" {
		return
	}
	_ = os.MkdirAll(l.storageDir, 0700)
	path := filepath.Join(l.storageDir, "audit_chain.json")
	data, err := json.MarshalIndent(l.events, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0600)
}

// GetGlobalAuditLogger returns the singleton AuditLogger instance.
func GetGlobalAuditLogger() *AuditLogger {
	globalAuditLoggerOnce.Do(func() {
		auditDir := os.Getenv("PLATFORM_AUDIT_DIR")
		if auditDir == "" {
			auditDir = filepath.Join(os.TempDir(), "platform_audit")
		}
		_ = os.MkdirAll(auditDir, 0700)

		// Secure Key Management: Read key from environment or use secure persisted key
		rawKey := os.Getenv("PLATFORM_AUDIT_KEY")
		var key []byte
		if rawKey != "" {
			key = []byte(rawKey)
		} else {
			keyPath := filepath.Join(auditDir, "audit.key")
			existingKey, err := os.ReadFile(keyPath)
			if err == nil && len(existingKey) >= 16 {
				key = existingKey
			} else {
				key = make([]byte, 32)
				_, _ = rand.Read(key)
				_ = os.WriteFile(keyPath, key, 0600)
			}
		}

		globalAuditLogger = &AuditLogger{
			events:          make([]AuditEvent, 0),
			signingKey:      key,
			lastHash:        GenesisHash,
			sequenceCounter: 0,
			storageDir:      auditDir,
		}
		globalAuditLogger.loadPersistentAuditChain()
	})
	return globalAuditLogger
}

// Log records a security event into the immutable cryptographic hash chain and saves to disk.
func (l *AuditLogger) Log(eventType, userID, orgID, details string) AuditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sequenceCounter++
	now := time.Now().UTC()
	prev := l.lastHash

	sig := computeSignature(l.signingKey, l.sequenceCounter, now, eventType, userID, orgID, details, prev)

	evt := AuditEvent{
		Sequence:  l.sequenceCounter,
		Timestamp: now,
		EventType: eventType,
		UserID:    userID,
		OrgID:     orgID,
		Details:   details,
		PrevHash:  prev,
		Signature: sig,
	}

	l.events = append(l.events, evt)
	l.lastHash = sig
	l.savePersistentAuditChain()

	log.Printf("[AUDIT #%d] %s | User: %s | Org: %s | Sig: %s... | %s",
		evt.Sequence, eventType, userID, orgID, sig[:12], details)

	return evt
}

// GetEvents returns a defensive copy of recorded audit events.
func (l *AuditLogger) GetEvents() []AuditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()

	res := make([]AuditEvent, len(l.events))
	copy(res, l.events)
	return res
}

// VerifyChain performs complete cryptographic integrity verification across all recorded events.
// Returns (isValid, tamperedIndex, error).
func (l *AuditLogger) VerifyChain() (bool, int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	expectedPrev := GenesisHash
	for i, evt := range l.events {
		// 1. Verify hash link to predecessor
		if evt.PrevHash != expectedPrev {
			return false, i, fmt.Errorf("audit chain broken at sequence %d (index %d): expected prev_hash %s, found %s",
				evt.Sequence, i, expectedPrev, evt.PrevHash)
		}

		// 2. Verify cryptographic signature of the event payload
		expectedSig := computeSignature(l.signingKey, evt.Sequence, evt.Timestamp, evt.EventType, evt.UserID, evt.OrgID, evt.Details, evt.PrevHash)
		if subtle.ConstantTimeCompare([]byte(evt.Signature), []byte(expectedSig)) != 1 {
			return false, i, fmt.Errorf("audit event payload tampering detected at sequence %d (index %d, type: %s): signature mismatch",
				evt.Sequence, i, evt.EventType)
		}

		expectedPrev = evt.Signature
	}

	return true, -1, nil
}

// TamperWithEventForTesting modifies an event in memory to verify that VerifyChain detects tampering.
func (l *AuditLogger) TamperWithEventForTesting(index int, newDetails string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if index < 0 || index >= len(l.events) {
		return fmt.Errorf("event index %d out of range", index)
	}
	l.events[index].Details = newDetails
	return nil
}

// RestoreTamperedEventForTesting fixes an event's signature after testing.
func (l *AuditLogger) RestoreTamperedEventForTesting(index int, originalDetails string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if index < 0 || index >= len(l.events) {
		return fmt.Errorf("event index %d out of range", index)
	}
	l.events[index].Details = originalDetails
	return nil
}
