package assessment

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type persistedLedger struct {
	Runs         map[string]*AssessmentRun `json:"runs"`
	ByAssessment map[string]string         `json:"by_assessment"`
}

// Ledger provides persistent, thread-safe tracking of assessment runs and security findings.
type Ledger struct {
	mu           sync.RWMutex
	runs         map[string]*AssessmentRun // run_id -> run
	byAssessment map[string]string         // assessment_id -> latest run_id
	persistPath  string
	lastLoaded   time.Time
}

var (
	globalLedger     *Ledger
	globalLedgerOnce sync.Once
)

func getLedgerPersistencePath() string {
	if p := os.Getenv("ASSESSMENT_LEDGER_FILE"); p != "" {
		return p
	}
	return filepath.Join(os.TempDir(), "bifrost_assessment_ledger.json")
}

// GetGlobalLedger returns the singleton Ledger.
func GetGlobalLedger() *Ledger {
	globalLedgerOnce.Do(func() {
		globalLedger = NewLedger()
		globalLedger.persistPath = getLedgerPersistencePath()
		globalLedger.mu.Lock()
		globalLedger.loadFromFileLocked()
		globalLedger.mu.Unlock()
	})
	return globalLedger
}

// NewLedger creates an in-memory assessment ledger.
func NewLedger() *Ledger {
	return &Ledger{
		runs:         make(map[string]*AssessmentRun),
		byAssessment: make(map[string]string),
	}
}

func (l *Ledger) loadFromFileLocked() {
	if l.persistPath == "" {
		return
	}
	fi, err := os.Stat(l.persistPath)
	if err != nil {
		return
	}
	if !fi.ModTime().After(l.lastLoaded) {
		return
	}
	data, err := os.ReadFile(l.persistPath)
	if err != nil {
		return
	}
	var state persistedLedger
	if err := json.Unmarshal(data, &state); err != nil {
		return
	}
	if state.Runs != nil {
		for k, v := range state.Runs {
			l.runs[k] = v
		}
	}
	if state.ByAssessment != nil {
		for k, v := range state.ByAssessment {
			l.byAssessment[k] = v
		}
	}
	l.lastLoaded = fi.ModTime()
}

func (l *Ledger) saveToFileLocked() {
	if l.persistPath == "" {
		return
	}
	state := persistedLedger{
		Runs:         l.runs,
		ByAssessment: l.byAssessment,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return
	}

	// Atomic write: write to temporary file, sync, then atomically replace destination
	dir := filepath.Dir(l.persistPath)
	tmpFile, err := os.CreateTemp(dir, "ledger-*.tmp")
	if err == nil {
		tmpPath := tmpFile.Name()
		if _, wErr := tmpFile.Write(data); wErr == nil {
			_ = tmpFile.Sync()
			_ = tmpFile.Close()
			_ = os.Remove(l.persistPath)
			if rErr := os.Rename(tmpPath, l.persistPath); rErr == nil {
				if fi, sErr := os.Stat(l.persistPath); sErr == nil {
					l.lastLoaded = fi.ModTime()
				}
				return
			}
		} else {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}

	// Fallback to direct write if temp file creation fails
	_ = os.WriteFile(l.persistPath, data, 0600)
	if fi, err := os.Stat(l.persistPath); err == nil {
		l.lastLoaded = fi.ModTime()
	}
}

// RecordRun creates or updates an assessment run record.
func (l *Ledger) RecordRun(run *AssessmentRun) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.loadFromFileLocked()

	run.UpdatedAt = time.Now().UTC()
	l.runs[run.RunID] = run
	l.byAssessment[run.AssessmentID] = run.RunID
	l.saveToFileLocked()
}

// GetRun retrieves a run by its RunID.
func (l *Ledger) GetRun(runID string) (*AssessmentRun, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	run, ok := l.runs[runID]
	if !ok {
		return nil, fmt.Errorf("assessment run %q not found", runID)
	}
	return run, nil
}

// GetRunByAssessment retrieves the latest run for a given assessment ID.
func (l *Ledger) GetRunByAssessment(assessmentID string) (*AssessmentRun, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	runID, ok := l.byAssessment[assessmentID]
	if !ok {
		return nil, fmt.Errorf("no execution record found for assessment %q", assessmentID)
	}
	run, ok := l.runs[runID]
	if !ok {
		return nil, fmt.Errorf("assessment run %q not found", runID)
	}
	return run, nil
}

// GetLatestRunForOrg finds the most recent assessment run visible to the organization.
func (l *Ledger) GetLatestRunForOrg(orgID string, isPlatformAdmin bool) (*AssessmentRun, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var latest *AssessmentRun
	for _, r := range l.runs {
		if isPlatformAdmin || orgID == "system-admin-org" || r.OrgID == orgID {
			if latest == nil || r.CreatedAt.After(latest.CreatedAt) {
				latest = r
			}
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("no assessment runs found for organization %q", orgID)
	}
	return latest, nil
}

// ListRunsByOrg returns all runs for an organization.
func (l *Ledger) ListRunsByOrg(orgID string, isPlatformAdmin bool) []*AssessmentRun {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var list []*AssessmentRun
	for _, r := range l.runs {
		if isPlatformAdmin || orgID == "system-admin-org" || r.OrgID == orgID {
			list = append(list, r)
		}
	}
	return list
}

