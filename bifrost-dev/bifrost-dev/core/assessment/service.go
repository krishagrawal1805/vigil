package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/authmanager"
	"github.com/maximhq/bifrost/core/labmanager"
)

// AssessmentService manages the execution lifecycle of autonomous VIGIL penetration tests.
type AssessmentService struct {
	mu              sync.Mutex
	ledger          *Ledger
	authMgr         *authmanager.Manager
	labMgr          *labmanager.LabManager
	activeCmds      map[string]*exec.Cmd       // runID -> cmd
	activeRunsByAsm map[string]string          // assessmentID -> runID
	runsDir         string
}

var (
	globalAssessmentService     *AssessmentService
	globalAssessmentServiceOnce sync.Once
)

// GetGlobalAssessmentService returns the singleton assessment service.
func GetGlobalAssessmentService() *AssessmentService {
	globalAssessmentServiceOnce.Do(func() {
		globalAssessmentService = NewAssessmentService(
			GetGlobalLedger(),
			authmanager.GetGlobalManager(),
			labmanager.GetGlobalLabManager(),
		)
	})
	return globalAssessmentService
}

// NewAssessmentService constructs an AssessmentService instance.
func NewAssessmentService(ledger *Ledger, authMgr *authmanager.Manager, labMgr *labmanager.LabManager) *AssessmentService {
	runsDir := os.Getenv("PLATFORM_RUNS_DIR")
	if runsDir == "" {
		runsDir = filepath.Join(os.TempDir(), "bifrost_VIGIL_runs")
	}
	_ = os.MkdirAll(runsDir, 0755)

	return &AssessmentService{
		ledger:          ledger,
		authMgr:         authMgr,
		labMgr:          labMgr,
		activeCmds:      make(map[string]*exec.Cmd),
		activeRunsByAsm: make(map[string]string),
		runsDir:         runsDir,
	}
}

// StartAssessment initiates an autonomous VIGIL pentest mission against an authorized target in multiagent mode.
func (s *AssessmentService) StartAssessment(ctx context.Context, caller *labmanager.CallerIdentity, grant *authmanager.AuthorizationGrant) (*AssessmentRun, error) {
	return s.StartAssessmentWithMode(ctx, caller, grant, "multiagent", 2)
}

// StartAssessmentWithMode initiates an autonomous pentest mission with explicitly specified mode ("multiagent" or "single") and concurrency.
func (s *AssessmentService) StartAssessmentWithMode(ctx context.Context, caller *labmanager.CallerIdentity, grant *authmanager.AuthorizationGrant, mode string, concurrency int) (*AssessmentRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if mode == "" {
		mode = "multiagent"
	}
	if concurrency <= 0 {
		concurrency = 2
	}

	// 1. Check if an active assessment is already running for this assessment ID
	if existingRunID, ok := s.activeRunsByAsm[grant.AssessmentID]; ok {
		if run, err := s.ledger.GetRun(existingRunID); err == nil {
			if run.Status == StateStarting || run.Status == StateRunning || run.Status == StateQueued {
				return nil, fmt.Errorf("an active assessment run (%s) is already in progress for assessment %q", existingRunID, grant.AssessmentID)
			}
		}
	}

	// 2. Validate grant conditions
	if grant.ApprovalStatus != authmanager.StatusApproved {
		return nil, fmt.Errorf("authorization grant status is %q; only approved grants may start assessments", grant.ApprovalStatus)
	}
	if grant.IsRevoked {
		return nil, fmt.Errorf("authorization grant %s is revoked", grant.GrantID)
	}
	if time.Now().After(grant.ExpiryTime) {
		return nil, fmt.Errorf("authorization grant %s has expired", grant.GrantID)
	}

	// 3. For managed labs, verify container is still running
	if grant.AssessmentType == authmanager.AssessmentTypeManagedLab && grant.LabInstanceID != "" {
		lab, err := s.labMgr.GetLab(grant.LabInstanceID)
		if err != nil || lab.Status != labmanager.LabStatusRunning {
			return nil, fmt.Errorf("managed practice lab %q is not running (status: %s)", grant.LabInstanceID, lab.Status)
		}
	}

	// 4. Create initial AssessmentRun record
	now := time.Now().UTC()
	runID := authmanager.GenerateRandomID("run", 8)
	outFile := filepath.Join(s.runsDir, fmt.Sprintf("%s_result.json", runID))

	modelName := os.Getenv("BIFROST_MODEL")
	if modelName == "" {
		modelName = os.Getenv("GEMINI_MODEL")
	}
	if modelName == "" {
		modelName = "gemini-3.5-flash-lite"
	}

	run := &AssessmentRun{
		RunID:        runID,
		AssessmentID: grant.AssessmentID,
		GrantID:      grant.GrantID,
		UserID:       caller.UserID,
		OrgID:        caller.OrgID,
		TargetURL:    grant.ResolvedTarget,
		Status:       StateStarting,
		StartTime:    now,
		AgentModel:   modelName,
		Mode:         mode,
		Concurrency:  concurrency,
		Scope: map[string]any{
			"authorized_host": grant.AuthorizedHost,
			"authorized_port": grant.AuthorizedPort,
			"allowed_cidrs":   grant.AllowedCIDRs,
			"allowed_paths":   grant.AllowedPaths,
			"blocked_paths":   grant.BlockedPaths,
			"allowed_methods": grant.AllowedMethods,
		},
		ToolsExecuted:   make([]ToolExecutionSummary, 0),
		BlockedRequests: make([]BlockedScopeViolation, 0),
		Findings:        make([]Finding, 0),
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	s.ledger.RecordRun(run)
	s.activeRunsByAsm[grant.AssessmentID] = runID

	// 5. Locate python interpreter, working directory, and runner script
	pythonExe := os.Getenv("PYTHON_BIN")
	if pythonExe == "" {
		if runtime.GOOS == "windows" {
			winVenv := filepath.Join(os.Getenv("USERPROFILE"), ".venv", "Scripts", "python.exe")
			if _, err := os.Stat(winVenv); err == nil {
				pythonExe = winVenv
			}
		}
	}
	if pythonExe == "" {
		if p, err := exec.LookPath("python3"); err == nil {
			pythonExe = p
		} else if p, err := exec.LookPath("python"); err == nil {
			pythonExe = p
		} else {
			pythonExe = "python"
		}
	}

	workDir := os.Getenv("PLATFORM_APP_DIR")
	if workDir == "" {
		if _, err := os.Stat("/app"); err == nil {
			workDir = "/app"
		} else if _, err := os.Stat(`c:\Users\krish\Downloads\hacathon\bifrost-dev\bifrost-dev`); err == nil {
			workDir = `c:\Users\krish\Downloads\hacathon\bifrost-dev\bifrost-dev`
		} else {
			workDir, _ = os.Getwd()
		}
	}

	runnerScript := filepath.Join(workDir, "core", "assessment", "runner", "vigil_runner.py")
	if _, err := os.Stat(runnerScript); err != nil {
		runnerScript = filepath.Join(workDir, "core", "assessment", "runner", "strix_runner.py")
		if _, err2 := os.Stat(runnerScript); err2 != nil {
			runnerScript = filepath.Join("core", "assessment", "runner", "vigil_runner.py")
		}
	}

	roeMode := "broad"
	if len(grant.AllowedMethods) > 0 {
		hasWrite := false
		for _, m := range grant.AllowedMethods {
			if m == "POST" || m == "PUT" || m == "DELETE" || m == "PATCH" {
				hasWrite = true
				break
			}
		}
		if !hasWrite {
			roeMode = "restricted"
		}
	}

	userID := caller.UserID
	if grant.UserID != "" {
		userID = grant.UserID
	}
	orgID := caller.OrgID
	if grant.OrgID != "" {
		orgID = grant.OrgID
	}

	cmdArgs := []string{
		runnerScript,
		"--assessment-id", grant.AssessmentID,
		"--grant-id", grant.GrantID,
		"--user-id", userID,
		"--org-id", orgID,
		"--target", grant.ResolvedTarget,
		"--out-file", outFile,
		"--roe-mode", roeMode,
		"--mode", mode,
		"--model", modelName,
	}
	if mode == "multiagent" {
		cmdArgs = append(cmdArgs, "--concurrency", fmt.Sprintf("%d", concurrency))
	}

	fullArgs := append([]string{"-u"}, cmdArgs...)
	cmd := exec.Command(pythonExe, fullArgs...)

	// Inherit environment variables
	cmd.Env = os.Environ()
	cmd.Dir = workDir

	logFilePath := filepath.Join(s.runsDir, fmt.Sprintf("%s.log", runID))
	logFile, _ := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}

	if err := cmd.Start(); err != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		run.Status = StateFailed
		run.ErrorMessage = fmt.Sprintf("Failed to spawn VIGIL runner process: %v", err)
		s.ledger.RecordRun(run)
		delete(s.activeRunsByAsm, grant.AssessmentID)
		labmanager.GetGlobalAuditLogger().Log("VIGIL_SPAWN_FAILED", caller.UserID, caller.OrgID, run.ErrorMessage)
		return nil, fmt.Errorf("failed to start VIGIL runner: %w", err)
	}

	run.Status = StateRunning
	if cmd.Process != nil {
		run.PID = cmd.Process.Pid
	}
	s.ledger.RecordRun(run)
	s.activeCmds[runID] = cmd

	labmanager.GetGlobalAuditLogger().Log("VIGIL_STARTED", caller.UserID, caller.OrgID,
		fmt.Sprintf("VIGIL autonomous assessment runner started (RunID: %s, PID: %d, Target: %s)", runID, run.PID, grant.ResolvedTarget))

	// 6. Monitor execution in background goroutine
	go s.monitorProcess(runID, grant.AssessmentID, cmd, outFile, logFile)

	return run, nil
}

func (s *AssessmentService) monitorProcess(runID, assessmentID string, cmd *exec.Cmd, outFile string, logFile *os.File) {
	defer func() {
		if logFile != nil {
			_ = logFile.Close()
		}
	}()
	doneChan := make(chan error, 1)
	go func() {
		doneChan <- cmd.Wait()
	}()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var err error
	for {
		select {
		case err = <-doneChan:
			goto processDone
		case <-ticker.C:
			// Check if output file was written and is valid completed JSON
			if outBytes, readErr := os.ReadFile(outFile); readErr == nil && len(outBytes) > 50 {
				var resCheck struct {
					Status string `json:"status"`
				}
				if json.Unmarshal(outBytes, &resCheck) == nil && resCheck.Status == "completed" {
					if cmd.Process != nil {
						_ = exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", cmd.Process.Pid)).Run()
						_ = cmd.Process.Kill()
					}
					err = nil
					goto processDone
				}
			}
		}
	}

processDone:
	s.mu.Lock()
	delete(s.activeCmds, runID)
	delete(s.activeRunsByAsm, assessmentID)
	s.mu.Unlock()

	run, getErr := s.ledger.GetRun(runID)
	if getErr != nil {
		return
	}

	// If already cancelled or stopped, do not overwrite
	if run.Status == StateCancelled {
		return
	}

	endTime := time.Now().UTC()
	run.EndTime = &endTime
	run.DurationSeconds = int(endTime.Sub(run.StartTime).Seconds())

	if err != nil {
		run.Status = StateFailed
		run.ErrorMessage = fmt.Sprintf("VIGIL process exited with error: %v", err)
		log.Printf("[assessment] VIGIL run %s failed: %v", runID, err)
		labmanager.GetGlobalAuditLogger().Log("VIGIL_FAILED", run.UserID, run.OrgID, fmt.Sprintf("VIGIL run %s failed: %v", runID, err))
	} else {
		// Parse output file
		if outBytes, readErr := os.ReadFile(outFile); readErr == nil {
			var result struct {
				Status              string                  `json:"status"`
				DurationSeconds     int                     `json:"duration_seconds"`
				AgentModel          string                  `json:"agent_model"`
				TurnsExecuted       int                     `json:"turns_executed"`
				ToolsExecuted       []ToolExecutionSummary  `json:"tools_executed"`
				DiscoveredEndpoints []string                `json:"discovered_endpoints"`
				ToolInvocations     []ToolInvocationRecord  `json:"tool_invocations"`
				Hypotheses          []any                   `json:"hypotheses"`
				BlockedRequests     []BlockedScopeViolation `json:"blocked_requests"`
				Findings            []Finding               `json:"findings"`
				FinalReport         string                  `json:"final_report"`
			}
			if unmarshalErr := json.Unmarshal(outBytes, &result); unmarshalErr == nil {
				run.Status = StateCompleted
				if result.DurationSeconds > 0 {
					run.DurationSeconds = result.DurationSeconds
				}
				run.AgentModel = result.AgentModel
				run.TurnsExecuted = result.TurnsExecuted
				run.ToolsExecuted = result.ToolsExecuted
				run.DiscoveredEndpoints = result.DiscoveredEndpoints
				run.ToolInvocations = result.ToolInvocations
				run.Hypotheses = result.Hypotheses
				run.BlockedRequests = result.BlockedRequests
				run.Findings = result.Findings
				run.FinalReport = result.FinalReport
				log.Printf("[assessment] VIGIL run %s completed with %d findings (%d discovered endpoints, %d tool invocations)!", runID, len(run.Findings), len(run.DiscoveredEndpoints), len(run.ToolInvocations))
			} else {
				run.Status = StateCompleted
				log.Printf("[assessment] VIGIL run %s completed (result parse warning: %v)", runID, unmarshalErr)
			}
		} else {
			run.Status = StateCompleted
		}
		labmanager.GetGlobalAuditLogger().Log("VIGIL_COMPLETED", run.UserID, run.OrgID,
			fmt.Sprintf("VIGIL autonomous assessment %s completed (%d findings discovered)", runID, len(run.Findings)))
	}

	s.ledger.RecordRun(run)
}

// StopAssessment cleanly terminates an active assessment run.
func (s *AssessmentService) StopAssessment(runID string, reason string) error {
	s.mu.Lock()
	cmd, exists := s.activeCmds[runID]
	s.mu.Unlock()

	run, err := s.ledger.GetRun(runID)
	if err != nil {
		return err
	}

	if reason == "" {
		reason = "Operator cancelled assessment"
	}

	if exists && cmd != nil && cmd.Process != nil {
		// On Windows, use taskkill to kill process tree cleanly
		_ = exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", cmd.Process.Pid)).Run()
		_ = cmd.Process.Kill()
	}

	s.mu.Lock()
	delete(s.activeCmds, runID)
	delete(s.activeRunsByAsm, run.AssessmentID)
	s.mu.Unlock()

	now := time.Now().UTC()
	run.Status = StateCancelled
	run.CancellationReason = reason
	run.EndTime = &now
	run.DurationSeconds = int(now.Sub(run.StartTime).Seconds())
	s.ledger.RecordRun(run)

	labmanager.GetGlobalAuditLogger().Log("VIGIL_CANCELLED", run.UserID, run.OrgID, fmt.Sprintf("Assessment run %s cancelled: %s", runID, reason))
	return nil
}

// CancelRunsForLab cancels any active assessment attached to a lab instance.
func (s *AssessmentService) CancelRunsForLab(labInstanceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for runID, cmd := range s.activeCmds {
		if run, err := s.ledger.GetRun(runID); err == nil {
			if grant, gErr := s.authMgr.GetGrant(run.GrantID); gErr == nil {
				if grant.LabInstanceID == labInstanceID {
					if cmd != nil && cmd.Process != nil {
						_ = exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", cmd.Process.Pid)).Run()
						_ = cmd.Process.Kill()
					}
					delete(s.activeCmds, runID)
					delete(s.activeRunsByAsm, run.AssessmentID)
					now := time.Now().UTC()
					run.Status = StateCancelled
					run.CancellationReason = "Practice lab terminated"
					run.EndTime = &now
					run.DurationSeconds = int(now.Sub(run.StartTime).Seconds())
					s.ledger.RecordRun(run)
					labmanager.GetGlobalAuditLogger().Log("VIGIL_CANCELLED", run.UserID, run.OrgID, fmt.Sprintf("Run %s cancelled due to lab %s shutdown", runID, labInstanceID))
				}
			}
		}
	}
}

func (s *AssessmentService) enrichActiveRun(run *AssessmentRun) *AssessmentRun {
	if run == nil {
		return nil
	}
	if run.Status == StateStarting || run.Status == StateRunning {
		progressFile := filepath.Join(s.runsDir, fmt.Sprintf("%s_result.json.progress.json", run.RunID))
		if data, pErr := os.ReadFile(progressFile); pErr == nil {
			var prog struct {
				DurationSeconds     int                     `json:"duration_seconds"`
				DiscoveredEndpoints []string                `json:"discovered_endpoints"`
				ToolInvocations     []ToolInvocationRecord  `json:"tool_invocations"`
				Hypotheses          []any                   `json:"hypotheses"`
				Findings            []Finding               `json:"findings"`
				BlockedRequests     []BlockedScopeViolation `json:"blocked_requests"`
			}
			if json.Unmarshal(data, &prog) == nil {
				runCopy := *run
				if prog.DurationSeconds > 0 {
					runCopy.DurationSeconds = prog.DurationSeconds
				}
				if len(prog.DiscoveredEndpoints) > 0 {
					runCopy.DiscoveredEndpoints = prog.DiscoveredEndpoints
				}
				if len(prog.ToolInvocations) > 0 {
					runCopy.ToolInvocations = prog.ToolInvocations
					if len(runCopy.ToolsExecuted) == 0 {
						toolCounts := make(map[string]int)
						for _, inv := range prog.ToolInvocations {
							toolCounts[inv.Tool]++
						}
						summaries := make([]ToolExecutionSummary, 0, len(toolCounts))
						for tName, cnt := range toolCounts {
							summaries = append(summaries, ToolExecutionSummary{
								Tool:        tName,
								Invocations: cnt,
								Status:      "success",
							})
						}
						runCopy.ToolsExecuted = summaries
					}
				}
				if len(prog.Hypotheses) > 0 {
					runCopy.Hypotheses = prog.Hypotheses
				}
				if len(prog.Findings) > 0 {
					runCopy.Findings = prog.Findings
				}
				if len(prog.BlockedRequests) > 0 {
					runCopy.BlockedRequests = prog.BlockedRequests
				}
				return &runCopy
			}
		}
	}
	return run
}

// GetLatestRun retrieves the most recent assessment run for an organization.
func (s *AssessmentService) GetLatestRun(orgID string, isPlatformAdmin bool) (*AssessmentRun, error) {
	run, err := s.ledger.GetLatestRunForOrg(orgID, isPlatformAdmin)
	return s.enrichActiveRun(run), err
}

// GetRun retrieves a specific assessment run.
func (s *AssessmentService) GetRun(runID string) (*AssessmentRun, error) {
	run, err := s.ledger.GetRun(runID)
	return s.enrichActiveRun(run), err
}

// GetRunByAssessment retrieves the run for a given assessment ID.
func (s *AssessmentService) GetRunByAssessment(assessmentID string) (*AssessmentRun, error) {
	run, err := s.ledger.GetRunByAssessment(assessmentID)
	return s.enrichActiveRun(run), err
}
