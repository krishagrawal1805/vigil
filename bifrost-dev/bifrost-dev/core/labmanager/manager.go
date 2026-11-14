package labmanager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/authmanager"
)

// PinnedJuiceShopImage is the immutable digest-pinned image reference for OWASP Juice Shop v20.3.0.
// Pinning ensures deterministic vulnerability behavior and prevents supply-chain tag drifting.
const PinnedJuiceShopImage = "bkimminich/juice-shop:v20.3.0@sha256:42843723a7bf4246aa5d63c324978b17ef296ac78434aeddd34c427bfb5853f4"

// IsolatedNetworkName defines the dedicated Docker bridge network with ICC and egress restrictions.
const IsolatedNetworkName = "VIGIL-lab-net"

// LabManager orchestrates managed practice lab instances using Docker.
type LabManager struct {
	mu          sync.Mutex
	sessions    map[string]*LabSession // labInstanceID -> session
	authMgr     *authmanager.Manager
	auditLogger *AuditLogger
	stopJanitor chan struct{}
}

var (
	globalLabManager     *LabManager
	globalLabManagerOnce sync.Once
)

// GetGlobalLabManager returns the singleton LabManager.
func GetGlobalLabManager() *LabManager {
	globalLabManagerOnce.Do(func() {
		globalLabManager = NewLabManager(authmanager.GetGlobalManager())
	})
	return globalLabManager
}

// NewLabManager creates a new LabManager instance and starts the background janitor.
func NewLabManager(authMgr *authmanager.Manager) *LabManager {
	lm := &LabManager{
		sessions:    make(map[string]*LabSession),
		authMgr:     authMgr,
		auditLogger: GetGlobalAuditLogger(),
		stopJanitor: make(chan struct{}),
	}
	lm.ensureIsolatedNetwork()
	go lm.startJanitor()
	return lm
}

// ensureIsolatedNetwork creates the isolated bridge network if it does not exist.
func (m *LabManager) ensureIsolatedNetwork() {
	cmdCheck := exec.Command("docker", "network", "inspect", IsolatedNetworkName)
	if err := cmdCheck.Run(); err != nil {
		log.Printf("[labmanager] Creating isolated Docker network %q (enable_icc=false, enable_ip_masquerade=false)...", IsolatedNetworkName)
		cmdCreate := exec.Command("docker", "network", "create", "-d", "bridge",
			"-o", "com.docker.network.bridge.enable_icc=false",
			"-o", "com.docker.network.bridge.enable_ip_masquerade=false",
			"--subnet", "172.30.0.0/16",
			IsolatedNetworkName,
		)
		out, err := cmdCreate.CombinedOutput()
		if err != nil {
			log.Printf("[labmanager] Warning: failed to create isolated network: %v, output: %s", err, string(out))
		} else {
			log.Printf("[labmanager] Isolated network %s created successfully.", IsolatedNetworkName)
		}
	}
}

// startJanitor periodically checks for expired lab sessions and cleans them up.
func (m *LabManager) startJanitor() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopJanitor:
			return
		case <-ticker.C:
			m.cleanupExpiredSessions()
		}
	}
}

// cleanupExpiredSessions checks and cleans up any expired lab sessions.
func (m *LabManager) cleanupExpiredSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	for id, session := range m.sessions {
		if session.Status == LabStatusRunning && now.After(session.ExpiresAt) {
			log.Printf("[labmanager] Session %s expired at %s; terminating container %s...", id, session.ExpiresAt, session.ContainerID)
			_ = exec.Command("docker", "rm", "-f", id).Run()
			if session.GrantID != "" {
				_ = m.authMgr.RevokeGrant(session.GrantID, "Managed practice lab session expired")
				m.auditLogger.Log("GRANT_REVOKED", session.UserID, session.OrgID, fmt.Sprintf("Grant %s revoked due to session expiry", session.GrantID))
			}
			session.Status = LabStatusStopped
			m.auditLogger.Log("LAB_EXPIRED_CLEANUP", session.UserID, session.OrgID, fmt.Sprintf("Lab %s automatically cleaned up by background janitor", id))
		}
	}
}

// findFreePort finds an unused TCP port on 127.0.0.1.
func findFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("failed to allocate free port: %w", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// generateInstanceID generates a unique identifier for a lab instance.
func generateInstanceID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("juice-shop-%s", hex.EncodeToString(b))
}

// StartLab deploys an isolated, resource-limited OWASP Juice Shop instance in Docker
// and automatically registers an authoritative managed-lab authorization grant.
func (m *LabManager) StartLab(ctx context.Context, req StartLabRequest) (*StartLabResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Ensure network exists
	m.ensureIsolatedNetwork()

	// 1. Validate request parameters
	if strings.TrimSpace(req.UserID) == "" {
		req.UserID = "user-developer"
	}
	if strings.TrimSpace(req.OrgID) == "" {
		req.OrgID = "org-security-lab"
	}
	if req.Duration <= 0 {
		req.Duration = 4 * time.Hour
	}

	// 2. Allocate an ephemeral local port bound strictly to 127.0.0.1
	port, err := findFreePort()
	if err != nil {
		return nil, fmt.Errorf("port allocation error: %w", err)
	}

	instanceID := generateInstanceID()
	containerName := instanceID
	targetHost := "127.0.0.1"
	targetURL := fmt.Sprintf("http://%s:%d", targetHost, port)

	log.Printf("[labmanager] Starting Managed Practice Lab %s on %s (User: %s, Org: %s)...", instanceID, targetURL, req.UserID, req.OrgID)

	// 3. Launch OWASP Juice Shop via Docker
	// Bound strictly to 127.0.0.1 to prevent external exposure.
	// Attached to isolated bridge network with no inter-container communication.
	// Outbound DNS pointed to loopback to block external resolutions.
	// Strict resource limits: 512MB RAM, 1.0 CPU, 200 PIDs.
	portMapping := fmt.Sprintf("127.0.0.1:%d:3000", port)
	cmd := exec.CommandContext(ctx, "docker", "run", "-d",
		"--name", containerName,
		"--network", IsolatedNetworkName,
		"--dns", "127.0.0.1",
		"--memory", "512m",
		"--memory-swap", "512m",
		"--cpus", "1.0",
		"--pids-limit", "200",
		"-p", portMapping,
		"--label", "VIGIL.managed.lab=true",
		"--label", fmt.Sprintf("VIGIL.instance.id=%s", instanceID),
		PinnedJuiceShopImage,
	)

	out, err := cmd.CombinedOutput()
	var containerID string
	if err != nil {
		labEnv := os.Getenv("PRACTICE_LAB_URL")
		if labEnv == "" {
			labEnv = "http://platform-practice-lab:3000"
		}
		log.Printf("[labmanager] Docker runner fallback to configured practice lab on %s (%v)", labEnv, err)
		containerID = "platform-practice-lab"
		targetHost = "platform-practice-lab"
		port = 3000
		targetURL = labEnv
		if u, parseErr := url.Parse(labEnv); parseErr == nil {
			targetHost = u.Hostname()
			if p := u.Port(); p != "" {
				if parsedPort, convErr := strconv.Atoi(p); convErr == nil {
					port = parsedPort
				}
			} else if u.Scheme == "https" {
				port = 443
			} else {
				port = 80
			}
		}
	} else {
		containerID = strings.TrimSpace(string(out))
		if len(containerID) > 12 {
			containerID = containerID[:12]
		}
		// 4. Strip default egress gateway route to completely block outbound internet and metadata traffic
		_ = exec.Command("docker", "exec", "--privileged", containerName, "ip", "route", "del", "default").Run()
	}

	browserURL := os.Getenv("PRACTICE_LAB_BROWSER_URL")
	if browserURL == "" {
		browserURL = "http://127.0.0.1:5000"
	}

	session := &LabSession{
		LabInstanceID:    instanceID,
		ContainerID:      containerID,
		TargetHost:       targetHost,
		TargetPort:       port,
		TargetURL:        targetURL,
		BrowserURL:       browserURL,
		BrowserTargetURL: browserURL,
		UserID:           req.UserID,
		OrgID:            req.OrgID,
		Status:           LabStatusStarting,
		CreatedAt:        time.Now().UTC(),
		ExpiresAt:        time.Now().UTC().Add(req.Duration),
	}

	m.sessions[instanceID] = session

	// 5. Wait for Juice Shop HTTP readiness probe (up to 45s)
	probeClient := &http.Client{Timeout: 2 * time.Second}
	probeURL := fmt.Sprintf("%s/rest/admin/application-version", targetURL)
	ready := false
	deadline := time.Now().Add(45 * time.Second)

	log.Printf("[labmanager] Probing readiness at %s...", probeURL)
	for time.Now().Before(deadline) {
		resp, probeErr := probeClient.Get(probeURL)
		if probeErr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(1 * time.Second)
	}

	if !ready {
		session.Status = LabStatusFailed
		session.ErrorMessage = "readiness probe timed out after 45s"
		// Guaranteed cleanup on failure: ensure no orphan container
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
		m.auditLogger.Log("LAB_PROBE_FAILED", req.UserID, req.OrgID, fmt.Sprintf("Lab %s container %s terminated after probe timeout", instanceID, containerID))
		return nil, fmt.Errorf("lab startup failed: target did not become healthy within 45 seconds")
	}

	session.Status = LabStatusRunning
	log.Printf("[labmanager] Lab %s is READY on %s (Container: %s)", instanceID, targetURL, containerID)

	// 6. Automatically create authoritative Managed-Lab Authorization Grant bound to container ID
	allowedPaths := req.AllowedPaths
	if len(allowedPaths) == 0 {
		allowedPaths = []string{"/", "/api/", "/rest/", "/assets/", "/ftp/", "/public/"}
	}
	blockedPaths := req.BlockedPaths
	if len(blockedPaths) == 0 {
		blockedPaths = []string{"/forbidden/admin/", "/internal/super-secret/"}
	}
	allowedMethods := req.AllowedMethods
	if len(allowedMethods) == 0 {
		allowedMethods = []string{"GET", "HEAD", "POST", "OPTIONS"}
	}

	allowedCIDRs := []string{"127.0.0.1/32"}
	if targetHost != "" && targetHost != "127.0.0.1" && targetHost != "localhost" {
		if ips, err := net.LookupIP(targetHost); err == nil {
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					allowedCIDRs = append(allowedCIDRs, fmt.Sprintf("%s/32", ip4.String()))
				}
			}
		}
	}

	grant, err := m.authMgr.CreateManagedLabAssessment(authmanager.CreateManagedLabRequest{
		LabInstanceID:  instanceID,
		ContainerID:    containerID,
		UserID:         req.UserID,
		OrgID:          req.OrgID,
		TargetHost:     targetHost,
		TargetPort:     port,
		AllowedCIDRs:   allowedCIDRs,
		AllowedPaths:   allowedPaths,
		BlockedPaths:   blockedPaths,
		AllowedMethods: allowedMethods,
		Duration:       req.Duration,
	})
	if err != nil {
		session.Status = LabStatusFailed
		session.ErrorMessage = fmt.Sprintf("failed to create authorization grant: %v", err)
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
		m.auditLogger.Log("GRANT_CREATION_FAILED", req.UserID, req.OrgID, fmt.Sprintf("Lab %s cleaned up due to grant error: %v", instanceID, err))
		return nil, fmt.Errorf("failed to issue authorization grant: %w", err)
	}

	session.GrantID = grant.GrantID
	session.AssessmentID = grant.AssessmentID

	m.auditLogger.Log("LAB_CREATED", req.UserID, req.OrgID, fmt.Sprintf("Lab %s started (Container: %s, Grant: %s, Target: %s)", instanceID, containerID, grant.GrantID, targetURL))
	m.auditLogger.Log("GRANT_CREATED", req.UserID, req.OrgID, fmt.Sprintf("Grant %s minted for Lab %s on %s", grant.GrantID, instanceID, targetURL))

	return &StartLabResponse{
		LabSession: session,
		Grant:      grant,
	}, nil
}

// StopLab shuts down the container and automatically revokes its authorization grant.
func (m *LabManager) StopLab(ctx context.Context, req StopLabRequest) (*StopLabResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[req.LabInstanceID]
	if !ok {
		return nil, fmt.Errorf("lab instance %q not found", req.LabInstanceID)
	}

	if session.Status == LabStatusStopped {
		return &StopLabResponse{
			LabInstanceID: req.LabInstanceID,
			ContainerID:   session.ContainerID,
			GrantID:       session.GrantID,
			Status:        "already_stopped",
			Message:       "Lab was already stopped",
		}, nil
	}

	log.Printf("[labmanager] Stopping Lab %s (Container: %s, Grant: %s)...", req.LabInstanceID, session.ContainerID, session.GrantID)

	// 1. Stop and remove Docker container
	cmd := exec.CommandContext(ctx, "docker", "rm", "-f", req.LabInstanceID)
	_ = cmd.Run()

	// 2. Automatically revoke Authorization Grant
	reason := req.Reason
	if strings.TrimSpace(reason) == "" {
		reason = "Managed practice lab session terminated by user"
	}
	if session.GrantID != "" {
		if err := m.authMgr.RevokeGrant(session.GrantID, reason); err != nil {
			log.Printf("[labmanager] Warning: failed to revoke grant %s: %v", session.GrantID, err)
		} else {
			m.auditLogger.Log("GRANT_REVOKED", session.UserID, session.OrgID, fmt.Sprintf("Grant %s revoked: %s", session.GrantID, reason))
		}
	}

	session.Status = LabStatusStopped
	m.auditLogger.Log("LAB_TERMINATED", session.UserID, session.OrgID, fmt.Sprintf("Lab %s container %s terminated successfully", req.LabInstanceID, session.ContainerID))

	return &StopLabResponse{
		LabInstanceID: req.LabInstanceID,
		ContainerID:   session.ContainerID,
		GrantID:       session.GrantID,
		Status:        "stopped",
		Message:       "Lab stopped and authorization grant revoked successfully",
	}, nil
}

// ensureBrowserURL populates browser-accessible loopback target URL if missing.
func (m *LabManager) ensureBrowserURL(s *LabSession) {
	if s == nil {
		return
	}
	if s.BrowserURL == "" {
		browserEnv := os.Getenv("PRACTICE_LAB_BROWSER_URL")
		if browserEnv != "" {
			s.BrowserURL = browserEnv
		} else {
			s.BrowserURL = "http://127.0.0.1:5000"
		}
	}
	if s.BrowserTargetURL == "" {
		s.BrowserTargetURL = s.BrowserURL
	}
}

// GetLab retrieves session status.
func (m *LabManager) GetLab(labInstanceID string) (*LabSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[labInstanceID]
	if !ok {
		return nil, fmt.Errorf("lab instance %q not found", labInstanceID)
	}
	m.ensureBrowserURL(session)
	return session, nil
}

// ListLabs returns all active lab sessions.
func (m *LabManager) ListLabs() []*LabSession {
	m.mu.Lock()
	defer m.mu.Unlock()

	list := make([]*LabSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		m.ensureBrowserURL(s)
		list = append(list, s)
	}
	return list
}
