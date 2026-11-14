package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/core/assessment"
	"github.com/maximhq/bifrost/core/authmanager"
	"github.com/maximhq/bifrost/core/labmanager"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/transports/v2/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// LabHandler provides authenticated, tenant-isolated API endpoints for practice labs.
type LabHandler struct {
	labMgr            *labmanager.LabManager
	configStore       configstore.ConfigStore
	authMiddleware    *AuthMiddleware
	assessmentService *assessment.AssessmentService
}

// NewLabHandler creates a new LabHandler instance.
func NewLabHandler(labMgr *labmanager.LabManager, configStore configstore.ConfigStore, authMiddleware *AuthMiddleware) *LabHandler {
	if labMgr == nil {
		labMgr = labmanager.GetGlobalLabManager()
	}
	return &LabHandler{
		labMgr:            labMgr,
		configStore:       configStore,
		authMiddleware:    authMiddleware,
		assessmentService: assessment.GetGlobalAssessmentService(),
	}
}

// resolveCaller extracts and verifies the caller's authenticated identity.
// It derives identity from verified server-side session credentials, ignoring body parameters.
func (h *LabHandler) resolveCaller(ctx *fasthttp.RequestCtx) (*labmanager.CallerIdentity, int, string) {
	// Helper to resolve admin username from server-side config store
	getAdminUsername := func() string {
		adminUser := "admin"
		if h.configStore != nil {
			if authConfig, err := h.configStore.GetAuthConfig(ctx); err == nil && authConfig != nil {
				if u := authConfig.AdminUserName.GetValue(); u != "" {
					adminUser = u
				}
			}
		}
		return adminUser
	}

	// 1. Check if the request was authenticated via the Bifrost Setup Lock / Setup Session
	if setupAuthed, ok := ctx.UserValue(schemas.BifrostContextKeySetupTokenAuthenticated).(bool); ok && setupAuthed {
		return &labmanager.CallerIdentity{
			UserID: getAdminUsername(),
			OrgID:  "system-admin-org",
			Role:   "admin",
		}, 0, ""
	}

	if h.authMiddleware != nil {
		// Explicit X-Bifrost-Setup-Token header check
		if token := string(ctx.Request.Header.Peek(SetupTokenHeader)); token != "" {
			if h.authMiddleware.CheckConfiguredSetupToken(token) {
				return &labmanager.CallerIdentity{
					UserID: getAdminUsername(),
					OrgID:  "system-admin-org",
					Role:   "admin",
				}, 0, ""
			}
		}

		// HttpOnly setup session cookie check
		if cookie := string(ctx.Request.Header.Cookie(SetupSessionCookie)); cookie != "" {
			if h.authMiddleware.validSetupSession(cookie, time.Now()) {
				return &labmanager.CallerIdentity{
					UserID: getAdminUsername(),
					OrgID:  "system-admin-org",
					Role:   "admin",
				}, 0, ""
			}
		}
	}

	// 2. Extract Bearer token or session cookie
	var token string
	if authHdr := string(ctx.Request.Header.Peek("Authorization")); strings.HasPrefix(authHdr, "Bearer ") {
		token = strings.TrimPrefix(authHdr, "Bearer ")
	}
	if token == "" {
		token = string(ctx.Request.Header.Cookie("token"))
	}

	if token != "" {
		// A. Check Tenant Session Store for multi-tenant users
		if id, ok := labmanager.GetGlobalTenantSessionStore().ResolveToken(token); ok {
			return &id, 0, ""
		}

		// B. Check Bifrost configstore dashboard sessions
		if h.configStore != nil {
			session, err := h.configStore.GetSession(ctx, token)
			if err == nil && session != nil && session.ExpiresAt.After(time.Now()) {
				return &labmanager.CallerIdentity{
					UserID: getAdminUsername(),
					OrgID:  "system-admin-org",
					Role:   "admin",
				}, 0, ""
			}
		}
	}

	// Unauthenticated request
	return nil, fasthttp.StatusUnauthorized, "Unauthorized: authentication required for lab management"
}

// startLab handles POST /api/lab/start with strict caller identity binding.
func (h *LabHandler) startLab(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		labmanager.GetGlobalAuditLogger().Log("AUTH_FAILURE", "anonymous", "", "Unauthenticated call to /api/lab/start")
		SendError(ctx, code, errMsg)
		return
	}

	var req labmanager.StartLabRequest
	if len(ctx.PostBody()) > 0 {
		if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
			SendError(ctx, fasthttp.StatusBadRequest, "Invalid request JSON payload")
			return
		}
	}

	// MANDATORY SECURITY CONTROL: Never trust user_id or org_id from request body!
	// Overwrite with authenticated caller context:
	req.UserID = caller.UserID
	req.OrgID = caller.OrgID

	res, err := h.labMgr.StartLab(ctx, req)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}

	SendJSON(ctx, res)
}

// stopLab handles POST /api/lab/stop with IDOR / BOLA protection.
func (h *LabHandler) stopLab(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		labmanager.GetGlobalAuditLogger().Log("AUTH_FAILURE", "anonymous", "", "Unauthenticated call to /api/lab/stop")
		SendError(ctx, code, errMsg)
		return
	}

	var req labmanager.StopLabRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request JSON payload")
		return
	}

	if strings.TrimSpace(req.LabInstanceID) == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "lab_instance_id is required")
		return
	}

	// Retrieve lab session before performing any action
	session, err := h.labMgr.GetLab(req.LabInstanceID)
	if err != nil {
		SendError(ctx, fasthttp.StatusNotFound, err.Error())
		return
	}

	// IDOR / BOLA CHECK:
	// Verify caller ownership or org-admin privileges BEFORE stopping container or revoking grant
	isOwner := caller.UserID == session.UserID
	isOrgAdmin := caller.Role == "org-admin" && caller.OrgID == session.OrgID
	isPlatformAdmin := caller.Role == "admin"

	if !isOwner && !isOrgAdmin && !isPlatformAdmin {
		labmanager.GetGlobalAuditLogger().Log("CROSS_TENANT_ATTEMPT", caller.UserID, caller.OrgID,
			fmt.Sprintf("Unauthorized attempt to stop lab %s owned by user %s (org: %s)", req.LabInstanceID, session.UserID, session.OrgID))
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden: you do not have permission to terminate this lab instance")
		return
	}

	// Cancel any active assessment runs tied to this lab instance before stopping it
	if h.assessmentService != nil {
		h.assessmentService.CancelRunsForLab(req.LabInstanceID)
	}

	res, err := h.labMgr.StopLab(ctx, req)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}

	SendJSON(ctx, res)
}

// getLabStatus handles GET /api/lab/status with tenant access restrictions.
func (h *LabHandler) getLabStatus(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		labmanager.GetGlobalAuditLogger().Log("AUTH_FAILURE", "anonymous", "", "Unauthenticated call to /api/lab/status")
		SendError(ctx, code, errMsg)
		return
	}

	id := string(ctx.QueryArgs().Peek("lab_instance_id"))
	if id == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "lab_instance_id parameter is required")
		return
	}

	session, err := h.labMgr.GetLab(id)
	if err != nil {
		SendError(ctx, fasthttp.StatusNotFound, err.Error())
		return
	}

	isOwner := caller.UserID == session.UserID
	isOrgAdmin := caller.Role == "org-admin" && caller.OrgID == session.OrgID
	isPlatformAdmin := caller.Role == "admin"

	if !isOwner && !isOrgAdmin && !isPlatformAdmin {
		labmanager.GetGlobalAuditLogger().Log("CROSS_TENANT_ATTEMPT", caller.UserID, caller.OrgID,
			fmt.Sprintf("Unauthorized attempt to inspect lab %s owned by user %s (org: %s)", id, session.UserID, session.OrgID))
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden: you do not have permission to view this lab instance")
		return
	}

	SendJSON(ctx, session)
}

// listLabs handles GET /api/lab/list, filtering labs by tenant permission.
func (h *LabHandler) listLabs(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		labmanager.GetGlobalAuditLogger().Log("AUTH_FAILURE", "anonymous", "", "Unauthenticated call to /api/lab/list")
		SendError(ctx, code, errMsg)
		return
	}

	all := h.labMgr.ListLabs()
	filtered := make([]*labmanager.LabSession, 0)
	for _, s := range all {
		if caller.Role == "admin" {
			filtered = append(filtered, s)
		} else if caller.Role == "org-admin" && caller.OrgID == s.OrgID {
			filtered = append(filtered, s)
		} else if caller.UserID == s.UserID {
			filtered = append(filtered, s)
		}
	}

	SendJSON(ctx, filtered)
}

// getCallerProfile handles GET /api/lab/me returning the server-validated caller identity.
func (h *LabHandler) getCallerProfile(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		SendError(ctx, code, errMsg)
		return
	}
	SendJSON(ctx, map[string]any{
		"user_id":       caller.UserID,
		"org_id":        caller.OrgID,
		"role":          caller.Role,
		"authenticated": true,
	})
}

// registerExternalAssessment handles POST /api/auth/external/register
func (h *LabHandler) registerExternalAssessment(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		SendError(ctx, code, errMsg)
		return
	}

	var req authmanager.CreateExternalAssessmentRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request JSON payload")
		return
	}

	// Strictly bind caller identity from server session
	req.UserID = caller.UserID
	req.OrgID = caller.OrgID

	grant, err := authmanager.GetGlobalManager().CreateExternalAssessment(req)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	labmanager.GetGlobalAuditLogger().Log("ASSESSMENT_REGISTERED", caller.UserID, caller.OrgID,
		fmt.Sprintf("Registered external assessment %s for %s", grant.AssessmentID, grant.AuthorizedHost))

	SendJSON(ctx, map[string]any{
		"grant": grant,
		"dns_challenge": map[string]string{
			"record_type":  "TXT",
			"record_name":  fmt.Sprintf("_strix-auth.%s", grant.AuthorizedHost),
			"record_value": grant.DNSChallengeToken,
			"instructions": fmt.Sprintf("Create a DNS TXT record at _strix-auth.%s with value %q to prove domain ownership.", grant.AuthorizedHost, grant.DNSChallengeToken),
		},
		"note": "DNS verification establishes control of DNS, NOT permission to perform security testing. Formal approval remains required.",
	})
}

// verifyExternalDNS handles POST /api/auth/external/verify-dns
func (h *LabHandler) verifyExternalDNS(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		SendError(ctx, code, errMsg)
		return
	}

	var payload struct {
		AssessmentID string `json:"assessment_id"`
		Token        string `json:"token"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request JSON payload")
		return
	}

	if strings.TrimSpace(payload.AssessmentID) == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "assessment_id is required")
		return
	}

	grant, err := authmanager.GetGlobalManager().GetGrantByAssessment(payload.AssessmentID)
	if err != nil {
		SendError(ctx, fasthttp.StatusNotFound, err.Error())
		return
	}

	// Cross-tenant check: caller must belong to the grant's organization or be platform admin
	if caller.Role != "admin" && caller.OrgID != grant.OrgID {
		labmanager.GetGlobalAuditLogger().Log("CROSS_TENANT_ATTEMPT", caller.UserID, caller.OrgID,
			fmt.Sprintf("Cross-tenant DNS verify attempt on assessment %s belonging to org %s", payload.AssessmentID, grant.OrgID))
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden: cannot verify DNS for another organization's assessment")
		return
	}

	err = authmanager.GetGlobalManager().VerifyDNSChallenge(payload.AssessmentID, payload.Token)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	grant, _ = authmanager.GetGlobalManager().GetGrantByAssessment(payload.AssessmentID)
	labmanager.GetGlobalAuditLogger().Log("DNS_VERIFIED", caller.UserID, caller.OrgID,
		fmt.Sprintf("Verified DNS control for assessment %s. Pending owner authorization.", payload.AssessmentID))

	SendJSON(ctx, map[string]any{
		"assessment_id": payload.AssessmentID,
		"status":        authmanager.StatusDNSVerifiedPendingApproval,
		"dns_verified":  true,
		"grant":         grant,
		"message":       "DNS control successfully verified. Explicit owner or administrator authorization approval is now required before assessment can proceed.",
	})
}

// approveExternalAssessment handles POST /api/auth/external/approve
func (h *LabHandler) approveExternalAssessment(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		SendError(ctx, code, errMsg)
		return
	}

	var req authmanager.ApproveAssessmentRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request JSON payload")
		return
	}

	if strings.TrimSpace(req.AssessmentID) == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "assessment_id is required")
		return
	}

	// 1. Retrieve the authoritative assessment grant
	existingGrant, err := authmanager.GetGlobalManager().GetGrantByAssessment(req.AssessmentID)
	if err != nil {
		SendError(ctx, fasthttp.StatusNotFound, err.Error())
		return
	}

	// 2. Cross-tenant check: caller must belong to the grant's organization or be platform admin
	if caller.Role != "admin" && caller.OrgID != existingGrant.OrgID {
		labmanager.GetGlobalAuditLogger().Log("CROSS_TENANT_ATTEMPT", caller.UserID, caller.OrgID,
			fmt.Sprintf("Cross-tenant approval attempt on assessment %s belonging to org %s", req.AssessmentID, existingGrant.OrgID))
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden: cannot approve an assessment grant belonging to another organization")
		return
	}

	// 3. Two-person separation: requester cannot approve their own assessment
	if existingGrant.UserID == caller.UserID {
		labmanager.GetGlobalAuditLogger().Log("SELF_APPROVAL_ATTEMPT", caller.UserID, caller.OrgID,
			fmt.Sprintf("User %s attempted to self-approve assessment %s (two-person separation violation)", caller.UserID, req.AssessmentID))
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden: assessment requester cannot approve their own assessment (two-person separation required)")
		return
	}

	// 4. Approver role check: only admin, org-admin, or security_officer may approve
	if caller.Role != "admin" && caller.Role != "org-admin" && caller.Role != "security_officer" {
		labmanager.GetGlobalAuditLogger().Log("UNAUTHORIZED_APPROVER_ROLE", caller.UserID, caller.OrgID,
			fmt.Sprintf("User %s with role %s attempted to approve assessment %s without authorized approver role", caller.UserID, caller.Role, req.AssessmentID))
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden: only users with admin, org-admin, or security_officer roles can approve assessment grants")
		return
	}

	// 5. Evidence reference verification: must be substantive (minimum 8 characters)
	evidence := strings.TrimSpace(req.AuthEvidenceRef)
	if evidence == "" || len(evidence) < 8 {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid auth_evidence_ref: substantive reference required (minimum 8 characters)")
		return
	}

	req.ApproverID = caller.UserID
	req.ApproverOrgID = caller.OrgID
	if caller.Role == "admin" {
		req.ApproverRole = "system_admin"
	} else if caller.Role == "org-admin" {
		req.ApproverRole = "org_admin"
	} else if caller.Role == "security_officer" {
		req.ApproverRole = "security_officer"
	}

	grant, err := authmanager.GetGlobalManager().ApproveExternalAssessment(req)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	labmanager.GetGlobalAuditLogger().Log("ASSESSMENT_APPROVED", caller.UserID, caller.OrgID,
		fmt.Sprintf("Approved external assessment %s for %s by %s (%s). Active until %s", grant.AssessmentID, grant.AuthorizedHost, caller.UserID, req.ApproverRole, grant.ExpiryTime.Format(time.RFC3339)))

	SendJSON(ctx, grant)
}

// listExternalAssessments handles GET /api/auth/external/list
func (h *LabHandler) listExternalAssessments(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		SendError(ctx, code, errMsg)
		return
	}

	grants := authmanager.GetGlobalManager().ListGrantsByOrg(caller.OrgID)
	filtered := make([]*authmanager.AuthorizationGrant, 0)
	for _, g := range grants {
		if g.AssessmentType == authmanager.AssessmentTypeExternal {
			filtered = append(filtered, g)
		}
	}

	SendJSON(ctx, filtered)
}

// getExternalAssessmentStatus handles GET /api/auth/external/status?assessment_id=...
func (h *LabHandler) getExternalAssessmentStatus(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		SendError(ctx, code, errMsg)
		return
	}

	assessmentID := string(ctx.QueryArgs().Peek("assessment_id"))
	if assessmentID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "assessment_id is required")
		return
	}

	grant, err := authmanager.GetGlobalManager().GetGrantByAssessment(assessmentID)
	if err != nil {
		SendError(ctx, fasthttp.StatusNotFound, err.Error())
		return
	}

	if caller.Role != "admin" && caller.OrgID != grant.OrgID {
		labmanager.GetGlobalAuditLogger().Log("CROSS_TENANT_ATTEMPT", caller.UserID, caller.OrgID,
			fmt.Sprintf("Cross-tenant status inspection attempt on assessment %s belonging to org %s", assessmentID, grant.OrgID))
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden: cannot inspect another organization's assessment grant")
		return
	}

	SendJSON(ctx, grant)
}

// revokeExternalAssessment handles POST /api/auth/external/revoke
func (h *LabHandler) revokeExternalAssessment(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		SendError(ctx, code, errMsg)
		return
	}

	var payload struct {
		GrantID string `json:"grant_id"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request JSON payload")
		return
	}

	if strings.TrimSpace(payload.GrantID) == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "grant_id is required")
		return
	}

	grant, err := authmanager.GetGlobalManager().GetGrant(payload.GrantID)
	if err != nil {
		SendError(ctx, fasthttp.StatusNotFound, err.Error())
		return
	}

	if caller.Role != "admin" && caller.OrgID != grant.OrgID && caller.UserID != grant.UserID {
		labmanager.GetGlobalAuditLogger().Log("CROSS_TENANT_ATTEMPT", caller.UserID, caller.OrgID,
			fmt.Sprintf("Cross-tenant revocation attempt on grant %s belonging to org %s", payload.GrantID, grant.OrgID))
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden: unauthorized to revoke this grant")
		return
	}

	if payload.Reason == "" {
		payload.Reason = "operator_revocation"
	}

	if err := authmanager.GetGlobalManager().RevokeGrant(payload.GrantID, payload.Reason); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}

	labmanager.GetGlobalAuditLogger().Log("GRANT_REVOKED", caller.UserID, caller.OrgID,
		fmt.Sprintf("Grant %s revoked: %s", payload.GrantID, payload.Reason))

	SendJSON(ctx, map[string]any{
		"grant_id": payload.GrantID,
		"status":   authmanager.StatusRevoked,
		"message":  "Authorization grant revoked successfully",
	})
}

// startAssessmentRun handles POST /api/assessment/start
func (h *LabHandler) startAssessmentRun(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		SendError(ctx, code, errMsg)
		return
	}

	var req struct {
		GrantID      string `json:"grant_id"`
		AssessmentID string `json:"assessment_id"`
		Mode         string `json:"mode"`
		Concurrency  int    `json:"concurrency"`
	}
	if len(ctx.PostBody()) > 0 {
		_ = json.Unmarshal(ctx.PostBody(), &req)
	}

	var grant *authmanager.AuthorizationGrant
	if req.GrantID != "" {
		grant, _ = authmanager.GetGlobalManager().GetGrant(req.GrantID)
	} else if req.AssessmentID != "" {
		grant, _ = authmanager.GetGlobalManager().GetGrantByAssessment(req.AssessmentID)
	} else {
		// Default to most recent running lab grant if exists
		labs := h.labMgr.ListLabs()
		for _, l := range labs {
			if l.Status == labmanager.LabStatusRunning && (caller.Role == "admin" || caller.OrgID == l.OrgID) {
				grant, _ = authmanager.GetGlobalManager().GetGrant(l.GrantID)
				break
			}
		}
	}

	if grant == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "No active authorization grant found. Please start a practice lab or obtain an approved external grant.")
		return
	}

	// Cross-tenant check: caller must belong to the grant's organization or be platform admin
	if caller.Role != "admin" && caller.OrgID != grant.OrgID {
		labmanager.GetGlobalAuditLogger().Log("CROSS_TENANT_ATTEMPT", caller.UserID, caller.OrgID,
			fmt.Sprintf("Cross-tenant attempt to start assessment with grant %s belonging to org %s", grant.GrantID, grant.OrgID))
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden: cannot start assessment using another organization's grant")
		return
	}

	if grant.ApprovalStatus != authmanager.StatusApproved {
		SendError(ctx, fasthttp.StatusForbidden, fmt.Sprintf("Forbidden: assessment cannot start. Current grant status is %q. DNS verification alone does not authorize security testing.", grant.ApprovalStatus))
		return
	}
	if grant.IsRevoked {
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden: authorization grant is revoked")
		return
	}
	if time.Now().After(grant.ExpiryTime) {
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden: authorization grant has expired")
		return
	}

	labmanager.GetGlobalAuditLogger().Log("ASSESSMENT_STARTED", caller.UserID, caller.OrgID,
		fmt.Sprintf("Autonomous assessment initiated against %s with grant %s", grant.ResolvedTarget, grant.GrantID))

	mode := "multiagent"
	if req.Mode != "" {
		mode = req.Mode
	}
	concurrency := 2
	if req.Concurrency > 0 {
		concurrency = req.Concurrency
	}

	// Launch autonomous assessment via AssessmentService in configured mode
	run, err := h.assessmentService.StartAssessmentWithMode(ctx, caller, grant, mode, concurrency)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Failed to start autonomous assessment: %v", err))
		return
	}

	SendJSON(ctx, map[string]any{
		"status":        run.Status,
		"run_id":        run.RunID,
		"assessment_id": run.AssessmentID,
		"grant_id":      run.GrantID,
		"target":        run.TargetURL,
		"mode":          run.Mode,
		"concurrency":   run.Concurrency,
		"pid":           run.PID,
		"start_time":    run.StartTime.Format(time.RFC3339),
		"message":       "Autonomous assessment runner launched successfully in " + run.Mode + " mode under verified scope",
	})
}

// getAssessmentResults handles GET /api/assessment/results
func (h *LabHandler) getAssessmentResults(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		SendError(ctx, code, errMsg)
		return
	}

	runID := string(ctx.QueryArgs().Peek("run_id"))
	asmID := string(ctx.QueryArgs().Peek("assessment_id"))

	var run *assessment.AssessmentRun
	var err error

	if runID != "" {
		run, err = h.assessmentService.GetRun(runID)
	} else if asmID != "" {
		run, err = h.assessmentService.GetRunByAssessment(asmID)
	} else {
		run, err = h.assessmentService.GetLatestRun(caller.OrgID, caller.Role == "admin")
	}

	if err == nil && run != nil {
		// Cross-tenant check
		if caller.Role != "admin" && caller.OrgID != run.OrgID {
			SendError(ctx, fasthttp.StatusForbidden, "Forbidden: cannot view another organization's assessment results")
			return
		}

		endTimeStr := ""
		if run.EndTime != nil {
			endTimeStr = run.EndTime.Format(time.RFC3339)
		}

		SendJSON(ctx, map[string]any{
			"run_id":           run.RunID,
			"assessment_id":    run.AssessmentID,
			"target":           run.TargetURL,
			"grant_id":         run.GrantID,
			"status":           run.Status,
			"mode":             run.Mode,
			"concurrency":      run.Concurrency,
			"pid":              run.PID,
			"agent_model":      run.AgentModel,
			"start_time":       run.StartTime.Format(time.RFC3339),
			"end_time":         endTimeStr,
			"duration_seconds": run.DurationSeconds,
			"scope":            run.Scope,
			"tools_executed":   run.ToolsExecuted,
			"findings":         run.Findings,
			"blocked_requests": run.BlockedRequests,
			"final_report":     run.FinalReport,
			"error_message":    run.ErrorMessage,
		})
		return
	}

	// If no run found yet, return empty initial view for active lab
	targetURL := "http://127.0.0.1:5000"
	activeGrantID := "grant-lab-active"
	labs := h.labMgr.ListLabs()
	for _, l := range labs {
		if caller.Role == "admin" || caller.OrgID == l.OrgID {
			targetURL = l.TargetURL
			activeGrantID = l.GrantID
			break
		}
	}

	now := time.Now().UTC()
	SendJSON(ctx, map[string]any{
		"assessment_id":    "none",
		"target":           targetURL,
		"grant_id":         activeGrantID,
		"status":           "not_started",
		"start_time":       now.Format(time.RFC3339),
		"end_time":         "",
		"duration_seconds": 0,
		"scope": map[string]any{
			"allowed_cidrs":   []string{"127.0.0.1/32"},
			"allowed_ports":   []int{5000, 3000},
			"allowed_paths":   []string{"/", "/api/", "/rest/", "/assets/", "/ftp/", "/public/"},
			"blocked_paths":   []string{"/forbidden/admin/", "/internal/super-secret/"},
			"allowed_methods": []string{"GET", "HEAD", "POST", "OPTIONS"},
		},
		"tools_executed":   []assessment.ToolExecutionSummary{},
		"findings":         []assessment.Finding{},
		"blocked_requests": []assessment.BlockedScopeViolation{},
	})
}

// stopAssessmentRun handles POST /api/assessment/stop
func (h *LabHandler) stopAssessmentRun(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		SendError(ctx, code, errMsg)
		return
	}

	var req struct {
		RunID  string `json:"run_id"`
		Reason string `json:"reason"`
	}
	if len(ctx.PostBody()) > 0 {
		_ = json.Unmarshal(ctx.PostBody(), &req)
	}

	if req.RunID == "" {
		latest, err := h.assessmentService.GetLatestRun(caller.OrgID, caller.Role == "admin")
		if err == nil && latest != nil && (latest.Status == assessment.StateRunning || latest.Status == assessment.StateStarting) {
			req.RunID = latest.RunID
		}
	}

	if req.RunID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "run_id is required or no active run found")
		return
	}

	run, err := h.assessmentService.GetRun(req.RunID)
	if err != nil || run == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Assessment run not found")
		return
	}

	// Cross-tenant verification
	if caller.Role != "admin" && caller.OrgID != run.OrgID {
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden: cannot terminate another organization's assessment run")
		return
	}

	if err := h.assessmentService.StopAssessment(req.RunID, req.Reason); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}

	SendJSON(ctx, map[string]any{
		"status":  "cancelled",
		"run_id":  req.RunID,
		"message": "Assessment run cancelled successfully",
	})
}

// getAssessmentStatus handles GET /api/assessment/status
func (h *LabHandler) getAssessmentStatus(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		SendError(ctx, code, errMsg)
		return
	}

	runID := string(ctx.QueryArgs().Peek("run_id"))
	var run *assessment.AssessmentRun
	var err error

	if runID != "" {
		run, err = h.assessmentService.GetRun(runID)
	} else {
		run, err = h.assessmentService.GetLatestRun(caller.OrgID, caller.Role == "admin")
	}

	if err != nil || run == nil {
		SendJSON(ctx, map[string]any{
			"status":  "idle",
			"message": "No assessment runs found",
		})
		return
	}

	// Cross-tenant verification
	if caller.Role != "admin" && caller.OrgID != run.OrgID {
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden: access to assessment status denied")
		return
	}

	SendJSON(ctx, map[string]any{
		"run_id":           run.RunID,
		"assessment_id":    run.AssessmentID,
		"status":           run.Status,
		"target":           run.TargetURL,
		"pid":              run.PID,
		"start_time":       run.StartTime.Format(time.RFC3339),
		"duration_seconds": run.DurationSeconds,
		"findings_count":   len(run.Findings),
		"tools_count":      len(run.ToolsExecuted),
		"blocked_count":    len(run.BlockedRequests),
		"agent_model":      run.AgentModel,
		"error_message":    run.ErrorMessage,
	})
}

// rejectDirectManagedGrant explicitly forbids direct public invocation of /api/auth/managed-lab.
func (h *LabHandler) rejectDirectManagedGrant(ctx *fasthttp.RequestCtx) {
	caller, _, _ := h.resolveCaller(ctx)
	callerID := "anonymous"
	callerOrg := ""
	if caller != nil {
		callerID = caller.UserID
		callerOrg = caller.OrgID
	}
	labmanager.GetGlobalAuditLogger().Log("SECURITY_VIOLATION", callerID, callerOrg,
		"Direct invocation of /api/auth/managed-lab rejected; managed grants must be minted via lab orchestrator")
	SendError(ctx, fasthttp.StatusForbidden, "Forbidden: managed lab grants cannot be minted directly via API; they are issued exclusively by the internal lab orchestrator")
}

// getAuditEvents handles GET /api/lab/audit for admin audit review.
func (h *LabHandler) getAuditEvents(ctx *fasthttp.RequestCtx) {
	caller, code, errMsg := h.resolveCaller(ctx)
	if caller == nil {
		SendError(ctx, code, errMsg)
		return
	}

	events := labmanager.GetGlobalAuditLogger().GetEvents()
	filtered := make([]labmanager.AuditEvent, 0)
	for _, e := range events {
		if caller.Role == "admin" || (caller.Role == "org-admin" && caller.OrgID == e.OrgID) || caller.UserID == e.UserID {
			filtered = append(filtered, e)
		}
	}

	SendJSON(ctx, filtered)
}

// RegisterRoutes registers all authenticated lab management routes on the router.
func (h *LabHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.GET("/api/lab/me", lib.ChainMiddlewares(h.getCallerProfile, middlewares...))
	r.POST("/api/lab/start", lib.ChainMiddlewares(h.startLab, middlewares...))
	r.POST("/api/lab/stop", lib.ChainMiddlewares(h.stopLab, middlewares...))
	r.GET("/api/lab/status", lib.ChainMiddlewares(h.getLabStatus, middlewares...))
	r.GET("/api/lab/list", lib.ChainMiddlewares(h.listLabs, middlewares...))
	r.GET("/api/lab/audit", lib.ChainMiddlewares(h.getAuditEvents, middlewares...))
	r.POST("/api/auth/managed-lab", lib.ChainMiddlewares(h.rejectDirectManagedGrant, middlewares...))

	// External assessment routes
	r.POST("/api/auth/external/register", lib.ChainMiddlewares(h.registerExternalAssessment, middlewares...))
	r.POST("/api/auth/external/verify-dns", lib.ChainMiddlewares(h.verifyExternalDNS, middlewares...))
	r.POST("/api/auth/external/approve", lib.ChainMiddlewares(h.approveExternalAssessment, middlewares...))
	r.GET("/api/auth/external/list", lib.ChainMiddlewares(h.listExternalAssessments, middlewares...))
	r.GET("/api/auth/external/status", lib.ChainMiddlewares(h.getExternalAssessmentStatus, middlewares...))
	r.POST("/api/auth/external/revoke", lib.ChainMiddlewares(h.revokeExternalAssessment, middlewares...))

	// Assessment run and results routes
	r.POST("/api/assessment/start", lib.ChainMiddlewares(h.startAssessmentRun, middlewares...))
	r.POST("/api/assessment/stop", lib.ChainMiddlewares(h.stopAssessmentRun, middlewares...))
	r.GET("/api/assessment/status", lib.ChainMiddlewares(h.getAssessmentStatus, middlewares...))
	r.GET("/api/assessment/results", lib.ChainMiddlewares(h.getAssessmentResults, middlewares...))
}

