package authmanager

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/scopepolicy"
)

func TestAuthorizationManager(t *testing.T) {
	mgr := NewManager()

	// 1. Setup a valid Managed Lab Grant
	managedLab, err := mgr.CreateManagedLabAssessment(CreateManagedLabRequest{
		LabInstanceID:  "juice-shop-inst-42",
		ContainerID:    "test-container-42",
		UserID:         "user-alice",
		OrgID:          "org-acme",
		TargetHost:     "172.28.0.100",
		TargetPort:     3000,
		AllowedCIDRs:   []string{"172.28.0.100/32"},
		AllowedPaths:   []string{"/public/", "/products/"},
		BlockedPaths:   []string{"/admin/", "/payments/"},
		AllowedMethods: []string{"GET", "HEAD"},
		Duration:       1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create managed lab: %v", err)
	}

	// 2. Setup an External Assessment (starts Pending)
	externalAsm, err := mgr.CreateExternalAssessment(CreateExternalAssessmentRequest{
		UserID:         "user-bob",
		OrgID:          "org-cyber",
		TargetHost:     "target.corp.local",
		TargetPort:     3000,
		AllowedCIDRs:   []string{"172.28.0.100/32"},
		AllowedPaths:   []string{"/public/", "/products/"},
		BlockedPaths:   []string{"/admin/"},
		AllowedMethods: []string{"GET"},
	})
	if err != nil {
		t.Fatalf("Failed to create external assessment: %v", err)
	}

	// ---------------------------------------------------------
	// Scenario 1: Valid managed lab grant allows registered target
	// ---------------------------------------------------------
	t.Run("1_ValidManagedLabAllowed", func(t *testing.T) {
		grant, err := mgr.ValidateRequest(ValidationRequest{
			GrantID:   managedLab.GrantID,
			UserID:    "user-alice",
			OrgID:     "org-acme",
			TargetURL: "http://172.28.0.100:3000/products",
			Method:    "GET",
		})
		if err != nil {
			t.Fatalf("Expected valid managed lab to be allowed, got error: %v", err)
		}
		if grant.GrantID != managedLab.GrantID {
			t.Errorf("Mismatched grant returned: %s", grant.GrantID)
		}
	})

	// ---------------------------------------------------------
	// Scenario 2: Replacing managed lab target with netflix.com is blocked
	// ---------------------------------------------------------
	t.Run("2_ManagedLabTargetSubstitutionBlocked", func(t *testing.T) {
		_, err := mgr.ValidateRequest(ValidationRequest{
			GrantID:   managedLab.GrantID,
			UserID:    "user-alice",
			OrgID:     "org-acme",
			TargetURL: "https://netflix.com/browse",
			Method:    "GET",
		})
		if err == nil {
			t.Fatalf("CRITICAL SECURITY FAILURE: Arbitrary target netflix.com was allowed in managed lab mode!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 3: External website with no grant is blocked
	// ---------------------------------------------------------
	t.Run("3_NoGrantBlocked", func(t *testing.T) {
		_, err := mgr.ValidateRequest(ValidationRequest{
			GrantID:   "",
			UserID:    "user-bob",
			OrgID:     "org-cyber",
			TargetURL: "http://target.corp.local:3000/products",
			Method:    "GET",
		})
		if err == nil {
			t.Fatalf("CRITICAL SECURITY FAILURE: Request with missing grant was allowed!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 4: DNS verification without owner authorization is insufficient
	// ---------------------------------------------------------
	t.Run("4_DNSVerificationInsufficient", func(t *testing.T) {
		// Complete DNS challenge
		err := mgr.VerifyDNSChallenge(externalAsm.AssessmentID, externalAsm.DNSChallengeToken)
		if err != nil {
			t.Fatalf("DNS verification failed: %v", err)
		}

		// Attempt to scan without owner/admin approval
		_, err = mgr.ValidateRequest(ValidationRequest{
			AssessmentID: externalAsm.AssessmentID,
			UserID:       "user-bob",
			OrgID:        "org-cyber",
			TargetURL:    "http://target.corp.local:3000/products",
			Method:       "GET",
		})
		if err == nil {
			t.Fatalf("CRITICAL SECURITY FAILURE: DNS verification alone was accepted without owner approval!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 5: Pending external assessment is blocked
	// ---------------------------------------------------------
	t.Run("5_PendingExternalAssessmentBlocked", func(t *testing.T) {
		pendingAsm, _ := mgr.CreateExternalAssessment(CreateExternalAssessmentRequest{
			UserID:     "user-charlie",
			OrgID:      "org-test",
			TargetHost: "pending.corp.local",
			TargetPort: 3000,
		})
		_, err := mgr.ValidateRequest(ValidationRequest{
			AssessmentID: pendingAsm.AssessmentID,
			UserID:       "user-charlie",
			OrgID:        "org-test",
			TargetURL:    "http://pending.corp.local:3000/public/",
			Method:       "GET",
		})
		if err == nil {
			t.Fatalf("CRITICAL: Pending assessment was allowed before approval!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 6: Approved external assessment permits only approved scope
	// ---------------------------------------------------------
	t.Run("6_ApprovedExternalAssessmentAllowed", func(t *testing.T) {
		// Formally approve external assessment with owner evidence
		approvedGrant, err := mgr.ApproveExternalAssessment(ApproveAssessmentRequest{
			AssessmentID:    externalAsm.AssessmentID,
			ApproverID:      "admin-dave@target.corp.local",
			ApproverRole:    "target_owner",
			AuthEvidenceRef: "signed_permission_doc_sha256_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Duration:        2 * time.Hour,
		})
		if err != nil {
			t.Fatalf("Failed to approve external assessment: %v", err)
		}

		// Valid in-scope request
		g, err := mgr.ValidateRequest(ValidationRequest{
			GrantID:   approvedGrant.GrantID,
			UserID:    "user-bob",
			OrgID:     "org-cyber",
			TargetURL: "http://target.corp.local:3000/products",
			Method:    "GET",
		})
		if err != nil {
			t.Fatalf("Expected approved external assessment to be allowed, got: %v", err)
		}
		if g.ApprovalStatus != StatusApproved {
			t.Errorf("Expected StatusApproved, got %s", g.ApprovalStatus)
		}
	})

	// ---------------------------------------------------------
	// Scenario 7: Different user's grant cannot be reused
	// ---------------------------------------------------------
	t.Run("7_DifferentUserBlocked", func(t *testing.T) {
		_, err := mgr.ValidateRequest(ValidationRequest{
			GrantID:   managedLab.GrantID,
			UserID:    "user-attacker", // Not user-alice
			OrgID:     "org-acme",
			TargetURL: "http://172.28.0.100:3000/products",
			Method:    "GET",
		})
		if err == nil {
			t.Fatalf("CRITICAL: User was able to use another user's grant!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 8: Different organization's grant cannot be reused
	// ---------------------------------------------------------
	t.Run("8_DifferentOrgBlocked", func(t *testing.T) {
		_, err := mgr.ValidateRequest(ValidationRequest{
			GrantID:   managedLab.GrantID,
			UserID:    "user-alice",
			OrgID:     "org-competitor", // Not org-acme
			TargetURL: "http://172.28.0.100:3000/products",
			Method:    "GET",
		})
		if err == nil {
			t.Fatalf("CRITICAL: Organization was able to use another org's grant!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 9: Expired grant is blocked
	// ---------------------------------------------------------
	t.Run("9_ExpiredGrantBlocked", func(t *testing.T) {
		expiredLab, _ := mgr.CreateManagedLabAssessment(CreateManagedLabRequest{
			LabInstanceID: "lab-expired",
			ContainerID:   "test-container-expired",
			UserID:        "user-eve",
			OrgID:         "org-eve",
			TargetHost:    "172.28.0.100",
			TargetPort:    3000,
			Duration:      -1 * time.Minute, // Expired in the past
		})

		_, err := mgr.ValidateRequest(ValidationRequest{
			GrantID:   expiredLab.GrantID,
			UserID:    "user-eve",
			OrgID:     "org-eve",
			TargetURL: "http://172.28.0.100:3000/products",
			Method:    "GET",
		})
		if err == nil {
			t.Fatalf("CRITICAL: Expired grant was allowed!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 10: Revoked grant is blocked
	// ---------------------------------------------------------
	t.Run("10_RevokedGrantBlocked", func(t *testing.T) {
		revokableLab, _ := mgr.CreateManagedLabAssessment(CreateManagedLabRequest{
			LabInstanceID: "lab-to-revoke",
			ContainerID:   "test-container-revoke",
			UserID:        "user-frank",
			OrgID:         "org-frank",
			TargetHost:    "172.28.0.100",
			TargetPort:    3000,
			Duration:      1 * time.Hour,
		})

		// Revoke
		_ = mgr.RevokeGrant(revokableLab.GrantID, "security_team_intervention")

		_, err := mgr.ValidateRequest(ValidationRequest{
			GrantID:   revokableLab.GrantID,
			UserID:    "user-frank",
			OrgID:     "org-frank",
			TargetURL: "http://172.28.0.100:3000/products",
			Method:    "GET",
		})
		if err == nil {
			t.Fatalf("CRITICAL: Revoked grant was allowed!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 11: Target outside grant is blocked
	// ---------------------------------------------------------
	t.Run("11_TargetOutsideGrantBlocked", func(t *testing.T) {
		_, err := mgr.ValidateRequest(ValidationRequest{
			GrantID:   managedLab.GrantID,
			UserID:    "user-alice",
			OrgID:     "org-acme",
			TargetURL: "http://10.0.0.1:3000/products",
			Method:    "GET",
		})
		if err == nil {
			t.Fatalf("CRITICAL: Target outside grant was allowed!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 12: Unauthorized port is blocked
	// ---------------------------------------------------------
	t.Run("12_UnauthorizedPortBlocked", func(t *testing.T) {
		_, err := mgr.ValidateRequest(ValidationRequest{
			GrantID:   managedLab.GrantID,
			UserID:    "user-alice",
			OrgID:     "org-acme",
			TargetURL: "http://172.28.0.100:8443/products",
			Method:    "GET",
		})
		if err == nil {
			t.Fatalf("CRITICAL: Unauthorized port 8443 was allowed!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 13: Unauthorized path is blocked
	// ---------------------------------------------------------
	t.Run("13_UnauthorizedPathBlocked", func(t *testing.T) {
		_, err := mgr.ValidateRequest(ValidationRequest{
			GrantID:   managedLab.GrantID,
			UserID:    "user-alice",
			OrgID:     "org-acme",
			TargetURL: "http://172.28.0.100:3000/admin/secrets",
			Method:    "GET",
		})
		if err == nil {
			t.Fatalf("CRITICAL: Prohibited path /admin/secrets was allowed!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 14: Unauthorized HTTP method is blocked
	// ---------------------------------------------------------
	t.Run("14_UnauthorizedMethodBlocked", func(t *testing.T) {
		_, err := mgr.ValidateRequest(ValidationRequest{
			GrantID:   managedLab.GrantID,
			UserID:    "user-alice",
			OrgID:     "org-acme",
			TargetURL: "http://172.28.0.100:3000/products",
			Method:    "DELETE",
		})
		if err == nil {
			t.Fatalf("CRITICAL: Prohibited method DELETE was allowed!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 15: Redirect outside grant is blocked
	// ---------------------------------------------------------
	t.Run("15_RedirectOutsideGrantBlocked", func(t *testing.T) {
		adminHit := false
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/public/redirect" {
				http.Redirect(w, r, "/admin/", http.StatusFound)
			} else if r.URL.Path == "/admin/" {
				adminHit = true
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer ts.Close()

		var port int
		_, _ = fmt.Sscanf(ts.URL, "http://127.0.0.1:%d", &port)

		policy := scopepolicy.Policy{
			AllowedCIDRs: []string{"127.0.0.1/32"},
			AllowedPorts: []int{port},
			AllowedPaths: []string{"/public/"},
			BlockedPaths: []string{"/admin/"},
			AllowedMethods: []string{"GET"},
		}
		enforcer, _ := scopepolicy.NewFineGrainedScopeEnforcer(policy)
		client := scopepolicy.NewControlledHTTPClient(enforcer, false)

		_, err := client.Get(ts.URL + "/public/redirect")
		if err == nil {
			t.Fatalf("CRITICAL: Redirect to /admin/ was allowed!")
		}
		if adminHit {
			t.Fatalf("CRITICAL: Admin endpoint reached during redirect!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 16: Attempts to modify grant from MCP request are blocked
	// ---------------------------------------------------------
	t.Run("16_GrantTamperingIgnored", func(t *testing.T) {
		// Attacker attempts to inject expanded permissions in client request arguments
		tamperedScope := map[string]interface{}{
			"allowed_paths": []string{"/admin/", "/root/", "/"},
			"allowed_ports": []int{22, 443, 8080, 8443},
			"allowed_cidrs": []string{"0.0.0.0/0"},
			"allowed_methods": []string{"DELETE", "POST", "DROP"},
		}

		// Validation of a forbidden path must STILL FAIL because client scope is strictly ignored
		_, err := mgr.ValidateRequest(ValidationRequest{
			GrantID:             managedLab.GrantID,
			UserID:              "user-alice",
			OrgID:               "org-acme",
			TargetURL:           "http://172.28.0.100:3000/admin",
			Method:              "DELETE",
			ClientSuppliedScope: tamperedScope,
		})
		if err == nil {
			t.Fatalf("CRITICAL: Attacker successfully expanded grant permissions via client-supplied scope!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 17: Self-approval rejected by two-person separation rule
	// ---------------------------------------------------------
	t.Run("17_SelfApprovalRejected", func(t *testing.T) {
		selfAsm, _ := mgr.CreateExternalAssessment(CreateExternalAssessmentRequest{
			UserID:     "user-requester",
			OrgID:      "org-testing",
			TargetHost: "test.local",
			TargetPort: 8080,
		})
		_ = mgr.VerifyDNSChallenge(selfAsm.AssessmentID, selfAsm.DNSChallengeToken)

		// Requester tries to approve their own assessment
		_, err := mgr.ApproveExternalAssessment(ApproveAssessmentRequest{
			AssessmentID:    selfAsm.AssessmentID,
			ApproverID:      "user-requester", // Same as UserID!
			ApproverRole:    "org_admin",
			ApproverOrgID:   "org-testing",
			AuthEvidenceRef: "signed_permission_doc_12345",
			Duration:        time.Hour,
		})
		if err == nil {
			t.Fatalf("CRITICAL SECURITY FAILURE: Requester self-approval was allowed!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 18: Cross-tenant approval rejected
	// ---------------------------------------------------------
	t.Run("18_CrossTenantApprovalRejected", func(t *testing.T) {
		tenantAsm, _ := mgr.CreateExternalAssessment(CreateExternalAssessmentRequest{
			UserID:     "user-target-org",
			OrgID:      "org-victim",
			TargetHost: "victim.local",
			TargetPort: 8080,
		})
		_ = mgr.VerifyDNSChallenge(tenantAsm.AssessmentID, tenantAsm.DNSChallengeToken)

		// Attacker from org-attacker tries to approve org-victim's assessment
		_, err := mgr.ApproveExternalAssessment(ApproveAssessmentRequest{
			AssessmentID:    tenantAsm.AssessmentID,
			ApproverID:      "attacker-admin",
			ApproverRole:    "org_admin",
			ApproverOrgID:   "org-attacker", // Different from org-victim!
			AuthEvidenceRef: "signed_permission_doc_12345",
			Duration:        time.Hour,
		})
		if err == nil {
			t.Fatalf("CRITICAL SECURITY FAILURE: Cross-tenant approval was allowed!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 19: Unauthorized approver role rejected
	// ---------------------------------------------------------
	t.Run("19_UnauthorizedApproverRoleRejected", func(t *testing.T) {
		roleAsm, _ := mgr.CreateExternalAssessment(CreateExternalAssessmentRequest{
			UserID:     "user-alice",
			OrgID:      "org-corp",
			TargetHost: "corp.local",
			TargetPort: 8080,
		})
		_ = mgr.VerifyDNSChallenge(roleAsm.AssessmentID, roleAsm.DNSChallengeToken)

		// Approver with role 'guest' or 'developer'
		_, err := mgr.ApproveExternalAssessment(ApproveAssessmentRequest{
			AssessmentID:    roleAsm.AssessmentID,
			ApproverID:      "user-bob",
			ApproverRole:    "developer",
			ApproverOrgID:   "org-corp",
			AuthEvidenceRef: "signed_permission_doc_12345",
			Duration:        time.Hour,
		})
		if err == nil {
			t.Fatalf("CRITICAL SECURITY FAILURE: Unauthorized approver role 'developer' was allowed!")
		}
	})

	// ---------------------------------------------------------
	// Scenario 20: Substantive evidence check enforced
	// ---------------------------------------------------------
	t.Run("20_SubstantiveEvidenceEnforced", func(t *testing.T) {
		evAsm, _ := mgr.CreateExternalAssessment(CreateExternalAssessmentRequest{
			UserID:     "user-alice",
			OrgID:      "org-corp",
			TargetHost: "corp2.local",
			TargetPort: 8080,
		})
		_ = mgr.VerifyDNSChallenge(evAsm.AssessmentID, evAsm.DNSChallengeToken)

		// Short evidence (< 8 chars)
		_, err := mgr.ApproveExternalAssessment(ApproveAssessmentRequest{
			AssessmentID:    evAsm.AssessmentID,
			ApproverID:      "admin-carol",
			ApproverRole:    "org_admin",
			ApproverOrgID:   "org-corp",
			AuthEvidenceRef: "abc",
			Duration:        time.Hour,
		})
		if err == nil {
			t.Fatalf("CRITICAL SECURITY FAILURE: Short evidence was accepted!")
		}
	})
}

