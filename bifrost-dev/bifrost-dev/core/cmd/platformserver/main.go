package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/authmanager"
)

// corsMiddleware wraps an http.Handler with permissive local development CORS headers.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Bifrost-Setup-Token, X-CSRF-Token, Cookie")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs incoming HTTP requests with latency.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t0 := time.Now()
		next.ServeHTTP(w, r)
		dur := time.Since(t0)
		if !strings.HasPrefix(r.URL.Path, "/health") {
			log.Printf("[platform-server] %s %s (%v)", r.Method, r.URL.Path, dur)
		}
	})
}

// privateGatewayProtectionMiddleware blocks external requests to Bifrost internal administrative endpoints.
func privateGatewayProtectionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.ToLower(r.URL.Path)
		if strings.HasPrefix(p, "/setup_token") ||
			strings.HasPrefix(p, "/bifrost") ||
			strings.HasPrefix(p, "/virtual-keys") ||
			strings.HasPrefix(p, "/api/virtual-keys") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"Forbidden: direct access to internal LLM gateway infrastructure is restricted"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeadersAndCSRFMiddleware enforces security headers and double-submit CSRF protection.
func securityHeadersAndCSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Enforce Standard Security Headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' http: https:; font-src 'self' data:; frame-ancestors 'none';")
		w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")

		isHTTPS := r.TLS != nil ||
			strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") ||
			os.Getenv("PLATFORM_COOKIE_SECURE") == "true"
		if isHTTPS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Ensure client always receives a valid Double-Submit CSRF cookie on initial visit / GET requests
		csrfCookie, csrfErr := r.Cookie("csrf_token")
		if (csrfErr != nil || csrfCookie == nil || csrfCookie.Value == "") && (r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions) {
			csrfToken := authmanager.GenerateRandomID("csrf", 16)
			http.SetCookie(w, &http.Cookie{
				Name:     "csrf_token",
				Value:    csrfToken,
				Path:     "/",
				HttpOnly: false,
				Secure:   isHTTPS,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   86400,
			})
		}

		// 2. Double-Submit CSRF Verification on state-modifying HTTP methods
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch {
			// Exempt initial unauthenticated auth endpoints
			p := r.URL.Path
			isAuthExempt := p == "/api/v1/auth/login" ||
				p == "/api/v1/auth/register" ||
				p == "/api/v1/auth/bootstrap-admin"

			if !isAuthExempt {
				// If browser session cookie (token or auth_token) is present AND csrf_token cookie is present:
				// verify X-CSRF-Token matches the csrf_token cookie
				authCookie, authErr := r.Cookie("token")
				if authErr != nil || authCookie.Value == "" {
					authCookie, authErr = r.Cookie("auth_token")
				}
				csrfCookie, csrfErr := r.Cookie("csrf_token")

				if authErr == nil && authCookie.Value != "" && csrfErr == nil && csrfCookie.Value != "" {
					reqToken := r.Header.Get("X-CSRF-Token")
					if reqToken == "" {
						reqToken = r.Header.Get("X-XSRF-TOKEN")
					}
					if reqToken == "" || reqToken != csrfCookie.Value {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusForbidden)
						_, _ = w.Write([]byte(`{"error":"CSRF validation failed: missing or invalid X-CSRF-Token header"}`))
						return
					}
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	port := flag.Int("port", 8000, "Port for the standalone platform server")
	host := flag.String("host", "127.0.0.1", "Host to bind for the platform server")
	flag.Parse()

	handler := NewPlatformHandler()
	mux := http.NewServeMux()

	// =========================================================================
	// SYSTEM HEALTH & DIAGNOSTICS
	// =========================================================================
	mux.HandleFunc("/healthz", handler.handleHealth)
	mux.HandleFunc("/api/health", handler.handleHealth)

	// =========================================================================
	// PLATFORM V1 REST API
	// =========================================================================
	mux.HandleFunc("/api/v1/auth/register", handler.handleRegister)
	mux.HandleFunc("/api/v1/auth/login", handler.handleLogin)
	mux.HandleFunc("/api/v1/auth/logout", handler.handleLogout)
	mux.HandleFunc("/api/v1/auth/me", handler.handleMe)
	mux.HandleFunc("/api/v1/auth/csrf", handler.handleCSRFToken)
	mux.HandleFunc("/api/auth/csrf", handler.handleCSRFToken)
	mux.HandleFunc("/api/v1/auth/bootstrap-admin", handler.handleBootstrapAdmin)

	mux.HandleFunc("/api/v1/workspaces", handler.handleWorkspaces)

	mux.HandleFunc("/api/v1/grants/request", handler.handleRegisterGrant)
	mux.HandleFunc("/api/v1/grants/verify", handler.handleVerifyDNS)
	mux.HandleFunc("/api/v1/grants/verify-dns", handler.handleVerifyDNS)
	mux.HandleFunc("/api/v1/grants/approve", handler.handleApproveGrant)
	mux.HandleFunc("/api/v1/grants/revoke", handler.handleRevokeGrant)
	mux.HandleFunc("/api/v1/grants/status", handler.handleGetGrantStatus)
	mux.HandleFunc("/api/v1/grants", handler.handleListGrants)

	mux.HandleFunc("/api/v1/labs/stop", handler.handleStopLab)
	mux.HandleFunc("/api/v1/labs/status", handler.handleGetLabStatus)
	mux.HandleFunc("/api/v1/labs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handler.handleStartLab(w, r)
		} else {
			handler.handleListLabs(w, r)
		}
	})

	mux.HandleFunc("/api/v1/assessments/stop", handler.handleStopAssessment)
	mux.HandleFunc("/api/v1/assessments/status", handler.handleGetAssessmentStatus)
	mux.HandleFunc("/api/v1/assessments/results", handler.handleGetAssessmentResults)
	mux.HandleFunc("/api/v1/assessments/report", handler.handleGetReport)
	mux.HandleFunc("/api/v1/assessments/run", handler.handleStartAssessment)
	mux.HandleFunc("/api/v1/assessments", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handler.handleStartAssessment(w, r)
		} else {
			handler.handleGetAssessmentResults(w, r)
		}
	})

	mux.HandleFunc("/api/v1/findings", handler.handleListFindings)
	mux.HandleFunc("/api/v1/audit-logs/verify", handler.handleVerifyAuditChain)
	mux.HandleFunc("/api/v1/audit-logs", handler.handleGetAuditLogs)

	// =========================================================================
	// COMPATIBILITY API (Directly serves existing React RTK Query frontend)
	// =========================================================================
	mux.HandleFunc("/api/lab/me", handler.handleMe)
	mux.HandleFunc("/api/lab/start", handler.handleStartLab)
	mux.HandleFunc("/api/lab/stop", handler.handleStopLab)
	mux.HandleFunc("/api/lab/status", handler.handleGetLabStatus)
	mux.HandleFunc("/api/lab/list", handler.handleListLabs)
	mux.HandleFunc("/api/lab/audit/verify", handler.handleVerifyAuditChain)
	mux.HandleFunc("/api/lab/audit", handler.handleGetAuditLogs)
	mux.HandleFunc("/api/auth/managed-lab", handler.handleRejectManagedGrant)

	mux.HandleFunc("/api/auth/external/register", handler.handleRegisterGrant)
	mux.HandleFunc("/api/auth/external/verify-dns", handler.handleVerifyDNS)
	mux.HandleFunc("/api/auth/external/approve", handler.handleApproveGrant)
	mux.HandleFunc("/api/auth/external/revoke", handler.handleRevokeGrant)
	mux.HandleFunc("/api/auth/external/list", handler.handleListGrants)
	mux.HandleFunc("/api/auth/external/status", handler.handleGetGrantStatus)

	mux.HandleFunc("/api/assessment/start", handler.handleStartAssessment)
	mux.HandleFunc("/api/assessment/run", handler.handleStartAssessment)
	mux.HandleFunc("/api/assessment/stop", handler.handleStopAssessment)
	mux.HandleFunc("/api/assessment/status", handler.handleGetAssessmentStatus)
	mux.HandleFunc("/api/assessment/results", handler.handleGetAssessmentResults)

	// Wrap middlewares:
	// logging -> privateGatewayProtection -> securityHeadersAndCSRF -> cors
	protectedMux := privateGatewayProtectionMiddleware(mux)
	secureMux := securityHeadersAndCSRFMiddleware(protectedMux)
	loggedHandler := loggingMiddleware(secureMux)
	corsHandler := corsMiddleware(loggedHandler)

	addr := fmt.Sprintf("%s:%d", *host, *port)
	fmt.Println("================================================================================")
	fmt.Println("       INDEPENDENT AUTONOMOUS PENETRATION TESTING PLATFORM SERVER               ")
	fmt.Println("================================================================================")
	fmt.Printf("[*] Primary Standalone Server listening on: http://%s\n", addr)
	fmt.Println("[*] Application Architecture:")
	fmt.Println("    - Standalone Frontend Port:      3000 (React / Next.js)")
	fmt.Println("    - Standalone Backend Port:       8000 (Go Platform Server)")
	fmt.Println("    - Practice Lab Target Port:      5000 (Isolated Mock / Juice Shop)")
	fmt.Println("    - Controlled MCP Server Port:    3011 (Scope Enforcement & Tools)")
	fmt.Println("    - Internal Private LLM Gateway:  8080 (Bifrost loopback proxy only)")
	fmt.Println("[*] Security & Authentication Controls:")
	fmt.Println("    - Upgraded 600,000-Iteration PBKDF2 Passwords & Safe Migration")
	fmt.Println("    - Double-Submit CSRF Cookie Protection & Strict Security Headers")
	fmt.Println("    - HMAC-SHA256 Cryptographic Audit Trail with Sequence Verification")
	fmt.Println("    - Multi-Tenant & Workspace Isolation (RBAC: Admin, Security Officer, Pentester, Auditor)")
	fmt.Println("    - Strict Two-Person Authorization Separation (Requester != Approver)")
	fmt.Println("    - Multi-Agent Orchestration Default with Single-Agent Fallback")
	fmt.Println("    - Complete Bifrost LLM Gateway Isolation (Restricted Private Access)")
	fmt.Println("================================================================================")

	server := &http.Server{
		Addr:         addr,
		Handler:      corsHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Platform server fatal error: %v", err)
	}
}
