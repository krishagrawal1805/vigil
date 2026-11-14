package scopepolicy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPolicyEnforcement(t *testing.T) {
	policy := DefaultLabPolicy()
	enforcer, err := NewFineGrainedScopeEnforcer(policy)
	if err != nil {
		t.Fatalf("Failed to initialize enforcer: %v", err)
	}

	tests := []struct {
		name      string
		method    string
		rawURL    string
		wantAllow bool
	}{
		// --- 1. Allowed paths ---
		{
			name:      "Allowed: /products",
			method:    "GET",
			rawURL:    "http://172.28.0.100:3000/products",
			wantAllow: true,
		},
		{
			name:      "Allowed: /products/item-123",
			method:    "GET",
			rawURL:    "http://172.28.0.100:3000/products/item-123",
			wantAllow: true,
		},
		{
			name:      "Allowed: /public/info",
			method:    "GET",
			rawURL:    "http://172.28.0.100:3000/public/info",
			wantAllow: true,
		},
		{
			name:      "Allowed: HEAD method on /products",
			method:    "HEAD",
			rawURL:    "http://172.28.0.100:3000/products",
			wantAllow: true,
		},

		// --- 2. Blocked resources ---
		{
			name:      "Blocked: /admin",
			method:    "GET",
			rawURL:    "http://172.28.0.100:3000/admin",
			wantAllow: false,
		},
		{
			name:      "Blocked: /admin/users",
			method:    "GET",
			rawURL:    "http://172.28.0.100:3000/admin/users",
			wantAllow: false,
		},
		{
			name:      "Blocked: /payments",
			method:    "GET",
			rawURL:    "http://172.28.0.100:3000/payments",
			wantAllow: false,
		},
		{
			name:      "Blocked: /users/private/keys",
			method:    "GET",
			rawURL:    "http://172.28.0.100:3000/users/private/keys",
			wantAllow: false,
		},

		// --- 3. Action-level blocked methods ---
		{
			name:      "Blocked: DELETE method on /products/1",
			method:    "DELETE",
			rawURL:    "http://172.28.0.100:3000/products/1",
			wantAllow: false,
		},
		{
			name:      "Blocked: POST method on /products",
			method:    "POST",
			rawURL:    "http://172.28.0.100:3000/products",
			wantAllow: false,
		},

		// --- 4. Path traversal / evasion attempts ---
		{
			name:      "Evasion: /public/../admin",
			method:    "GET",
			rawURL:    "http://172.28.0.100:3000/public/../admin",
			wantAllow: false,
		},
		{
			name:      "Evasion: /public/%2e%2e/admin",
			method:    "GET",
			rawURL:    "http://172.28.0.100:3000/public/%2e%2e/admin",
			wantAllow: false,
		},
		{
			name:      "Evasion: Double URL encoded /public/%252e%252e/admin",
			method:    "GET",
			rawURL:    "http://172.28.0.100:3000/public/%252e%252e/admin",
			wantAllow: false,
		},
		{
			name:      "Evasion: Multiple slashes //admin",
			method:    "GET",
			rawURL:    "http://172.28.0.100:3000//admin",
			wantAllow: false,
		},
		{
			name:      "Evasion: Matrix param /public/..;/admin",
			method:    "GET",
			rawURL:    "http://172.28.0.100:3000/public/..;/admin",
			wantAllow: false,
		},
		{
			name:      "Evasion: Backslash \\admin",
			method:    "GET",
			rawURL:    "http://172.28.0.100:3000/\\admin",
			wantAllow: false,
		},

		// --- 5. Target-level out-of-scope ---
		{
			name:      "Target out of scope: 192.0.2.10",
			method:    "GET",
			rawURL:    "http://192.0.2.10:3000/products",
			wantAllow: false,
		},
		{
			name:      "Target port unauthorized: port 22",
			method:    "GET",
			rawURL:    "http://172.28.0.100:22/products",
			wantAllow: false,
		},
		{
			name:      "Target scheme unauthorized: ftp://",
			method:    "GET",
			rawURL:    "ftp://172.28.0.100:3000/products",
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := enforcer.CheckRequest(tt.method, tt.rawURL)
			if tt.wantAllow && err != nil {
				t.Errorf("expected ALLOW, got error: %v", err)
			}
			if !tt.wantAllow && err == nil {
				t.Errorf("expected BLOCK, but request was allowed")
			}
		})
	}
}

func TestRedirectInterception(t *testing.T) {
	adminHit := false
	productsHit := false

	// Test server that redirects /public/redirect-to-admin to /admin/
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/redirect-to-admin":
			http.Redirect(w, r, "/admin/", http.StatusFound)
		case "/public/redirect-to-products":
			http.Redirect(w, r, "/products/", http.StatusFound)
		case "/admin/":
			adminHit = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ADMIN SECRET"))
		case "/products/":
			productsHit = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("PRODUCTS LIST"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	// Extract port from ts.URL
	var port int
	_, _ = fmt.Sscanf(ts.URL, "http://127.0.0.1:%d", &port)

	policy := Policy{
		AllowedCIDRs:   []string{"127.0.0.1/32"},
		AllowedPorts:   []int{port},
		AllowedHosts:   []string{"127.0.0.1"},
		AllowedPaths:   []string{"/public/", "/products/"},
		BlockedPaths:   []string{"/admin/"},
		AllowedMethods: []string{"GET"},
		ReadOnlyMode:   true,
	}

	enforcer, err := NewFineGrainedScopeEnforcer(policy)
	if err != nil {
		t.Fatalf("Failed to initialize enforcer: %v", err)
	}

	client := NewControlledHTTPClient(enforcer, false)

	// 1. Test redirect to allowed path (/public/redirect-to-products -> /products/)
	resp1, err := client.Get(ts.URL + "/public/redirect-to-products")
	if err != nil {
		t.Fatalf("Expected redirect to allowed path to succeed, got: %v", err)
	}
	resp1.Body.Close()
	if !productsHit {
		t.Errorf("Expected /products/ handler to be reached on allowed redirect")
	}

	// 2. Test redirect to blocked path (/public/redirect-to-admin -> /admin/)
	_, err = client.Get(ts.URL + "/public/redirect-to-admin")
	if err == nil {
		t.Fatalf("Expected redirect to /admin/ to be BLOCKED, but it succeeded!")
	}

	// VERIFY: The admin handler was NEVER reached!
	if adminHit {
		t.Errorf("CRITICAL SECURITY FAILURE: /admin/ handler was reached despite redirect block!")
	}
}

