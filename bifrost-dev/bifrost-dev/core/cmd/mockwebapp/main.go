package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

const (
	jwtWeakSecret   = "secret123"
	jwtStrongSecret = "k9#mP$2vL!9xQ@7zR^4wY*1tB&5cN#8e"
	CanaryContent   = "CANARY_MARKER: TRAVERSAL_CANARY_VERIFIED_98432_SAFE_DISCLOSURE"
)

// isWithinDir checks if clean child path is within clean base directory (PentAGI containment pattern)
func isWithinDir(targetPath, baseDir string) bool {
	cleanTarget := filepath.Clean(targetPath)
	cleanBase := filepath.Clean(baseDir)
	return strings.HasPrefix(cleanTarget+string(filepath.Separator), cleanBase+string(filepath.Separator))
}

func initLabFiles(baseDir string) error {
	publicDir := filepath.Join(baseDir, "public")
	canaryDir := filepath.Join(baseDir, "canary")

	if err := os.MkdirAll(publicDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(canaryDir, 0755); err != nil {
		return err
	}

	welcomeFile := filepath.Join(publicDir, "welcome.txt")
	docFile := filepath.Join(publicDir, "documentation.txt")
	canaryFile := filepath.Join(canaryDir, "traversal-canary.txt")

	_ = os.WriteFile(welcomeFile, []byte("Welcome to OWASP Juice Shop Practice Lab Document Center.\nAuthorized file access baseline.\n"), 0644)
	_ = os.WriteFile(docFile, []byte("OWASP Juice Shop API Documentation: Version 16.0.0.\nPublic technical documentation.\n"), 0644)
	_ = os.WriteFile(canaryFile, []byte("CANARY_MARKER: TRAVERSAL_CANARY_VERIFIED_98432_SAFE_DISCLOSURE\nCONFIDENTIAL LAB FIXTURE - UNAUTHORIZED DISCLOSURE PROVES PATH TRAVERSAL\n"), 0644)

	log.Printf("[mock-web-app] Lab files initialized in %s", baseDir)
	return nil
}

type MockJWTClaims struct {
	Sub   int    `json:"sub"`
	Email string `json:"email"`
	Role  string `json:"role"`
	Iss   string `json:"iss,omitempty"`
	Aud   string `json:"aud,omitempty"`
	Iat   int64  `json:"iat,omitempty"`
	Exp   int64  `json:"exp,omitempty"`
}

func createMockJWT(claims MockJWTClaims, secret string, alg string) string {
	header := map[string]string{
		"alg": alg,
		"typ": "JWT",
	}
	headerBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)

	signingInput := headerB64 + "." + claimsB64
	if strings.ToLower(alg) == "none" || secret == "" {
		return signingInput + "."
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sigB64
}

func parseMockJWT(tokenString string) (map[string]any, MockJWTClaims, string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) < 2 {
		return nil, MockJWTClaims{}, "", fmt.Errorf("malformed token: must have at least header and payload")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, MockJWTClaims{}, "", fmt.Errorf("invalid header base64: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, MockJWTClaims{}, "", fmt.Errorf("invalid header json: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, MockJWTClaims{}, "", fmt.Errorf("invalid payload base64: %w", err)
	}
	var claims MockJWTClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, MockJWTClaims{}, "", fmt.Errorf("invalid claims json: %w", err)
	}

	sig := ""
	if len(parts) >= 3 {
		sig = parts[2]
	}

	return header, claims, sig, nil
}

func verifyMockJWTHMAC(tokenString string, secret string) bool {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return false
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	return hmac.Equal(sig, expectedSig)
}

var (
	publicHits           int64
	productsHits         int64
	adminHits            int64
	paymentsHits         int64
	privateHits          int64
	deleteHits           int64
	redirectEndpointHits int64
	totalRequests        int64
)

func main() {
	port := flag.Int("port", 5000, "Port for the mock web application")
	altPort := flag.Int("alt-port", 0, "Secondary port for backwards compatibility (disabled by default)")
	host := flag.String("host", "127.0.0.1", "Host for the mock web application")
	flag.Parse()

	if err := initLabFiles(filepath.Join("tmp", "lab-files")); err != nil {
		log.Printf("[mock-web-app] Warning: failed to initialize lab files: %v", err)
	}

	mux := http.NewServeMux()

	// 1. Allowed Endpoints
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			// fallback for unmatched routes
			http.NotFound(w, r)
			return
		}
		atomic.AddInt64(&totalRequests, 1)
		atomic.AddInt64(&publicHits, 1)

		// Modern CSP with frame-ancestors 'none' (supersedes X-Frame-Options)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none';")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
  <title>OWASP Juice Shop Practice Lab (Mocked)</title>
  <script src="/main.js"></script>
  <script src="/assets/public/vendor.js"></script>
  <script src="https://cdn.unauthorized-external-domain.com/tracker.js"></script>
  <script src="/public/redirect-bundle.js"></script>
</head>
<body>
<h1>Welcome to OWASP Juice Shop Practice Lab</h1>
<p>Authorized Security Assessment Target</p>
<form action="/rest/user/login" method="POST">
  <input type="text" name="email" placeholder="Email">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Log in</button>
</form>
<ul>
  <li><a href="/rest/products/search?q=juice">Product Search</a></li>
  <li><a href="/rest/basket/1">Basket 1 (Alice)</a></li>
  <li><a href="/rest/basket/2">Basket 2 (Bob)</a></li>
  <li><a href="/rest/user/whoami">User Profile (/rest/user/whoami)</a></li>
  <li><a href="/rest/admin/system-status">Admin Diagnostics (/rest/admin/system-status)</a></li>
  <li><a href="/rest/secure/verified-profile">Verified Profile (/rest/secure/verified-profile)</a></li>
  <li><a href="/rest/file/download?file=welcome.txt">Download Document (/rest/file/download?file=welcome.txt)</a></li>
  <li><a href="/rest/file/secure-download?file=welcome.txt">Secure Document Download (/rest/file/secure-download?file=welcome.txt)</a></li>
  <li><a href="/public/">Public Endpoint</a></li>
</ul>
</body>
</html>`))
	})

	// 1b. Realistic Juice Shop SQL Injection Authentication Endpoint
	mux.HandleFunc("/rest/user/login", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "Method not allowed"})
			return
		}

		var creds struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&creds)

		emailLow := strings.ToLower(creds.Email)
		// Check for classic SQL injection patterns
		isSQLi := strings.Contains(emailLow, "' or 1=1") ||
			strings.Contains(emailLow, "' or '1'='1") ||
			strings.Contains(emailLow, "' or true") ||
			strings.Contains(emailLow, "'--") ||
			strings.Contains(emailLow, "admin'--")

		if isSQLi {
			// Successful SQLi Authentication Bypass -> returns administrative session token
			adminClaims := MockJWTClaims{
				Sub:   1,
				Email: "admin@juice-sh.op",
				Role:  "admin",
				Iss:   "juice-shop-auth",
				Aud:   "juice-shop-api",
				Iat:   time.Now().Unix(),
				Exp:   time.Now().Add(24 * time.Hour).Unix(),
			}
			adminToken := createMockJWT(adminClaims, jwtWeakSecret, "HS256")

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "success",
				"data": map[string]any{
					"token": adminToken,
					"user": map[string]any{
						"id":    1,
						"email": "admin@juice-sh.op",
						"role":  "admin",
					},
				},
			})
			return
		}

		if creds.Email == "alice@juice-sh.op" && creds.Password == "alice123" {
			aliceClaims := MockJWTClaims{
				Sub:   2,
				Email: "alice@juice-sh.op",
				Role:  "customer",
				Iss:   "juice-shop-auth",
				Aud:   "juice-shop-api",
				Iat:   time.Now().Unix(),
				Exp:   time.Now().Add(24 * time.Hour).Unix(),
			}
			aliceToken := createMockJWT(aliceClaims, jwtWeakSecret, "HS256")

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "success",
				"data": map[string]any{
					"token": aliceToken,
					"user": map[string]any{
						"id":    2,
						"email": "alice@juice-sh.op",
						"role":  "customer",
					},
				},
			})
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "Invalid email or password.",
		})
	})

	// 1b-whoami. Standard Authenticated User Profile Endpoint
	mux.HandleFunc("/rest/user/whoami", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		w.Header().Set("Content-Type", "application/json")

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Authentication token required",
			})
			return
		}
		rawToken := strings.TrimSpace(authHeader[7:])
		header, claims, _, err := parseMockJWT(rawToken)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Invalid token format",
			})
			return
		}

		alg, _ := header["alg"].(string)
		if strings.ToLower(alg) == "none" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Algorithm none not permitted",
			})
			return
		}

		valid := verifyMockJWTHMAC(rawToken, jwtWeakSecret) || verifyMockJWTHMAC(rawToken, jwtStrongSecret)
		if !valid {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Invalid token signature",
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"user": map[string]any{
				"id":    claims.Sub,
				"email": claims.Email,
				"role":  claims.Role,
			},
		})
	})

	// 1b-admin. Vulnerable Admin System Diagnostics Endpoint (Accepts alg:none and weak secret forgery)
	mux.HandleFunc("/rest/admin/system-status", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		w.Header().Set("Content-Type", "application/json")

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Authentication token required",
			})
			return
		}
		rawToken := strings.TrimSpace(authHeader[7:])
		header, claims, sig, err := parseMockJWT(rawToken)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Malformed token",
			})
			return
		}

		alg, _ := header["alg"].(string)
		isNoneAlg := strings.ToLower(alg) == "none" || sig == ""

		// If algorithm is not "none", verify signature against weak or strong secret
		if !isNoneAlg {
			validWeak := verifyMockJWTHMAC(rawToken, jwtWeakSecret)
			validStrong := verifyMockJWTHMAC(rawToken, jwtStrongSecret)
			if !validWeak && !validStrong {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status": "error",
					"error":  "Invalid token signature",
				})
				return
			}
		}

		// Vulnerable authorization check: relies solely on token claim "role"
		if claims.Role != "admin" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Forbidden: Administrator role required",
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":      "success",
			"admin_panel": "System Diagnostics & Internal Telemetry",
			"diagnostics": map[string]any{
				"service":             "juice-shop-auth-service",
				"uptime_seconds":      86400,
				"system_token":        "SYS_DIAG_AUTHORIZED_7749",
				"active_sessions":     42,
				"internal_api_key":    "sec_k_9982348719_live_admin",
				"accepted_algorithm":  alg,
				"authenticated_admin": claims.Email,
			},
		})
	})

	// 1b-secure. Hardened & Verified Profile Endpoint (Defensive Reference Implementation)
	mux.HandleFunc("/rest/secure/verified-profile", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		w.Header().Set("Content-Type", "application/json")

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Authentication token required",
			})
			return
		}
		rawToken := strings.TrimSpace(authHeader[7:])
		header, claims, _, err := parseMockJWT(rawToken)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Malformed token",
			})
			return
		}

		// 1. Strict algorithm pinning
		alg, _ := header["alg"].(string)
		if alg != "HS256" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Invalid algorithm: only HS256 is permitted",
			})
			return
		}

		// 2. Strict cryptographic signature with strong secret only (rejects weak secret tokens)
		if !verifyMockJWTHMAC(rawToken, jwtStrongSecret) {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Signature verification failed",
			})
			return
		}

		// 3. Strict expiration enforcement
		if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Token has expired",
			})
			return
		}

		// 4. Strict claims validation
		if claims.Iss != "juice-shop-auth" || claims.Aud != "juice-shop-api" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Invalid token issuer or audience",
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"profile": map[string]any{
				"id":                 claims.Sub,
				"email":              claims.Email,
				"role":               claims.Role,
				"security_clearance": "VERIFIED_STRONG",
			},
		})
	})

	// 1c. Realistic Juice Shop BOLA / IDOR Basket Endpoint (/rest/basket/{id})
	mux.HandleFunc("/rest/basket/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		w.Header().Set("Content-Type", "application/json")

		basketIDStr := strings.TrimPrefix(r.URL.Path, "/rest/basket/")
		basketIDStr = strings.Trim(basketIDStr, "/")

		// Check Authorization Header
		authHeader := r.Header.Get("Authorization")
		log.Printf("[mock-web-app] /rest/basket/%s accessed with Auth: %q (Method: %s)", basketIDStr, authHeader, r.Method)

		if strings.TrimSpace(authHeader) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Authentication token required to view basket",
			})
			return
		}

		// Simulated DB items per basket
		baskets := map[string]map[string]any{
			"1": {
				"id":     1,
				"UserId": 1,
				"Owner":  "alice@juice-sh.op",
				"Products": []map[string]any{
					{"id": 1, "name": "Apple Juice (1000ml)", "price": 1.99, "quantity": 2},
					{"id": 3, "name": "Orange Juice (1000ml)", "price": 2.49, "quantity": 1},
				},
			},
			"2": {
				"id":     2,
				"UserId": 2,
				"Owner":  "bob@juice-sh.op",
				"Products": []map[string]any{
					{"id": 7, "name": "OWASP Juice Shop Iron-On Patch", "price": 4.99, "quantity": 1},
					{"id": 99, "name": "Confidential Executive Blueprint Drink", "price": 499.00, "quantity": 1},
				},
			},
		}

		basket, exists := baskets[basketIDStr]
		if !exists {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  fmt.Sprintf("Basket %s not found", basketIDStr),
			})
			return
		}

		// VULNERABLE BOLA: Returns basket data without verifying if authHeader matches basket Owner
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data":   basket,
		})
	})

	// 1c-protected. Protected Basket Endpoint with Enforced Object-Level Authorization
	mux.HandleFunc("/rest/basket/protected/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		w.Header().Set("Content-Type", "application/json")

		basketIDStr := strings.TrimPrefix(r.URL.Path, "/rest/basket/protected/")
		basketIDStr = strings.Trim(basketIDStr, "/")

		authHeader := r.Header.Get("Authorization")
		if strings.TrimSpace(authHeader) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Authentication token required",
			})
			return
		}

		// Enforce ownership: token-alice can only access basket 1, token-bob can only access basket 2
		if strings.Contains(authHeader, "token-alice") && basketIDStr != "1" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  fmt.Sprintf("Access denied: User alice is not authorized to access basket %s", basketIDStr),
			})
			return
		}
		if strings.Contains(authHeader, "token-bob") && basketIDStr != "2" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  fmt.Sprintf("Access denied: User bob is not authorized to access basket %s", basketIDStr),
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]any{
				"id":    basketIDStr,
				"owner": "authorized_user",
				"items": []string{"Authorized protected basket content"},
			},
		})
	})

	// 1d. Reflected XSS Endpoint (/rest/products/search?q=...)
	mux.HandleFunc("/rest/products/search", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		q := r.URL.Query().Get("q")

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)

		// Unsanitized reflection of 'q' in HTML document
		htmlOutput := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Juice Shop Search Results</title></head>
<body>
<h1>Product Search Results</h1>
<div id="search-query-container">
  <span>Searched for: </span><span id="query">%s</span>
</div>
<div id="results">
  <p>No products found matching your search term.</p>
</div>
</body>
</html>`, q)
		_, _ = w.Write([]byte(htmlOutput))
	})

	// 1d-safe. Sanitized Search Endpoint (Safe against XSS via HTML Entity Encoding)
	mux.HandleFunc("/rest/products/safe-search", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		q := r.URL.Query().Get("q")

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)

		// Sanitized reflection using html.EscapeString
		safeQ := html.EscapeString(q)
		htmlOutput := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Juice Shop Safe Search Results</title></head>
<body>
<h1>Product Search Results</h1>
<div id="search-query-container">
  <span>Searched for: </span><span id="query">%s</span>
</div>
<div id="results">
  <p>No products found matching your search term.</p>
</div>
</body>
</html>`, safeQ)
		_, _ = w.Write([]byte(htmlOutput))
	})

	// 1. Allowed Endpoints
	mux.HandleFunc("/public/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		atomic.AddInt64(&publicHits, 1)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"endpoint": "/public/",
			"message":  "Welcome to the public application endpoint",
			"status":   "success",
		})
	})

	mux.HandleFunc("/products", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		if r.Method == http.MethodDelete {
			atomic.AddInt64(&deleteHits, 1)
		}
		atomic.AddInt64(&productsHits, 1)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"endpoint": "/products",
			"items": []map[string]any{
				{"id": 1, "name": "Secure Gateway Widget", "price": 99.99},
				{"id": 2, "name": "Scope Enforcer Shield", "price": 149.99},
			},
			"status": "success",
		})
	})
	mux.HandleFunc("/products/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		if r.Method == http.MethodDelete {
			atomic.AddInt64(&deleteHits, 1)
		}
		atomic.AddInt64(&productsHits, 1)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"endpoint": "/products/",
			"detail":   "Product item details",
			"path":     r.URL.Path,
			"method":   r.Method,
			"status":   "success",
		})
	})

	// 1e. Bundled JavaScript Files for Deep Endpoint Discovery
	mux.HandleFunc("/main.js", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`// Realistic Frontend Angular Bundle for OWASP Juice Shop
const APP_ROUTES = [
  { path: 'login', component: 'LoginComponent', api: '/rest/user/login' },
  { path: 'basket', component: 'BasketComponent', api: '/rest/basket' },
  { path: 'whoami', component: 'UserProfileComponent', api: '/rest/user/whoami' },
  { path: 'system-status', component: 'AdminDiagnosticsComponent', api: '/rest/admin/system-status' },
  { path: 'verified-profile', component: 'SecureProfileComponent', api: '/rest/secure/verified-profile' },
  { path: 'download', component: 'FileDownloadComponent', api: '/rest/file/download' },
  { path: 'secure-download', component: 'SecureDownloadComponent', api: '/rest/file/secure-download' },
  { path: 'products', component: 'ProductComponent', api: '/api/Products' },
  { path: 'users', component: 'UserComponent', api: '/api/Users' },
  { path: 'version', component: 'VersionComponent', api: '/rest/admin/application-version' },
  { path: 'feedback', component: 'FeedbackComponent', api: '/api/Feedbacks' },
  { path: 'complaints', component: 'ComplaintComponent', api: '/api/Complaints' },
  { path: 'redirect', component: 'RedirectComponent', api: '/rest/redirect' },
  { path: 'safe-redirect', component: 'SafeRedirectComponent', api: '/rest/safe-redirect' },
  { path: 'image-preview', component: 'ImagePreviewComponent', api: '/rest/image/preview' },
  { path: 'safe-image-preview', component: 'SafeImagePreviewComponent', api: '/rest/image/safe-preview' },
  { path: 'change-email', component: 'ChangeEmailComponent', api: '/rest/user/change-email' },
  { path: 'secure-change-email', component: 'SecureChangeEmailComponent', api: '/rest/user/secure-change-email' }
];

function authenticateUser(email, password) {
  return $http.post('/rest/user/login', { email: email, password: password });
}

function fetchBasket(basketId) {
  return $http.get('/rest/basket/' + basketId);
}

function getUserProfile(token) {
  return $http.get('/rest/user/whoami', { headers: { Authorization: 'Bearer ' + token } });
}

function getSystemDiagnostics(token) {
  return $http.get('/rest/admin/system-status', { headers: { Authorization: 'Bearer ' + token } });
}

function getVerifiedProfile(token) {
  return $http.get('/rest/secure/verified-profile', { headers: { Authorization: 'Bearer ' + token } });
}

function downloadDocument(filename) {
  return fetch('/rest/file/download?file=' + encodeURIComponent(filename));
}

function downloadSecureDocument(filename) {
  return fetch('/rest/file/secure-download?file=' + encodeURIComponent(filename));
}

function loadCatalog() {
  return fetch('/api/Products').then(res => res.json());
}

function checkApplicationVersion() {
  return axios.get('/rest/admin/application-version');
}
`))
	})

	mux.HandleFunc("/assets/public/vendor.js", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`// Vendor bundle with shared utilities and duplicate references to test deduplication
const VENDOR_CONFIG = {
  apiBase: '/api',
  loginEndpoint: '/rest/user/login',
  trackingEndpoint: '/rest/track-order',
  catalogEndpoint: '/api/Products'
};
`))
	})

	// Redirect bundle to test redirect protection
	mux.HandleFunc("/public/redirect-bundle.js", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		http.Redirect(w, r, "/admin/malicious-bundle.js", http.StatusFound)
	})

	// 1f. Realistic Juice Shop API Endpoints
	mux.HandleFunc("/api/Products", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": []map[string]any{
				{"id": 1, "name": "Apple Juice (1000ml)", "price": 1.99},
				{"id": 2, "name": "Orange Juice (1000ml)", "price": 2.49},
				{"id": 3, "name": "Eggfruit Juice (500ml)", "price": 8.99},
			},
		})
	})

	mux.HandleFunc("/api/Users", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": []map[string]any{
				{"id": 1, "email": "admin@juice-sh.op", "role": "admin"},
				{"id": 2, "email": "alice@juice-sh.op", "role": "customer"},
			},
		})
	})

	mux.HandleFunc("/rest/admin/application-version", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":     "16.0.0",
			"environment": "practice-lab",
			"status":      "healthy",
		})
	})

	// 1g. Path Traversal Endpoint (/rest/file/download?file=...)
	// VULNERABLE: Resolves relative to tmp/lab-files/public without traversal filtering.
	// Contained strictly within tmp/lab-files to prevent touching real host files.
	mux.HandleFunc("/rest/file/download", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		fileParam := r.URL.Query().Get("file")
		if fileParam == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Parameter 'file' is required",
			})
			return
		}

		decoded := fileParam
		for i := 0; i < 3; i++ {
			if u, err := url.QueryUnescape(decoded); err == nil && u != decoded {
				decoded = u
			} else {
				break
			}
		}

		publicDir, _ := filepath.Abs(filepath.Join("tmp", "lab-files", "public"))
		baseLabDir, _ := filepath.Abs(filepath.Join("tmp", "lab-files"))
		resolvedPath := filepath.Clean(filepath.Join(publicDir, decoded))

		// Host Safety Barrier: strictly forbid escaping outside tmp/lab-files
		if !isWithinDir(resolvedPath, baseLabDir) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Access denied: Path escapes lab environment boundaries",
			})
			return
		}

		data, err := os.ReadFile(resolvedPath)
		if err != nil {
			if os.IsNotExist(err) {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status": "error",
					"error":  fmt.Sprintf("File not found: %s", html.EscapeString(fileParam)),
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "error", "error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

	// 1g-safe. Protected File Download Endpoint (/rest/file/secure-download?file=...)
	// DEFENSIVE: Enforces PentAGI's IsWithinDir canonical path validation. Rejects traversal attempts with 403 Forbidden.
	mux.HandleFunc("/rest/file/secure-download", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		fileParam := r.URL.Query().Get("file")
		if fileParam == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Parameter 'file' is required",
			})
			return
		}

		decoded := fileParam
		for i := 0; i < 3; i++ {
			if u, err := url.QueryUnescape(decoded); err == nil && u != decoded {
				decoded = u
			} else {
				break
			}
		}

		publicDir, _ := filepath.Abs(filepath.Join("tmp", "lab-files", "public"))
		resolvedPath := filepath.Clean(filepath.Join(publicDir, decoded))

		// PentAGI defensive check: verify path is strictly within publicDir
		if !isWithinDir(resolvedPath, publicDir) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "Access denied: Path traversal attempt detected",
			})
			return
		}

		data, err := os.ReadFile(resolvedPath)
		if err != nil {
			if os.IsNotExist(err) {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status": "error",
					"error":  fmt.Sprintf("File not found: %s", html.EscapeString(fileParam)),
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "error", "error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

	// 2. Blocked Endpoints (Handlers increment counters if reached - which indicates policy breach)
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		atomic.AddInt64(&adminHits, 1)

		log.Printf("[CRITICAL WARNING] /admin reached! Request should have been blocked!")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"endpoint": "/admin",
			"secret":   "ADMIN_CONFIDENTIAL_KEY_UNPROTECTED",
		})
	})
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		atomic.AddInt64(&adminHits, 1)

		log.Printf("[CRITICAL WARNING] /admin/ reached! Request should have been blocked!")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"endpoint": "/admin/",
			"secret":   "ADMIN_CONFIDENTIAL_KEY_UNPROTECTED",
		})
	})

	mux.HandleFunc("/payments", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		atomic.AddInt64(&paymentsHits, 1)

		log.Printf("[CRITICAL WARNING] /payments reached! Request should have been blocked!")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"endpoint": "/payments",
			"secret":   "PAYMENTS_VAULT_UNPROTECTED",
		})
	})
	mux.HandleFunc("/payments/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		atomic.AddInt64(&paymentsHits, 1)

		log.Printf("[CRITICAL WARNING] /payments/ reached! Request should have been blocked!")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"endpoint": "/payments/",
			"secret":   "PAYMENTS_VAULT_UNPROTECTED",
		})
	})

	mux.HandleFunc("/users/private/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		atomic.AddInt64(&privateHits, 1)

		log.Printf("[CRITICAL WARNING] /users/private/ reached! Request should have been blocked!")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"endpoint": "/users/private/",
			"secret":   "PRIVATE_USER_DATA_UNPROTECTED",
		})
	})

	// 3. Redirect Endpoint: /public/redirect-to-admin
	// Responds with 302 Found pointing to /admin/
	mux.HandleFunc("/public/redirect-to-admin", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		atomic.AddInt64(&redirectEndpointHits, 1)

		log.Printf("[mock-web-app] /public/redirect-to-admin called: Issuing 302 redirect -> /admin/")
		http.Redirect(w, r, "/admin/", http.StatusFound)
	})

	// Open Redirect (Vulnerable)
	mux.HandleFunc("/rest/redirect", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		dest := r.URL.Query().Get("url")
		if dest == "" {
			dest = r.URL.Query().Get("target")
		}
		if dest == "" {
			dest = r.URL.Query().Get("next")
		}
		if dest == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "Missing redirect destination parameter"})
			return
		}
		log.Printf("[mock-web-app] /rest/redirect called: 302 -> %s", dest)
		http.Redirect(w, r, dest, http.StatusFound)
	})

	// Open Redirect (Protected / Safe Counterevidence)
	mux.HandleFunc("/rest/safe-redirect", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		dest := r.URL.Query().Get("url")
		if dest == "" {
			dest = r.URL.Query().Get("target")
		}
		if dest == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "Missing destination"})
			return
		}
		// Enforce relative path or same host
		if strings.HasPrefix(dest, "/") && !strings.HasPrefix(dest, "//") {
			http.Redirect(w, r, dest, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "External redirection prohibited by security policy",
		})
	})

	// SSRF (Vulnerable)
	mux.HandleFunc("/rest/image/preview", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		targetURL := r.URL.Query().Get("url")
		if targetURL == "" {
			targetURL = r.URL.Query().Get("fetch")
		}
		if targetURL == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "Missing url parameter"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Simulate loopback or cloud metadata response
		if strings.Contains(targetURL, "127.0.0.1") || strings.Contains(targetURL, "localhost") || strings.Contains(targetURL, "169.254.") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":          200,
				"ssrf_target":     targetURL,
				"service":         "internal-loopback-service",
				"fetched_content": "SSRF_SIMULATED_INTERNAL_METADATA_SECRET_TOKEN_9921",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":      200,
			"ssrf_target": targetURL,
			"preview":     "image-preview-data-placeholder",
		})
	})

	// SSRF (Protected / Safe Counterevidence)
	mux.HandleFunc("/rest/image/safe-preview", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		targetURL := r.URL.Query().Get("url")
		if targetURL == "" {
			targetURL = r.URL.Query().Get("fetch")
		}
		if targetURL == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "Missing url parameter"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Defensive check: block loopback and private networks
		if strings.Contains(targetURL, "127.0.0.1") || strings.Contains(targetURL, "localhost") ||
			strings.Contains(targetURL, "169.254.") || strings.Contains(targetURL, "10.") ||
			strings.Contains(targetURL, "192.168.") || strings.Contains(targetURL, "172.16.") {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": "SSRF defense: fetch to loopback or private network rejected",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":      200,
			"ssrf_target": targetURL,
			"preview":     "safe-preview-data",
		})
	})

	// CSRF (Vulnerable)
	mux.HandleFunc("/rest/user/change-email", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Does NOT validate Origin or anti-CSRF token!
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    "success",
			"message":   "Email updated successfully",
			"csrf_safe": false,
		})
	})

	// CSRF (Protected / Safe Counterevidence)
	mux.HandleFunc("/rest/user/secure-change-email", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&totalRequests, 1)
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Enforce anti-CSRF token
		token := r.Header.Get("X-CSRF-Token")
		if token == "" || token != "valid-csrf-token-12345" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": "CSRF validation failed: missing or invalid anti-CSRF token",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    "success",
			"message":   "Email updated securely",
			"csrf_safe": true,
		})
	})

	// 4. Telemetry Endpoints
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total_requests":         atomic.LoadInt64(&totalRequests),
			"public_hits":            atomic.LoadInt64(&publicHits),
			"products_hits":          atomic.LoadInt64(&productsHits),
			"admin_hits":             atomic.LoadInt64(&adminHits),
			"payments_hits":          atomic.LoadInt64(&paymentsHits),
			"private_hits":           atomic.LoadInt64(&privateHits),
			"delete_hits":            atomic.LoadInt64(&deleteHits),
			"redirect_endpoint_hits": atomic.LoadInt64(&redirectEndpointHits),
		})
	})

	mux.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		atomic.StoreInt64(&totalRequests, 0)
		atomic.StoreInt64(&publicHits, 0)
		atomic.StoreInt64(&productsHits, 0)
		atomic.StoreInt64(&adminHits, 0)
		atomic.StoreInt64(&paymentsHits, 0)
		atomic.StoreInt64(&privateHits, 0)
		atomic.StoreInt64(&deleteHits, 0)
		atomic.StoreInt64(&redirectEndpointHits, 0)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "reset"})
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	if *altPort > 0 && *altPort != *port {
		go func() {
			altAddr := fmt.Sprintf("%s:%d", *host, *altPort)
			log.Printf("[mock-web-app] Also listening on secondary port http://%s (backwards compatibility)...", altAddr)
			if err := http.ListenAndServe(altAddr, mux); err != nil {
				log.Printf("[mock-web-app] Secondary port %d notice: %v", *altPort, err)
			}
		}()
	}

	addr := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("[mock-web-app] Starting mock web application on http://%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

