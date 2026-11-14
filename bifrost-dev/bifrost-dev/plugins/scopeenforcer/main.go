package scopeenforcer

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/authmanager"
	"github.com/maximhq/bifrost/core/schemas"
)

// PluginName identifies the scope enforcer plugin in Bifrost.
const PluginName = "scope_enforcer"

// ToolSchema defines parameter rules for an authorized security tool.
type ToolSchema struct {
	ServerName   string   `json:"server_name"`
	ToolName     string   `json:"tool_name"`
	TargetFields []string `json:"target_fields"`
	PortFields   []string `json:"port_fields"`
	AllowEmpty   bool     `json:"allow_empty"` // True only for utility tools that need no target
}

// ScopeConfig defines the mandatory scope rules for target authorization.
type ScopeConfig struct {
	AllowedCIDRs  []string              `json:"allowed_cidrs"`  // Mandatory: e.g. ["172.28.0.100/32"]
	AllowedPorts  []int                 `json:"allowed_ports"`  // Mandatory: e.g. [3000]
	AllowedHosts  []string              `json:"allowed_hosts"`  // Optional: e.g. ["lab.local"]
	BlockedCIDRs  []string              `json:"blocked_cidrs"`  // e.g. ["169.254.169.254/32", "127.0.0.0/8"]
	EnablePinning bool                  `json:"enable_pinning"` // Rewrite host in URLs to resolved IP
	RequireGrant  bool                  `json:"require_grant"`  // Enforce server-side authorization grant
	ToolsCatalog  map[string]ToolSchema `json:"tools_catalog"`  // ToolName -> Schema
}

// ScopeEnforcerPlugin enforces strict target and tool boundaries.
type ScopeEnforcerPlugin struct {
	config          ScopeConfig
	allowedPrefixes []netip.Prefix
	blockedPrefixes []netip.Prefix
	allowedPorts    map[int]struct{}
	allowedHosts    map[string]struct{}
	toolsCatalog    map[string]ToolSchema
	resolver        *net.Resolver
	mu              sync.RWMutex
}

// NewScopeEnforcerPlugin creates and validates the scope enforcer instance.
func NewScopeEnforcerPlugin(cfg ScopeConfig) (*ScopeEnforcerPlugin, error) {
	// Rule 1: AllowedCIDRs and AllowedPorts are MANDATORY
	if len(cfg.AllowedCIDRs) == 0 {
		return nil, fmt.Errorf("scope configuration error: allowed_cidrs is mandatory and cannot be empty")
	}
	if len(cfg.AllowedPorts) == 0 {
		return nil, fmt.Errorf("scope configuration error: allowed_ports is mandatory and cannot be empty")
	}

	p := &ScopeEnforcerPlugin{
		config:       cfg,
		allowedPorts: make(map[int]struct{}),
		allowedHosts: make(map[string]struct{}),
		toolsCatalog: make(map[string]ToolSchema),
		resolver: &net.Resolver{
			PreferGo: true,
		},
	}

	for _, cidr := range cfg.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed CIDR %q: %w", cidr, err)
		}
		p.allowedPrefixes = append(p.allowedPrefixes, prefix)
	}

	for _, cidr := range cfg.BlockedCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid blocked CIDR %q: %w", cidr, err)
		}
		p.blockedPrefixes = append(p.blockedPrefixes, prefix)
	}

	for _, port := range cfg.AllowedPorts {
		p.allowedPorts[port] = struct{}{}
	}

	for _, host := range cfg.AllowedHosts {
		p.allowedHosts[strings.ToLower(strings.TrimSpace(host))] = struct{}{}
	}

	// Default tool catalog if not provided
	if len(cfg.ToolsCatalog) == 0 {
		p.toolsCatalog = map[string]ToolSchema{
			"mock_scan": {
				ServerName:   "mock-security-server",
				ToolName:     "mock_scan",
				TargetFields: []string{"target", "url"},
				PortFields:   []string{"port"},
				AllowEmpty:   false,
			},
			"inspect_http": {
				ServerName:   "mock-security-server",
				ToolName:     "inspect_http",
				TargetFields: []string{"target", "url"},
				PortFields:   []string{"port"},
				AllowEmpty:   false,
			},
			"discover_endpoints": {
				ServerName:   "mock-security-server",
				ToolName:     "discover_endpoints",
				TargetFields: []string{"target", "url"},
				PortFields:   []string{"port"},
				AllowEmpty:   false,
			},
			"crawl_scope": {
				ServerName:   "mock-security-server",
				ToolName:     "crawl_scope",
				TargetFields: []string{"target", "url"},
				PortFields:   []string{"port"},
				AllowEmpty:   false,
			},
			"check_misconfigurations": {
				ServerName:   "mock-security-server",
				ToolName:     "check_misconfigurations",
				TargetFields: []string{"target", "url"},
				PortFields:   []string{"port"},
				AllowEmpty:   false,
			},
			"test_sql_injection": {
				ServerName:   "mock-security-server",
				ToolName:     "test_sql_injection",
				TargetFields: []string{"target", "url"},
				PortFields:   []string{"port"},
				AllowEmpty:   false,
			},
			"verify_bola": {
				ServerName:   "mock-security-server",
				ToolName:     "verify_bola",
				TargetFields: []string{"target", "url"},
				PortFields:   []string{"port"},
				AllowEmpty:   false,
			},
			"test_xss": {
				ServerName:   "mock-security-server",
				ToolName:     "test_xss",
				TargetFields: []string{"target", "url"},
				PortFields:   []string{"port"},
				AllowEmpty:   false,
			},
			"test_jwt_vulnerabilities": {
				ServerName:   "mock-security-server",
				ToolName:     "test_jwt_vulnerabilities",
				TargetFields: []string{"target", "url"},
				PortFields:   []string{"port"},
				AllowEmpty:   false,
			},
			"test_path_traversal": {
				ServerName:   "mock-security-server",
				ToolName:     "test_path_traversal",
				TargetFields: []string{"target", "url"},
				PortFields:   []string{"port"},
				AllowEmpty:   false,
			},
			"test_ssrf": {
				ServerName:   "mock-security-server",
				ToolName:     "test_ssrf",
				TargetFields: []string{"target", "url"},
				PortFields:   []string{"port"},
				AllowEmpty:   false,
			},
			"test_open_redirect": {
				ServerName:   "mock-security-server",
				ToolName:     "test_open_redirect",
				TargetFields: []string{"target", "url"},
				PortFields:   []string{"port"},
				AllowEmpty:   false,
			},
			"test_csrf": {
				ServerName:   "mock-security-server",
				ToolName:     "test_csrf",
				TargetFields: []string{"target", "url"},
				PortFields:   []string{"port"},
				AllowEmpty:   false,
			},
			"curl": {
				ServerName:   "security-tools",
				ToolName:     "curl",
				TargetFields: []string{"url"},
				AllowEmpty:   false,
			},
			"nmap": {
				ServerName:   "security-tools",
				ToolName:     "nmap",
				TargetFields: []string{"target", "host"},
				PortFields:   []string{"ports", "port", "-p", "p"},
				AllowEmpty:   false,
			},
			"ping": {
				ServerName: "utility",
				ToolName:   "ping",
				AllowEmpty: true,
			},
		}
	} else {
		p.toolsCatalog = cfg.ToolsCatalog
	}

	// Register server-prefixed tool names (e.g. "mock-security-server-mock_scan")
	// to match Bifrost's client-prefixed tool exposure.
	for _, s := range p.toolsCatalog {
		if s.ServerName != "" {
			p.toolsCatalog[s.ServerName+"-"+s.ToolName] = s
		}
	}

	return p, nil
}

// getToolSchema finds the schema for a tool name, matching bare names,
// client-prefixed names (e.g. "mock-security-server-mock_scan"), or registered tool suffixes.
func (p *ScopeEnforcerPlugin) getToolSchema(toolName string) (ToolSchema, bool) {
	if s, ok := p.toolsCatalog[toolName]; ok {
		return s, true
	}
	for _, s := range p.toolsCatalog {
		if s.ToolName == toolName {
			return s, true
		}
		if s.ServerName != "" && toolName == s.ServerName+"-"+s.ToolName {
			return s, true
		}
		if strings.HasSuffix(toolName, "-"+s.ToolName) {
			return s, true
		}
	}
	return ToolSchema{}, false
}

// GetName returns plugin name.
func (p *ScopeEnforcerPlugin) GetName() string {
	return PluginName
}

// Cleanup releases plugin resources.
func (p *ScopeEnforcerPlugin) Cleanup() error {
	return nil
}

// PreMCPHook intercepts and validates tool execution requests.
func (p *ScopeEnforcerPlugin) PreMCPHook(ctx *schemas.BifrostContext, req *schemas.BifrostMCPRequest) (*schemas.BifrostMCPRequest, *schemas.MCPPluginShortCircuit, error) {
	if req == nil || !req.RequestType.IsExecuteTool() {
		return req, nil, nil
	}

	toolName := req.GetToolName()
	if toolName == "" {
		return req, p.deny("missing tool name in MCP request"), nil
	}

	// Rule 4: Reject unknown security tools (Default-Deny)
	schema, ok := p.getToolSchema(toolName)
	if !ok {
		return req, p.deny(fmt.Sprintf("tool %q is not in the authorized tools catalog", toolName)), nil
	}

	// Utility tools permitted without target inspection
	if schema.AllowEmpty {
		return req, nil, nil
	}

	// Extract arguments
	argsMap, err := p.normalizeArguments(req.GetToolArguments())
	if err != nil {
		return req, p.deny(fmt.Sprintf("malformed arguments JSON: %v", err)), nil
	}

	// Rule 5: Reject missing or unrecognized target fields
	targets, err := p.extractTargetsBySchema(argsMap, schema)
	if err != nil {
		return req, p.deny(err.Error()), nil
	}
	if len(targets) == 0 {
		return req, p.deny(fmt.Sprintf("security tool %q requires a validated target field (%v), but none was provided", toolName, schema.TargetFields)), nil
	}

	// Authoritative Authorization Grant validation
	grantID, _ := argsMap["grant_id"].(string)
	assessmentID, _ := argsMap["assessment_id"].(string)
	userID, _ := argsMap["user_id"].(string)
	orgID, _ := argsMap["org_id"].(string)
	method, _ := argsMap["method"].(string)

	var activeGrant *authmanager.AuthorizationGrant
	if p.config.RequireGrant || grantID != "" || assessmentID != "" {
		if strings.TrimSpace(grantID) == "" && strings.TrimSpace(assessmentID) == "" {
			return req, p.deny("authorization denied: request lacks a valid server-side authorization grant"), nil
		}
		for _, target := range targets {
			g, valErr := authmanager.GetGlobalManager().ValidateRequest(authmanager.ValidationRequest{
				GrantID:             grantID,
				AssessmentID:        assessmentID,
				UserID:              userID,
				OrgID:               orgID,
				TargetURL:           target,
				Method:              method,
				ClientSuppliedScope: argsMap,
			})
			if valErr != nil {
				return req, p.deny(valErr.Error()), nil
			}
			activeGrant = g
		}
	}

	// If no authoritative grant was provided, validate against static scope configuration
	if activeGrant == nil {
		// Rule 7 & 8: Validate every extracted target against scope (IP, CIDR, Port, Scheme)
		for _, target := range targets {
			resolvedIP, err := p.validateTargetString(target)
			if err != nil {
				return req, p.deny(fmt.Sprintf("target %q out of scope: %v", target, err)), nil
			}

			// Rule 6: Fix hostname pinning without destroying scheme, port, path, query
			if p.config.EnablePinning && resolvedIP != "" {
				argsMap = p.pinTargetInArguments(argsMap, target, resolvedIP)
			}
		}

		// Validate tool port ranges if port fields are present (e.g. nmap)
		if len(schema.PortFields) > 0 {
			if err := p.validatePortArguments(argsMap, schema.PortFields); err != nil {
				return req, p.deny(fmt.Sprintf("port validation failed: %v", err)), nil
			}
		}
	}

	// Re-serialize modified arguments if pinning took place
	if p.config.EnablePinning {
		newJSON, err := json.Marshal(argsMap)
		if err == nil {
			if req.ChatAssistantMessageToolCall != nil {
				req.ChatAssistantMessageToolCall.Function.Arguments = string(newJSON)
			}
			if req.ResponsesToolMessage != nil {
				s := string(newJSON)
				req.ResponsesToolMessage.Arguments = &s
			}
		}
	}

	return req, nil, nil
}

// PostMCPHook passes through results.
func (p *ScopeEnforcerPlugin) PostMCPHook(ctx *schemas.BifrostContext, resp *schemas.BifrostMCPResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostMCPResponse, *schemas.BifrostError, error) {
	return resp, bifrostErr, nil
}

// deny constructs an MCPPluginShortCircuit returning HTTP 403 Forbidden.
func (p *ScopeEnforcerPlugin) deny(reason string) *schemas.MCPPluginShortCircuit {
	status := 403
	return &schemas.MCPPluginShortCircuit{
		Error: &schemas.BifrostError{
			IsBifrostError: true,
			StatusCode:     &status,
			Error: &schemas.ErrorField{
				Message: "ScopeEnforcer: access denied - " + reason,
			},
		},
	}
}

// extractTargetsBySchema extracts target strings from authorized schema fields only.
func (p *ScopeEnforcerPlugin) extractTargetsBySchema(args map[string]interface{}, schema ToolSchema) ([]string, error) {
	var targets []string
	allowedFieldMap := make(map[string]struct{})
	for _, f := range schema.TargetFields {
		allowedFieldMap[strings.ToLower(f)] = struct{}{}
	}

	var walk func(val interface{}, fieldName string)
	walk = func(val interface{}, fieldName string) {
		if val == nil {
			return
		}
		switch v := val.(type) {
		case map[string]interface{}:
			for k, innerVal := range v {
				walk(innerVal, strings.ToLower(k))
			}
		case []interface{}:
			for _, item := range v {
				walk(item, fieldName)
			}
		case string:
			if _, allowed := allowedFieldMap[fieldName]; allowed {
				trimmed := strings.TrimSpace(v)
				if trimmed != "" {
					targets = append(targets, trimmed)
				}
			}
		}
	}

	walk(args, "")
	return targets, nil
}

// validateTargetString checks scheme, port, IP, CIDR, and host rules.
func (p *ScopeEnforcerPlugin) validateTargetString(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("target is empty")
	}

	var host string
	var port int

	// Rule 9: Restrict network protocols (only http and https allowed)
	if strings.Contains(raw, "://") {
		parsedURL, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("malformed URL: %w", err)
		}
		scheme := strings.ToLower(parsedURL.Scheme)
		if scheme != "http" && scheme != "https" {
			return "", fmt.Errorf("unauthorized protocol scheme %q; only http and https are permitted", scheme)
		}

		host = parsedURL.Hostname()
		portStr := parsedURL.Port()
		if portStr != "" {
			pVal, err := strconv.Atoi(portStr)
			if err != nil {
				return "", fmt.Errorf("invalid port in URL: %w", err)
			}
			port = pVal
		} else {
			if scheme == "http" {
				port = 80
			} else {
				port = 443
			}
		}
	} else if strings.Contains(raw, ":") && !strings.Contains(raw, "]") {
		h, pStr, err := net.SplitHostPort(raw)
		if err != nil {
			return "", fmt.Errorf("malformed host:port string: %w", err)
		}
		pVal, err := strconv.Atoi(pStr)
		if err != nil {
			return "", fmt.Errorf("invalid port %q: %w", pStr, err)
		}
		host = h
		port = pVal
	} else {
		// Bare host without port
		host = raw
		if len(p.allowedPorts) == 1 {
			for onlyPort := range p.allowedPorts {
				port = onlyPort
			}
		} else {
			return "", fmt.Errorf("target %q omitted port; explicit port is required", raw)
		}
	}

	// Port enforcement
	if _, ok := p.allowedPorts[port]; !ok {
		return "", fmt.Errorf("port %d is not authorized (allowed: %v)", port, p.config.AllowedPorts)
	}

	// IP parsing & unmapping
	ipAddr, err := netip.ParseAddr(host)
	if err == nil {
		ipAddr = ipAddr.Unmap()
		if err := p.checkIPAgainstPrefixes(ipAddr); err != nil {
			return "", err
		}
		return ipAddr.String(), nil
	}

	// Hostname validation & DNS lookup
	lowerHost := strings.ToLower(host)
	if len(p.allowedHosts) > 0 {
		if _, ok := p.allowedHosts[lowerHost]; !ok {
			return "", fmt.Errorf("host %q not in approved host whitelist", lowerHost)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ips, err := p.resolver.LookupIPAddr(ctx, lowerHost)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("failed to resolve hostname %q: %v", lowerHost, err)
	}

	var pinnedIP string
	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip.IP.String())
		if err != nil {
			return "", fmt.Errorf("invalid resolved IP: %w", err)
		}
		addr = addr.Unmap()
		if err := p.checkIPAgainstPrefixes(addr); err != nil {
			return "", fmt.Errorf("DNS resolution for host %q returned unauthorized IP %s: %w", lowerHost, addr, err)
		}
		if pinnedIP == "" {
			pinnedIP = addr.String()
		}
	}

	return pinnedIP, nil
}

// checkIPAgainstPrefixes enforces blocked and allowed CIDR ranges.
func (p *ScopeEnforcerPlugin) checkIPAgainstPrefixes(addr netip.Addr) error {
	for _, blocked := range p.blockedPrefixes {
		if blocked.Contains(addr) {
			return fmt.Errorf("IP %s falls into prohibited CIDR %s", addr, blocked)
		}
	}
	for _, allowed := range p.allowedPrefixes {
		if allowed.Contains(addr) {
			return nil
		}
	}
	return fmt.Errorf("IP %s is not in any allowed CIDR range", addr)
}

// pinTargetInArguments rewrites hostname to resolved IP preserving scheme, port, path, query.
func (p *ScopeEnforcerPlugin) pinTargetInArguments(args map[string]interface{}, originalTarget, resolvedIP string) map[string]interface{} {
	rewriteURL := func(raw string) string {
		if !strings.Contains(raw, "://") {
			return resolvedIP
		}
		u, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		port := u.Port()
		if port != "" {
			u.Host = net.JoinHostPort(resolvedIP, port)
		} else {
			u.Host = resolvedIP
		}
		return u.String()
	}

	var walkUpdate func(val interface{}) interface{}
	walkUpdate = func(val interface{}) interface{} {
		switch v := val.(type) {
		case string:
			if v == originalTarget {
				return rewriteURL(v)
			}
			return v
		case map[string]interface{}:
			for k, inner := range v {
				v[k] = walkUpdate(inner)
			}
			return v
		case []interface{}:
			for i, item := range v {
				v[i] = walkUpdate(item)
			}
			return v
		default:
			return val
		}
	}

	return walkUpdate(args).(map[string]interface{})
}

// validatePortArguments parses and validates port numbers/ranges.
func (p *ScopeEnforcerPlugin) validatePortArguments(args map[string]interface{}, portFields []string) error {
	var portVal string
	for _, f := range portFields {
		if val, exists := args[f]; exists {
			portVal = fmt.Sprintf("%v", val)
			break
		}
	}
	if portVal == "" {
		return nil
	}

	portVal = strings.TrimSpace(portVal)
	if portVal == "*" || portVal == "-p-" || strings.HasPrefix(portVal, "1-65535") {
		return fmt.Errorf("wildcard port scans are forbidden")
	}

	parts := strings.Split(portVal, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rp := strings.Split(part, "-")
			if len(rp) != 2 {
				return fmt.Errorf("malformed port range %q", part)
			}
			s, err1 := strconv.Atoi(rp[0])
			e, err2 := strconv.Atoi(rp[1])
			if err1 != nil || err2 != nil || s > e {
				return fmt.Errorf("invalid range numbers in %q", part)
			}
			for pt := s; pt <= e; pt++ {
				if _, ok := p.allowedPorts[pt]; !ok {
					return fmt.Errorf("range contains unauthorized port %d", pt)
				}
			}
		} else {
			pt, err := strconv.Atoi(part)
			if err != nil {
				return fmt.Errorf("invalid port %q", part)
			}
			if _, ok := p.allowedPorts[pt]; !ok {
				return fmt.Errorf("port %d is not in allowed ports list", pt)
			}
		}
	}
	return nil
}

// normalizeArguments converts raw args to map[string]interface{}.
func (p *ScopeEnforcerPlugin) normalizeArguments(args interface{}) (map[string]interface{}, error) {
	if args == nil {
		return make(map[string]interface{}), nil
	}
	switch v := args.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return make(map[string]interface{}), nil
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			return nil, err
		}
		return m, nil
	case *string:
		if v == nil || strings.TrimSpace(*v) == "" {
			return make(map[string]interface{}), nil
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(*v), &m); err != nil {
			return nil, err
		}
		return m, nil
	case map[string]interface{}:
		return v, nil
	default:
		b, err := json.Marshal(args)
		if err != nil {
			return nil, err
		}
		var m map[string]interface{}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		return m, nil
	}
}
