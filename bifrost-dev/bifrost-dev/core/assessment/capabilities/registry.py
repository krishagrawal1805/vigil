"""
Security Capability Registry
============================
Layer 2 of the Extensible Security Intelligence Architecture.

Connects:
- Layer 1: Decoupled Security Knowledge (Strix Markdown Skills & PentAGI Techniques)
- Layer 3: Controlled Security MCP Tools (ScopeEnforcer + Authorization Manager)

Enables dynamic capability querying so autonomous agents can discover relevant
tools, parameters, and counterevidence requirements based on endpoint hints,
eliminating hardcoded testing sequences.
"""

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Dict, Any, Optional


@dataclass
class SecurityCapability:
    id: str
    name: str
    cwe: str
    category: str
    severity: str
    tool_name: str
    mcp_tool: str
    description: str
    methodology_skill: str
    relevant_patterns: List[str] = field(default_factory=list)
    target_parameters: List[str] = field(default_factory=list)
    counterevidence_rule: str = ""
    required_evidence: str = ""
    defensive_pattern: str = ""
    status: str = "implemented"
    is_tool_implemented: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecurityCapabilityRegistry:
    """Registry maintaining all available autonomous security testing capabilities."""

    def __init__(self):
        self._capabilities: Dict[str, SecurityCapability] = {}
        self._register_default_capabilities()

    def register(self, cap: SecurityCapability):
        self._capabilities[cap.id] = cap

    def get(self, cap_id: str) -> Optional[SecurityCapability]:
        return self._capabilities.get(cap_id)

    def list_all(self) -> List[SecurityCapability]:
        return list(self._capabilities.values())

    def _register_default_capabilities(self):
        # 1. Path Traversal & Local File Inclusion
        self.register(SecurityCapability(
            id="path_traversal",
            name="Path Traversal & Local File Inclusion",
            cwe="CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            category="Path Traversal / Local File Inclusion",
            severity="High",
            tool_name="test_path_traversal",
            mcp_tool="mock_security_server-test_path_traversal",
            description="Tests file retrieval and document endpoints for relative directory traversal escapes and local file inclusion using harmless canary marker verification.",
            methodology_skill="path_traversal_lfi_rfi",
            relevant_patterns=["file", "download", "document", "path", "read", "view", "doc", "template", "include", "resource", "/rest/file/"],
            target_parameters=["file", "path", "filename", "doc", "document", "name", "template"],
            counterevidence_rule="Canary token TRAVERSAL_CANARY_VERIFIED_98432_SAFE_DISCLOSURE must be retrieved. If endpoint returns 403 Forbidden via canonical prefix checking (PentAGI IsWithinDir pattern) or rejects dot sequences, hypothesis must be REJECTED.",
            required_evidence="Disclosed canary token content matching exact canary marker from lab fixture directory tmp/lab-files/canary/.",
            defensive_pattern="Strict canonicalization using filepath.Clean followed by directory separator prefix validation (strings.HasPrefix(cleanTarget + sep, cleanBase + sep))."
        ))

        # 2. SQL Injection Authentication Bypass
        self.register(SecurityCapability(
            id="sql_injection",
            name="SQL Injection (Authentication Bypass)",
            cwe="CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            category="Injection",
            severity="High",
            tool_name="test_sql_injection",
            mcp_tool="mock_security_server-test_sql_injection",
            description="Safely tests authentication endpoints for SQL injection vulnerabilities using controlled boolean probes and counterevidence comparison.",
            methodology_skill="sql_injection",
            relevant_patterns=["login", "auth", "signin", "authenticate", "user", "password", "/rest/user/login"],
            target_parameters=["email", "username", "password", "query"],
            counterevidence_rule="Baseline negative probe must return 401 Unauthorized; positive probe must return 200 OK with session token; malformed probe must return 401. If baseline is 200 or all inputs return 401, hypothesis must be REJECTED.",
            required_evidence="Differential response: 200 OK with valid user token on injected payload vs 401 Unauthorized on legitimate failed credentials.",
            defensive_pattern="Parameterized queries and prepared statements with strict object mapping."
        ))

        # 3. Broken Object Level Authorization (BOLA/IDOR)
        self.register(SecurityCapability(
            id="bola_idor",
            name="Broken Object Level Authorization (BOLA / IDOR)",
            cwe="CWE-639: Authorization Bypass Through User-Controlled Key",
            category="Broken Object Level Authorization",
            severity="High",
            tool_name="verify_bola",
            mcp_tool="mock_security_server-verify_bola",
            description="Verifies whether resource endpoints enforce object-level ownership checks across different authenticated tenants.",
            methodology_skill="idor",
            relevant_patterns=["basket", "order", "account", "invoice", "user", "profile", "/rest/basket/"],
            target_parameters=["id", "basket_id", "user_id", "order_id"],
            counterevidence_rule="Unauthenticated request must return 401; cross-account authenticated request must return 200 with foreign tenant data. If protected endpoint returns 403 Forbidden with ownership enforcement, hypothesis must be REJECTED.",
            required_evidence="Foreign account ID disclosure (e.g. Alice viewing Bob's basket) under cross-account session token.",
            defensive_pattern="Server-side subject-to-resource authorization checks binding authenticated session ID to object owner."
        ))

        # 4. Reflected Cross-Site Scripting (XSS)
        self.register(SecurityCapability(
            id="reflected_xss",
            name="Reflected Cross-Site Scripting (XSS)",
            cwe="CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            category="Cross-Site Scripting",
            severity="Medium",
            tool_name="test_xss",
            mcp_tool="mock_security_server-test_xss",
            description="Tests reflection endpoints using benign HTML/script probes verified through contained Headless Chrome DOM execution.",
            methodology_skill="xss",
            relevant_patterns=["search", "query", "q", "msg", "message", "keyword", "filter", "/rest/products/search"],
            target_parameters=["q", "query", "search", "msg", "text"],
            counterevidence_rule="DOM title change or script execution confirmed in browser context. If input is HTML-entity encoded (&lt;img...&gt;) and DOM title remains unchanged, hypothesis must be REJECTED.",
            required_evidence="Headless Chrome execution confirmation: document.title modified to canary string in unsanitized context.",
            defensive_pattern="Contextual HTML entity encoding and strict Content-Security-Policy."
        ))

        # 5. JWT Security & Authentication Bypass
        self.register(SecurityCapability(
            id="jwt_security",
            name="JSON Web Token (JWT) Security Assessment",
            cwe="CWE-287: Improper Authentication",
            category="Broken Authentication",
            severity="High",
            tool_name="test_jwt_vulnerabilities",
            mcp_tool="mock_security_server-test_jwt_vulnerabilities",
            description="Performs offline cryptographic inspection, key dictionary analysis, alg:none bypass, signature tampering, and expiration validation on JWT tokens.",
            methodology_skill="authentication_jwt",
            relevant_patterns=["token", "jwt", "auth", "admin", "system-status", "whoami", "profile", "/rest/admin/system-status"],
            target_parameters=["token", "Authorization", "access_token"],
            counterevidence_rule="Target endpoint returns 200 OK under tampered/forged token. If endpoint enforces strict HS256 pinning, strong key verification, or expiration, hypothesis must be REJECTED or calibrated.",
            required_evidence="Administrative endpoint access (HTTP 200) achieved with reconstructed/forged administrative JWT token.",
            defensive_pattern="Pin accepted algorithms, enforce high-entropy keys, validate expiration and issuer/audience claims."
        ))

        # 6. Security Misconfiguration
        self.register(SecurityCapability(
            id="security_misconfiguration",
            name="Security Misconfiguration (Defensive Headers)",
            cwe="CWE-16: Security Misconfiguration",
            category="Security Misconfiguration",
            severity="Low",
            tool_name="check_misconfigurations",
            mcp_tool="mock_security_server-check_misconfigurations",
            description="Audits response headers for missing defensive standards (CSP, HSTS, XFO) and CORS misconfigurations.",
            methodology_skill="severity_calibration",
            relevant_patterns=["/", "public", "headers", "options", "cors"],
            target_parameters=[],
            counterevidence_rule="If CSP header contains 'frame-ancestors', Clickjacking is mitigated; missing XFO must NOT be reported as a vulnerability.",
            required_evidence="Defensive header absence without compensating standard header controls.",
            defensive_pattern="Implement modern Content-Security-Policy with frame-ancestors, HSTS, and X-Content-Type-Options: nosniff."
        ))

        # 7. Deep Endpoint Discovery
        self.register(SecurityCapability(
            id="deep_discovery",
            name="Deep Attack Surface & JavaScript Bundle Discovery",
            cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
            category="Information Disclosure",
            severity="Informational",
            tool_name="discover_endpoints",
            mcp_tool="mock_security_server-discover_endpoints",
            description="Extracts candidate REST routes, parameters, and application endpoints from HTML forms, anchor tags, and same-origin JavaScript bundles.",
            methodology_skill="counterevidence",
            relevant_patterns=["/", "main.js", "vendor.js", "assets", "routes", "api"],
            target_parameters=["paths"],
            counterevidence_rule="Discovered candidates must be same-origin and permitted by authorization scope; out-of-scope or foreign targets are rejected.",
            required_evidence="Extracted endpoint inventory classified by HTTP method, candidate parameters, and source origin.",
            defensive_pattern="Enforce route authorization on all backend endpoints rather than relying on frontend obscurity."
        ))

        # 8. Server-Side Request Forgery (SSRF)
        self.register(SecurityCapability(
            id="ssrf",
            name="Server-Side Request Forgery (SSRF)",
            cwe="CWE-918: Server-Side Request Forgery (SSRF)",
            category="Server-Side Request Forgery",
            severity="High",
            tool_name="test_ssrf",
            mcp_tool="mock_security_server-test_ssrf",
            description="Tests URL fetchers, webhook verifiers, and image previewers for internal network, loopback, or cloud metadata access.",
            methodology_skill="ssrf",
            relevant_patterns=["url", "fetch", "webhook", "src", "preview", "image", "avatar", "link", "/rest/image/preview"],
            target_parameters=["url", "fetch", "src", "link", "webhook", "image"],
            counterevidence_rule="Proves outbound server fetch to internal loopback or cloud metadata. If server validates destination against allowlist or blocks loopback/private addresses with 403, hypothesis must be REJECTED.",
            required_evidence="Internal service response data or loopback reflection obtained via server fetch parameter.",
            defensive_pattern="Strict URL parsing, schema pinning (https only), DNS resolution pinning, and blocking RFC1918, link-local, and 127.0.0.0/8 IPs."
        ))

        # 9. Open Redirect
        self.register(SecurityCapability(
            id="open_redirect",
            name="Open Redirection",
            cwe="CWE-601: URL Redirection to Untrusted Site ('Open Redirect')",
            category="Open Redirection",
            severity="Medium",
            tool_name="test_open_redirect",
            mcp_tool="mock_security_server-test_open_redirect",
            description="Tests navigation and redirect endpoints for unvalidated redirection to arbitrary external domains.",
            methodology_skill="open_redirect",
            relevant_patterns=["redirect", "url", "next", "return_to", "returnUrl", "continue", "goto", "target", "callback", "r", "/rest/redirect"],
            target_parameters=["url", "redirect", "next", "return_to", "target", "goto"],
            counterevidence_rule="HTTP 3xx response with Location header pointing to unvalidated external domain. If destination is constrained to relative same-origin paths or strict allowlist, hypothesis must be REJECTED.",
            required_evidence="HTTP 301/302 response with Location pointing to foreign/attacker canary destination.",
            defensive_pattern="Enforce relative URL paths or match destination against an exact origin allowlist."
        ))

        # 10. Cross-Site Request Forgery (CSRF)
        self.register(SecurityCapability(
            id="csrf",
            name="Cross-Site Request Forgery (CSRF)",
            cwe="CWE-352: Cross-Site Request Forgery (CSRF)",
            category="Cross-Site Request Forgery",
            severity="Medium",
            tool_name="test_csrf",
            mcp_tool="mock_security_server-test_csrf",
            description="Tests state-changing endpoints for missing anti-CSRF tokens, absent Origin header validation, or insecure SameSite cookie policies.",
            methodology_skill="csrf",
            relevant_patterns=["change", "update", "transfer", "email", "password", "settings", "profile", "/rest/user/change-email"],
            target_parameters=["email", "password", "token"],
            counterevidence_rule="State-changing POST succeeds without anti-CSRF token or with arbitrary Origin. If request is rejected with 403 or requires non-replayable token, hypothesis must be REJECTED.",
            required_evidence="Successful state modification without origin or anti-CSRF token verification.",
            defensive_pattern="Enforce anti-CSRF tokens, verify Origin/Referer headers, and set SameSite=Strict/Lax cookies."
        ))

        # 11. Command Injection (RCE) - Registered Knowledge / Methodology (No Safe MCP Tool in Controlled Lab)
        self.register(SecurityCapability(
            id="command_injection",
            name="OS Command Injection",
            cwe="CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            category="Command Injection",
            severity="Critical",
            tool_name="none",
            mcp_tool="none",
            description="Theoretical assessment of endpoints invoking system processes. NOTE: No controlled MCP execution tool exists in current safe environment. Do NOT attempt to execute tools. Record coverage as 'not_applicable' or 'needs_follow_up'.",
            methodology_skill="rce",
            relevant_patterns=["exec", "cmd", "command", "system", "shell", "run", "ping", "traceroute", "lookup"],
            target_parameters=["cmd", "command", "host", "target", "ip"],
            counterevidence_rule="Canary token execution observed via command output or timing. If input is rejected or passed as safe literal array without shell expansion, hypothesis must be REJECTED.",
            required_evidence="Deterministic canary execution output from shell-free or controlled command evaluation.",
            defensive_pattern="Avoid shell execution; use execve with separate argument vectors without shell evaluation.",
            status="registered_no_tool",
            is_tool_implemented=False
        ))

    def query(self, query_str: str = "", endpoint: str = "") -> List[Dict[str, Any]]:
        """
        Dynamically retrieves relevant security capabilities matching query keywords or an endpoint URL.
        """
        q_lower = query_str.lower().strip()
        ep_lower = endpoint.lower().strip()
        results = []

        for cap in self._capabilities.values():
            score = 0
            # Direct ID or name match
            if q_lower and (q_lower in cap.id.lower() or q_lower in cap.name.lower() or q_lower in cap.tool_name.lower()):
                score += 10

            # Pattern match in endpoint or query
            for pat in cap.relevant_patterns:
                if ep_lower and pat in ep_lower:
                    score += 5
                if q_lower and pat in q_lower:
                    score += 3

            # Parameter match
            for param in cap.target_parameters:
                if ep_lower and (f"{param}=" in ep_lower or f"/{param}" in ep_lower):
                    score += 4
                if q_lower and param in q_lower:
                    score += 2

            if score > 0:
                results.append((score, cap.to_dict()))

        # Sort by score descending
        results.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in results]


# Global singleton instance
_GLOBAL_REGISTRY = SecurityCapabilityRegistry()


def get_capability_registry() -> SecurityCapabilityRegistry:
    return _GLOBAL_REGISTRY


def query_security_capabilities(query: str = "", endpoint: str = "") -> str:
    """
    Agent tool function: returns formatted capabilities matching the query or endpoint.
    """
    registry = get_capability_registry()
    matches = registry.query(query_str=query, endpoint=endpoint)
    if not matches:
        all_caps = [f"- {c.id}: {c.name} (Tool: {c.tool_name}, CWE: {c.cwe})" for c in registry.list_all()]
        return (
            f"No specific capability matches for query='{query}' / endpoint='{endpoint}'.\n"
            "All available capabilities in registry:\n" + "\n".join(all_caps)
        )

    out = [f"=== Security Capabilities Matching query='{query}' endpoint='{endpoint}' ==="]
    for m in matches:
        out.append(f"\n[*] Capability: {m['name']} [{m['id']}]")
        out.append(f"    - CWE: {m['cwe']}")
        out.append(f"    - Severity: {m['severity']} | Category: {m['category']}")
        if not m.get("is_tool_implemented", True) or m.get("status") == "registered_no_tool":
            out.append(f"    - Controlled Tool: NONE (Status: registered_no_tool — No controlled MCP tool exists in current lab. DO NOT execute tools. Record coverage as 'not_applicable' or 'needs_follow_up')")
        else:
            out.append(f"    - Controlled Tool: {m['tool_name']} ({m['mcp_tool']}) [Status: {m.get('status', 'implemented')}]")
        out.append(f"    - Relevant Parameters: {', '.join(m['target_parameters']) if m['target_parameters'] else 'None'}")
        out.append(f"    - Strix Methodology Skill: {m['methodology_skill']}")
        out.append(f"    - Counterevidence Requirement: {m['counterevidence_rule']}")
        out.append(f"    - Defensive Pattern: {m['defensive_pattern']}")
    return "\n".join(out)


if __name__ == "__main__":
    # Test queries
    print("--- Test Query: file download ---")
    print(query_security_capabilities(query="file download", endpoint="/rest/file/download?file=welcome.txt"))
    print("\n--- Test Query: token ---")
    print(query_security_capabilities(query="jwt token", endpoint="/rest/admin/system-status"))

