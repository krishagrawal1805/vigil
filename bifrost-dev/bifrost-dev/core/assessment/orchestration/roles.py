"""
Unified Agent Roles & Catalog
==============================
Defines standardized, deduplicated agent roles combining AEGIS and AEGIS architectures.
Each role possesses:
- Specific operational purpose
- Tailored system instructions
- Strict least-privilege tool bindings
- AEGIS methodology skills association
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class AgentRole:
    role_id: str
    name: str
    description: str
    category: str  # orchestrator, planning, reconnaissance, specialist, validation, monitoring, reporting
    allowed_tools: List[str]
    associated_skills: List[str]
    system_prompt_template: str
    max_turns: int = 10
    is_conditional: bool = False  # e.g., Coder/Installer for whitebox only

class RoleCatalog:
    """Catalog maintaining all unified agent role definitions."""

    def __init__(self):
        self._roles: Dict[str, AgentRole] = {}
        self._register_default_roles()

    def register(self, role: AgentRole):
        self._roles[role.role_id] = role

    def get(self, role_id: str) -> Optional[AgentRole]:
        return self._roles.get(role_id)

    def list_roles(self) -> List[AgentRole]:
        return list(self._roles.values())

    def _register_default_roles(self):
        # 1. Primary Orchestrator (AEGIS Root Agent + AEGIS Primary Agent)
        self.register(AgentRole(
            role_id="orchestrator",
            name="Primary Orchestrator",
            description="Owns the overall assessment, maintains threat model & scope, delegates subtasks to specialists, monitors budgets, and aggregates verified results.",
            category="orchestrator",
            allowed_tools=[
                "save_threat_model_summary",
                "get_threat_model_summary",
                "query_capabilities",
                "list_available_skills",
                "list_coverage_entries",
                "finish_assessment"
            ],
            associated_skills=["counterevidence", "severity_calibration"],
            system_prompt_template=(
                "You are the Primary Assessment Orchestrator for the Bifrost Autonomous Security Platform.\n"
                "You coordinate specialist agents across the assessment lifecycle.\n"
                "Responsibilities:\n"
                "- Maintain overall threat model and target scope.\n"
                "- Review reconnaissance intelligence and planning recommendations.\n"
                "- Delegate focused tasks to specialized security investigation agents.\n"
                "- Ensure every finding undergoes independent counterevidence validation.\n"
                "- Avoid performing all tests directly; delegate to specialized roles."
            ),
            max_turns=15
        ))

        # 2. Reconnaissance Agent (AEGIS Discovery + AEGIS Research)
        self.register(AgentRole(
            role_id="reconnaissance",
            name="Attack Surface Reconnaissance Specialist",
            description="Maps the target's attack surface by crawling authorized HTML and same-origin JavaScript bundles for REST API routes, endpoints, and input parameters.",
            category="reconnaissance",
            allowed_tools=[
                "discover_endpoints",
                "inspect_http",
                "check_misconfigurations",
                "record_coverage_entry"
            ],
            associated_skills=["counterevidence"],
            system_prompt_template=(
                "You are the Attack Surface Reconnaissance Specialist.\n"
                "Your objective is to map authorized in-scope routes, identify REST APIs, and examine response headers.\n"
                "Execute `discover_endpoints` to crawl HTML and JavaScript bundles.\n"
                "Inspect response headers with `inspect_http` and `check_misconfigurations`.\n"
                "Record preliminary surface coverage and return structured route intelligence to the Orchestrator."
            ),
            max_turns=8
        ))

        # 3. Planning Agent (AEGIS Generator + AEGIS Task Planning)
        self.register(AgentRole(
            role_id="planner",
            name="Subtask Planning Agent",
            description="Decomposes discovered attack surface into a prioritized, dependency-aware sequence of focused security testing tasks.",
            category="planning",
            allowed_tools=[
                "query_capabilities",
                "list_available_skills"
            ],
            associated_skills=["counterevidence", "severity_calibration"],
            system_prompt_template=(
                "You are the Subtask Planning Agent (adapted from AEGIS Generator).\n"
                "Your objective is to analyze the discovered attack surface and generate a minimal, high-impact investigation plan.\n"
                "Identify dependencies (e.g. Surface discovery before Auth testing), prioritize high-risk entry points, and assign specific specialists.\n"
                "For capabilities with no execution tools (e.g. Command Injection), designate them for coverage recording as 'not_applicable'."
            ),
            max_turns=6
        ))

        # 4. Refiner / Replanning Agent (AEGIS Refiner)
        self.register(AgentRole(
            role_id="refiner",
            name="Plan Refinement & Optimization Agent",
            description="Dynamically reviews completed investigation outcomes, prunes obsolete tasks, reprioritizes remaining tasks based on counterevidence, and fills coverage gaps.",
            category="planning",
            allowed_tools=[
                "query_capabilities",
                "list_coverage_entries"
            ],
            associated_skills=["counterevidence"],
            system_prompt_template=(
                "You are the Plan Refinement & Optimization Agent (adapted from AEGIS Refiner).\n"
                "Review outcomes of completed specialist tasks.\n"
                "Adapt the remaining investigation plan: eliminate redundant probes on hardened endpoints, create follow-ups for promising leads, and avoid pursuing disproven hypotheses."
            ),
            max_turns=6
        ))

        # 5. Injection Specialist (AEGIS SQLi + AEGIS Pentester)
        self.register(AgentRole(
            role_id="injection_specialist",
            name="SQL Injection Specialist",
            description="Investigates SQL injection vulnerabilities on authentication and query endpoints using benign, controlled probes and 3-step verification.",
            category="specialist",
            allowed_tools=[
                "test_sql_injection",
                "formulate_hypothesis",
                "record_finding",
                "evaluate_counterevidence",
                "reject_hypothesis",
                "abandon_hypothesis",
                "mark_hypothesis_inconclusive",
                "load_skill",
                "record_coverage_entry"
            ],
            associated_skills=["sql_injection", "authentication_bypass"],
            system_prompt_template=(
                "You are the SQL Injection Specialist Agent.\n"
                "Focus exclusively on investigating SQL injection on assigned endpoints (e.g. /rest/user/login).\n"
                "1. Formulate a structured hypothesis with `formulate_hypothesis`.\n"
                "2. Execute `test_sql_injection` to evaluate baseline 401, bypass 200, and negative control 401.\n"
                "3. If confirmed by working proof and negative control, commit the finding via `record_finding`.\n"
                "4. If defended or non-vulnerable, rule out via `reject_hypothesis` or `abandon_hypothesis`.\n"
                "5. Record coverage via `record_coverage_entry`."
            ),
            max_turns=8
        ))

        # 6. Authorization & JWT Specialist (AEGIS BOLA/JWT + AEGIS Pentester)
        self.register(AgentRole(
            role_id="auth_specialist",
            name="Authorization & Token Security Specialist",
            description="Investigates Broken Object Level Authorization (BOLA/IDOR) on resource endpoints and verifies JWT cryptographic posture on administrative routes.",
            category="specialist",
            allowed_tools=[
                "verify_bola",
                "test_jwt_vulnerabilities",
                "formulate_hypothesis",
                "record_finding",
                "evaluate_counterevidence",
                "reject_hypothesis",
                "abandon_hypothesis",
                "mark_hypothesis_inconclusive",
                "load_skill",
                "record_coverage_entry"
            ],
            associated_skills=["idor", "authentication_jwt"],
            system_prompt_template=(
                "You are the Authorization & Token Security Specialist.\n"
                "Focus on object ownership enforcement (BOLA/IDOR on /rest/basket/*) and JWT cryptographic posture (/rest/admin/system-status).\n"
                "1. Formulate hypotheses prior to probing with `formulate_hypothesis`.\n"
                "2. Evaluate dual-account access proofs (`verify_bola`) or JWT validation (`test_jwt_vulnerabilities`).\n"
                "3. If verified with working proof and negative control, commit via `record_finding`.\n"
                "4. If protected or access denied, rule out via `reject_hypothesis` or `abandon_hypothesis`.\n"
                "5. Record coverage via `record_coverage_entry`."
            ),
            max_turns=8
        ))

        # 7. Content & Web Specialist (AEGIS Web Vulnerability Specialists)
        self.register(AgentRole(
            role_id="content_specialist",
            name="Content & Web Vulnerability Specialist",
            description="Investigates Reflected XSS, Path Traversal/LFI, SSRF, Open Redirect, and CSRF on assigned endpoints under controlled canary verification.",
            category="specialist",
            allowed_tools=[
                "test_xss",
                "test_path_traversal",
                "test_ssrf",
                "test_open_redirect",
                "test_csrf",
                "formulate_hypothesis",
                "record_finding",
                "evaluate_counterevidence",
                "reject_hypothesis",
                "abandon_hypothesis",
                "mark_hypothesis_inconclusive",
                "load_skill",
                "record_coverage_entry"
            ],
            associated_skills=["xss", "path_traversal", "ssrf", "open_redirect", "csrf"],
            system_prompt_template=(
                "You are the Content & Web Vulnerability Specialist.\n"
                "Investigate assigned endpoints for XSS, Path Traversal, SSRF, Open Redirect, and CSRF.\n"
                "Strict safety controls: SSRF probes strictly access internal loopback canaries; Open Redirect uses non-following client; CSRF tests reversible changes.\n"
                "1. Formulate hypotheses with `formulate_hypothesis`.\n"
                "2. Run controlled tools (`test_xss`, `test_path_traversal`, etc.).\n"
                "3. If confirmed by working proof and negative control, commit via `record_finding`.\n"
                "4. If sanitized or defended, rule out via `reject_hypothesis` or `abandon_hypothesis`.\n"
                "5. Record coverage via `record_coverage_entry`."
            ),
            max_turns=10
        ))

        # 8. Independent Validation Agent (AEGIS Validation Chain)
        self.register(AgentRole(
            role_id="validator",
            name="Independent Evidence Validation Agent",
            description="Independently verifies candidate findings proposed by specialists. Enforces working proof, negative control evaluation, and counterevidence before ledger commitment.",
            category="validation",
            allowed_tools=[
                "evaluate_counterevidence",
                "record_finding",
                "reject_hypothesis",
                "mark_hypothesis_inconclusive"
            ],
            associated_skills=["counterevidence", "severity_calibration"],
            system_prompt_template=(
                "You are the Independent Evidence Validation Agent.\n"
                "You review candidate findings from specialists.\n"
                "Rules:\n"
                "1. If positive proof AND negative control prove vulnerability -> Commit finding via `record_finding`.\n"
                "2. If input is sanitized, escaped, or protected by access control -> Rule out via `reject_hypothesis`.\n"
                "3. If legitimate proof gap exists -> Mark `mark_hypothesis_inconclusive`.\n"
                "Never accept uncorroborated assertions or findings lacking tool execution records."
            ),
            max_turns=8
        ))

        # 9. Execution Adviser & Reflector (AEGIS Adviser + Reflector)
        self.register(AgentRole(
            role_id="adviser",
            name="Execution Adviser & Telemetry Monitor",
            description="Monitors multi-agent execution telemetry, detects stalled tasks, repeated tool calls (anti-looping), and enforces turn budgets.",
            category="monitoring",
            allowed_tools=[
                "list_coverage_entries"
            ],
            associated_skills=["counterevidence"],
            system_prompt_template=(
                "You are the Execution Adviser & Telemetry Monitor.\n"
                "Track multi-agent execution health. Detect stalled investigations, repeated tool calls, or turn exhaustion.\n"
                "Recommend when to conclude an unpromising hypothesis, prune tasks, or advise the Orchestrator to wrap up."
            ),
            max_turns=5
        ))

        # 10. Reporter Agent (AEGIS Reporter + AEGIS Reporting)
        self.register(AgentRole(
            role_id="reporter",
            name="Assessment Reporting Agent",
            description="Compiles final executive penetration testing report with verified findings, evaluated negative space, threat model alignment, and remediation roadmap.",
            category="reporting",
            allowed_tools=[
                "list_coverage_entries",
                "get_threat_model_summary"
            ],
            associated_skills=["severity_calibration"],
            system_prompt_template=(
                "You are the Assessment Reporting Agent.\n"
                "Compile the comprehensive assessment report summarizing the verified findings ledger, evaluated negative space coverage, and strategic remediation recommendations."
            ),
            max_turns=5
        ))

# Global Catalog Singleton
_ROLE_CATALOG = RoleCatalog()

def get_role_catalog() -> RoleCatalog:
    return _ROLE_CATALOG
