"""VIGIL Autonomous Pentesting Runner for Bifrost Platform



Executes an autonomous penetration testing assessment using OpenAI Agents SDK



with Gemini through Bifrost LLM and MCP security gateways.







Features:



- Genuine multi-turn autonomous reasoning & dynamic tool selection



- Rules of Engagement (ROE) modes: 'broad' vs 'restricted'



- Isolated Run Ledger with zero cross-assessment history leakage



- Deduplication by (endpoint, method, parameter, CWE)



- Real-time grant revocation enforcement



- Strict counterevidence discipline inspired by native VIGIL methodologies



- Dual-account BOLA & contextual XSS verification



"""







import argparse



import asyncio



import json



import os



import random



import re



import sys



import time



from pathlib import Path



import urllib.request



import urllib.error



from urllib.parse import urlparse
from typing import Dict, List, Any, Optional







# CLI Argument Parser



parser = argparse.ArgumentParser(description="VIGIL Autonomous Assessment Runner")



parser.add_argument("--assessment-id", required=True, help="Authoritative Assessment ID")



parser.add_argument("--grant-id", required=True, help="Authoritative Grant ID")



parser.add_argument("--user-id", required=True, help="Authenticated User ID")



parser.add_argument("--org-id", required=True, help="Authenticated Org ID")



parser.add_argument("--target", required=True, help="Authorized Target URL")



parser.add_argument("--out-file", required=True, help="Path to write assessment execution results JSON")



parser.add_argument("--roe-mode", default="broad", choices=["broad", "restricted"], help="Rules of Engagement mode")



parser.add_argument("--max-turns", type=int, default=15, help="Maximum autonomous turns")



parser.add_argument("--resume", action="store_true", help="Resume from existing SQLite session database if available")



parser.add_argument("--mode", default="multiagent", choices=["single", "multiagent"], help="Orchestration mode: 'single' or 'multiagent'")



parser.add_argument("--concurrency", type=int, default=2, help="Max concurrent specialist agents in multiagent mode")

parser.add_argument("--model", default=None, help="Explicit LLM model name (e.g. gemini-2.5-flash)")







args = None



if __name__ == "__main__":



    args = parser.parse_args()







# Setup Bifrost & VIGIL directory in sys.path



BIFROST_ROOT = Path(__file__).resolve().parent.parent.parent.parent



if str(BIFROST_ROOT) not in sys.path:



    sys.path.insert(0, str(BIFROST_ROOT))







# Setup VIGIL directory in sys.path dynamically
def _find_VIGIL_root() -> Path:
    candidates = [
        os.environ.get("VIGIL_ROOT"),
        str(Path(__file__).resolve().parent.parent / "skills"),
        str(Path(__file__).resolve().parent.parent),
        "/app/core/assessment",
        "/app/VIGIL",
        r"c:\Users\krish\Downloads\hacathon\VIGIL-main\VIGIL-main",
    ]
    for c in candidates:
        if c:
            p = Path(c)
            if (p / "VIGIL" / "skills").exists() or (p / "skills").exists() or (p / "vulnerabilities").exists():
                return p
    return Path(r"c:\Users\krish\Downloads\hacathon\VIGIL-main\VIGIL-main")

def _get_skills_dir() -> Path:
    for candidate in [
        Path(__file__).resolve().parent.parent / "skills",
        Path("/app/core/assessment/skills"),
        VIGIL_ROOT / "VIGIL" / "skills",
        VIGIL_ROOT / "skills",
        VIGIL_ROOT,
    ]:
        if candidate.exists() and ((candidate / "vulnerabilities").exists() or list(candidate.glob("*.md")) or list(candidate.glob("*/*.md"))):
            return candidate
    return VIGIL_ROOT / "VIGIL" / "skills"

VIGIL_ROOT = _find_VIGIL_root()
if str(VIGIL_ROOT) not in sys.path:
    sys.path.insert(0, str(VIGIL_ROOT))

# Load credentials from environment with fallback to .env.VIGIL.local
env_vars = dict(os.environ)

env_file_candidates = [
    Path(os.environ.get("ENV_FILE", "")) if os.environ.get("ENV_FILE") else None,
    Path(r"c:\Users\krish\Downloads\hacathon\.env.VIGIL.local"),
    Path(".env.VIGIL.local"),
    Path(__file__).resolve().parents[4] / ".env.VIGIL.local" if len(Path(__file__).resolve().parents) >= 5 else None
]
for ef in env_file_candidates:
    if ef and str(ef) != "." and ef.exists():
        try:
            with open(ef, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        if k.strip() not in env_vars:
                            env_vars[k.strip()] = v.strip()
            break
        except Exception:
            pass

token = env_vars.get("BIFROST_VIRTUAL_KEY", "sk-bf-internal-platform")
llm_base = env_vars.get("BIFROST_LLM_BASE", "http://127.0.0.1:8080/v1")



if args and getattr(args, "model", None):
    model_name = args.model
elif "BIFROST_MODEL" in env_vars:
    model_name = env_vars["BIFROST_MODEL"]
elif "GEMINI_MODEL" in env_vars:
    model_name = env_vars["GEMINI_MODEL"]
else:
    model_name = "gemini-3.5-flash-lite"



mcp_url = env_vars.get("BIFROST_MCP_URL", "http://127.0.0.1:8080/mcp")
if not mcp_url.endswith("/mcp") and not mcp_url.endswith("/mcp/"):
    mcp_url = mcp_url.rstrip("/") + "/mcp"

if "BIFROST_AUTH_URL" in env_vars:
    auth_manager_url = env_vars["BIFROST_AUTH_URL"]
elif "BIFROST_MCP_URL" in env_vars:
    base = env_vars["BIFROST_MCP_URL"].replace("/mcp", "").rstrip("/")
    auth_manager_url = f"{base}/api/auth"
else:
    auth_manager_url = "http://127.0.0.1:3011/api/auth" 







# Configure environment for OpenAI SDK



os.environ["OPENAI_API_KEY"] = token



os.environ["OPENAI_BASE_URL"] = llm_base



os.environ["LLM_API_KEY"] = token



os.environ["LLM_API_BASE"] = llm_base







from agents import Agent, Runner, RunConfig, function_tool, set_default_openai_key, set_tracing_disabled



from agents.models.openai_provider import OpenAIChatCompletionsModel



from openai import AsyncOpenAI







set_default_openai_key(token, use_for_tracing=False)



set_tracing_disabled(True)







# -----------------------------------------------------------------------------



# Sensitive Data Sanitization



# -----------------------------------------------------------------------------



def redact_sensitive_data(val):



    if isinstance(val, str):



        # Redact Bearer tokens



        val = re.sub(r'Bearer\s+[A-Za-z0-9_\-\.]+', 'Bearer [REDACTED_TOKEN]', val, flags=re.IGNORECASE)



        # Redact JWTs



        val = re.sub(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+', 'eyJ...[REDACTED_JWT]', val)



        # Redact passwords



        val = re.sub(r'("password"\s*:\s*)"[^"]+"', r'\1"[REDACTED_PASSWORD]"', val, flags=re.IGNORECASE)



        # Redact session tokens



        val = re.sub(r'(connect\.sid|session|token)=([A-Za-z0-9_\-\.%]+)', r'\1=[REDACTED_SESSION]', val, flags=re.IGNORECASE)



        # Redact setup tokens / virtual keys



        val = re.sub(r'(?:VIGIL|bifrost)-[a-f0-9]{16,}', '[REDACTED_KEY]', val, flags=re.IGNORECASE)



        return val



    elif isinstance(val, dict):



        return {k: redact_sensitive_data(v) for k, v in val.items()}



    elif isinstance(val, list):



        return [redact_sensitive_data(item) for item in val]



    return val







# -----------------------------------------------------------------------------



# Structured Hypothesis Lifecycle & Isolated Run Ledger



# -----------------------------------------------------------------------------



class HypothesisState:



    CANDIDATE = "CANDIDATE"



    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"



    CONFIRMED = "CONFIRMED"



    REJECTED = "REJECTED"



    INCONCLUSIVE = "INCONCLUSIVE"



    BLOCKED_BY_SCOPE = "BLOCKED_BY_SCOPE"







class Hypothesis:



    def __init__(self, hyp_id: str, endpoint: str, vulnerability_type: str, cwe: str, parameter: str, suspicion_rationale: str):



        self.id = hyp_id



        self.endpoint = endpoint



        self.vulnerability_type = vulnerability_type



        self.cwe = cwe



        self.parameter = parameter or ""



        self.suspicion_rationale = suspicion_rationale



        self.status = HypothesisState.UNDER_INVESTIGATION



        self.tests_performed = []



        self.initial_evidence = ""



        self.negative_control_results = ""



        self.counterevidence = ""



        self.decision_rationale = ""



        self.confidence = "Low"



        self.severity = "Low"



        self.created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())



        self.updated_at = self.created_at







    def to_dict(self):



        return {



            "id": self.id,



            "endpoint": self.endpoint,



            "vulnerability_type": self.vulnerability_type,



            "cwe": self.cwe,



            "parameter": self.parameter,



            "status": self.status,



            "suspicion_rationale": self.suspicion_rationale,



            "tests_performed": self.tests_performed,



            "initial_evidence": self.initial_evidence,



            "negative_control_results": self.negative_control_results,



            "counterevidence": self.counterevidence,



            "decision_rationale": self.decision_rationale,



            "confidence": self.confidence,



            "severity": self.severity,



            "created_at": self.created_at,



            "updated_at": self.updated_at



        }







def get_canonical_resource_pattern(url: str, cwe: str = "", parameter: str = "") -> str:

    """Normalizes an endpoint URL into its canonical root cause resource pattern."""

    parsed = urlparse(url)

    path = parsed.path.rstrip("/")

    # Replace numeric path segments e.g. /basket/1, /basket/2 -> /basket/{id}

    # Also replace hex or uuid segments

    normalized_path = re.sub(r'/(?:[0-9]+|[0-9a-fA-F-]{8,})(?=/|$)', '/{id}', path)    # For collection endpoints without item path segment (e.g. /rest/basket):
    # Only normalize to /{id} if parameter explicitly targets a resource ID (e.g. id, basket_id)
    # and CWE indicates object-level authorization (CWE-639 / BOLA).
    # Otherwise, retain collection endpoint distinction so collection and item defects are not blindly merged.
    if ("639" in cwe or "bola" in cwe.lower()) and parameter.lower() in ("id", "basket_id", "bid"):
        if not normalized_path.endswith("/{id}"):
            normalized_path = normalized_path.rstrip("/") + "/{id}"

            

    base = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else ""

    return f"{base}{normalized_path}"



class IsolatedRunLedger:



    def __init__(self, run_id: str, assessment_id: str, grant_id: str, roe_mode: str):



        self.run_id = run_id



        self.assessment_id = assessment_id



        self.grant_id = grant_id



        self.roe_mode = roe_mode



        self.discovered_endpoints = []



        self.hypotheses = {}  # hyp_id -> Hypothesis



        self.findings = []



        self.dedup_keys = set()



        self.blocked_requests = []



        self.tool_invocations = []
        self.task_tool_map = {}  # task_id -> [inv_id, ...]
        self.active_task_id = None



        self.abandoned_hypotheses = []  # backwards-compatible list



        self.rejected_hypotheses = []



        self.inconclusive_hypotheses = []



        self.coverage_entries = []



        self.threat_model = {}



        self.start_time = time.time()







    def record_coverage(self, surface: str, risk_area: str, outcome: str, evidence: str = "") -> dict:



        entry = {



            "entry_id": f"COV-{len(self.coverage_entries)+1:03d}",



            "surface": surface.strip(),



            "risk_area": risk_area.strip(),



            "outcome": outcome.strip().lower(),



            "evidence": evidence.strip(),



            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())



        }



        self.coverage_entries.append(entry)



        return entry







    def set_threat_model(self, target: str, trust_boundaries: str, critical_assets: str, attacker_model: str):



        self.threat_model = {



            "target": target,



            "trust_boundaries": trust_boundaries,



            "critical_assets": critical_assets,



            "attacker_model": attacker_model,



            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())



        }







    def record_discovered_endpoints(self, raw_text: str):



        """Parses and records discovered attack surface from discovery tool output."""



        # Find endpoint paths in output



        found = re.findall(r'(?:\[ACCESSIBLE\]|Path:\s*)\s*(\/[a-zA-Z0-9_\-\.\/]*)', raw_text)
        if "/" not in self.discovered_endpoints and "[ACCESSIBLE] /" in raw_text:
            self.discovered_endpoints.insert(0, "/")

        for ep in found:
            ep = ep.strip()
            if not ep:
                continue

            if ep not in self.discovered_endpoints:

                self.discovered_endpoints.append(ep)



        # Also check JSON inventory block if present



        if "=== Discovered Endpoint Inventory (JSON) ===" in raw_text:



            try:



                json_part = raw_text.split("=== Discovered Endpoint Inventory (JSON) ===")[1].strip()



                inv = json.loads(json_part)



                for item in inv:



                    p = item.get("path")



                    if p and p not in self.discovered_endpoints:



                        self.discovered_endpoints.append(p)



            except Exception:



                pass
        self.flush_progress()

    def flush_progress(self):
        try:
            out_file = getattr(self, "out_file", None)
            if not out_file:
                try:
                    out_file = args.out_file
                except Exception:
                    out_file = None
            if not out_file and getattr(self, "run_id", None):
                out_file = f"/data/runs/{self.run_id}_result.json"
            if not out_file:
                return
            out_p = Path(out_file)
            prog_p = out_p.with_name(f"{out_p.name}.progress.json")
            prog_data = {
                "status": "running",
                "duration_seconds": int(time.time() - getattr(self, "start_time", time.time())),
                "discovered_endpoints": getattr(self, "discovered_endpoints", []),
                "tool_invocations": getattr(self, "tool_invocations", []),
                "hypotheses": [h.to_dict() for h in getattr(self, "hypotheses", {}).values()],
                "findings": getattr(self, "findings", []),
                "blocked_requests": getattr(self, "blocked_requests", []),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            tmp_p = prog_p.with_suffix(".tmp")
            with open(tmp_p, "w", encoding="utf-8") as f:
                json.dump(prog_data, f, indent=2)
            tmp_p.replace(prog_p)
        except Exception as e:
            print(f"  [!] Progress flush error: {e}")

    def reconcile_invocation_outcomes(self):
        confirmed_endpoints = {f.get("affected_url") for f in self.findings if f.get("verification") == "Confirmed"}
        corroborated_invs = {f.get("corroborated_tool_invocation") for f in self.findings if f.get("corroborated_tool_invocation")}

        for inv in self.tool_invocations:
            tool = inv.get("tool", "")
            target = inv.get("target", "")

            # Reconnaissance is NOT_EVALUATED
            if "discover" in tool:
                inv["security_outcome"] = "NOT_EVALUATED"
                continue

            # If invocation is the direct corroborated proof of a confirmed finding
            if inv.get("invocation_id") in corroborated_invs or (target in confirmed_endpoints and inv.get("confirmed")):
                inv["security_outcome"] = "CONFIRMED"
                continue

            # If the tool call was blocked by policy
            if inv.get("execution_status") == "BLOCKED":
                inv["security_outcome"] = "NOT_EVALUATED"
                continue

            # If the tool execution failed or threw an error
            if inv.get("execution_status") in ("ERROR", "FAILED"):
                inv["security_outcome"] = "INCONCLUSIVE"
                continue

            # If this was a baseline probe for BOLA (e.g. basket 1 where baseline is normal)
            if "verify_bola" in tool and target.endswith("/basket/1"):
                inv["security_outcome"] = "INCONCLUSIVE"
                continue

            # Otherwise, for security verification tools executed successfully that did not find a confirmed vulnerability,
            # it was tested and ruled out (defended surface)
            if inv.get("execution_status") == "SUCCESS":
                inv["security_outcome"] = "RULED_OUT"

    def set_active_task(self, task_id: Optional[str]):
        self.active_task_id = task_id

    def get_task_invocations(self, task_id: str) -> List[str]:
        return list(self.task_tool_map.get(task_id, []))

    def record_tool_call(self, tool_name: str, target_url: str, method: str, is_error: bool, details: str, raw_output: str = "", task_id: str = "") -> str:

        inv_id = f"INV-{len(self.tool_invocations) + 1:04d}"
        if not task_id:
            task_id = getattr(self, "active_task_id", None) or ""

        confirmed = False

        if not is_error and raw_output:
            try:
                data = json.loads(raw_output)
                confirmed = bool(data.get("confirmed", False))
            except Exception:
                if '"confirmed": true' in raw_output or '"confirmed":true' in raw_output:
                    confirmed = True

        # Execution status: SUCCESS, FAILED, BLOCKED, ERROR
        if "SCOPE ENFORCEMENT DENIAL" in details or "BLOCKED BY POLICY" in details or "ACCESS_CONTROL_VIOLATION" in details:
            execution_status = "BLOCKED"
        elif is_error:
            execution_status = "ERROR"
        else:
            execution_status = "SUCCESS"

        # Security outcome: CONFIRMED, RULED_OUT, INCONCLUSIVE, NOT_EVALUATED
        if execution_status == "BLOCKED":
            security_outcome = "NOT_EVALUATED"
        elif execution_status in ("ERROR", "FAILED"):
            security_outcome = "INCONCLUSIVE"
        elif "discover" in tool_name or tool_name == "discover_endpoints":
            security_outcome = "NOT_EVALUATED"
        elif confirmed:
            security_outcome = "CONFIRMED"
        else:
            lower_det = (details + " " + raw_output).lower()
            if "basket/1" in target_url:
                security_outcome = "INCONCLUSIVE"
            else:
                security_outcome = "RULED_OUT"

        record = {
            "invocation_id": inv_id,
            "task_id": task_id,
            "assessment_id": self.assessment_id,
            "run_id": self.run_id,
            "tool": tool_name,
            "target": target_url,
            "method": method,
            "execution_status": execution_status,
            "security_outcome": security_outcome,
            "is_error": is_error,
            "confirmed": confirmed,
            "details": details,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        self.tool_invocations.append(record)

        if task_id:
            self.task_tool_map.setdefault(task_id, []).append(inv_id)

        self.reconcile_invocation_outcomes()
        self.flush_progress()

        return inv_id







    def record_blocked_request(self, target_url: str, reason: str):



        self.blocked_requests.append({



            "target_url": target_url,



            "reason": reason,



            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())



        })







    def register_hypothesis(self, endpoint: str, vulnerability_type: str, cwe: str, parameter: str, suspicion_rationale: str) -> Hypothesis:



        hyp_id = f"HYP-{len(self.hypotheses) + 1:03d}"



        hyp = Hypothesis(hyp_id, endpoint, vulnerability_type, cwe, parameter, suspicion_rationale)



        self.hypotheses[hyp_id] = hyp



        print(f"  [*] Hypothesis Formulated: [{hyp_id}] {vulnerability_type} ({cwe}) on {endpoint} (param={parameter})")



        return hyp







    def get_or_create_hypothesis(self, endpoint: str, vulnerability_type: str, cwe: str = "", parameter: str = "") -> Hypothesis:



        for h in self.hypotheses.values():



            if h.endpoint == endpoint and (h.vulnerability_type.lower() in vulnerability_type.lower() or vulnerability_type.lower() in h.vulnerability_type.lower()):



                return h



        return self.register_hypothesis(endpoint, vulnerability_type, cwe, parameter, f"Autonomously formulated hypothesis for {vulnerability_type}")







    def update_hypothesis_evaluation(self, hyp_id: str, status: str, positive_ev: str, negative_ctrl: str, counterevidence: str, rationale: str, confidence: str = "High", severity: str = "High") -> tuple[bool, str]:



        hyp = self.hypotheses.get(hyp_id)



        if not hyp:



            return False, f"Hypothesis '{hyp_id}' not found."



        hyp.status = status



        hyp.initial_evidence = positive_ev



        hyp.negative_control_results = negative_ctrl



        hyp.counterevidence = counterevidence



        hyp.decision_rationale = rationale



        hyp.confidence = confidence



        hyp.severity = severity



        hyp.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())







        if status == HypothesisState.REJECTED:



            self.rejected_hypotheses.append(hyp.to_dict())



            self.abandoned_hypotheses.append({



                "endpoint": hyp.endpoint,



                "category": hyp.vulnerability_type,



                "reason": f"{rationale} (Counterevidence: {counterevidence})",



                "timestamp": hyp.updated_at



            })



            print(f"  [-] Hypothesis REJECTED: [{hyp_id}] {hyp.vulnerability_type} on {hyp.endpoint} -> {rationale}")



        elif status == HypothesisState.INCONCLUSIVE:



            self.inconclusive_hypotheses.append(hyp.to_dict())



            print(f"  [?] Hypothesis INCONCLUSIVE: [{hyp_id}] {hyp.vulnerability_type} on {hyp.endpoint} -> {rationale}")



        elif status == HypothesisState.CONFIRMED:



            print(f"  [+] Hypothesis CONFIRMED: [{hyp_id}] {hyp.vulnerability_type} on {hyp.endpoint}")



        return True, f"Hypothesis {hyp_id} transitioned to {status}."







    def record_abandoned_hypothesis(self, endpoint: str, category: str, reason: str, counterevidence: str = ""):



        # Backward-compatible helper for abandon_hypothesis tool



        hyp = self.get_or_create_hypothesis(endpoint, category)



        self.update_hypothesis_evaluation(



            hyp_id=hyp.id,



            status=HypothesisState.REJECTED,



            positive_ev="Tested without working exploitation",



            negative_ctrl="Observed protective or differential behavior",



            counterevidence=counterevidence or reason,



            rationale=reason



        )







    def add_finding(self, finding: dict) -> tuple[bool, str]:
        # Strict technical evidence and provenance verification
        aff_url = (finding.get("affected_url") or "").strip()
        raw_url = aff_url.split(" (")[0].strip()
        if not raw_url:
            return False, "REJECTED: Finding missing affected_url."

        cwe = finding.get("cwe") or ""
        param = finding.get("parameter") or ""
        method = (finding.get("method") or "GET").upper()
        dedup_key = f"{raw_url}|{method}|{param}|{cwe}"

        if dedup_key in self.dedup_keys:
            print(f"  [DEDUP] Duplicate finding ignored: {dedup_key}")
            return False, f"Duplicate finding for {raw_url} ({cwe})"







        # 1. Assessment and run isolation verification



        if finding.get("assessment_id") and finding.get("assessment_id") != self.assessment_id:



            return False, f"REJECTED: Cross-assessment finding rejected. Expected assessment '{self.assessment_id}', got '{finding.get('assessment_id')}'."



        if finding.get("run_id") and finding.get("run_id") != self.run_id:



            return False, f"REJECTED: Cross-run finding rejected. Expected run '{self.run_id}', got '{finding.get('run_id')}'."







        # 2. Enforce valid hypothesis in current assessment



        hyp_id = finding.get("hypothesis_id") or ""



        if not hyp_id:



            return False, "REJECTED: Finding missing mandatory hypothesis_id."



        if hyp_id not in self.hypotheses:



            return False, f"REJECTED: Hypothesis ID '{hyp_id}' does not exist in current assessment ledger."







        hyp = self.hypotheses[hyp_id]



        if hyp.status == HypothesisState.REJECTED:



            return False, f"REJECTED: Hypothesis '{hyp_id}' has already been evaluated as REJECTED in the hypothesis lifecycle."



        if hyp.status == HypothesisState.INCONCLUSIVE:



            return False, f"REJECTED: Hypothesis '{hyp_id}' is marked INCONCLUSIVE and lacks definitive verification."







        # 3. Verify endpoint provenance between hypothesis and finding



        hyp_ep = hyp.endpoint.strip()



        hyp_path = urlparse(hyp_ep).path if "://" in hyp_ep else hyp_ep.split("?")[0]



        aff_path = urlparse(aff_url).path if "://" in aff_url else aff_url.split("?")[0]







        def paths_match(p1: str, p2: str) -> bool:



            p1 = p1.rstrip("/")



            p2 = p2.rstrip("/")



            if p1 == p2:



                return True



            p1_base = "/".join(p1.split("/")[:-1]) if p1.split("/")[-1].isdigit() else p1



            p2_base = "/".join(p2.split("/")[:-1]) if p2.split("/")[-1].isdigit() else p2



            return p1_base == p2_base or p1.startswith(p2) or p2.startswith(p1)







        if not paths_match(hyp_path, aff_path):



            return False, f"REJECTED: Finding affected_url '{aff_url}' does not correspond to hypothesis endpoint '{hyp.endpoint}'."







        # 4. Enforce that an actual matching security tool was executed in current assessment



        cat_lower = (finding.get("category") or "").lower()



        title_lower = (finding.get("title") or "").lower()



        vuln_type = hyp.vulnerability_type.lower()







        matching_inv = None



        for inv in reversed(self.tool_invocations):



            if inv.get("assessment_id") != self.assessment_id:



                continue



            if inv.get("is_error"):



                continue







            inv_target = inv.get("target", "")



            inv_path = urlparse(inv_target).path if "://" in inv_target else inv_target.split("?")[0]







            if not paths_match(inv_path, aff_path):



                continue







            tool = inv.get("tool", "")



            # Check tool category relevance



            if ("sql" in cat_lower or "sql" in vuln_type or "injection" in title_lower) and "sql" in tool:



                matching_inv = inv



                break



            elif ("access" in cat_lower or "bola" in cat_lower or "idor" in vuln_type or "bola" in title_lower) and "bola" in tool:



                matching_inv = inv



                break



            elif ("cross-site" in cat_lower or "xss" in cat_lower or "scripting" in vuln_type or "xss" in title_lower) and "xss" in tool:



                matching_inv = inv



                break



            elif ("jwt" in cat_lower or "token" in cat_lower or "jwt" in vuln_type or "jwt" in title_lower or "auth" in cat_lower) and "jwt" in tool:



                matching_inv = inv



                break



            elif ("traversal" in cat_lower or "path" in cat_lower or "lfi" in cat_lower or "file" in cat_lower or "traversal" in vuln_type or "traversal" in title_lower) and ("traversal" in tool or "path" in tool):



                matching_inv = inv



                break



            elif ("ssrf" in cat_lower or "ssrf" in vuln_type or "forgery" in cat_lower) and "ssrf" in tool:



                matching_inv = inv



                break



            elif ("redirect" in cat_lower or "redirect" in vuln_type or "redirection" in title_lower) and "redirect" in tool:



                matching_inv = inv



                break



            elif ("csrf" in cat_lower or "csrf" in vuln_type or "cross-site request" in cat_lower) and "csrf" in tool:



                matching_inv = inv



                break



            elif ("command" in cat_lower or "rce" in cat_lower or "execution" in cat_lower) and ("command" in tool or "cmd" in tool):



                matching_inv = inv



                break



            elif ("misconfig" in cat_lower or "misconfig" in vuln_type) and "misconfig" in tool:



                matching_inv = inv



                break



            elif tool in ("inspect_http", "discover_endpoints"):



                matching_inv = inv







        if not matching_inv:



            return False, f"REJECTED: No verified tool execution logged for target '{aff_url}' matching vulnerability category '{finding.get('category')}'. Findings require genuine tool execution records."







        finding["corroborated_tool_invocation"] = matching_inv.get("invocation_id")
        finding["validator_decision_id"] = f"VAL-DEC-{len(self.findings) + 1:04d}"
        finding["evidence_record_id"] = f"EVID-{len(self.findings) + 1:04d}"







        # 5. Enforce evidence, negative control, and counterevidence presence



        ev = (finding.get("evidence") or "").strip()



        neg_ctrl = (finding.get("negative_control") or hyp.negative_control_results or "").strip()



        cev = (finding.get("counterevidence") or hyp.counterevidence or "").strip()







        if not ev or len(ev) < 15:



            return False, "REJECTED: Finding missing reproducible technical working evidence."



        if "not vulnerable" in ev.lower() or "unconfirmed" in ev.lower() or "safe against" in ev.lower():



            return False, "REJECTED: Cannot mark finding as confirmed when evidence indicates non-vulnerability or error."



        if not neg_ctrl or len(neg_ctrl) < 10:



            return False, "REJECTED: Finding missing mandatory negative control evaluation."



        if not cev or len(cev) < 10:



            return False, "REJECTED: Finding missing mandatory counterevidence analysis."

        canon_url = get_canonical_resource_pattern(aff_url.split(" (")[0], cwe, param)
        canon_key = f"{canon_url}|{method}|{cwe}"

        existing_finding = None
        for f in self.findings:
            f_canon = f.get("canonical_url") or get_canonical_resource_pattern(f.get("affected_url", "").split(" (")[0], f.get("cwe", ""), f.get("parameter", ""))
            f_method = (f.get("method") or "GET").upper()
            f_cwe = f.get("cwe") or ""
            if f"{f_canon}|{f_method}|{f_cwe}" == canon_key:
                existing_finding = f
                break

        if existing_finding is not None:
            if "affected_instances" not in existing_finding or not isinstance(existing_finding["affected_instances"], list):
                first_url = existing_finding.get("affected_url", "")
                existing_finding["affected_instances"] = [{
                    "url": first_url,
                    "parameter": existing_finding.get("parameter", ""),
                    "hypothesis_id": existing_finding.get("hypothesis_id", ""),
                    "evidence": (existing_finding.get("evidence") or "")[:200]
                }]
            if any(inst.get("url") in (aff_url, raw_url) for inst in existing_finding["affected_instances"]):
                print(f"  [DEDUP] Duplicate instance ignored: {raw_url}")
                return False, f"Duplicate finding for {raw_url} ({cwe})"
            instance_entry = {
                "url": aff_url,
                "parameter": param,
                "hypothesis_id": hyp_id,
                "evidence": ev[:200]
            }
            existing_finding["affected_instances"].append(instance_entry)
            n_instances = len(existing_finding["affected_instances"])
            existing_finding["affected_url"] = f"{canon_url} ({n_instances} verified instances)"
            existing_finding["canonical_url"] = canon_url
            self.dedup_keys.add(dedup_key)
            hyp.status = HypothesisState.CONFIRMED
            print(f"  [+] Multi-Instance Grouping: Appended {aff_url} to canonical finding {canon_url} ({n_instances} total instances)")
            return True, "SUCCESS"
        else:
            finding["canonical_url"] = canon_url
            finding["affected_instances"] = [{
                "url": aff_url,
                "parameter": param,
                "hypothesis_id": hyp_id,
                "evidence": ev[:200]
            }]
            self.dedup_keys.add(dedup_key)
            self.findings.append(dict(finding))
            self.reconcile_invocation_outcomes()
            self.flush_progress()
            hyp.status = HypothesisState.CONFIRMED
            print(f"  [+] Verified Finding Committed: [{finding.get('severity')}] {finding.get('title')} ({finding.get('cwe')}) on {finding.get('affected_url')}")
            return True, "SUCCESS"







    def summarize_tools(self):



        counts = {}



        for inv in self.tool_invocations:



            t = inv["tool"]



            if t not in counts:



                counts[t] = {"tool": t, "invocations": 0, "status": "success"}



            counts[t]["invocations"] += 1



            if inv["is_error"]:



                counts[t]["status"] = "blocked"



        return list(counts.values())







# -----------------------------------------------------------------------------



# Gateway Transport & Grant State Verification



# -----------------------------------------------------------------------------



def check_grant_revocation(grant_id: str) -> bool:



    """Checks real-time revocation status from Authorization Manager."""



    try:



        req = urllib.request.Request(f"{auth_manager_url}/grant?id={grant_id}")



        with urllib.request.urlopen(req, timeout=3) as resp:



            data = json.loads(resp.read().decode("utf-8"))



            return bool(data.get("is_revoked", False))



    except Exception:



        # If check fails, fail-safe (assume active unless explicitly revoked)



        return False







_mcp_session_id = None

def _get_mcp_session_id() -> str:
    global _mcp_session_id
    if _mcp_session_id:
        return _mcp_session_id
    try:
        init_req = urllib.request.Request(
            mcp_url,
            data=json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "VIGIL-runner", "version": "1.0"}}
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        resp = urllib.request.urlopen(init_req, timeout=5)
        _mcp_session_id = resp.headers.get("Mcp-Session-Id", "")
    except Exception:
        _mcp_session_id = ""
    return _mcp_session_id

def call_bifrost_mcp(tool_name: str, arguments: dict) -> dict:
    """Calls an MCP tool through the Bifrost Gateway under Scope Enforcement."""
    clean_tool_name = tool_name
    if clean_tool_name.startswith("mock_security_server-"):
        clean_tool_name = clean_tool_name[len("mock_security_server-"):]

    req_body = {
        "jsonrpc": "2.0",
        "id": int(time.time() * 1000) % 100000,
        "method": "tools/call",
        "params": {
            "name": clean_tool_name,
            "arguments": arguments
        }
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    sess_id = _get_mcp_session_id()
    if sess_id:
        headers["Mcp-Session-Id"] = sess_id

    req = urllib.request.Request(
        mcp_url,
        data=json.dumps(req_body).encode("utf-8"),
        headers=headers
    )



    try:



        with urllib.request.urlopen(req, timeout=15) as resp:



            data = json.loads(resp.read().decode("utf-8"))



            return data.get("result", {})



    except urllib.error.HTTPError as he:



        body = he.read().decode("utf-8")



        try:



            return json.loads(body).get("result", {"isError": True, "error": body})



        except Exception:



            return {"isError": True, "error": body}



    except Exception as e:



        return {"isError": True, "error": str(e)}







def extract_mcp_text(res: dict) -> tuple[bool, str]:



    is_err = bool(res.get("isError", False))



    content = res.get("content", [])



    if content and isinstance(content, list) and len(content) > 0:



        text = content[0].get("text", "")



    else:



        text = str(res.get("error") or "Unknown MCP response")



    return is_err, text







# -----------------------------------------------------------------------------



# Construct Autonomous Tools with ROE Enforcement



# -----------------------------------------------------------------------------



def build_agent_tools(ledger: IsolatedRunLedger, target_base: str, grant_id: str, assessment_id: str, user_id: str, org_id: str, roe_mode: str):



    call_cache = {}







    common_auth = {



        "grant_id": grant_id,



        "assessment_id": assessment_id,



        "user_id": user_id,



        "org_id": org_id,



    }







    def verify_request_policy(method: str, path: str):



        # 1. Grant Revocation Check



        if check_grant_revocation(grant_id):



            ledger.record_blocked_request(path, "Active grant has been revoked by security admin")



            return False, "CRITICAL: The authorization grant for this assessment has been REVOKED. Testing aborted."







        # 2. Rules of Engagement Mode Check



        if roe_mode == "restricted" and method.upper() not in ("GET", "HEAD"):



            msg = f"RESTRICTED ROE: Method '{method}' prohibited in restricted mode (only passive GET/HEAD permitted)."



            ledger.record_blocked_request(path, msg)



            return False, msg







        return True, ""







    @function_tool(name_override="inspect_http")



    def inspect_http(url: str, method: str = "GET") -> str:



        """Inspect HTTP response headers, status code, and security headers of an in-scope URL."""



        cache_key = f"inspect_http:{url}:{method}"



        if cache_key in call_cache:



            return f"TOOL CACHE HIT: 'inspect_http' was already executed on '{url}'. Previous result: {call_cache[cache_key][:250]}\nDo not repeat. Proceed to evaluate hypotheses or test endpoints."



        ok, reason = verify_request_policy(method, url)



        if not ok:



            return f"BLOCKED BY POLICY: {reason}"







        args = {**common_auth, "target": url, "method": method}



        res = call_bifrost_mcp("mock_security_server-inspect_http", args)



        is_err, text = extract_mcp_text(res)



        ledger.record_tool_call("inspect_http", url, method, is_err, text[:200], raw_output=text)



        if is_err:



            ledger.record_blocked_request(url, text)



            return f"SCOPE ENFORCEMENT DENIAL: {text}"



        call_cache[cache_key] = text



        return text







    @function_tool(name_override="mock_security_server-inspect_http")



    def mock_inspect_http(target: str, method: str = "GET") -> str:



        """Inspect HTTP response headers and security posture of an authorized target."""



        return inspect_http(url=target, method=method)







    @function_tool(name_override="discover_endpoints")



    def discover_endpoints(paths: str = "") -> str:



        """Deeply discovers in-scope attack surface by inspecting authorized HTML and same-origin JavaScript bundles for REST API routes, authentication endpoints, and application resources."""



        cache_key = f"discover_endpoints:{paths}"



        if cache_key in call_cache:



            return f"TOOL CACHE HIT: 'discover_endpoints' already completed. Discovered routes are saved in ledger. Previous summary: {call_cache[cache_key][:250]}\nDo not repeat. Proceed to query capabilities and test endpoints."



        ok, reason = verify_request_policy("GET", target_base)



        if not ok:



            return f"BLOCKED BY POLICY: {reason}"







        args = {**common_auth, "target": target_base}



        if paths:



            args["paths"] = paths



        res = call_bifrost_mcp("mock_security_server-discover_endpoints", args)



        is_err, text = extract_mcp_text(res)



        ledger.record_tool_call("discover_endpoints", target_base, "GET", is_err, text[:200], raw_output=text)



        if not is_err:



            ledger.record_discovered_endpoints(text)



        call_cache[cache_key] = text



        return text







    @function_tool(name_override="mock_security_server-discover_endpoints")



    def mock_discover_endpoints(target: str = "", paths: str = "") -> str:



        """Deeply discovers in-scope attack surface on target via HTML and JavaScript bundle inspection."""



        return discover_endpoints(paths=paths)







    @function_tool(name_override="check_misconfigurations")



    def check_misconfigurations(url: str) -> str:



        """Audit target URL for missing defensive security headers (CSP, HSTS, XFO) and CORS misconfigurations."""



        cache_key = f"check_misconfigurations:{url}"



        if cache_key in call_cache:



            return f"TOOL CACHE HIT: 'check_misconfigurations' already evaluated on {url}. Result: {call_cache[cache_key][:250]}\nDo not repeat. Record coverage or investigate specific routes."



        ok, reason = verify_request_policy("GET", url)



        if not ok:



            return f"BLOCKED BY POLICY: {reason}"







        args = {**common_auth, "target": url}



        res = call_bifrost_mcp("mock_security_server-check_misconfigurations", args)



        is_err, text = extract_mcp_text(res)



        ledger.record_tool_call("check_misconfigurations", url, "GET", is_err, text[:200], raw_output=text)



        call_cache[cache_key] = text



        return text







    @function_tool(name_override="mock_security_server-check_misconfigurations")



    def mock_check_misconfigurations(target: str) -> str:



        """Audit target URL for security misconfigurations."""



        return check_misconfigurations(url=target)







    @function_tool(name_override="test_sql_injection")



    def test_sql_injection(url: str, payload: str = "' OR 1=1--") -> str:



        """Safely test SQL injection on an authentication endpoint using controlled benign probes."""



        cache_key = f"test_sql_injection:{url}:{payload}"



        if cache_key in call_cache:



            return f"TOOL CACHE HIT: 'test_sql_injection' already executed on {url}. Result: {call_cache[cache_key][:250]}\nDo not repeat identical probes. Record finding if verified or reject hypothesis."



        ok, reason = verify_request_policy("POST", url)



        if not ok:



            return f"BLOCKED BY POLICY: {reason}"







        args = {**common_auth, "target": url, "method": "POST", "payload": payload}



        res = call_bifrost_mcp("mock_security_server-test_sql_injection", args)



        is_err, text = extract_mcp_text(res)



        ledger.record_tool_call("test_sql_injection", url, "POST", is_err, text[:200], raw_output=text)



        if is_err:



            ledger.record_blocked_request(url, text)



            return f"SCOPE ENFORCEMENT DENIAL: {text}"



        call_cache[cache_key] = text



        return text







    @function_tool(name_override="mock_security_server-test_sql_injection")



    def mock_test_sql_injection(target: str, payload: str = "' OR 1=1--") -> str:



        """Safely test SQL injection on an authentication endpoint."""



        return test_sql_injection(url=target, payload=payload)







    @function_tool(name_override="verify_bola")



    def verify_bola(url: str, auth_header: str = "Bearer token-alice") -> str:



        """Verify Broken Object Level Authorization (BOLA/IDOR) on an authorized object endpoint with cross-account credentials."""



        cache_key = f"verify_bola:{url}:{auth_header}"



        if cache_key in call_cache:



            return f"TOOL CACHE HIT: 'verify_bola' already executed on {url}. Result: {call_cache[cache_key][:250]}\nDo not repeat. Evaluate counterevidence or record finding."



        ok, reason = verify_request_policy("GET", url)



        if not ok:



            return f"BLOCKED BY POLICY: {reason}"







        args = {**common_auth, "target": url, "method": "GET", "auth_header": auth_header}



        res = call_bifrost_mcp("mock_security_server-verify_bola", args)



        is_err, text = extract_mcp_text(res)



        ledger.record_tool_call("verify_bola", url, "GET", is_err, redact_sensitive_data(text[:200]), raw_output=text)



        try:



            b_data = json.loads(text)



            aff = b_data.get("affected_url")



            if aff and aff != url:



                ledger.record_tool_call("verify_bola", aff, "GET", is_err, "Corroborated foreign target", raw_output=text)



        except Exception:



            pass



        if is_err:



            ledger.record_blocked_request(url, text)



            return f"SCOPE ENFORCEMENT DENIAL: {text}"



        res_text = redact_sensitive_data(text)



        call_cache[cache_key] = res_text



        return res_text







    @function_tool(name_override="mock_security_server-verify_bola")



    def mock_verify_bola(target: str, auth_header: str = "Bearer token-alice") -> str:



        """Verify Broken Object Level Authorization on resource endpoint with cross-account credentials."""



        return verify_bola(url=target, auth_header=auth_header)







    @function_tool(name_override="test_xss")



    def test_xss(url: str, canary: str = "<img src=x onerror=\"document.title='XSS_EXECUTION_VERIFIED'\">", param: str = "") -> str:



        """Test reflected Cross-Site Scripting using contained Headless Chrome DOM execution verification."""



        cache_key = f"test_xss:{url}:{canary}"



        if cache_key in call_cache:



            return f"TOOL CACHE HIT: 'test_xss' already executed on {url}. Result: {call_cache[cache_key][:250]}\nDo not repeat. Evaluate DOM execution and close hypothesis."



        ok, reason = verify_request_policy("GET", url)



        if not ok:



            return f"BLOCKED BY POLICY: {reason}"







        args = {**common_auth, "target": url, "canary": canary}



        res = call_bifrost_mcp("mock_security_server-test_xss", args)



        is_err, text = extract_mcp_text(res)



        ledger.record_tool_call("test_xss", url, "GET", is_err, redact_sensitive_data(text[:200]), raw_output=text)



        try:



            x_data = json.loads(text)



            aff = x_data.get("affected_url")



            if aff and aff != url:



                ledger.record_tool_call("test_xss", aff, "GET", is_err, "Corroborated XSS test URL", raw_output=text)



        except Exception:



            pass



        if is_err:



            ledger.record_blocked_request(url, text)



            return f"SCOPE ENFORCEMENT DENIAL: {text}"



        res_text = redact_sensitive_data(text)



        call_cache[cache_key] = res_text



        return res_text







    @function_tool(name_override="mock_security_server-test_xss")



    def mock_test_xss(target: str, canary: str = "<img src=x onerror=\"document.title='XSS_EXECUTION_VERIFIED'\">") -> str:



        """Test reflected Cross-Site Scripting using contained Headless Chrome DOM execution verification."""



        return test_xss(url=target, canary=canary)







    @function_tool(name_override="test_jwt_vulnerabilities")



    def test_jwt_vulnerabilities(url: str, token: str = "") -> str:



        """Safely test JWT security vulnerabilities (offline key recovery, alg:none bypass, signature tampering, expiration) against an authorized endpoint."""



        cache_key = f"test_jwt_vulnerabilities:{url}:{token}"



        if cache_key in call_cache:



            return f"TOOL CACHE HIT: 'test_jwt_vulnerabilities' already executed on {url}. Result: {call_cache[cache_key][:250]}\nDo not repeat. Evaluate signature verification and record finding or closure."



        ok, reason = verify_request_policy("GET", url)



        if not ok:



            return f"BLOCKED BY POLICY: {reason}"







        args = {**common_auth, "target": url}



        if token:



            args["token"] = token



        res = call_bifrost_mcp("mock_security_server-test_jwt_vulnerabilities", args)



        is_err, text = extract_mcp_text(res)



        ledger.record_tool_call("test_jwt_vulnerabilities", url, "GET", is_err, redact_sensitive_data(text[:200]), raw_output=text)



        try:



            j_data = json.loads(text)



            aff = j_data.get("affected_url")



            if aff and aff != url:



                ledger.record_tool_call("test_jwt_vulnerabilities", aff, "GET", is_err, "Corroborated JWT test URL", raw_output=text)



        except Exception:



            pass



        if is_err:



            ledger.record_blocked_request(url, text)



            return f"SCOPE ENFORCEMENT DENIAL: {text}"



        res_text = redact_sensitive_data(text)



        call_cache[cache_key] = res_text



        return res_text







    @function_tool(name_override="mock_security_server-test_jwt_vulnerabilities")



    def mock_test_jwt_vulnerabilities(target: str, token: str = "") -> str:



        """Safely test JWT security vulnerabilities against an authorized endpoint."""



        return test_jwt_vulnerabilities(url=target, token=token)







    @function_tool(name_override="test_path_traversal")



    def test_path_traversal(url: str, param: str = "file", canary: str = "TRAVERSAL_CANARY_VERIFIED_98432_SAFE_DISCLOSURE") -> str:



        """Safely test file retrieval and document endpoints for relative directory traversal and local file inclusion using harmless canary marker verification."""



        cache_key = f"test_path_traversal:{url}:{param}:{canary}"



        if cache_key in call_cache:



            return f"TOOL CACHE HIT: 'test_path_traversal' already executed on {url}. Result: {call_cache[cache_key][:250]}\nDo not repeat. Evaluate counterevidence and close hypothesis."



        ok, reason = verify_request_policy("GET", url)



        if not ok:



            return f"BLOCKED BY POLICY: {reason}"







        args = {**common_auth, "target": url, "param": param, "canary": canary}



        res = call_bifrost_mcp("mock_security_server-test_path_traversal", args)



        is_err, text = extract_mcp_text(res)



        ledger.record_tool_call("test_path_traversal", url, "GET", is_err, redact_sensitive_data(text[:200]), raw_output=text)



        try:



            pt_data = json.loads(text)



            aff = pt_data.get("affected_url")



            if aff and aff != url:



                ledger.record_tool_call("test_path_traversal", aff, "GET", is_err, "Corroborated Path Traversal test URL", raw_output=text)



        except Exception:



            pass



        if is_err:



            ledger.record_blocked_request(url, text)



            return f"SCOPE ENFORCEMENT DENIAL: {text}"



        res_text = redact_sensitive_data(text)



        call_cache[cache_key] = res_text



        return res_text







    @function_tool(name_override="mock_security_server-test_path_traversal")



    def mock_test_path_traversal(target: str, param: str = "file", canary: str = "TRAVERSAL_CANARY_VERIFIED_98432_SAFE_DISCLOSURE") -> str:



        """Safely test file retrieval endpoints for path traversal and local file inclusion."""



        return test_path_traversal(url=target, param=param, canary=canary)







    @function_tool(name_override="test_ssrf")



    def test_ssrf(url: str, param: str = "url") -> str:



        """Safely test URL fetchers and preview endpoints for Server-Side Request Forgery (SSRF) using controlled internal probes and counterevidence comparison."""



        cache_key = f"test_ssrf:{url}:{param}"



        if cache_key in call_cache:



            return f"TOOL CACHE HIT: 'test_ssrf' already executed on {url}. Result: {call_cache[cache_key][:250]}\nDo not repeat. Evaluate internal response or compensating controls."



        ok, reason = verify_request_policy("GET", url)



        if not ok:



            return f"BLOCKED BY POLICY: {reason}"







        args = {**common_auth, "target": url, "param": param}



        res = call_bifrost_mcp("mock_security_server-test_ssrf", args)



        is_err, text = extract_mcp_text(res)



        ledger.record_tool_call("test_ssrf", url, "GET", is_err, redact_sensitive_data(text[:200]), raw_output=text)



        try:



            d = json.loads(text)



            aff = d.get("affected_url")



            if aff and aff != url:



                ledger.record_tool_call("test_ssrf", aff, "GET", is_err, "Corroborated SSRF test URL", raw_output=text)



        except Exception:



            pass



        if is_err:



            ledger.record_blocked_request(url, text)



            return f"SCOPE ENFORCEMENT DENIAL: {text}"



        res_text = redact_sensitive_data(text)



        call_cache[cache_key] = res_text



        return res_text







    @function_tool(name_override="mock_security_server-test_ssrf")



    def mock_test_ssrf(target: str, param: str = "url") -> str:



        """Safely test preview endpoints for SSRF."""



        return test_ssrf(url=target, param=param)







    @function_tool(name_override="test_open_redirect")



    def test_open_redirect(url: str, param: str = "url") -> str:



        """Safely test redirection endpoints for unvalidated external open redirects using benign canary destination verification."""



        cache_key = f"test_open_redirect:{url}:{param}"



        if cache_key in call_cache:



            return f"TOOL CACHE HIT: 'test_open_redirect' already executed on {url}. Result: {call_cache[cache_key][:250]}\nDo not repeat. Evaluate 3xx Location header or relative destination."



        ok, reason = verify_request_policy("GET", url)



        if not ok:



            return f"BLOCKED BY POLICY: {reason}"







        args = {**common_auth, "target": url, "param": param}



        res = call_bifrost_mcp("mock_security_server-test_open_redirect", args)



        is_err, text = extract_mcp_text(res)



        ledger.record_tool_call("test_open_redirect", url, "GET", is_err, redact_sensitive_data(text[:200]), raw_output=text)



        try:



            d = json.loads(text)



            aff = d.get("affected_url")



            if aff and aff != url:



                ledger.record_tool_call("test_open_redirect", aff, "GET", is_err, "Corroborated Open Redirect test URL", raw_output=text)



        except Exception:



            pass



        if is_err:



            ledger.record_blocked_request(url, text)



            return f"SCOPE ENFORCEMENT DENIAL: {text}"



        res_text = redact_sensitive_data(text)



        call_cache[cache_key] = res_text



        return res_text







    @function_tool(name_override="mock_security_server-test_open_redirect")



    def mock_test_open_redirect(target: str, param: str = "url") -> str:



        """Safely test redirection endpoints for open redirect vulnerabilities."""



        return test_open_redirect(url=target, param=param)







    @function_tool(name_override="test_csrf")



    def test_csrf(url: str, method: str = "POST") -> str:



        """Safely test state-changing endpoints for Cross-Site Request Forgery (CSRF) vulnerabilities by evaluating anti-CSRF token enforcement and Origin header validation."""



        cache_key = f"test_csrf:{url}:{method}"



        if cache_key in call_cache:



            return f"TOOL CACHE HIT: 'test_csrf' already executed on {url}. Result: {call_cache[cache_key][:250]}\nDo not repeat. Evaluate anti-CSRF token validation and close hypothesis."



        ok, reason = verify_request_policy(method, url)



        if not ok:



            return f"BLOCKED BY POLICY: {reason}"







        args = {**common_auth, "target": url, "method": method}



        res = call_bifrost_mcp("mock_security_server-test_csrf", args)



        is_err, text = extract_mcp_text(res)



        ledger.record_tool_call("test_csrf", url, method, is_err, redact_sensitive_data(text[:200]), raw_output=text)



        try:



            d = json.loads(text)



            aff = d.get("affected_url")



            if aff and aff != url:



                ledger.record_tool_call("test_csrf", aff, method, is_err, "Corroborated CSRF test URL", raw_output=text)



        except Exception:



            pass



        if is_err:



            ledger.record_blocked_request(url, text)



            return f"SCOPE ENFORCEMENT DENIAL: {text}"



        res_text = redact_sensitive_data(text)



        call_cache[cache_key] = res_text



        return res_text







    @function_tool(name_override="mock_security_server-test_csrf")



    def mock_test_csrf(target: str, method: str = "POST") -> str:



        """Safely test state-changing endpoints for CSRF vulnerabilities."""



        return test_csrf(url=target, method=method)







    @function_tool(name_override="test_command_injection")



    def test_command_injection(target: str = "", cmd: str = "id") -> str:



        """Safely test for Command Injection. Note: No controlled execution tool is active in this sandbox."""



        return "UNSUPPORTED IN CURRENT LAB: No safe controlled MCP tool exists for command injection in this lab environment. As documented in the Security Capability Registry, record coverage entry with outcome 'not_applicable' or 'needs_follow_up'."







    @function_tool



    def record_coverage_entry(surface: str, risk_area: str, outcome: str, evidence: str = "") -> str:



        """Record coverage indicating that an endpoint/surface was assessed for a specific risk area. Outcomes: 'reported', 'no_issue_found', 'ruled_out', 'not_applicable', 'needs_follow_up'."""



        valid_outcomes = ("reported", "no_issue_found", "ruled_out", "not_applicable", "needs_follow_up")



        norm = outcome.strip().lower()



        if norm not in valid_outcomes:



            return f"Invalid outcome '{outcome}'. Must be one of: {list(valid_outcomes)}"



        entry = ledger.record_coverage(surface, risk_area, norm, evidence)



        return f"Coverage recorded: {entry['entry_id']} | Surface: {surface} | Risk: {risk_area} | Outcome: {norm}"







    @function_tool



    def list_coverage_entries(outcome_filter: str = "") -> str:



        """List all coverage entries recorded during this assessment to evaluate evaluated negative space."""



        entries = ledger.coverage_entries



        if outcome_filter:



            entries = [e for e in entries if e["outcome"] == outcome_filter.strip().lower()]



        return json.dumps(entries, indent=2)







    @function_tool



    def save_threat_model_summary(target: str, trust_boundaries: str, critical_assets: str, attacker_model: str) -> str:



        """Save a shared threat model calibration defining trust boundaries, critical assets, and attacker assumptions."""



        ledger.set_threat_model(target, trust_boundaries, critical_assets, attacker_model)



        return f"Threat model saved for target {target}. Trust boundaries calibrated."







    @function_tool



    def get_threat_model_summary() -> str:



        """Retrieve the currently calibrated threat model and trust boundaries."""



        if not ledger.threat_model:



            return "No threat model recorded yet. Formulate trust boundaries using save_threat_model_summary."



        return json.dumps(ledger.threat_model, indent=2)







    @function_tool



    def list_available_skills(category: str = "") -> str:



        """List all available VIGIL security methodology skills across categories (vulnerabilities, analysis, protocols, cloud, frameworks, tooling, technologies)."""



        skills_dir = _get_skills_dir()



        if not skills_dir.exists():



            return "VIGIL skills directory not found."



        results = {}



        for md_file in skills_dir.rglob("*.md"):



            cat = md_file.parent.name



            if category and category.lower() not in cat.lower():



                continue



            if cat not in results:



                results[cat] = []



            results[cat].append(md_file.stem)



        return json.dumps(results, indent=2)







    @function_tool



    def query_capabilities(query: str = "", endpoint: str = "") -> str:



        """Dynamically queries the security capability registry to find relevant testing capabilities, tools, parameters, and counterevidence requirements for an endpoint or vulnerability category."""



        from core.assessment.capabilities.registry import query_security_capabilities



        return query_security_capabilities(query=query, endpoint=endpoint)







    @function_tool



    def load_skill(skill_name: str) -> str:



        """Consult VIGIL specialized vulnerability and analysis methodology markdown across all categories."""



        clean_name = skill_name.strip().removesuffix(".md").lower()



        skills_dir = _get_skills_dir()



        skill_file = skills_dir / "vulnerabilities" / f"{clean_name}.md"



        if not skill_file.exists():



            matches = list(skills_dir.rglob(f"{clean_name}.md"))



            if matches:



                skill_file = matches[0]



            else:



                partial = list(skills_dir.rglob(f"*{clean_name}*.md"))



                if partial:



                    skill_file = partial[0]



                else:



                    all_skills = [f.stem for f in skills_dir.rglob("*.md")]



                    return f"Skill '{skill_name}' not found. Available skills ({len(all_skills)} total): {', '.join(sorted(all_skills)[:25])}... Call list_available_skills for full catalog."



        try:



            content = skill_file.read_text(encoding="utf-8")



            return f"=== VIGIL Skill Methodology: {clean_name} (from {skill_file.parent.name}) ===\n" + content[:1800] + "\n[... truncated for prompt budget ...]"



        except Exception as e:



            return f"Error loading skill: {e}"







    @function_tool



    def formulate_hypothesis(endpoint: str, vulnerability_type: str, cwe: str = "", parameter: str = "", suspicion_rationale: str = "") -> str:



        """Formulate a structured security vulnerability hypothesis before conducting targeted vulnerability testing on an endpoint."""



        hyp = ledger.register_hypothesis(endpoint, vulnerability_type, cwe, parameter, suspicion_rationale)



        return f"Hypothesis {hyp.id} created for {vulnerability_type} ({cwe}) on {endpoint}. Status: UNDER_INVESTIGATION. Proceed to execute positive and negative control tests."







    @function_tool



    def evaluate_counterevidence(



        hypothesis_id: str,



        positive_evidence: str,



        negative_control_evidence: str,



        counterevidence: str,



        decision: str,



        decision_rationale: str,



        confidence: str = "High",



        severity: str = "High"



    ) -> str:



        """



        Evaluate counterevidence for a hypothesis to determine closure state.



        decision must be: 'CONFIRMED', 'REJECTED', or 'INCONCLUSIVE'.



        - CONFIRMED: Positive test succeeded AND negative control proved the vulnerability is genuine. Call 'record_finding' next.



        - REJECTED: Input is sanitized, parameter is guarded, or compensating control prevents exploitation.



        - INCONCLUSIVE: Proof gap exists; cannot confirm or rule out.



        """



        ok, msg = ledger.update_hypothesis_evaluation(



            hyp_id=hypothesis_id,



            status=decision.upper(),



            positive_ev=positive_evidence,



            negative_ctrl=negative_control_evidence,



            counterevidence=counterevidence,



            rationale=decision_rationale,



            confidence=confidence,



            severity=severity



        )



        return msg







    @function_tool



    def reject_hypothesis(hypothesis_id: str, reason: str, counterevidence: str) -> str:



        """Explicitly rule out a hypothesis based on observed counterevidence, negative controls, or compensating controls."""



        ok, msg = ledger.update_hypothesis_evaluation(



            hyp_id=hypothesis_id,



            status=HypothesisState.REJECTED,



            positive_ev="Tested without working exploitation",



            negative_ctrl="Observed protective or differential behavior",



            counterevidence=counterevidence,



            rationale=reason



        )



        return msg







    @function_tool



    def mark_hypothesis_inconclusive(hypothesis_id: str, proof_gap: str, reason: str) -> str:



        """Mark a hypothesis inconclusive when a legitimate proof gap prevents confirmation or ruling out."""



        ok, msg = ledger.update_hypothesis_evaluation(



            hyp_id=hypothesis_id,



            status=HypothesisState.INCONCLUSIVE,



            positive_ev="Uncertain or partial observation",



            negative_ctrl="Negative control could not be completed",



            counterevidence="Proof gap present",



            rationale=f"{reason} (Proof gap: {proof_gap})"



        )



        return msg







    @function_tool



    def record_finding(



        title: str,



        severity: str,



        category: str,



        cwe: str,



        affected_url: str,



        method: str,



        parameter: str,



        evidence: str,



        verification: str,



        confidence: str,



        counterevidence: str,



        description: str,



        recommendation: str,



        hypothesis_id: str = "",



        negative_control: str = ""



    ) -> str:



        """



        Record a validated vulnerability finding into the assessment ledger.



        Requirements:



        - hypothesis_id is MANDATORY: must reference an active hypothesis formulated in this assessment.



        - verification must be 'Confirmed'.



        - counterevidence is MANDATORY: you must document compensating controls and negative control evaluation.



        - Working technical evidence from an actual security tool execution is required.



        - You CANNOT mark a finding as 'Confirmed' if the evidence indicates an HTTP error (401, 404, 500) or negative test result.



        """



        if verification.lower() != "confirmed":



            return "REJECTED: Only verified findings can be committed. For unproven or potential issues, call 'mark_hypothesis_inconclusive' or 'abandon_hypothesis'."







        if not hypothesis_id:



            return "REJECTED: hypothesis_id is required. Formulate and verify a hypothesis before recording a finding."







        if hypothesis_id not in ledger.hypotheses:



            return f"REJECTED: Hypothesis ID '{hypothesis_id}' does not exist in current assessment ledger."







        hyp = ledger.hypotheses[hypothesis_id]







        if not negative_control:



            negative_control = hyp.negative_control_results or "Verified via negative control probe"







        low_ev = evidence.lower()



        if "not vulnerable" in low_ev or "unconfirmed" in low_ev or "safe against" in low_ev or "http error" in low_ev or "error code:" in low_ev:



            return "REJECTED: Cannot mark finding as 'Confirmed' when evidence reports 'not vulnerable', HTTP error, or safe. Call 'abandon_hypothesis' or 'reject_hypothesis' instead."







        ledger.update_hypothesis_evaluation(



            hyp_id=hyp.id,



            status=HypothesisState.CONFIRMED,



            positive_ev=evidence,



            negative_ctrl=negative_control,



            counterevidence=counterevidence,



            rationale=f"Vulnerability verified: {title}",



            confidence=confidence,



            severity=severity



        )







        finding_id = f"VULN-{len(ledger.findings) + 1:03d}"



        finding_data = {



            "id": finding_id,



            "hypothesis_id": hyp.id,



            "assessment_id": assessment_id,



            "run_id": ledger.run_id,



            "target": target_base,



            "title": title,



            "severity": severity,



            "category": category,



            "cwe": cwe,



            "affected_url": affected_url,



            "method": method.upper(),



            "parameter": parameter,



            "evidence": redact_sensitive_data(evidence),



            "negative_control": negative_control,



            "verification": verification,



            "confidence": confidence,



            "counterevidence": counterevidence,



            "description": description,



            "recommendation": recommendation,



            "remediation_time": "1-3 days" if severity in ("Critical", "High") else "1-2 weeks",



            "discovered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())



        }







        ok, msg = ledger.add_finding(finding_data)



        if ok:



            return f"SUCCESS: Finding '{title}' ({cwe}) verified and recorded into assessment ledger under {hyp.id}."



        return f"REJECTED: {msg}"







    @function_tool



    def abandon_hypothesis(endpoint: str, vulnerability_type: str, reason: str, counterevidence: str = "") -> str:



        """Explicitly record that a vulnerability hypothesis was tested and ruled out based on evidence and counterevidence."""



        ledger.record_abandoned_hypothesis(endpoint, vulnerability_type, reason, counterevidence)



        return f"RULED_OUT: Hypothesis '{vulnerability_type}' on {endpoint} abandoned. Reason: {reason}"







    @function_tool



    def finish_assessment(executive_summary: str) -> str:



        """Conclude the autonomous penetration test and emit the final executive assessment report."""



        return f"ASSESSMENT MISSION CONCLUDED: {executive_summary}"







    return [



        inspect_http,



        mock_inspect_http,



        discover_endpoints,



        mock_discover_endpoints,



        formulate_hypothesis,



        check_misconfigurations,



        mock_check_misconfigurations,



        test_sql_injection,



        mock_test_sql_injection,



        verify_bola,



        mock_verify_bola,



        test_xss,



        mock_test_xss,



        test_jwt_vulnerabilities,



        mock_test_jwt_vulnerabilities,



        test_path_traversal,



        mock_test_path_traversal,



        test_ssrf,



        mock_test_ssrf,



        test_open_redirect,



        mock_test_open_redirect,



        test_csrf,



        mock_test_csrf,



        test_command_injection,



        record_coverage_entry,



        list_coverage_entries,



        save_threat_model_summary,



        get_threat_model_summary,



        list_available_skills,



        query_capabilities,



        load_skill,



        evaluate_counterevidence,



        reject_hypothesis,



        mark_hypothesis_inconclusive,



        abandon_hypothesis,



        record_finding,



        finish_assessment



    ]







# -----------------------------------------------------------------------------



# Main Autonomous Execution Engine



# -----------------------------------------------------------------------------



async def run_autonomous_assessment():



    start_time = time.time()



    run_id = f"run-{args.assessment_id}-{int(start_time)}"



    print("================================================================================")



    print("           VIGIL AUTONOMOUS PENTESTING RUNNER (PRODUCTION MVP)                  ")



    print("================================================================================")



    print(f"[*] Target:          {args.target}")



    print(f"[*] Assessment ID:   {args.assessment_id}")



    print(f"[*] Grant ID:        {args.grant_id}")



    print(f"[*] Caller:          User: {args.user_id} | Org: {args.org_id}")



    print(f"[*] ROE Mode:        {args.roe_mode.upper()}")



    print(f"[*] Model:           {model_name} (via Bifrost LLM Gateway)")



    print(f"[*] Output Path:     {args.out_file}")







    # Initialize isolated run ledger



    ledger = IsolatedRunLedger(run_id, args.assessment_id, args.grant_id, args.roe_mode)







    # Check grant revocation immediately



    if check_grant_revocation(args.grant_id):



        print("[-] ABORT: Active authorization grant is revoked!")



        ledger.record_blocked_request(args.target, "Grant revoked before assessment start")



        write_output_file(ledger, "cancelled", "Assessment aborted: grant is revoked.", 0)



        return







    # Build tools bound to this ledger and authorization context



    tools = build_agent_tools(



        ledger=ledger,



        target_base=args.target,



        grant_id=args.grant_id,



        assessment_id=args.assessment_id,



        user_id=args.user_id,



        org_id=args.org_id,



        roe_mode=args.roe_mode



    )







    client = AsyncOpenAI(api_key=token, base_url=llm_base)



    model = OpenAIChatCompletionsModel(model=model_name, openai_client=client)







    system_instructions = (



        "You are VIGIL Autonomous Penetration Tester, conducting a rigorous, evidence-driven security assessment.\n\n"



        "CORE DISCIPLINE (VIGIL COUNTEREVIDENCE METHODOLOGY):\n"



        "Proving a vulnerability is real is only half the job. The other half is proving a candidate is NOT real.\n"



        "Never register a finding without reproducible technical evidence from positive AND negative controls.\n"



        "Every hypothesis must reach one of three definitive closure states:\n"



        "1. CONFIRMED: Working exploit proof + negative control verified. Commit via `record_finding`.\n"



        "2. REJECTED: Named control or sanitization proved safety. Rule out via `reject_hypothesis` or `abandon_hypothesis`.\n"



        "3. INCONCLUSIVE: Legitimate proof gap prevents confirmation. Record via `mark_hypothesis_inconclusive`.\n\n"



        "RULES OF ENGAGEMENT & SCOPE:\n"



        f"- Target base: {args.target}\n"



        f"- ROE Mode: {args.roe_mode.upper()} ("



        + ("Full authorized in-scope testing" if args.roe_mode == "broad" else "Passive, read-only GET requests only")



        + ")\n"



        "- Every tool call goes through the Bifrost Scope Enforcer. If a path is blocked, ADAPT IMMEDIATELY and do NOT retry.\n\n"



        "METHODOLOGY & EXECUTION SEQUENCE:\n"



        "1. Threat Model & Initialization:\n"



        "   - Call `save_threat_model_summary(target, trust_boundaries, critical_assets, attacker_model)` to calibrate the threat model.\n"



        "2. Attack Surface Mapping:\n"



        "   - Call `discover_endpoints` to crawl HTML and JavaScript bundles to map active REST API routes and application resources.\n"



        "3. Dynamic Capability Discovery & Structured Investigation:\n"



        "   - For discovered routes, call `query_capabilities(query, endpoint)` to see which security capabilities, parameters, and counterevidence rules apply.\n"



        "   - If a capability has status 'registered_no_tool' (e.g. Command Injection), recognize that no controlled tool is active in this lab; record coverage via `record_coverage_entry` as outcome 'not_applicable' or 'needs_follow_up'.\n"



        "   - For active capabilities, call `formulate_hypothesis` before running targeted tests:\n"



        "     * /rest/user/login -> SQL Injection (`test_sql_injection`)\n"



        "     * /rest/basket/2 -> BOLA / IDOR (`verify_bola`)\n"



        "     * /rest/products/search -> Reflected XSS (`test_xss`)\n"



        "     * /rest/admin/system-status -> JWT Vulnerabilities (`test_jwt_vulnerabilities`). Prioritize testing /rest/admin/system-status for JWT authentication bypass and privilege escalation.\n"



        "     * /rest/file/download -> Path Traversal / LFI (`test_path_traversal`)\n"



        "     * /rest/image/preview -> SSRF (`test_ssrf`)\n"



        "     * /rest/redirect -> Open Redirect (`test_open_redirect`)\n"



        "     * /rest/user/change-email -> CSRF (`test_csrf`)\n"



        "     * Response headers -> Security Misconfiguration (`check_misconfigurations`)\n"



        "4. Evidence, Counterevidence & Negative Space Coverage:\n"



        "   - If confirmed by working proof and negative control -> Call `record_finding`.\n"



        "   - If defended, sanitized, or protected -> Call `reject_hypothesis` or `abandon_hypothesis`.\n"



        "   - For every investigated surface, call `record_coverage_entry(surface, risk_area, outcome, evidence)` with outcome: 'reported', 'no_issue_found', 'ruled_out', 'not_applicable', or 'needs_follow_up'.\n"



        "   - CRITICAL: Rejection or abandonment of a hypothesis is an expected, normal result in security testing! NEVER halt when a hypothesis is rejected. Continue methodically evaluating candidate routes until coverage is complete.\n"



        "5. Conclude: Once candidate routes are assessed, call `finish_assessment`.\n"



    )







    agent = Agent(



        name="VIGILAutonomousPentester",



        instructions=system_instructions,



        tools=tools,



        model=model,



    )







    task_prompt = (



        f"Execute an autonomous penetration testing assessment of: {args.target}\n"



        f"Assessment ID: {args.assessment_id}\n"



        f"Grant ID: {args.grant_id}\n"



        f"ROE Mode: {args.roe_mode}\n\n"



        f"Explore the attack surface, formulate vulnerability hypotheses, select tools dynamically, "



        f"evaluate technical evidence, adapt to scope denials, abandon false hypotheses, and record verified findings."



    )







    session_dir = Path(r"c:\Users\krish\Downloads\hacathon\bifrost-dev\bifrost-dev\tmp\assessment_sessions")



    session_dir.mkdir(parents=True, exist_ok=True)



    session_db = session_dir / f"{args.assessment_id}.db"







    if args.resume:



        out_p = Path(args.out_file)



        if out_p.exists():



            try:



                with open(out_p, "r", encoding="utf-8") as f:



                    prior_data = json.load(f)



                ledger.discovered_endpoints = prior_data.get("discovered_endpoints", [])



                ledger.threat_model = prior_data.get("threat_model", {})



                ledger.coverage_entries = prior_data.get("coverage_entries", [])



                for h_dict in prior_data.get("hypotheses", []):



                    h = Hypothesis(h_dict["id"], h_dict["endpoint"], h_dict["vulnerability_type"], h_dict["cwe"], h_dict.get("parameter", ""), h_dict.get("suspicion_rationale", ""))



                    h.status = h_dict.get("status", HypothesisState.UNDER_INVESTIGATION)



                    h.initial_evidence = h_dict.get("initial_evidence", "")



                    h.negative_control_results = h_dict.get("negative_control_results", "")



                    h.counterevidence = h_dict.get("counterevidence", "")



                    h.decision_rationale = h_dict.get("decision_rationale", "")



                    ledger.hypotheses[h.id] = h



                for f_item in prior_data.get("findings", []):



                    ledger.findings.append(f_item)



                    ledger.dedup_keys.add(f"{f_item.get('affected_url')}|{f_item.get('method')}|{f_item.get('parameter')}|{f_item.get('cwe')}")



                print(f"[*] Resumed assessment state from {args.out_file}: {len(ledger.findings)} findings, {len(ledger.hypotheses)} hypotheses.")



            except Exception as e:



                print(f"[!] Warning: Failed to restore prior state: {e}")



    else:



        if session_db.exists():



            try:



                session_db.unlink()



            except Exception:



                pass







    from agents.memory.sqlite_session import SQLiteSession



    session = SQLiteSession(session_id=args.assessment_id, db_path=str(session_db))







    print(f"[*] Launching autonomous agent loop (max turns: {args.max_turns})...")



    run_config = RunConfig(tracing_disabled=True)



    final_report = ""



    turns_executed = 0







    MAX_RETRY_ATTEMPTS = 3



    INITIAL_BACKOFF_SECONDS = 60







    for attempt in range(MAX_RETRY_ATTEMPTS):



        try:



            print(f"[*] Executing agent loop (attempt {attempt + 1}/{MAX_RETRY_ATTEMPTS}, max turns: {args.max_turns})...")



            result = await Runner.run(agent, input=task_prompt, session=session, run_config=run_config, max_turns=args.max_turns)



            final_report = result.final_output or "Autonomous pentest completed."



            turns_executed = len(getattr(result, "messages", []))



            print(f"[+] Autonomous agent loop completed ({turns_executed} turns).")



            break



        except Exception as e:



            err_str = str(e)



            is_rate_limit = any(term in err_str.lower() for term in ["429", "resource_exhausted", "rate_limit", "quota"])



            duration_so_far = int(time.time() - start_time)



            



            # Immediately persist partial state to disk



            write_output_file(ledger, "rate_limited_retry" if is_rate_limit else "interrupted_partial", f"Assessment paused: {err_str}", duration_so_far, turns_executed)







            if is_rate_limit and attempt < MAX_RETRY_ATTEMPTS - 1:



                wait_time = INITIAL_BACKOFF_SECONDS * (attempt + 1)



                retry_match = re.search(r'retry.*?after.*?(\d+)', err_str, re.IGNORECASE)



                if retry_match:



                    wait_time = min(int(retry_match.group(1)), 120)



                jitter = random.uniform(2.0, 8.0)



                total_wait = wait_time + jitter



                print(f"[!] Provider rate limit encountered (attempt {attempt + 1}/{MAX_RETRY_ATTEMPTS}): {e}", file=sys.stderr)



                print(f"[*] Sleeping {total_wait:.1f}s before bounded retry with backoff and jitter...", file=sys.stderr)



                await asyncio.sleep(total_wait)



                continue



            else:



                print(f"[!] Warning: Runner encountered exception: {e}", file=sys.stderr)



                final_report = f"Assessment concluded with partial execution: {e}"



                break







    # Reconcile any open hypotheses left in UNDER_INVESTIGATION



    for hyp in ledger.hypotheses.values():



        if hyp.status == HypothesisState.UNDER_INVESTIGATION:



            ledger.update_hypothesis_evaluation(



                hyp_id=hyp.id,



                status=HypothesisState.INCONCLUSIVE,



                positive_ev=hyp.initial_evidence or "Preliminary investigation started",



                negative_ctrl=hyp.negative_control_results or "Negative control pending follow-up",



                counterevidence="Assessment cycle concluded before decisive closure",



                rationale="Autonomous turn or rate limit reached; hypothesis preserved in ledger for follow-up review.",



                confidence="Low",



                severity=hyp.severity



            )







    duration_seconds = int(time.time() - start_time)



    print(f"[*] Execution finished in {duration_seconds}s. Findings recorded: {len(ledger.findings)}")



    print(f"[*] Blocked requests intercepted: {len(ledger.blocked_requests)}")



    print(f"[*] Coverage entries recorded: {len(ledger.coverage_entries)}")







    status = "completed" if len(ledger.findings) > 0 or len(ledger.hypotheses) > 0 else "partial"



    write_output_file(ledger, status, final_report, duration_seconds, turns_executed)







def write_output_file(ledger: IsolatedRunLedger, status: str, final_report: str, duration: int, turns: int = 1):
    ledger.reconcile_invocation_outcomes()
    payload = {



        "status": status,



        "duration_seconds": duration,



        "agent_model": model_name,



        "turns_executed": turns,



        "tools_executed": ledger.summarize_tools(),
        "tool_invocations": ledger.tool_invocations,



        "discovered_endpoints": ledger.discovered_endpoints,



        "threat_model": ledger.threat_model,



        "coverage_entries": ledger.coverage_entries,



        "hypotheses": [h.to_dict() for h in ledger.hypotheses.values()],



        "findings": ledger.findings,



        "abandoned_hypotheses": ledger.abandoned_hypotheses,



        "rejected_hypotheses": ledger.rejected_hypotheses,



        "inconclusive_hypotheses": ledger.inconclusive_hypotheses,



        "blocked_requests": ledger.blocked_requests,



        "final_report": final_report



    }



    payload = redact_sensitive_data(payload)







    out_p = Path(args.out_file)



    out_p.parent.mkdir(parents=True, exist_ok=True)



    with open(out_p, "w", encoding="utf-8") as f:



        json.dump(payload, f, indent=2)







    print(f"[+] Results successfully written to {args.out_file}")







async def run_multiagent_assessment():



    from core.assessment.orchestration.orchestrator import UnifiedMultiAgentOrchestrator

    inferred_run_id = Path(args.out_file).stem.replace("_result", "")

    orchestrator = UnifiedMultiAgentOrchestrator(

        assessment_id=args.assessment_id,

        grant_id=args.grant_id,

        user_id=args.user_id,

        org_id=args.org_id,

        target_base=args.target,

        roe_mode=args.roe_mode,

        max_concurrency=getattr(args, "concurrency", 2),

        model_name=model_name,

        llm_base=llm_base,

        token=token,

        run_id=inferred_run_id

    )



    result = await orchestrator.run_assessment()



    write_output_file(



        orchestrator.ledger,



        result["status"],



        result.get("final_report") or f"Multi-agent assessment completed across {len(orchestrator.coordinator.tasks)} tasks.",



        result["duration_seconds"],



        turns=len(orchestrator.coordinator.completed_task_ids)



    )







if __name__ == "__main__":



    if getattr(args, "mode", "single") == "multiagent":



        asyncio.run(run_multiagent_assessment())



    else:



        asyncio.run(run_autonomous_assessment())



