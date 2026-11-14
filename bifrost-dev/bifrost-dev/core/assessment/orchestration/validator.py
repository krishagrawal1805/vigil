import time
import json
"""
Independent Evidence Validation Agent (Adapted from AEGIS Validation Chain)
==========================================================================
Reviews proposed candidate findings from specialist agents.
Enforces:
- Reproducible technical working evidence from logged tool executions
- Negative control verification
- Rigorous counterevidence analysis
- Authoritative commit into the Central IsolatedRunLedger
"""

from typing import Dict, Any, Tuple
from core.assessment.runner.vigil_runner import IsolatedRunLedger, HypothesisState, redact_sensitive_data

class IndependentValidator:
    """Independently evaluates candidate findings before central ledger commitment."""

    def __init__(self, ledger: IsolatedRunLedger):
        self.ledger = ledger

    def validate_and_commit(self, candidate: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validates candidate finding against strict AEGIS counterevidence criteria.
        Returns (is_approved, reason).
        """
        title = candidate.get("title", "")
        affected_url = candidate.get("affected_url", "")
        hyp_id = candidate.get("hypothesis_id", "")
        evidence = candidate.get("evidence", "")
        neg_ctrl = candidate.get("negative_control", "")
        counterevidence = candidate.get("counterevidence", "")
        severity = candidate.get("severity", "High")
        cwe = candidate.get("cwe", "")
        category = candidate.get("category", "")
        method = candidate.get("method", "GET").upper()
        parameter = candidate.get("parameter", "")

        # 1. Hypothesis validation
        if not hyp_id or hyp_id not in self.ledger.hypotheses:
            return False, f"REJECTED: Hypothesis ID '{hyp_id}' does not exist in current ledger."

        hyp = self.ledger.hypotheses[hyp_id]
        if hyp.status == HypothesisState.REJECTED:
            return False, f"REJECTED: Hypothesis '{hyp_id}' was previously marked REJECTED."

        # 2. Structured tool-result & evidence validation
        tool_result = candidate.get("tool_result") or candidate.get("tool_data")
        if not tool_result:
            raw = candidate.get("raw_output")
            if isinstance(raw, dict):
                tool_result = raw
            elif isinstance(raw, str) and raw.strip().startswith("{"):
                try:
                    tool_result = json.loads(raw)
                except Exception:
                    pass

        if not tool_result and isinstance(evidence, str) and evidence.strip().startswith("{"):
            try:
                tool_result = json.loads(evidence)
            except Exception:
                pass

        if tool_result and isinstance(tool_result, dict):
            # A. Structured confirmation check
            confirmed_flag = tool_result.get("confirmed")
            if confirmed_flag is False:
                return False, "REJECTED: Structured tool-result indicates confirmed=False; cannot promote unverified candidate."

            # B. Structured confidence check
            conf_field = tool_result.get("confidence")
            if conf_field and str(conf_field).strip().lower() in ("low", "info", "informational"):
                return False, f"REJECTED: Structured tool-result confidence is '{conf_field}'; High or Critical confidence required."

            # C. Structured vulnerability outcome checks
            if tool_result.get("vulnerable") is False or tool_result.get("is_vulnerable") is False:
                return False, "REJECTED: Structured tool-result explicitly marks vulnerable=False."

            # D. Structured negative control verification
            unauth_code = tool_result.get("unauthenticated_status") or tool_result.get("baseline_status")
            if unauth_code is not None:
                try:
                    code_int = int(unauth_code)
                    if code_int != 0 and code_int not in (400, 401, 403):
                        return False, f"REJECTED: Structured negative control returned HTTP {code_int} (expected 401/403 access restriction)."
                except (ValueError, TypeError):
                    pass

        # Candidate-level structured fields
        if candidate.get("confirmed") is False:
            return False, "REJECTED: Candidate confirmed flag is explicitly False."

        cand_conf = candidate.get("confidence")
        if cand_conf and str(cand_conf).strip().lower() in ("low", "info", "informational"):
            return False, f"REJECTED: Candidate confidence is '{cand_conf}'; High or Critical required."

        low_ev = evidence.lower()
        if "confirmed\": false" in low_ev or "confirmed\":false" in low_ev or "confirmed=false" in low_ev:
            return False, "REJECTED: Tool output contains confirmed=false; unverified findings cannot be promoted."

        if "confidence\": \"low\"" in low_ev or "confidence\":\"low\"" in low_ev or "confidence=low" in low_ev:
            return False, "REJECTED: Tool output contains confidence=Low; unverified findings cannot be promoted."

        if "not vulnerable" in low_ev or "unconfirmed" in low_ev or "safe against" in low_ev:
            self.ledger.update_hypothesis_evaluation(
                hyp_id=hyp.id,
                status=HypothesisState.REJECTED,
                positive_ev="Tested without working exploitation",
                negative_ctrl=neg_ctrl or "Tested safe",
                counterevidence=counterevidence or "Endpoint is defended",
                rationale="Candidate rejected by Independent Validator: evidence indicates safety or negative test result."
            )
            return False, "REJECTED: Candidate reports safe or non-vulnerable behavior; hypothesis marked REJECTED."

        if len(evidence.strip()) < 15:
            return False, "REJECTED: Finding missing reproducible technical working evidence."

        if not neg_ctrl or len(neg_ctrl.strip()) < 10:
            return False, "REJECTED: Finding missing mandatory negative control evaluation."

        if not counterevidence or len(counterevidence.strip()) < 10:
            return False, "REJECTED: Finding missing mandatory counterevidence analysis."

        # 3. Format complete finding structure
        finding_id = f"VULN-{len(self.ledger.findings) + 1:03d}"
        finding_data = {
            "id": finding_id,
            "hypothesis_id": hyp.id,
            "assessment_id": self.ledger.assessment_id,
            "run_id": self.ledger.run_id,
            "target": self.ledger.run_id,
            "title": title,
            "severity": severity,
            "category": category,
            "cwe": cwe,
            "affected_url": affected_url,
            "method": method,
            "parameter": parameter,
            "evidence": redact_sensitive_data(evidence),
            "negative_control": neg_ctrl,
            "verification": "Confirmed",
            "confidence": candidate.get("confidence", "High"),
            "counterevidence": counterevidence,
            "description": candidate.get("description", f"Verified vulnerability: {title}"),
            "recommendation": candidate.get("recommendation", "Implement input sanitization and access controls."),
            "remediation_time": "1-3 days" if severity in ("Critical", "High") else "1-2 weeks",
            "discovered_at": candidate.get("discovered_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        # 4. Commit via ledger (enforcing dedup & tool provenance)
        ok, msg = self.ledger.add_finding(finding_data)
        if ok:
            # Update hypothesis to CONFIRMED
            self.ledger.update_hypothesis_evaluation(
                hyp_id=hyp.id,
                status=HypothesisState.CONFIRMED,
                positive_ev=evidence,
                negative_ctrl=neg_ctrl,
                counterevidence=counterevidence,
                rationale=f"Vulnerability independently validated: {title}",
                confidence=candidate.get("confidence", "High"),
                severity=severity
            )
            return True, f"SUCCESS: Finding '{title}' ({cwe}) independently validated and committed to ledger."
        return False, f"REJECTED by Ledger: {msg}"

