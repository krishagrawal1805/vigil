# Unified Strix + PentAGI Capability Inventory

## 1. Executive Summary

This document provides a comprehensive inventory of security intelligence, vulnerability methodologies, testing implementations, and execution techniques across the **Strix** and **PentAGI** repositories. It categorizes every capability into one of five integration classifications:
1. **Directly Reusable**: Usable with existing architecture without modifications.
2. **Reusable with Adapter**: Requires wrapping inside controlled MCP tools to enforce ScopeEnforcer and AuthorizationManager.
3. **Methodology Reference**: Informational knowledge and counterevidence rules usable by the autonomous LLM agent.
4. **Reference Only**: Architectural or infrastructure patterns (e.g., container isolation, OSINT).
5. **Not Applicable / Incompatible**: Out of scope (e.g., unconstrained shell execution, direct network bypass).

---

## 2. Strix Capability Classification

### A. Vulnerability Testing Methodologies (`strix/skills/vulnerabilities/`)
| Skill / Capability | CWE | Classification | Controlled MCP Tool Target | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `path_traversal_lfi_rfi.md` | CWE-22 | Directly Reusable (Integrated) | `test_path_traversal` | Canary verification with `IsWithinDir` defense pattern |
| `sql_injection.md` | CWE-89 | Directly Reusable (Integrated) | `test_sql_injection` | Controlled boolean & auth bypass probes |
| `idor.md` (BOLA) | CWE-639 | Directly Reusable (Integrated) | `verify_bola` | Dual-account authorization verification |
| `xss.md` | CWE-79 | Directly Reusable (Integrated) | `test_xss` | Contained headless Chrome DOM verification |
| `authentication_jwt.md` | CWE-287 | Directly Reusable (Integrated) | `test_jwt_vulnerabilities` | Cryptographic audit, none-alg, brute force |
| `ssrf.md` | CWE-918 | **Reusable with Adapter (Phase 5)** | `test_ssrf` | Controlled loopback & metadata probe verification |
| `open_redirect.md` | CWE-601 | **Reusable with Adapter (Phase 5)** | `test_open_redirect` | External 3xx Location header verification |
| `csrf.md` | CWE-352 | **Reusable with Adapter (Phase 5)** | `test_csrf` | Origin stripping, SameSite & token check verification |
| `rce.md` (Command Injection) | CWE-78 | **Reusable with Adapter (Phase 5)** | `test_command_injection` | Safe canary argument injection probes |
| `insecure_deserialization.md` | CWE-502 | Methodology Reference | Future Adapter | Gadget chain analysis and parser bounds |
| `xxe.md` | CWE-611 | Methodology Reference | Future Adapter | XML entity parser testing |
| `mass_assignment.md` | CWE-915 | Methodology Reference | Future Adapter | Unfiltered parameter binding verification |
| `nosql_injection.md` | CWE-943 | Methodology Reference | Future Adapter | Operator injection ($gt, $ne) |
| `ssti.md` | CWE-94 | Methodology Reference | Future Adapter | Template syntax probes (${7*7}) |
| `broken_function_level_auth.md` | CWE-285 | Methodology Reference | Future Adapter | Privilege escalation probes |
| `http_request_smuggling.md` | CWE-444 | Methodology Reference | Future Adapter | TE.CL / CL.TE desync analysis |

### B. Core Execution & Tooling (`strix/tools/`)
| Strix Tool Module | Classification | Integration Strategy |
| :--- | :--- | :--- |
| `coverage/tools.py` | **Directly Reusable (Phase 5)** | Integrated as `record_coverage_entry` & `list_coverage_entries` to log reviewed negative space |
| `threat_model/tools.py` | **Directly Reusable (Phase 5)** | Integrated as `save_threat_model_summary` for shared trust boundary calibration |
| `load_skill/tool.py` | **Directly Reusable (Phase 5)** | Extended in runner to access all 68 Strix skills dynamically |
| `notes/tools.py`, `todo/tools.py` | Reference Only | Subsumed by structured hypothesis lifecycle |
| `shell/` | **Incompatible / Prohibited** | Direct raw shell bypasses deterministic network and target-scope enforcement |

---

## 3. PentAGI Capability Classification

| PentAGI Component | Classification | Integration Strategy |
| :--- | :--- | :--- |
| `pkg/flowfiles/files.go` (`IsWithinDir`) | **Directly Reusable (Integrated)** | Standard defensive canonical path containment pattern in mock and enforcer |
| `pkg/tools/searchers/` (Sploitus, Shodan) | Reference Only | OSINT and public exploit searchers for future external reconnaissance phase |
| `cmd/ftester/worker/executor.go` | Reference Only | Sandboxed subprocess management principles adapted for Python runner execution |
| `pkg/graph/` (Task Graph Planning) | Reference Only | Dynamic hypothesis dependency graph inspiration |

---

## 4. Phase 5 Integration Targets

In this phase, we operationalize:
1. **Registry Expansion**: 3 new high-priority capabilities:
   - SSRF (CWE-918)
   - Open Redirect (CWE-601)
   - CSRF (CWE-352)
2. **Controlled MCP Tools**: Safe, deterministic verification tools in `mocksecurityserver`:
   - `test_ssrf`
   - `test_open_redirect`
   - `test_csrf`
3. **Execution Reliability**:
   - 429 rate limit backoff with jitter and Retry-After parsing
   - Immediate partial state persistence
4. **Coverage Ledger & Threat Modeling**:
   - Agent-reported surface tracking (`record_coverage_entry`)
   - Threat boundary sharing (`save_threat_model_summary`)
5. **Full Dynamic Skill Retrieval**:
   - Unlocking all 68 Strix markdown skills for in-conversation methodology loading.

