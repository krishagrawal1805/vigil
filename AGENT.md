# VIGIL — Operational Agent Guide

This document provides autonomous AI agents and automated operators with guidelines for interacting with the **VIGIL** autonomous security platform.

---

## 1. System Endpoints & Service Topology

| Service | Internal Address | Host Port | Role |
| :--- | :--- | :--- | :--- |
| **Edge Gateway** | `platform-edge-gateway` | `80`, `443` | Reverse proxy terminating TLS and routing frontend/API requests |
| **Backend Core** | `platform-backend:8000` | Internal | REST API for authentication, assessments, grants, and audit trails |
| **Controlled MCP** | `controlled-security-mcp:3011` | Internal | 13 controlled security tools with deterministic ScopeEnforcer checks |
| **Bifrost LLM Gateway** | `bifrost-internal-llm:8080` | Internal | Loopback-only proxy for LLM reasoning (Gemini 2.5 Flash) |
| **Practice Lab** | `platform-practice-lab:3000` | `5000` | Intentionally vulnerable OWASP Juice Shop target |

---

## 2. Authentication & Session Management

- **User Registration**: `POST /api/auth/register`
- **User Login**: `POST /api/auth/login` (Returns secure session cookie / JWT)
- **Profile / Current User**: `GET /api/auth/profile`
- **Role Hierarchy**:
  - `system_admin`: Full administrative control
  - `security_officer`: Authorized to approve external assessment grants
  - `pentester`: Authorized to create targets and launch assessments

---

## 3. Assessment Lifecycle

1. **Practice Lab Execution (1-Click)**
   - Start Lab: `POST /api/lab/start` (Payload: `{"duration_minutes": 60}`)
   - Launch Run: `POST /api/pentest/run` (Payload: `{"grant_id": "<grant_id>"}`)
   - Poll Status: `GET /api/pentest/status`
   - Retrieve Results: `GET /api/pentest/results?run_id=<run_id>`

2. **External Target Execution**
   - Register Target: `POST /api/external/register`
   - Verify Ownership: `POST /api/external/verify-dns` (Requires matching TXT token at `_VIGIL-challenge.<domain>`)
   - Independent Approval: `POST /api/external/approve` (Enforces separation of duties; requester cannot approve)
   - Launch Run: `POST /api/pentest/run` with approved grant ID

---

## 4. Safety & Scope Rules

- **Deterministic Scope Enforcement**: All network transmissions pass through ScopeEnforcer. Attempts to contact out-of-scope hosts or restricted URI prefixes are blocked immediately with high-priority audit events (`SCOPE_INTERCEPTION`).
- **Exploit Verification**: Findings are classified as **Confirmed** only after independent corroboration by the isolated validator engine with negative-control proof verification.
- **Non-Destructive Proofs**: Probing is restricted to read-only demonstration payloads (e.g. non-destructive file reads, canary echo strings, or differential object authorization checks).

