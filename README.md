# VIGIL — Autonomous AI Security Intelligence & Penetration Testing Platform

[![Architecture: Multi-Agent](https://img.shields.io/badge/Architecture-Autonomous%20Multi--Agent-blue.svg)](#architecture)
[![Scope: Deterministic](https://img.shields.io/badge/Scope%20Enforcement-Deterministic%20Kernel%20Bounds-emerald.svg)](#safety--scope-enforcement)
[![Target: OWASP Juice Shop](https://img.shields.io/badge/Practice%20Lab-OWASP%20Juice%20Shop%20v20.3-orange.svg)](#quick-start)
[![License: Proprietary](https://img.shields.io/badge/License-Proprietary%20Hackathon%20Edition-purple.svg)](#)

**VIGIL** is a modern enterprise autonomous penetration testing platform designed to assess web applications and REST APIs safely, rigorously, and without human intervention. Built with a crisp, professional white UI inspired by Burp Suite Enterprise, VIGIL orchestrates specialized AI agents to discover attack surfaces, formulate targeted hypotheses, test injection and access-control vulnerabilities, and independently verify exploit proofs.

---

## Key Capabilities

1. **1-Click Practice Lab Assessment**
   - Instant single-click launch against an isolated, managed OWASP Juice Shop sandbox on port 5000.
   - Zero setup or credential prompting: automatically provisions test sessions and runs autonomous scans.

2. **Real-Time Split-Screen Live Demo Mode**
   - Side-by-side presentation showing the active target application on the left and live autonomous agent reasoning, tool invocations, and route visualizers on the right.

3. **Burp Suite Enterprise Security Workspace**
   - Comprehensive 8-tab operational dashboard:
     - `Overview`: Severity distribution (Certain, Firm, Tentative), trend charts, scanned URL ratios, and prioritized vulnerabilities.
     - `Issues`: Vulnerability catalog with CWE classifications, CVSS scoring, affected URLs, and parameters.
     - `URLs`: Discovered attack surface inventory and route testing statuses.
     - `Coverage`: OWASP Top 10:2025 assessment matrix with tested vs. defended endpoints.
     - `Activity`: Specialist agent telemetry and real-time execution provenance.
     - `Traffic`: Full HTTP request and response inspection records.
     - `Scope`: Deterministic CIDR, method, and URI path boundaries.
     - `Report`: Multi-format report generator (Executive Summary & Detailed Technical) in HTML, Markdown, CSV, JSON, and PDF.

4. **Deterministic ScopeEnforcer Protection**
   - Hard kernel-level boundaries preventing unauthorized egress, lateral network movement, or out-of-scope requests.
   - External target testing requires cryptographic DNS TXT ownership verification and two-person authorization.

5. **Independent Exploit Verification**
   - Findings require negative-control baseline validation and differential corroboration before being classified as confirmed.

---

## Architecture Overview

```
                                  +-----------------------------+
                                  |     Public Web Browser      |
                                  |  (Clean White Enterprise UI)|
                                  +--------------+--------------+
                                                 |
                                         Ports 80 / 443 (TLS)
                                                 v
                                  +-----------------------------+
                                  |    platform-edge-gateway    |
                                  |    (Nginx Reverse Proxy)    |
                                  +--------------+--------------+
                                                 |
                     +---------------------------+---------------------------+
                     |                                                       |
              Port 8000 (Internal)                                    Loopback / UI
                     v                                                       v
      +-----------------------------+                         +-----------------------------+
      |    platform-backend-core    |                         |    platform-practice-lab    |
      |   (Go Platform Server API)  |                         |  (OWASP Juice Shop Sandbox) |
      +--------------+--------------+                         |       Port 5000:3000        |
                     |                                        +-----------------------------+
         +-----------+-----------+
         |                       |
         v                       v
+------------------+   +-------------------+
|  platform-mcp-   |   |   platform-       |
|    security      |   |   bifrost-llm     |
| (13 Security MCP |   | (Loopback LLM     |
|   Capabilities)  |   |    Gateway)       |
+------------------+   +-------------------+
```

---

## Quick Start

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/)
- Node.js 18+ (for frontend development)
- Python 3.10+ (for local test runner)
- Modern web browser (Chrome, Edge, Firefox, Safari)

### 1. Configure Environment & TLS
Copy the environment template and generate local dev TLS certificates:
```bash
# 1. Create environment configuration
cp .env.example deploy/.env.production

# 2. Generate local development TLS certificates (self-signed)
# On Linux / macOS:
chmod +x deploy/generate-certs.sh && ./deploy/generate-certs.sh

# On Windows PowerShell:
.\deploy\generate-certs.ps1
```

### 2. Launch Platform
From the repository root, start all services with Docker Compose using the production environment file:
```bash
docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml up -d
```

### 3. Access the Application
- **VIGIL Web Platform**: Open [https://localhost](https://localhost) (or [http://localhost](http://localhost))
- **Default Operator Credentials**:
  - **Operator Account**: `krish` / `AdminPassword2026!`
  - **Administrator Account**: `admin` / `AdminPassword2026!`
- **Practice Lab Target (OWASP Juice Shop)**: Running in isolated sandbox on port `5000` (`http://localhost:5000`)

### 4. Running Test Verification
Run the end-to-end automated verification suite:
```bash
python tests/test_final_verification.py
```

---

## Directory Structure

```
├── deploy/                     # Docker Compose configuration, Nginx configs, and TLS certs
│   ├── docker-compose.prod.yml # Production multi-service orchestration definition
│   ├── nginx.conf              # Edge reverse proxy configuration
│   └── certs/                  # TLS certificates (generated locally, ignored by Git)
├── bifrost-dev/                # Core backend, MCP security server, and agent orchestration
│   └── bifrost-dev/
│       ├── core/               # Platform server, authentication, scope enforcement, and lab manager
│       │   ├── assessment/     # Multi-agent runner, capability registry, skills, and ledger
│       │   ├── authmanager/    # Token management, RBAC, and DNS verification
│       │   └── labmanager/     # Docker sandbox container provisioning
│       ├── transports/         # Loopback Bifrost HTTP LLM Gateway
│       └── Dockerfile.*        # Service build recipes
├── web/                        # React 18 + Vite + Tailwind CSS frontend
│   └── src/
│       ├── components/views/   # Onboarding, Dashboard, Live Assessment, and Findings views
│       ├── components/layout/  # AppHeader and collapsible Sidebar
│       └── lib/                # Telemetry mathematics and report generator
└── tests/                      # Automated regression and acceptance verification test suites
```

---

## Safety & Responsible Disclosure

VIGIL is built strictly for authorized security assessments:
- Internal practice testing is restricted to containerized sandbox environments.
- External assessments enforce domain ownership via `_VIGIL-challenge.<domain>` DNS TXT records.
- All requests adhere to deterministic rate limits and non-destructive proof payloads.

