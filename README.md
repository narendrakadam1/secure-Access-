# SECUREASSESS 🛡️
> **Autonomous, Universal, LLM-Orchestrated Web-Application Security Assessment Platform**  
> *MVP Solution for Smart India Hackathon 2026 | Problem Statement ID: 26163*  
> *Organization: NTRO | Theme: Smart Automation | Focus: Security Assessment of Web & Intelligence Applications*

---

## 1. Executive Overview

**SECUREASSESS** is a target-agnostic, LLM-orchestrated autonomous security assessment platform designed to perform in-depth Dynamic Application Security Testing (DAST) and Static Application Security Testing (SAST). 

Designed to assess modern web and intelligence dashboards (such as the target **World Monitor** intelligence dashboard), SECUREASSESS bridges the gap between raw vulnerability scanner outputs and verified, actionable remediation intelligence with zero hallucination.

### Key Architectural Highlights
- **Universal & Target-Agnostic:** Zero target-specific logic in core engines; supports any authorized web application (DAST) or repository (SAST).
- **Five-Agent Sequential State Machine:** Recon → Scan → Analysis → Validation → Report.
- **Hermes/OpenClaw-Style Memory:** Per-job SQLite shared state eliminating context-window bloat and context exhaustion.
- **Evidence-Gated Non-Destructive Validation:** Every candidate finding must pass a bounded, safe HTTP verification playbook before being marked **CONFIRMED**.
- **SUDARSHAN DAST Scan Report UI:** Dark-themed real-time dashboard delivering counter cards, confidence scoring, evidence snippets, and downloadable JSON/PDF reports.

---

## 2. Research Gap Coverage Matrix

SECUREASSESS directly tackles fundamental research gaps identified in autonomous offensive and defensive security literature:

| Research Gap & Citation | Identified Limitation | SECUREASSESS Solution |
| :--- | :--- | :--- |
| **#1 / #17 AutoPT** | Context loss & token exhaustion over long security scans | **SQLite Shared State Machine:** Agents read and write isolated state slices. LLM context never carries raw multi-megabyte tool outputs. |
| **#8 Peng et al.** | LLM hallucination of non-existent vulnerabilities | **Confirmed / Unverified Split:** Strict evidence-gated verification. Only findings confirmed by reproducible HTTP checks receive Confirmed status. |
| **#11 Deng et al.** | LLM planning traps and dead-branch loops | **Fixed 5-Agent Deterministic Pipeline:** LLM acts as an analyzer and deduplicator, not an unconstrained planner. Hard-bounded validator playbook (≤5 requests/finding). |
| **#16 / #20 PTFusion** | Incompatible heterogeneous scanner outputs | **Deterministic Parsers + Unified Schema:** Standardized parser normalization layer feeds a single structured LLM dedup & correlation pass. |
| **#13 / #19 Alazmi** | Single-tool scanner coverage blind spots | **Multi-Tool Kali Fusion:** Combines OWASP ZAP + Nikto for DAST; Semgrep + Gitleaks for SAST. |
| **#4 EvoMaster** | Policy and access control evaluation blind spots | **SIH Scope Categorization:** Explicit classification including `authorization/RBAC` and `auth & session` rules. |
| **#3 Kalopisis** | Complex browser/DOM execution blind spots | Addressed via Semgrep client-side rules today; headless DOM agent documented as Future Work. |

---

## 3. Architecture & Pipeline

```
                                      ┌─────────────────────────────────────────────────────────────┐
                                      │                    SECUREASSESS FRONTEND                    │
                                      │         (React + Vite + Tailwind - SUDARSHAN UI)            │
                                      └──────────────────────────────┬──────────────────────────────┘
                                                                     │ Target URL / Repo Link
                                                                     ▼
                                      ┌─────────────────────────────────────────────────────────────┐
                                      │                   ALLOWLIST & SAFETY GATE                   │
                                      │      (Accepts only localhost / RFC1918 / Allowed Domains)   │
                                      └──────────────────────────────┬──────────────────────────────┘
                                                                     │ Job UUID
                                                                     ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                             SEC-AI ORCHESTRATOR                                                  │
│                                                                                                                   │
│   ┌─────────────────┐       ┌─────────────────┐       ┌──────────────────┐       ┌────────────────────────────┐  │
│   │ 1. RECON AGENT  │ ────► │  2. SCAN AGENT  │ ────► │ 3. ANALYSIS AGENT│ ────► │    4. VALIDATION AGENT     │  │
│   │  httpx probe    │       │   Kali Docker   │       │  Tool Parsers +  │       │ (Non-destructive Playbook: │  │
│   │  nmap banners   │       │   ZAP + Nikto   │       │  LLM Correlation │       │  ≤5 requests / 10s timeout)│  │
│   │  robots / tech  │       │ Semgrep/Gitleaks│       │  CVSS + SIH Map  │       │ Confirmed vs Unverified    │  │
│   └────────┬────────┘       └────────┬────────┘       └────────┬─────────┘       └─────────────┬──────────────┘  │
│            │                         │                         │                               │                 │
│            ▼                         ▼                         ▼                               ▼                 │
│   ┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│   │                     HERMES / OPENCLAW-STYLE PERSISTENT MEMORY (SQLite State Engine)                       │  │
│   │                     Tables: scan_state | tool_outputs | findings | agent_log                             │  │
│   └───────────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                │                 │
│                                                                                                ▼                 │
│                                                                                  ┌────────────────────────────┐  │
│                                                                                  │      5. REPORT AGENT       │  │
│                                                                                  │ LLM Impact + Remediation   │  │
│                                                                                  │ Jinja2 HTML + WeasyPrint   │  │
│                                                                                  └─────────────┬──────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────────────┼──────────────────┘
                                                                                                 ▼
                                                                                   ┌────────────────────────────┐
                                                                                   │   REPORT & EXPORT ENGINE   │
                                                                                   │  • SUDARSHAN Web View      │
                                                                                   │  • report.json             │
                                                                                   │  • secureassess_<id>.pdf   │
                                                                                   │  • audit.log Trail         │
                                                                                   └────────────────────────────┘
```

---

## 4. Hard Safety Constraints & Validation Playbook

Enforced strictly in **code**, never in prompts:

1. **Pre-Packet Allowlist Gate:** Only `localhost`, `127.0.0.1`, `::1`, RFC1918 subnets, or targets in `ALLOWED_TARGETS` are permitted. All others are blocked before any packet leaves. In SAST mode, only public `https://github.com/` URLs are accepted.
2. **Validator Playbook (Strictly Non-Destructive):**
   - Maximum 5 requests per finding; 10s strict timeout per request.
   - Zero DoS, zero shellcode/RCE, zero brute force, zero state modification.
   - Fixed checks:
     - `missing-security-headers`: Baseline HTTP GET checking CSP, HSTS, X-Frame-Options, X-Content-Type-Options.
     - `cookie-flags`: Inspects `Set-Cookie` for missing `HttpOnly`, `Secure`, or `SameSite`.
     - `cors-misconfig`: Benign origin `Origin: https://evil-example.com` reflection check.
     - `marker-reflection`: Safe alphanumeric token `?q=sa_marker_7f3a` reflection check.
     - `verbose-error`: Non-existent path requesting check for stack traces and leaked version banners.
3. **Container Sandboxing:** Kali scanner container runs on an internal bridge network with **zero exposed/published ports**.
4. **Per-Scan Audit Log:** Comprehensive log recording target, timestamp, tool executions, and exact validation requests sent.
5. **Deterministic Demo Mode (`DEMO_MODE=true`):** Allows 100% offline demonstration using realistic recorded tool artifacts.
6. **Concurrency & Timeouts:** Single scan enforcement (overlapping scans receive `409 Conflict`); total scan timeout hard-capped by `SCAN_TIMEOUT_S`.

---

## 5. Directory Structure

```
world monitor/
├── .env.example              # Environment variables template (Safety & LLM config)
├── .gitignore                # Source control exclusions
├── docker-compose.yml        # Multi-container orchestration (backend, frontend, kali, ollama)
├── Dockerfile.kali           # Kali Linux container with ZAP, Nikto, Nmap, Semgrep, Gitleaks
├── README.md                 # Project documentation & SIH specification
├── backend/
│   ├── Dockerfile            # Python 3.11 FastAPI + WeasyPrint runtime
│   ├── requirements.txt      # Pinned Python dependencies
│   ├── data/                 # SQLite storage and audit logs (mounted volume)
│   └── app/
│       ├── __init__.py
│       ├── main.py           # FastAPI entrypoint & routes (/scan, /status, /report)
│       ├── models.py         # Unified Pydantic Finding & ScanState schemas
│       ├── state.py          # SQLite persistence engine (Hermes memory)
│       ├── audit.py          # Audit logging subsystem
│       ├── llm_client.py     # Resilient LLM Gateway (Ollama / Cloud / Rule Fallback)
│       ├── orchestrator.py   # 5-Agent sequential state machine
│       ├── agents/           # Recon, Scan, Analysis, Validation, Report agents
│       ├── scanners/         # Docker tool execution & artifact parsing
│       ├── reporting/        # Jinja2 templates & WeasyPrint PDF renderer
│       └── sample_artifacts/ # Recorded tool outputs for zero-dependency DEMO_MODE
└── frontend/
    ├── Dockerfile            # Multi-stage Vite build + Nginx
    ├── nginx.conf            # Reverse proxy configuration
    ├── package.json          # React, Tailwind, Lucide dependencies
    └── src/                  # SUDARSHAN report dashboard components
```

---

## 6. Quickstart Guide

### Prerequisites
- Docker & Docker Compose **OR** Python 3.11+ and Node.js 18+ (if running without Docker in DEMO_MODE).

### Option A: Running via Docker Compose
```bash
# 1. Clone or navigate to the repository
cd "world monitor"

# 2. Configure environment
cp .env.example .env

# 3. Validate configuration
docker compose config

# 4. Launch SECUREASSESS stack
docker compose up --build
```
- Dashboard UI: `http://localhost:5173`
- Backend API Docs: `http://localhost:8000/docs`

### Option B: Running Local Fast-Track (DEMO_MODE=true)
```bash
# 1. Setup Backend
cd backend
python -m venv .venv
source .venv/bin/activate  # Or .venv\Scripts\activate on Windows
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# 2. Setup Frontend (in separate terminal)
cd ../frontend
npm install
npm run dev -- --port 5173
```

---

## 7. SIH 2026 Deliverables Mapping

| Required Deliverable | SECUREASSESS Implementation |
| :--- | :--- |
| **≥1 Valid Documented Vulnerability** | Surfaced via DAST/SAST multi-tool correlation |
| **Evidence Supporting Existence** | Verified via non-destructive playbook & `poc_evidence` snippets |
| **Risk & Impact Clearly Explained** | CVSS 3.1 vector + AI-synthesized `business_impact` paragraph |
| **Practical Mitigation Provided** | Actionable `remediation` with description, fix, and code snippet |
| **Authorized-Testing Constraints** | Strict pre-packet allowlist + immutable audit trail |
| **Report Export Formats** | Real-time SUDARSHAN UI + `report.json` + `report.pdf` |

---

---

## 8. Build Roadmap & Phase Status

- [x] **Phase 1: Project Scaffolding & Container Infrastructure** — Docker Compose, Kali Sandbox, Nginx, Backend, Frontend.
- [x] **Phase 2: Core Data Models & Persistence Subsystem** — 15-field Unified Finding Schema, SQLite state machine, append-only JSONL audit logger.
- [x] **Phase 3: Multi-Tier Resilient LLM Gateway** — Cloud OpenAI/NIM → local Ollama → deterministic rule-based fallback with bracket-depth JSON repair.
- [x] **Phase 4: Agent Core & Pipeline Orchestrator** — 5-Agent pipeline (Recon, Scan, Analysis, Validation, Report), allowlist pre-packet gate, and concurrency lock.
- [x] **Phase 5: Containerized Scanner Execution Engine** — Docker Kali scanner runner for ZAP, Nikto, Semgrep, and Gitleaks with zero-crash fallback.
- [x] **Phase 6: Report Generation Engine** — Jinja2 dark SUDARSHAN HTML template and cross-platform WeasyPrint/ReportLab dual-engine PDF compiler (`secureassess_<id>.pdf`).
- [x] **Phase 7: React Frontend Dashboard** — SUDARSHAN DAST Scan Report UI, 5-agent stepper, 6 counter cards, live terminal console, finding cards with verified PoC evidence, and JSON/PDF deliverable downloads.
- [x] **Phase 8: Evaluation Runbooks & Compliance Documentation** — World Monitor demo runbook, SIH 26163 formal compliance matrix, and future work roadmap.

---

## 9. Comprehensive Documentation & Evaluation Guides

For detailed evaluation guides and architectural proofs, consult the dedicated documentation:

1. 📖 **[World Monitor Assessment Runbook](docs/WORLD_MONITOR_RUNBOOK.md)**: Complete evaluator walkthrough running DAST and SAST assessments against the World Monitor intelligence dashboard (`http://localhost:3000`).
2. 📜 **[SIH 2026 PS ID 26163 Compliance Matrix](docs/SIH_26163_COMPLIANCE.md)**: Clause-by-clause requirement traceability matrix, 8 deliverable fields audit, and academic literature citations.
3. 🚀 **[Future Work & Enterprise Roadmap](docs/FUTURE_WORK.md)**: Long-term vision detailing the Headless Browser Agent (Playwright), Automated Patch PR Generator, and Ephemeral Sandbox Pods.

---

## 10. Automated Test Suite Verification

```powershell
$env:PYTHONPATH = "backend"
$env:DEMO_MODE = "true"
$env:ALLOWED_TARGETS = "localhost,127.0.0.1,::1,http://localhost:3000"
python -m pytest backend/tests/ -v
```

```
backend/tests/test_docker_runner.py::test_docker_runner_degrades_when_docker_absent PASSED [  4%]
backend/tests/test_docker_runner.py::test_scan_agent_graceful_degradation_when_docker_absent PASSED [  9%]
backend/tests/test_docker_runner.py::test_docker_runner_mock_container_execution PASSED [ 13%]
backend/tests/test_llm_client.py::TestLLMClient::test_cloud_llm_degradation_to_fallback PASSED [ 18%]
backend/tests/test_llm_client.py::TestLLMClient::test_cloud_llm_success PASSED [ 22%]
backend/tests/test_llm_client.py::TestLLMClient::test_json_clean_and_repair PASSED [ 27%]
backend/tests/test_llm_client.py::TestLLMClient::test_ollama_off_fallback_path PASSED [ 31%]
backend/tests/test_llm_client.py::TestLLMClient::test_report_impact_remediation_fallback PASSED [ 36%]
backend/tests/test_pipeline_e2e.py::test_safety_gate_rejects_unauthorized_target PASSED [ 40%]
backend/tests/test_pipeline_e2e.py::test_concurrency_gate_returns_409 PASSED [ 45%]
backend/tests/test_pipeline_e2e.py::test_e2e_dast_scan_and_report_json PASSED [ 50%]
backend/tests/test_pipeline_e2e.py::test_e2e_sast_scan_and_secret_confirmation PASSED [ 54%]
backend/tests/test_report_generator.py::test_html_rendering_sudarshan_theme PASSED [ 59%]
backend/tests/test_report_generator.py::test_pdf_compilation_reportlab PASSED [ 63%]
backend/tests/test_report_generator.py::test_safe_escaping_no_xml_parser_crash PASSED [ 68%]
backend/tests/test_report_generator.py::test_report_agent_full_artifact_generation PASSED [ 72%]
backend/tests/test_report_generator.py::test_api_report_endpoints PASSED [ 77%]
backend/tests/test_state_audit.py::test_create_job_and_phase_progression PASSED [ 81%]
backend/tests/test_state_audit.py::test_agent_log_streaming PASSED       [ 86%]
backend/tests/test_state_audit.py::test_tool_outputs_persistence PASSED  [ 90%]
backend/tests/test_state_audit.py::test_write_finding_and_reload_from_db PASSED [ 95%]
backend/tests/test_state_audit.py::test_audit_logger PASSED              [100%]

======================= 22 passed, 1 warning in 47.35s ========================
```

