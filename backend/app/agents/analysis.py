"""
SECUREASSESS - Vulnerability Analysis & Correlation Agent
SIH 2026 Problem Statement ID: 26163 (NTRO)

Research Gaps Addressed:
- #16/#20 PTFusion: Deterministic per-tool normalization followed by single LLM deduplication pass.
- #4 EvoMaster: SIH scope categorization including authorization/RBAC, auth & session, input validation.
- #1/#17 AutoPT: Reads raw tools from SQLite, sending only structured candidates to LLM.
"""

from __future__ import annotations

import json
import logging
from typing import List, Dict, Any

from app.models import (
    ScanMode,
    Finding,
    FindingSeverity,
    FindingStatus,
    SIHScopeCategory,
    Remediation,
)
from app.state import StateManager
from app.audit import AuditLogger
from app.llm_client import LLMClient
from app.scanners.parsers import (
    parse_zap_json,
    parse_nikto_json,
    parse_semgrep_json,
    parse_gitleaks_json,
)

logger = logging.getLogger("secureassess.agent.analysis")


def run_analysis(
    job_id: str,
    target: str,
    mode: ScanMode,
    state_mgr: StateManager,
    audit_logger: AuditLogger,
    llm_client: LLMClient,
) -> List[Finding]:
    """Correlates heterogeneous scanner outputs, performs dedup, and normalizes findings."""
    state_mgr.append_log(job_id, "Analysis Agent reading scanner outputs from SQLite store...", "AnalysisAgent")

    tool_outputs = state_mgr.get_tool_outputs(job_id)
    candidate_findings: List[Dict[str, Any]] = []

    for out in tool_outputs:
        if out.tool_name == "zap":
            state_mgr.append_log(job_id, "Parsing OWASP ZAP baseline JSON outputs...", "AnalysisAgent")
            candidate_findings.extend(parse_zap_json(out.raw_output))
        elif out.tool_name == "nikto":
            state_mgr.append_log(job_id, "Parsing Nikto scanner JSON outputs...", "AnalysisAgent")
            candidate_findings.extend(parse_nikto_json(out.raw_output))
        elif out.tool_name == "semgrep":
            state_mgr.append_log(job_id, "Parsing Semgrep AST analysis findings...", "AnalysisAgent")
            candidate_findings.extend(parse_semgrep_json(out.raw_output))
        elif out.tool_name == "gitleaks":
            state_mgr.append_log(job_id, "Parsing Gitleaks secret detection findings...", "AnalysisAgent")
            candidate_findings.extend(parse_gitleaks_json(out.raw_output))

    state_mgr.append_log(
        job_id,
        f"Extracted {len(candidate_findings)} raw candidate findings. Initiating AI correlation & deduplication pass...",
        "AnalysisAgent",
    )

    # Construct single structured LLM prompt (Research Gap #11: single bounded call)
    prompt = f"""
You are the SECUREASSESS Security Analysis Engine.
Analyze, deduplicate, and classify the following candidate security findings extracted from target: {target} (Mode: {mode.value.upper()}).

For each unique finding, you must provide:
- id: e.g. "DAST-001", "SAST-001"
- title: concise title
- description: clear vulnerability description
- affected_component: URL, parameter, or file:line
- owasp_category: e.g. "A03:2021-Injection"
- sih_scope_category: exactly one of: "auth & session", "authorization/RBAC", "input validation", "API security", "client-side controls", "secure communication", "data storage & secrets"
- severity: "Critical" | "High" | "Medium" | "Low"
- cvss_score: float between 0.0 and 10.0
- cvss_vector: standard CVSS:3.1 vector string
- status: "Unverified"
- confidence_pct: integer 1-100
- steps_to_reproduce: list of concise step strings
- business_impact: concise risk explanation
- remediation: {{"description": "...", "fix": "...", "example_code": "..."}}
- source_tool: originating scanner tool
- evidence: list of evidence strings

CANDIDATE_FINDINGS:
{json.dumps(candidate_findings[:15], indent=2)}

Respond with JSON format: {{"findings": [...]}}
"""

    llm_result = llm_client.generate(prompt=prompt, task_type="analysis")
    raw_findings = llm_result.get("findings", [])

    normalized_findings: List[Finding] = []
    prefix = "DAST" if mode == ScanMode.DAST else "SAST"

    for idx, f_dict in enumerate(raw_findings):
        try:
            finding_id = f"{prefix}-{idx+1:03d}"
            
            # Map SIH scope category safely
            sih_raw = f_dict.get("sih_scope_category", "client-side controls")
            try:
                sih_cat = SIHScopeCategory(sih_raw)
            except ValueError:
                sih_cat = SIHScopeCategory.CLIENT_SIDE_CONTROLS

            # Map severity
            sev_raw = f_dict.get("severity", "Medium").capitalize()
            try:
                severity = FindingSeverity(sev_raw)
            except ValueError:
                severity = FindingSeverity.MEDIUM

            # Map remediation
            rem_dict = f_dict.get("remediation", {})
            remediation = Remediation(
                description=rem_dict.get("description", "Apply defense-in-depth mitigation."),
                fix=rem_dict.get("fix", "Harden component configuration."),
                example_code=rem_dict.get("example_code", "# Apply mitigation"),
            )

            finding = Finding(
                id=finding_id,
                title=f_dict.get("title", f"Finding {finding_id}"),
                description=f_dict.get("description", "Vulnerability detected during security assessment."),
                affected_component=f_dict.get("affected_component", target),
                owasp_category=f_dict.get("owasp_category", "A05:2021-Security Misconfiguration"),
                sih_scope_category=sih_cat,
                severity=severity,
                cvss_score=float(f_dict.get("cvss_score", 5.0)),
                cvss_vector=f_dict.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
                status=FindingStatus.UNVERIFIED,
                confidence_pct=int(f_dict.get("confidence_pct", 90)),
                steps_to_reproduce=f_dict.get("steps_to_reproduce", [f"Navigate to {target}"]),
                poc_evidence=None,
                business_impact=f_dict.get("business_impact", "Security vulnerability requires remediation."),
                remediation=remediation,
                source_tool=f_dict.get("source_tool", "scanner"),
                evidence=f_dict.get("evidence", []),
            )
            normalized_findings.append(finding)
        except Exception as e:
            logger.warning(f"Error normalizing finding item {idx}: {e}")

    # Persist normalized candidate findings in SQLite
    state_mgr.save_findings(job_id, normalized_findings)
    state_mgr.append_log(
        job_id,
        f"Analysis complete: Correlated and persisted {len(normalized_findings)} candidate findings.",
        "AnalysisAgent",
    )
    return normalized_findings
