"""
SECUREASSESS - Deterministic Per-Tool Parsers
SIH 2026 Problem Statement ID: 26163 (NTRO)

Research Gaps Addressed:
- #16/#20 PTFusion (Heterogeneous Scanner Output):
  Converts disparate, non-standardized JSON outputs from ZAP, Nikto, Semgrep, and Gitleaks
  into normalized candidate finding structures prior to LLM deduplication and classification.
"""

from __future__ import annotations

import json
from typing import List, Dict, Any


def parse_zap_json(raw_json: str) -> List[Dict[str, Any]]:
    """Normalizes OWASP ZAP baseline JSON reports into candidate findings."""
    candidates = []
    try:
        data = json.loads(raw_json)
        sites = data.get("site", [])
        for site in sites:
            base_url = site.get("@name", "")
            for alert in site.get("alerts", []):
                alert_name = alert.get("name", alert.get("alert", "ZAP Finding"))
                desc = alert.get("desc", "")
                instances = alert.get("instances", [])

                affected = base_url
                evidence_list = []
                if instances:
                    inst = instances[0]
                    affected = inst.get("uri", base_url)
                    if inst.get("param"):
                        affected += f" (param: {inst['param']})"
                    if inst.get("evidence"):
                        evidence_list.append(f"ZAP Evidence: {inst['evidence']}")
                    if inst.get("attack"):
                        evidence_list.append(f"ZAP Probe: {inst['attack']}")

                candidates.append({
                    "title": alert_name,
                    "description": desc,
                    "affected_component": affected,
                    "source_tool": "owasp-zap",
                    "evidence": evidence_list or [desc[:150]],
                    "steps_to_reproduce": [
                        f"1. Navigate to {affected}.",
                        "2. Inspect server response for defensive header or reflected value.",
                        "3. Verify non-compliance with secure defaults."
                    ]
                })
    except Exception as e:
        candidates.append({
            "title": "Raw ZAP Baseline Output",
            "description": f"Failed to parse structured ZAP JSON: {e}",
            "affected_component": "/",
            "source_tool": "owasp-zap",
            "evidence": [raw_json[:200]],
            "steps_to_reproduce": ["Inspect raw ZAP logs."]
        })
    return candidates


def parse_nikto_json(raw_json: str) -> List[Dict[str, Any]]:
    """Normalizes Nikto scanner JSON output into candidate findings."""
    candidates = []
    try:
        data = json.loads(raw_json)
        host = data.get("host", "localhost")
        port = data.get("port", 80)
        base_url = f"http://{host}:{port}"
        banner = data.get("banner", "")

        for vuln in data.get("vulnerabilities", []):
            msg = vuln.get("msg", "Nikto finding")
            uri = vuln.get("url", "/")
            full_target = f"{base_url}{uri}"

            # Derive title from Nikto message
            title = msg.split(".")[0]
            if len(title) > 70:
                title = title[:67] + "..."

            candidates.append({
                "title": title,
                "description": msg,
                "affected_component": full_target,
                "source_tool": "nikto",
                "evidence": [f"Nikto match on {uri}: {msg}", f"Server Banner: {banner}"],
                "steps_to_reproduce": [
                    f"1. Send an HTTP request to {full_target}.",
                    "2. Examine server headers and response status."
                ]
            })
    except Exception as e:
        candidates.append({
            "title": "Raw Nikto Output",
            "description": f"Failed to parse structured Nikto JSON: {e}",
            "affected_component": "/",
            "source_tool": "nikto",
            "evidence": [raw_json[:200]],
            "steps_to_reproduce": ["Inspect raw Nikto logs."]
        })
    return candidates


def parse_semgrep_json(raw_json: str) -> List[Dict[str, Any]]:
    """Normalizes Semgrep SAST rule hits into candidate findings."""
    candidates = []
    try:
        data = json.loads(raw_json)
        results = data.get("results", [])
        for res in results:
            check_id = res.get("check_id", "semgrep.rule")
            path = res.get("path", "unknown_file")
            start = res.get("start", {}).get("line", 1)
            location = f"{path}:{start}"

            extra = res.get("extra", {})
            message = extra.get("message", "Semgrep code match")
            lines = extra.get("lines", "").strip()

            title = check_id.split(".")[-1].replace("-", " ").title()
            if "Xss" in title:
                title = f"DOM-Based Cross-Site Scripting ({title})"

            evidence_items = [f"Code location: {location}"]
            if lines:
                evidence_items.append(f"Snippet: {lines}")

            candidates.append({
                "title": title,
                "description": message,
                "affected_component": location,
                "source_tool": "semgrep",
                "evidence": evidence_items,
                "steps_to_reproduce": [
                    f"1. Open repository file '{path}' at line {start}.",
                    f"2. Inspect the assignment: {lines}",
                    "3. Trace tainted source variable to execution sink."
                ]
            })
    except Exception as e:
        candidates.append({
            "title": "Raw Semgrep Output",
            "description": f"Failed to parse Semgrep JSON: {e}",
            "affected_component": "repository",
            "source_tool": "semgrep",
            "evidence": [raw_json[:200]],
            "steps_to_reproduce": ["Inspect semgrep rule output."]
        })
    return candidates


def parse_gitleaks_json(raw_json: str) -> List[Dict[str, Any]]:
    """Normalizes Gitleaks secret findings into candidate findings."""
    candidates = []
    try:
        items = json.loads(raw_json)
        if isinstance(items, dict):
            items = [items]

        for item in items:
            rule = item.get("RuleID", "exposed-secret")
            file_path = item.get("File", "unknown")
            line = item.get("StartLine", 1)
            location = f"{file_path}:{line}"
            desc = item.get("Description", "Exposed Secret / Token")
            secret_match = item.get("Secret", "")
            # Redact middle of secret for safety
            redacted_secret = secret_match[:6] + "..." + secret_match[-4:] if len(secret_match) > 12 else "[REDACTED]"

            candidates.append({
                "title": f"Hardcoded Secret Detected: {desc}",
                "description": f"A hardcoded credential ({desc}) was discovered in repository source code at {location}.",
                "affected_component": location,
                "source_tool": "gitleaks",
                "evidence": [
                    f"Rule: {rule}",
                    f"File: {location}",
                    f"Token prefix/fingerprint: {redacted_secret}"
                ],
                "steps_to_reproduce": [
                    f"1. Navigate to {file_path} in the repository clone.",
                    f"2. Inspect line {line}.",
                    "3. Verify presence of plaintext token/API key."
                ]
            })
    except Exception as e:
        candidates.append({
            "title": "Raw Gitleaks Output",
            "description": f"Failed to parse Gitleaks JSON: {e}",
            "affected_component": "repository",
            "source_tool": "gitleaks",
            "evidence": [raw_json[:200]],
            "steps_to_reproduce": ["Inspect gitleaks log."]
        })
    return candidates
