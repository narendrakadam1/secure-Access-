"""
SECUREASSESS - Hard Safety Constraints and Target Allowlist Gate
SIH 2026 Problem Statement ID: 26163 (NTRO)

Satisfies Hard Safety Constraints:
1. Allowlist gate BEFORE any packet: accept only localhost, 127.0.0.1, ::1,
   RFC1918 private ranges, or domains in ALLOWED_TARGETS env. Reject all else.
   In repo (SAST) mode: public github.com URLs only.
2. Non-destructive validation only: strictly bounded safe probes, <=5 requests/finding, 10s timeout.
"""

from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlparse
from typing import Tuple

from app.models import ScanMode


def is_rfc1918_or_loopback(host: str) -> bool:
    """Checks if a given host/IP is a loopback or RFC1918 private address."""
    # Check localhost aliases
    if host.lower() in ("localhost", "127.0.0.1", "::1", "localhost.localdomain"):
        return True

    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def validate_target_allowed(target: str) -> Tuple[bool, str, ScanMode]:
    """
    Validates scan target against strict security allowlist BEFORE any network packet is dispatched.
    
    Returns:
        (is_allowed: bool, reason: str, mode: ScanMode)
    """
    if not target or not isinstance(target, str):
        return False, "Target cannot be empty.", ScanMode.DAST

    cleaned_target = target.strip()

    # 1. Detect Mode: SAST (GitHub repository link) vs DAST (Web application URL)
    if "github.com" in cleaned_target.lower():
        # Validate GitHub repository format
        github_pattern = r"^https?://(?:www\.)?github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/)?$"
        if not re.match(github_pattern, cleaned_target):
            return (
                False,
                f"Invalid GitHub repository URL '{cleaned_target}'. SAST mode permits only public repository URLs (e.g. https://github.com/owner/repo).",
                ScanMode.SAST,
            )
        return True, "Valid public GitHub target accepted for SAST assessment.", ScanMode.SAST

    # 2. DAST URL Validation
    # Support raw port inputs (e.g. "3000", ":3000", "port 3000", "port:8000")
    digits_only = re.sub(r"[^\d]", "", cleaned_target)
    if cleaned_target.isdigit() or (cleaned_target.startswith(":") and cleaned_target[1:].isdigit()):
        port = cleaned_target.lstrip(":")
        cleaned_target = f"http://localhost:{port}"
    elif cleaned_target.lower().startswith("port") and digits_only:
        cleaned_target = f"http://localhost:{digits_only}"

    parsed = urlparse(cleaned_target)
    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        # Auto-prefix http:// if raw host:port provided
        parsed = urlparse(f"http://{cleaned_target}")

    hostname = parsed.hostname
    if not hostname:
        return False, f"Invalid URL target format: '{target}'", ScanMode.DAST

    # Check Loopback & RFC1918 Private Ranges
    if is_rfc1918_or_loopback(hostname):
        return True, f"Target '{hostname}' is within authorized loopback/RFC1918 private scope.", ScanMode.DAST

    # Check ALLOWED_TARGETS environment variable
    allowed_env = os.getenv("ALLOWED_TARGETS", "")
    allowed_list = [item.strip().lower() for item in allowed_env.split(",") if item.strip()]

    for allowed_item in allowed_list:
        allowed_parsed = urlparse(allowed_item)
        allowed_host = allowed_parsed.hostname or allowed_item
        if hostname.lower() == allowed_host or hostname.lower().endswith("." + allowed_host):
            return True, f"Target '{hostname}' matched ALLOWED_TARGETS allowlist rule.", ScanMode.DAST

    # Reject unauthorized targets
    return (
        False,
        f"Target '{hostname}' is outside authorized testing scope. Under Safety Constraint #1, only localhost, RFC1918 private subnets, and explicitly allowlisted domains in ALLOWED_TARGETS are permitted.",
        ScanMode.DAST,
    )
