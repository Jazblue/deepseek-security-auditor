"""
Security Auditor - Security Headers Scanner Module
"""
import logging
import re
from pathlib import Path

from .config import SECURITY_HEADERS, Finding, Severity

logger = logging.getLogger("security_auditor.headers")

HTML_EXTENSIONS = {".html", ".htm", ".xhtml", ".j2", ".jinja", ".jinja2"}
FRAMEWORK_EXTENSIONS = {".py", ".js", ".ts"}


def scan_security_headers(target_dir: Path) -> list[Finding]:
    """Scan for missing security headers in web application source and templates."""
    findings: list[Finding] = []

    # Check Python/JS files for header configuration
    for ext in FRAMEWORK_EXTENSIONS:
        for filepath in target_dir.rglob(f"*{ext}"):
            if _is_skip_dir(filepath, target_dir):
                continue
            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            findings.extend(_scan_framework_headers(filepath, content, target_dir))

    # Check HTML/template files for meta-based security headers
    for ext in HTML_EXTENSIONS:
        for filepath in target_dir.rglob(f"*{ext}"):
            if _is_skip_dir(filepath, target_dir):
                continue
            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            findings.extend(_scan_html_headers(filepath, content, target_dir))

    return findings


def _is_skip_dir(filepath: Path, target_dir: Path) -> bool:
    rel = filepath.relative_to(target_dir)
    return any(part in (".git", "__pycache__", "node_modules") for part in rel.parts)


def _scan_framework_headers(filepath: Path, content: str, target_dir: Path) -> list[Finding]:
    findings = []
    rel_path = str(filepath.relative_to(target_dir))

    # Detect framework usage
    is_flask = "from flask" in content.lower() or "flask" in content.lower()
    is_express = "require('express')" in content or "from 'express'" in content

    if is_flask:
        for header, recommended in SECURITY_HEADERS.items():
            if header.lower() not in content.lower() and "after_request" not in content.lower():
                # Check for app.after_request or @app.after_request pattern
                if not re.search(r"after_request", content, re.IGNORECASE):
                    findings.append(Finding(
                        category="Missing Security Header",
                        severity=Severity.MEDIUM,
                        message=f"Flask app missing security header: {header}",
                        file_path=rel_path,
                        remediation=f"Add the '{header}' header via an @app.after_request handler or a middleware. Recommended value: {recommended}.",
                    ))

    if is_express:
        for header, recommended in SECURITY_HEADERS.items():
            if header.lower() not in content.lower():
                findings.append(Finding(
                    category="Missing Security Header",
                    severity=Severity.MEDIUM,
                    message=f"Express app missing security header: {header}",
                    file_path=rel_path,
                    remediation=f"Add the '{header}' header using express helmet middleware or res.setHeader(). Recommended: {recommended}.",
                ))

    return findings


def _scan_html_headers(filepath: Path, content: str, target_dir: Path) -> list[Finding]:
    findings = []
    rel_path = str(filepath.relative_to(target_dir))

    # Check for Content-Security-Policy meta tag
    if not re.search(r"Content-Security-Policy", content, re.IGNORECASE):
        findings.append(Finding(
            category="Missing Security Header",
            severity=Severity.MEDIUM,
            message=f"HTML template missing Content-Security-Policy meta tag: {rel_path}",
            file_path=rel_path,
            remediation="Add a <meta http-equiv=\"Content-Security-Policy\" content=\"...\"> tag or configure CSP via HTTP headers. Define a strict policy that restricts script sources.",
        ))

    # Check for X-Frame-Options equivalent
    if not re.search(r"X-Frame-Options|frame-ancestor", content, re.IGNORECASE):
        findings.append(Finding(
            category="Missing Security Header",
            severity=Severity.LOW,
            message=f"HTML template missing X-Frame-Options or CSP frame-ancestor directive: {rel_path}",
            file_path=rel_path,
            remediation="Add <meta http-equiv=\"X-Frame-Options\" content=\"DENY\"> or use CSP frame-ancestor directive to prevent clickjacking.",
        ))

    return findings
