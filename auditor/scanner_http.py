"""
Security Auditor - Insecure HTTP Scanner Module
"""
import logging
import re
from pathlib import Path

from .config import Finding, Severity

logger = logging.getLogger("security_auditor.http")

SCAN_EXTENSIONS = {".html", ".htm", ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".env", ".yaml", ".yml", ".xml", ".css", ".j2", ".jinja"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}


def scan_insecure_http(target_dir: Path) -> list[Finding]:
    """Scan for insecure HTTP (non-HTTPS) references."""
    findings: list[Finding] = []
    http_pattern = re.compile(r'http://[^\s\'"<>\)]+', re.IGNORECASE)

    for filepath in target_dir.rglob("*"):
        if not filepath.is_file():
            continue
        if any(skip in filepath.parts for skip in SKIP_DIRS):
            continue
        if filepath.suffix not in SCAN_EXTENSIONS:
            continue

        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for match in http_pattern.finditer(content):
            url = match.group(0)
            # Skip localhost/internal addresses and data URIs
            if re.match(r'http://(localhost|127\.0\.0\.1|0\.0\.0\.0)', url, re.IGNORECASE):
                continue
            if url.startswith("data:"):
                continue

            line_num = content[:match.start()].count("\n") + 1
            line_content = content.split("\n")[line_num - 1].strip()
            rel_path = str(filepath.relative_to(target_dir))

            severity = Severity.HIGH if _is_sensitive_context(url, line_content) else Severity.MEDIUM
            findings.append(Finding(
                category="Insecure HTTP Reference",
                severity=severity,
                message=f"Insecure HTTP URL detected: {url[:120]}",
                file_path=rel_path,
                line_number=line_num,
                code_snippet=line_content[:200],
                remediation="Replace http:// with https:// to ensure encrypted communication. If the upstream service does not support HTTPS, investigate and enable TLS. For local development, consider using http:// only if the traffic is not sensitive.",
            ))

    return findings


def _is_sensitive_context(url: str, line: str) -> bool:
    """Determine if the HTTP reference is in a sensitive context."""
    sensitive_keywords = [
        "password", "login", "auth", "token", "session", "cookie",
        "payment", "credit", "card", "secret", "api_key", "apikey",
        "user", "profile", "account", "email", "phone",
    ]
    line_lower = line.lower()
    return any(kw in line_lower for kw in sensitive_keywords)
