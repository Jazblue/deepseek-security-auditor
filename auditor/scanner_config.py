"""
Security Auditor - Unsafe Configuration Scanner Module
"""
import logging
import re
from pathlib import Path

from .config import UNSAFE_CONFIG_PATTERNS, Finding, Severity, find_secrets_in_line, fingerprint, is_in_comment_or_docstring, mask_line_content

logger = logging.getLogger("security_auditor.config_scan")

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml", ".json", ".env", ".toml", ".ini", ".cfg", ".conf"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}


def scan_unsafe_config(target_dir: Path) -> list[Finding]:
    """Scan for unsafe configuration settings and dangerous patterns."""
    findings: list[Finding] = []

    for filepath in target_dir.rglob("*"):
        if not filepath.is_file():
            continue
        if any(skip in filepath.parts for skip in SKIP_DIRS):
            continue
        if filepath.suffix not in SCAN_EXTENSIONS:
            continue

        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue

        is_python = filepath.suffix == ".py"
        rel_path = str(filepath.relative_to(target_dir))

        for pattern_name, (pattern, description) in UNSAFE_CONFIG_PATTERNS.items():
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                line_content = content.split("\n")[line_num - 1].strip()

                # Skip comments and docstrings in Python files
                if is_python and is_in_comment_or_docstring(content, line_num, match.start()):
                    continue

                # Skip if scanning the auditor's own config module
                if "auditor/config.py" in str(filepath) or "auditor/config_scan.py" in str(filepath):
                    continue

                severity = _config_severity(pattern_name)
                match_text = match.group(0)

                # Mask any credential value embedded in this match so the
                # secret never leaks through the unsafe-config scanner.
                masked_match = mask_line_content(match_text[:100])
                masked_snippet = mask_line_content(line_content[:200])

                # Attach the fingerprint of any secret on this line so the
                # orchestrator can deduplicate against the credential scanner.
                secrets = find_secrets_in_line(line_content)
                secret_fp = fingerprint(secrets[0][1]) if secrets else None

                findings.append(Finding(
                    category="Unsafe Configuration",
                    severity=severity,
                    message=f"{description}: {masked_match}",
                    file_path=rel_path,
                    line_number=line_num,
                    code_snippet=masked_snippet,
                    remediation=_config_remediation(pattern_name, description),
                    secret_fingerprint=secret_fp,
                ))

    return findings


def _config_severity(pattern_name: str) -> Severity:
    critical = {"eval_usage", "exec_usage", "pickle_usage"}
    high = {"debug_mode", "hardcoded_password", "sql_raw_query"}
    medium = {"insecure_random", "insecure_cookie"}

    if pattern_name in critical:
        return Severity.CRITICAL
    if pattern_name in high:
        return Severity.HIGH
    if pattern_name in medium:
        return Severity.MEDIUM
    return Severity.LOW


def _config_remediation(pattern_name: str, description: str) -> str:
    remediations = {
        "eval_usage": "Remove eval() calls immediately. Use ast.literal_eval() for parsing literals, or json.loads() for JSON data. eval() allows arbitrary code execution.",
        "exec_usage": "Remove exec() calls immediately. Refactor to use proper function calls, dispatch tables, or safe evaluation methods. exec() allows arbitrary code execution.",
        "pickle_usage": "Replace pickle with JSON or another safe serialization format. Pickle deserialization can execute arbitrary code and is a known attack vector.",
        "debug_mode": "Disable debug mode in production. Set DEBUG=False in production environment variables. Debug mode exposes stack traces and an interactive debugger.",
        "hardcoded_password": "Remove hardcoded passwords. Use environment variables, .env files (added to .gitignore), or a secrets manager.",
        "sql_raw_query": "Use parameterized queries or an ORM. Never interpolate user input into SQL strings. Use cursor.execute(sql, params) with placeholder syntax.",
        "insecure_random": "Use the 'secrets' module for cryptographic purposes instead of 'random'. The random module is not cryptographically secure.",
        "insecure_cookie": "Set HttpOnly, Secure, and SameSite attributes on all cookies. Use secure cookie configuration to prevent XSS and CSRF attacks.",
    }
    return remediations.get(pattern_name, f"Investigate and remediate: {description}")
