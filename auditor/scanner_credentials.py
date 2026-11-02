"""
Security Auditor - Credential Scanner Module
"""
import logging
import re
from pathlib import Path

from .config import (
    CREDENTIAL_PATTERNS,
    Finding,
    Severity,
    extract_secret,
    find_secrets_in_line,
    fingerprint,
    is_example_credential,
    is_in_comment_or_docstring,
    mask_line_content,
    mask_secret,
)

logger = logging.getLogger("security_auditor.credentials")

# Extensions to scan for credentials
CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".html", ".css"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "env"}


def _iter_target_files(target: Path):
    """Yield every scannable file under *target*.

    Supports both a single file path and a directory tree.  When *target* is a
    file it is yielded directly; when it is a directory, every file beneath it
    is yielded via ``rglob``.
    """
    if target.is_file():
        if target.suffix in CODE_EXTENSIONS:
            yield target
        return
    for filepath in target.rglob("*"):
        if not filepath.is_file():
            continue
        if any(skip in filepath.parts for skip in SKIP_DIRS):
            continue
        if filepath.suffix not in CODE_EXTENSIONS:
            continue
        yield filepath


def scan_credentials(target_dir: Path) -> list[Finding]:
    """Scan a directory tree (or a single file) for hardcoded credentials."""
    raw_findings: list[Finding] = []
    # Deduplicate on the *secret value* itself, so the same credential matched
    # by two different patterns (e.g. ``generic_secret`` + ``github_token``)
    # collapses to a single finding.
    seen_secrets: set[str] = set()

    for filepath in _iter_target_files(Path(target_dir)):
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue

        is_python = filepath.suffix == ".py"
        # Relative path is the file itself when scanning a single file
        try:
            rel_path = str(filepath.relative_to(target_dir))
        except ValueError:
            rel_path = str(filepath)

        # Run specific token patterns before generic secret patterns. Otherwise a
        # GitHub token is consumed by the generic ``token=`` rule and the more
        # useful GitHub-specific finding is lost during deduplication.
        pattern_items = sorted(
            CREDENTIAL_PATTERNS.items(),
            key=lambda item: item[0] == "generic_secret",
        )
        for pattern_name, (pattern, description) in pattern_items:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                line_content = content.split("\n")[line_num - 1].strip()

                # Skip comments and docstrings in Python files
                if is_python and is_in_comment_or_docstring(content, line_num, match.start()):
                    continue

                # Avoid matching the pattern definition itself
                if "CREDENTIAL_PATTERNS" in str(filepath) or "config.py" in str(filepath):
                    continue

                secret = extract_secret(match)
                if not secret:
                    continue

                # Deduplicate by secret value (normalised)
                fp = fingerprint(secret)
                if fp in seen_secrets:
                    continue
                seen_secrets.add(fp)

                # Determine if this is an example/test credential
                example = is_example_credential(secret)
                severity = Severity.CRITICAL if pattern_name in ("aws_access_key", "aws_secret_key", "private_key", "github_token") else Severity.HIGH
                if example:
                    severity = Severity.INFO

                # Mask the secret in the message
                masked = mask_secret(secret)
                message = f"{description} ({'example/test' if example else 'potential'}): {masked}"

                # Mask the secret in the code snippet via the central helper
                masked_snippet = mask_line_content(line_content[:200])

                raw_findings.append(Finding(
                    category="Hardcoded Credential",
                    severity=severity,
                    message=message,
                    file_path=rel_path,
                    line_number=line_num,
                    code_snippet=masked_snippet,
                    remediation=_credential_remediation(pattern_name),
                    secret_fingerprint=fp,
                ))

    return raw_findings


def _credential_remediation(pattern_name: str) -> str:
    remediations = {
        "aws_access_key": "Remove the AWS access key from source code. Use environment variables, AWS IAM roles, or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
        "aws_secret_key": "Remove the AWS secret key from source code. Rotate the compromised key immediately. Use environment variables or IAM roles instead.",
        "generic_api_key": "Remove the API key from source code. Store it in environment variables or a secure secrets manager. Rotate the exposed key.",
        "generic_secret": "Remove secrets from source code. Use a secrets manager or environment variables. Rotate any exposed credentials.",
        "private_key": "Remove private keys from source code immediately. Store keys in a hardware security module (HSM) or secure key vault. Rotate affected certificates.",
        "github_token": "Revoke the exposed GitHub token immediately. Use environment variables or a secrets manager. Enable token scoping to limit access.",
    }
    return remediations.get(pattern_name, "Remove credentials from source code and use a secure secrets management solution.")
