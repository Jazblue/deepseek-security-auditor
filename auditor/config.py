"""
Security Auditor - Configuration Module
"""
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a single security finding."""
    category: str
    severity: Severity
    message: str
    file_path: str
    line_number: int | None = None
    code_snippet: str | None = None
    remediation: str = ""
    # Optional fingerprint of the underlying secret, used for cross-scanner
    # deduplication.  ``None`` means the finding does not reference a secret.
    secret_fingerprint: str | None = None

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity.value,
            "message": self.message,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
            "secret_fingerprint": self.secret_fingerprint,
        }


@dataclass
class ScanConfig:
    """Configuration for the security scanner."""
    target_paths: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=lambda: [".git", "__pycache__", ".pyc"])
    severity_filter: List[Severity] = field(default_factory=lambda: [s for s in Severity])
    output_format: str = "html"
    output_path: str = "security_report.html"

    @classmethod
    def default(cls, target_dir: str) -> "ScanConfig":
        return cls(
            target_paths=[target_dir],
            severity_filter=[s for s in Severity],
            output_path=os.path.join(target_dir, "security_report.html"),
        )


# Known example/test credential patterns (not real secrets)
EXAMPLE_CREDENTIALS: set[str] = {
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123",
    "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
}


def is_example_credential(value: str) -> bool:
    """Return True if the value matches a known example/test credential."""
    for example in EXAMPLE_CREDENTIALS:
        if example in value:
            return True
    return False


def mask_secret(value: str, visible_chars: int = 4) -> str:
    """Mask a secret value, showing only the first and last `visible_chars` characters."""
    value = value.strip().strip("\"'")
    if len(value) <= visible_chars * 2:
        return value[:visible_chars] + "***" + value[-visible_chars:] if len(value) > visible_chars * 2 else value
    return value[:visible_chars] + "…" + "*" * 8 + value[-visible_chars:]


def fingerprint(secret_match: str) -> str:
    """Create a normalized fingerprint of a credential match for deduplication."""
    import hashlib
    return hashlib.sha256(secret_match.strip().lower().encode()).hexdigest()[:16]


def extract_secret(match: re.Match) -> str:
    """Return the captured secret value from a credential regex match.

    Falls back to the whole match text when the pattern has no capture group.
    """
    try:
        return match.group(1)
    except IndexError:
        return match.group(0)


def mask_line_content(line: str) -> str:
    """Mask every credential value that appears on *line*.

    This is the single masking entry point used by every scanner and by the
    reporter, so a secret can never leak through one path while another
    masks it.  The original line is returned unchanged when it contains no
    recognisable credential.
    """
    if not line:
        return line
    masked = line
    for pattern_name, (pattern, _description) in CREDENTIAL_PATTERNS.items():
        for match in re.finditer(pattern, masked, re.IGNORECASE):
            secret = extract_secret(match)
            if secret and secret in masked:
                masked = masked.replace(secret, mask_secret(secret))
    return masked


def find_secrets_in_line(line: str) -> list[tuple[str, str]]:
    """Return ``(pattern_name, secret_value)`` for every credential on *line*."""
    found: list[tuple[str, str]] = []
    if not line:
        return found
    for pattern_name, (pattern, _description) in CREDENTIAL_PATTERNS.items():
        for match in re.finditer(pattern, line, re.IGNORECASE):
            secret = extract_secret(match)
            if secret:
                found.append((pattern_name, secret))
    return found


# Regex patterns for credential detection
#
# Every pattern captures the *secret value* in group(1).  The key-name prefix
# is matched with an alternation that tolerates both ``KEY`` and ``KEY_ID``
# (and the reverse order), and the separator may be ``:``, ``=`` or whitespace
# *following* an optional closing quote, so quoted dictionary keys such as
# ``"api_key": "value"`` or ``{"password": "value"}`` are detected.
CREDENTIAL_PATTERNS: dict[str, tuple] = {
    "aws_access_key": (
        r"""(?:AWS|aws)_?(?:ACCESS|access)?_?(?:KEY|key|KEY_ID|key_id|ID|id)?['\"]?\s*[:=]\s*['\"]?([A-Z0-9]{20})['\"]?""",
        "AWS Access Key ID",
    ),
    "aws_secret_key": (
        r"""(?:AWS|aws)_?(?:SECRET|secret)(?:_?(?:ACCESS|access)?_?(?:KEY|key))?['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?""",
        "AWS Secret Access Key",
    ),
    "generic_api_key": (
        r"""(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?""",
        "Generic API Key",
    ),
    "generic_secret": (
        r"""(?i)(?:secret|password|passwd|pwd|token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-!@#$%^&*]{8,})['\"]?""",
        "Generic Secret/Password",
    ),
    "private_key": (
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "Private Key Detected",
    ),
    "github_token": (
        r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
        "GitHub Token",
    ),
}

# SQL injection patterns
SQL_INJECTION_PATTERNS: list[tuple] = [
    (
        r"""['\"].*(?:OR|AND)\s+\d+\s*=\s*\d+""",
        "Classic SQL injection tautology (OR 1=1)",
    ),
    (
        r"""['\"].*\bUNION\s+(?:ALL\s+)?SELECT\b""",
        "UNION-based SQL injection",
    ),
    (
        r"""\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*\b(?:INTO|FROM|SET|WHERE)\b.*\+""",
        "String concatenation in SQL query",
    ),
    (
        r"""f['\"].*(?:SELECT|INSERT|UPDATE|DELETE).*\{""",
        "f-string used in SQL query construction",
    ),
    (
        r""""\s*%\s*[sdr]\s*%""",
        "Old-style Python string formatting in SQL context",
    ),
    (
        r"""(?:SELECT|INSERT|UPDATE|DELETE)\b[^)]*\.\s*format\s*\(""",
        "str.format() used in SQL query construction",
    ),
    (
        r"""\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*\b(?:INTO|FROM|SET|WHERE)\b.*%['\"]""",
        "Old-style % formatting in SQL query",
    ),
    (
        r"""(?:execute|cursor\.execute|fetchall|commit)\s*\(\s*f['\"]""",
        "Direct execution with f-string SQL",
    ),
]

# Insecure HTTP patterns
INSECURE_HTTP_PATTERNS: list[tuple] = [
    (r"https?://[^'\"]+", "HTTP URL reference"),
]

# Missing security headers (checked in HTML responses)
SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

# Unsafe configuration patterns
UNSAFE_CONFIG_PATTERNS: dict[str, tuple] = {
    "debug_mode": (
        r"""(?:app\.run|DEBUG\s*=|debug\s*=)\s*(?:True|true|True)""",
        "Debug mode enabled",
    ),
    "insecure_random": (
        r"\b(?:random\.(randint|choice|random|randrange)|uuid\.uuid[1-4])\b",
        "Use of non-cryptographic random",
    ),
    "eval_usage": (
        r"\beval\s*\(",
        "Use of eval()",
    ),
    "exec_usage": (
        r"\bexec\s*\(",
        "Use of exec()",
    ),
    "pickle_usage": (
        r"\b(?:pickle\.load|pickle\.loads|cPickle\.loads?)\s*\(",
        "Unsafe deserialization with pickle",
    ),
    "sql_raw_query": (
        r"""(?:execute|cursor\.execute)\s*\(\s*(?:\"|'|%)""",
        "Raw SQL query execution",
    ),
    "hardcoded_password": (
        r"""(?i)(?:password|passwd|pwd|secret)\s*[=:]\s*['"]([^'\"]{4,})['"]""",
        "Hardcoded password in source code",
    ),
    "insecure_cookie": (
        r"""(?:set_cookie|cookie\[)\s*.*?(?:httponly|secure|samesite)\s*=\s*False""",
        "Insecure cookie configuration",
    ),
}

def is_in_comment_or_docstring(content: str, line_num: int, match_start_offset: int = 0) -> bool:
    """Return True when the match at *line_num* (1-based) falls inside a
    comment or a triple-quoted docstring.

    *match_start_offset* – character offset of the regex match within the
    file (used for docstring detection).
    """
    lines = content.split("\n")
    if line_num < 1 or line_num > len(lines):
        return False

    line = lines[line_num - 1]
    stripped = line.strip()

    # Pure comment line
    if stripped.startswith("#"):
        return True

    # Inline comment heuristic: if there is a ``#`` before the match on the
    # same line and the character immediately before ``#`` is whitespace,
    # treat the rest of the line as a comment.
    if match_start_offset >= 0:
        # Find the line start relative to the match offset
        line_start = 0
        for i in range(len(content[:match_start_offset])):
            if content[i] == '\n':
                line_start = i + 1
        col_offset = match_start_offset - line_start
        prefix_on_line = line[:col_offset]
        hash_pos = prefix_on_line.rfind("#")
        if hash_pos >= 0 and (hash_pos == 0 or prefix_on_line[hash_pos - 1] in (" ", "\t")):
            return True

    # Triple-quoted docstring detection
    if is_in_python_docstring(content, match_start_offset):
        return True

    return False


def is_in_python_docstring(content: str, match_start: int) -> bool:
    """Return True when *match_start* lies inside a triple-quoted string."""
    triple_single = content[:match_start].count("'''") + content[:match_start].count('"""')
    return (triple_single % 2) == 1


# Logging configuration
def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure and return the application logger."""
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logger = logging.getLogger("security_auditor")
    logger.setLevel(level)
    if logger.handlers:
        logger.handlers.clear()
    logger.addHandler(handler)
    return logger
