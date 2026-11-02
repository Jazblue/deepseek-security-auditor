"""
Security Auditor - SQL Injection Scanner Module
"""
import logging
import re
from pathlib import Path

from .config import SQL_INJECTION_PATTERNS, Finding, Severity, is_in_comment_or_docstring

logger = logging.getLogger("security_auditor.sqli")

CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".sql", ".php", ".rb", ".java", ".c", ".cpp", ".go"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "env"}

# Patterns that indicate a safe parameterized query (should suppress warnings)
SAFE_PARAM_PATTERNS = [
    # cursor.execute("SELECT ... %s", (param,)) — positional params
    r"""execute\s*\(\s*["'][^"']*%\s*["']\s*,\s*[\(]""",
    # cursor.execute("SELECT ... ?", (param,)) — positional params
    r"""execute\s*\(\s*["'][^"']*\?\s*["']\s*,\s*[\(]""",
    # .format() with only positional/numbered placeholders like {0}, {1}
    r"""\.format\s*\(\s*[\w\d_]+\s*(?:,\s*[\w\d_]+)*\s*\)""",
]


def _is_safe_parameterized_query(line: str) -> bool:
    """Heuristic: return True when the line appears to use parameterized queries."""
    line_lower = line.lower()
    # Must contain a database execution call
    has_execute = "execute" in line_lower or "cursor." in line_lower
    if not has_execute:
        return False
    # Contains %s or ? placeholder with a tuple — safe
    if re.search(r'%s\s*[\"\'\)]\s*,\s*\(', line):
        return True
    if re.search(r'\?\s*[\"\'\)]\s*,\s*\(', line):
        return True
    return False


def scan_sql_injection(target_dir: Path) -> list[Finding]:
    """Scan source code for potential SQL injection vulnerabilities."""
    findings: list[Finding] = []

    for filepath in target_dir.rglob("*"):
        if not filepath.is_file():
            continue
        if any(skip in filepath.parts for skip in SKIP_DIRS):
            continue
        if filepath.suffix not in CODE_EXTENSIONS:
            continue

        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue

        is_python = filepath.suffix == ".py"
        rel_path = str(filepath.relative_to(target_dir))

        for pattern, description in SQL_INJECTION_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                line_content = content.split("\n")[line_num - 1].strip()

                # Skip comments and docstrings in Python files
                if is_python and is_in_comment_or_docstring(content, line_num, match.start()):
                    continue

                # Skip safe parameterized queries
                if _is_safe_parameterized_query(line_content):
                    continue

                severity = Severity.HIGH if "UNION" in match.group(0).upper() else Severity.MEDIUM
                findings.append(Finding(
                    category="SQL Injection",
                    severity=severity,
                    message=f"{description} at line {line_num}: {match.group(0)[:100]}",
                    file_path=rel_path,
                    line_number=line_num,
                    code_snippet=line_content[:200],
                    remediation=_sqli_remediation(description),
                ))

    return findings


def _sqli_remediation(description: str) -> str:
    if "UNION" in description.upper():
        return "Use parameterized queries or prepared statements. Never concatenate user input into SQL. Employ an ORM like SQLAlchemy with parameterized queries."
    if "f-string" in description.lower() or "string concatenation" in description.lower():
        return "Replace string formatting/concatenation with parameterized queries. Use ORM query builders or prepared statements with bound parameters."
    if "format" in description.lower():
        return "Replace str.format() with parameterized queries. Use positional or named parameters provided by your database driver."
    if "%" in description:
        return "Replace % formatting with parameterized queries. Use the database driver's placeholder syntax (e.g., %s for psycopg2, ? for sqlite3)."
    if "tautology" in description.lower() or "1=1" in description.lower():
        return "Never allow user input in SQL conditions. Use parameterized queries and input validation. Implement WAF rules to block common injection patterns."
    if "raw SQL" in description.lower():
        return "Avoid raw SQL execution. Use parameterized queries, ORM models, or stored procedures with input validation."
    return "Use parameterized queries or prepared statements. Validate and sanitize all user input. Implement an ORM layer where possible."
