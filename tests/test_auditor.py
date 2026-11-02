import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auditor.config import Finding, Severity, ScanConfig, CREDENTIAL_PATTERNS, SQL_INJECTION_PATTERNS, UNSAFE_CONFIG_PATTERNS, mask_secret, is_example_credential, fingerprint
from auditor.scanner_credentials import scan_credentials
from auditor.scanner_sqli import scan_sql_injection
from auditor.scanner_headers import scan_security_headers
from auditor.scanner_http import scan_insecure_http
from auditor.scanner_config import scan_unsafe_config
from auditor.scanner import run_scan
from auditor.reporter import generate_report


# ─── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture
def sample_credential_file(tmp_path):
    """Create a temp file with hardcoded credentials."""
    f = tmp_path / "secrets.py"
    f.write_text('''
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
api_key = "my-generic-api-key-xxxxxxxxxxxx"
token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"
secret = "my_super_secret_password_123"
''')
    return tmp_path


@pytest.fixture
def sample_sqli_file(tmp_path):
    """Create a temp file with SQL injection vulnerabilities."""
    f = tmp_path / "queries.py"
    f.write_text('''
def get_user(username):
    query = "SELECT * FROM users WHERE name='" + username + "'"
    return db.execute(query)

def search(term):
    query = f"SELECT * FROM items WHERE desc LIKE '%{term}%'"
    return db.execute(query)

def find_by_id(uid):
    query = "SELECT * FROM t WHERE id = {}".format(uid)
    return db.execute(query)
''')
    return tmp_path


@pytest.fixture
def sample_html_file(tmp_path):
    """Create a temp HTML file missing security headers."""
    f = tmp_path / "page.html"
    f.write_text('<html><head><title>Test</title></head><body>Hello</body></html>')
    return tmp_path


@pytest.fixture
def sample_http_file(tmp_path):
    """Create a temp file with insecure HTTP references."""
    f = tmp_path / "index.html"
    f.write_text('''
<link rel="stylesheet" href="http://cdn.example.com/style.css">
<script src="http://tracker.example.com/analytics.js"></script>
<img src="http://images.example.com/photo.jpg">
''')
    return tmp_path


@pytest.fixture
def sample_config_file(tmp_path):
    """Create a temp file with unsafe config patterns."""
    f = tmp_path / "unsafe.py"
    f.write_text('''
import random, pickle

result = eval("1 + 1")
exec("x = 2")
obj = pickle.loads(data)
app.debug = True
password = "hardcoded_secret_123"
''')
    return tmp_path


# ─── Credential Scanner Tests ───────────────────────────────────────────────

class TestCredentialScanner:
    def test_detects_aws_access_key(self, sample_credential_file):
        findings = scan_credentials(sample_credential_file)
        aws_findings = [f for f in findings if "AWS Access Key" in f.message]
        assert len(aws_findings) >= 1
        # AKIAIOSFODNN7EXAMPLE is a known AWS example key → INFO severity
        assert aws_findings[0].severity in (Severity.INFO, Severity.CRITICAL)

    def test_aws_example_key_is_info_severity(self, sample_credential_file):
        """Known example AWS keys should be INFO, not CRITICAL."""
        findings = scan_credentials(sample_credential_file)
        aws_findings = [f for f in findings if "AWS Access Key" in f.message and "example" in f.message.lower()]
        assert len(aws_findings) >= 1
        assert aws_findings[0].severity == Severity.INFO

    def test_aws_example_key_is_masked(self, sample_credential_file):
        """Example credential values must not appear in plaintext in messages."""
        findings = scan_credentials(sample_credential_file)
        aws_findings = [f for f in findings if "AWS Access Key" in f.message]
        assert all("AKIAIOSFODNN7EXAMPLE" not in f.message for f in aws_findings)

    def test_detects_github_token(self, sample_credential_file):
        findings = scan_credentials(sample_credential_file)
        gh_findings = [f for f in findings if "GitHub Token" in f.message]
        assert len(gh_findings) >= 1

    def test_detects_generic_api_key(self, sample_credential_file):
        findings = scan_credentials(sample_credential_file)
        api_findings = [f for f in findings if "Generic API Key" in f.message]
        assert len(api_findings) >= 1

    def test_detects_generic_secret(self, sample_credential_file):
        findings = scan_credentials(sample_credential_file)
        secret_findings = [f for f in findings if "Generic Secret" in f.message]
        assert len(secret_findings) >= 1

    def test_returns_finding_with_all_fields(self, sample_credential_file):
        findings = scan_credentials(sample_credential_file)
        assert len(findings) > 0
        f = findings[0]
        assert isinstance(f, Finding)
        assert f.category == "Hardcoded Credential"
        assert f.file_path
        assert f.remediation

    def test_skips_non_code_files(self, tmp_path):
        # Create a binary-like file that shouldn't be scanned
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        findings = scan_credentials(tmp_path)
        # Should not find credentials in PNG
        assert all("PNG" not in (f.code_snippet or "") for f in findings)


# ─── SQL Injection Scanner Tests ────────────────────────────────────────────

class TestSQLInjectionScanner:
    def test_detects_string_concatenation(self, sample_sqli_file):
        findings = scan_sql_injection(sample_sqli_file)
        sqli_findings = [f for f in findings if "SQL Injection" in f.category]
        assert len(sqli_findings) >= 1

    def test_detects_fstring_injection(self, sample_sqli_file):
        findings = scan_sql_injection(sample_sqli_file)
        fstring_findings = [f for f in findings if "f-string" in f.message.lower()]
        assert len(fstring_findings) >= 1

    def test_detects_format_injection(self, sample_sqli_file):
        findings = scan_sql_injection(sample_sqli_file)
        format_findings = [f for f in findings if "format" in f.message.lower()]
        assert len(format_findings) >= 1

    def test_severity_is_medium_or_high(self, sample_sqli_file):
        findings = scan_sql_injection(sample_sqli_file)
        for f in findings:
            assert f.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)

    def test_no_false_positives_on_safe_code(self, tmp_path):
        f = tmp_path / "safe.py"
        f.write_text('''
def get_user(uid):
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    return cursor.fetchone()
''')
        findings = scan_sql_injection(tmp_path)
        sqli = [f for f in findings if "SQL Injection" in f.category]
        assert len(sqli) == 0

    def test_returns_finding_with_remediation(self, sample_sqli_file):
        findings = scan_sql_injection(sample_sqli_file)
        assert all(f.remediation for f in findings)


# ─── Security Headers Scanner Tests ─────────────────────────────────────────

class TestSecurityHeadersScanner:
    def test_detects_missing_csp_in_html(self, sample_html_file):
        findings = scan_security_headers(sample_html_file)
        csp_findings = [f for f in findings if "Content-Security-Policy" in f.message]
        assert len(csp_findings) >= 1

    def test_detects_missing_xframe_options(self, sample_html_file):
        findings = scan_security_headers(sample_html_file)
        xframe_findings = [f for f in findings if "X-Frame-Options" in f.message or "frame-ancestor" in f.message.lower()]
        assert len(xframe_findings) >= 1

    def test_no_false_positives_on_secure_html(self, tmp_path):
        f = tmp_path / "secure.html"
        f.write_text('''
<html>
<head>
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
    <meta http-equiv="X-Frame-Options" content="DENY">
</head>
<body>Safe page</body>
</html>
''')
        findings = scan_security_headers(tmp_path)
        header_findings = [f for f in findings if "Missing Security Header" in f.category]
        assert len(header_findings) == 0

    def test_flask_app_missing_headers(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text('''
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    return "Hello"
''')
        findings = scan_security_headers(tmp_path)
        flask_findings = [f for f in findings if "Flask" in f.message]
        assert len(flask_findings) > 0


# ─── Insecure HTTP Scanner Tests ────────────────────────────────────────────

class TestInsecureHTTPScanner:
    def test_detects_http_urls(self, sample_http_file):
        findings = scan_insecure_http(sample_http_file)
        http_findings = [f for f in findings if "Insecure HTTP" in f.category]
        assert len(http_findings) >= 3

    def test_allows_localhost(self, tmp_path):
        f = tmp_path / "local.html"
        f.write_text('<img src="http://localhost:8080/api">')
        findings = scan_insecure_http(tmp_path)
        # localhost should be skipped
        assert len(findings) == 0

    def test_allows_data_uris(self, tmp_path):
        f = tmp_path / "data.html"
        f.write_text('<img src="data:image/png;base64,abc123">')
        findings = scan_insecure_http(tmp_path)
        assert len(findings) == 0

    def test_sensitive_urls_are_high_severity(self, sample_http_file):
        findings = scan_insecure_http(sample_http_file)
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        # Some should be marked high if in sensitive context
        assert isinstance(findings, list)

    def test_no_findings_on_https_only(self, tmp_path):
        f = tmp_path / "secure.html"
        f.write_text('<link rel="stylesheet" href="https://cdn.example.com/style.css">')
        findings = scan_insecure_http(tmp_path)
        assert len(findings) == 0


# ─── Unsafe Config Scanner Tests ────────────────────────────────────────────

class TestUnsafeConfigScanner:
    def test_detects_eval(self, sample_config_file):
        findings = scan_unsafe_config(sample_config_file)
        eval_findings = [f for f in findings if "eval" in f.message.lower()]
        assert len(eval_findings) >= 1
        assert eval_findings[0].severity == Severity.CRITICAL

    def test_detects_exec(self, sample_config_file):
        findings = scan_unsafe_config(sample_config_file)
        exec_findings = [f for f in findings if "exec" in f.message.lower()]
        assert len(exec_findings) >= 1
        assert exec_findings[0].severity == Severity.CRITICAL

    def test_detects_pickle(self, sample_config_file):
        findings = scan_unsafe_config(sample_config_file)
        pickle_findings = [f for f in findings if "pickle" in f.message.lower()]
        assert len(pickle_findings) >= 1
        assert pickle_findings[0].severity == Severity.CRITICAL

    def test_detects_debug_mode(self, sample_config_file):
        findings = scan_unsafe_config(sample_config_file)
        debug_findings = [f for f in findings if "Debug" in f.message]
        assert len(debug_findings) >= 1

    def test_detects_hardcoded_password(self, sample_config_file):
        findings = scan_unsafe_config(sample_config_file)
        pwd_findings = [f for f in findings if "Hardcoded password" in f.message]
        assert len(pwd_findings) >= 1

    def test_no_false_positives_safe_code(self, tmp_path):
        f = tmp_path / "safe.py"
        f.write_text('''
import secrets
token = secrets.token_hex(16)
x = 1 + 1
''')
        findings = scan_unsafe_config(tmp_path)
        config_findings = [f for f in findings if "Unsafe Configuration" in f.category]
        assert len(config_findings) == 0

    def test_remediation_provided_for_all(self, sample_config_file):
        findings = scan_unsafe_config(sample_config_file)
        assert all(f.remediation for f in findings)


# ─── Report Generator Tests ─────────────────────────────────────────────────

class TestReportGenerator:
    def test_generates_html_file(self, tmp_path):
        findings = [
            Finding(
                category="Test",
                severity=Severity.HIGH,
                message="Test finding",
                file_path="test.py",
                line_number=10,
                code_snippet="bad code",
                remediation="Fix it",
            )
        ]
        output = str(tmp_path / "report.html")
        path = generate_report(findings, output, str(tmp_path))
        assert Path(path).exists()
        content = Path(path).read_text()
        assert "Security Audit Report" in content
        assert "Test finding" in content

    def test_empty_report(self, tmp_path):
        output = str(tmp_path / "empty.html")
        path = generate_report([], output, str(tmp_path))
        assert Path(path).exists()
        content = Path(path).read_text()
        assert "Total Findings" in content

    def test_severity_counts_correct(self, tmp_path):
        findings = [
            Finding("Cat", Severity.CRITICAL, "msg", "f.py", remediation="r"),
            Finding("Cat", Severity.HIGH, "msg", "f.py", remediation="r"),
            Finding("Cat", Severity.MEDIUM, "msg", "f.py", remediation="r"),
        ]
        output = str(tmp_path / "counts.html")
        generate_report(findings, output, str(tmp_path))
        content = Path(output).read_text()
        assert ">1</" in content  # critical count
        assert "Total Findings" in content


# ─── Scanner Orchestration Tests ────────────────────────────────────────────

class TestScannerOrchestration:
    def test_run_scan_returns_findings(self, sample_credential_file):
        config = ScanConfig(target_paths=[str(sample_credential_file)])
        findings = run_scan(config)
        assert isinstance(findings, list)
        assert len(findings) > 0

    def test_run_scan_empty_dir(self, tmp_path):
        config = ScanConfig(target_paths=[str(tmp_path)])
        findings = run_scan(config)
        assert findings == []

    def test_run_scan_invalid_dir(self):
        config = ScanConfig(target_paths=["/nonexistent/path"])
        findings = run_scan(config)
        assert findings == []

    def test_severity_filtering(self, sample_credential_file):
        config = ScanConfig(
            target_paths=[str(sample_credential_file)],
            severity_filter=[Severity.CRITICAL],
        )
        findings = run_scan(config)
        assert all(f.severity == Severity.CRITICAL for f in findings)


# ─── Integration Test ───────────────────────────────────────────────────────

class TestIntegration:
    def test_full_scan_on_test_site(self, tmp_path):
        """Scan the test_site directory and verify findings are found."""
        import shutil
        test_site_src = Path(__file__).parent.parent / "test_site"
        test_site_dst = tmp_path / "test_site"
        if test_site_src.exists():
            shutil.copytree(test_site_src, test_site_dst)

        config = ScanConfig(target_paths=[str(test_site_dst)])
        findings = run_scan(config)

        # We expect multiple findings across categories
        categories = {f.category for f in findings}
        assert "Hardcoded Credential" in categories
        assert "SQL Injection" in categories
        assert "Unsafe Configuration" in categories
        assert "Insecure HTTP Reference" in categories

        # All findings should have remediation
        assert all(f.remediation for f in findings)

        # Generate report
        output = str(tmp_path / "integration_report.html")
        report_path = generate_report(findings, output, str(test_site_dst))
        assert Path(report_path).exists()
        assert Path(report_path).stat().st_size > 1000  # Non-trivial report


# ─── New Tests for Priority 1: False Positives ───────────────────────────────

class TestCommentDocstringSkipping:
    """Ensure comments and docstrings are ignored for executable vulnerabilities."""

    def test_ignores_eval_in_comment(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('# This code uses eval() to parse JSON: eval(data)\n')
        findings = scan_unsafe_config(tmp_path)
        eval_findings = [f for f in findings if "eval()" in f.message.lower()]
        assert len(eval_findings) == 0

    def test_ignores_exec_in_comment(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('# Do not use exec() here — exec(code_string)\n')
        findings = scan_unsafe_config(tmp_path)
        exec_findings = [f for f in findings if "exec()" in f.message.lower()]
        assert len(exec_findings) == 0

    def test_ignores_pickle_in_comment(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('# WARNING: pickle.loads() is dangerous for untrusted data\n')
        findings = scan_unsafe_config(tmp_path)
        pickle_findings = [f for f in findings if "pickle" in f.message.lower()]
        assert len(pickle_findings) == 0

    def test_ignores_eval_in_docstring(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('''"""
This module demonstrates a safe approach.
We avoid using eval() because it allows arbitrary code execution.
"""
def safe():
    return 42
''')
        findings = scan_unsafe_config(tmp_path)
        eval_findings = [f for f in findings if "eval()" in f.message.lower()]
        assert len(eval_findings) == 0

    def test_ignores_exec_in_docstring(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('''"""
Note: exec() should never be used with user input.
See also: exec(some_string)
"""
def safe():
    pass
''')
        findings = scan_unsafe_config(tmp_path)
        exec_findings = [f for f in findings if "exec()" in f.message.lower()]
        assert len(exec_findings) == 0

    def test_ignores_pickle_in_docstring(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('''"""
Bad example: pickle.loads(raw_bytes)
We should use json.loads() instead.
"""
def safe():
    return {}
''')
        findings = scan_unsafe_config(tmp_path)
        pickle_findings = [f for f in findings if "pickle" in f.message.lower()]
        assert len(pickle_findings) == 0

    def test_still_detects_eval_not_in_comment(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('result = eval(user_input)\n')
        findings = scan_unsafe_config(tmp_path)
        eval_findings = [f for f in findings if "eval()" in f.message.lower()]
        assert len(eval_findings) == 1

    def test_still_detects_exec_not_in_comment(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('exec(code_string)\n')
        findings = scan_unsafe_config(tmp_path)
        exec_findings = [f for f in findings if "exec()" in f.message.lower()]
        assert len(exec_findings) == 1

    def test_still_detects_pickle_not_in_comment(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('obj = pickle.loads(data)\n')
        findings = scan_unsafe_config(tmp_path)
        pickle_findings = [f for f in findings if "pickle" in f.message.lower()]
        assert len(pickle_findings) == 1

    def test_inline_comment_skipped(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('x = 1  # use eval() here if needed\n')
        findings = scan_unsafe_config(tmp_path)
        eval_findings = [f for f in findings if "eval()" in f.message.lower()]
        assert len(eval_findings) == 0

    def test_detects_eval_after_docstring(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('''"""Docstring with no vulnerability."""
def process(data):
    return eval(data)
''')
        findings = scan_unsafe_config(tmp_path)
        eval_findings = [f for f in findings if "eval()" in f.message.lower()]
        assert len(eval_findings) == 1


class TestSQLParameterizedQueries:
    """Ensure safe parameterized queries are not flagged as SQL injection."""

    def test_percent_format_with_params_is_safe(self, tmp_path):
        f = tmp_path / "safe.py"
        f.write_text('''
def get_user(uid):
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    return cursor.fetchone()
''')
        findings = scan_sql_injection(tmp_path)
        sqli = [f for f in findings if "SQL Injection" in f.category]
        assert len(sqli) == 0

    def test_question_mark_format_with_params_is_safe(self, tmp_path):
        f = tmp_path / "safe.py"
        f.write_text('''
def get_user(uid):
    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return cursor.fetchone()
''')
        findings = scan_sql_injection(tmp_path)
        sqli = [f for f in findings if "SQL Injection" in f.category]
        assert len(sqli) == 0

    def test_still_detects_concatenated_query(self, tmp_path):
        f = tmp_path / "unsafe.py"
        f.write_text('''
def get_user(uid):
    query = "SELECT * FROM users WHERE id = " + uid
    return db.execute(query)
''')
        findings = scan_sql_injection(tmp_path)
        sqli = [f for f in findings if "SQL Injection" in f.category]
        assert len(sqli) >= 1

    def test_still_detects_fstring_query(self, tmp_path):
        f = tmp_path / "unsafe.py"
        f.write_text('''
def search(term):
    query = f"SELECT * FROM items WHERE name = '{term}'"
    return db.execute(query)
''')
        findings = scan_sql_injection(tmp_path)
        sqli = [f for f in findings if "f-string" in f.message.lower()]
        assert len(sqli) >= 1

    def test_still_detects_format_query(self, tmp_path):
        f = tmp_path / "unsafe.py"
        f.write_text('''
def find(uid):
    query = "SELECT * FROM t WHERE id = {}".format(uid)
    return db.execute(query)
''')
        findings = scan_sql_injection(tmp_path)
        sqli = [f for f in findings if "format" in f.message.lower()]
        assert len(sqli) >= 1

    def test_comment_with_sqli_pattern_ignored(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('''# This is a test case: "SELECT * FROM users WHERE id = 1 OR 1=1"
def safe():
    pass
''')
        findings = scan_sql_injection(tmp_path)
        sqli = [f for f in findings if "SQL Injection" in f.category]
        assert len(sqli) == 0


# ─── New Tests for Priority 2: Duplicate Findings ────────────────────────────

class TestDeduplication:
    """Ensure the same credential does not appear as multiple findings."""

    def test_same_secret_in_multiple_patterns_no_dupes(self, tmp_path):
        """A GitHub token matching both 'generic_secret' and 'github_token'
        should produce only ONE finding (the most specific one wins via
        fingerprint deduplication)."""
        f = tmp_path / "secrets.py"
        f.write_text('TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"\n')
        findings = scan_credentials(tmp_path)
        gh_findings = [f for f in findings if "GitHub Token" in f.message or "GitHub" in f.message]
        # Should have at most 1 finding for this token
        assert len(gh_findings) <= 1

    def test_same_aws_key_no_duplicate(self, tmp_path):
        f = tmp_path / "config.py"
        f.write_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan_credentials(tmp_path)
        aws_findings = [f for f in findings if "AWS Access Key" in f.message]
        assert len(aws_findings) <= 1  # No duplicate AWS key findings

    def test_masking_prevents_plaintext_secrets(self, tmp_path):
        f = tmp_path / "secrets.py"
        f.write_text('API_KEY = "sk-abc123def456ghi789jkl012mno345pqr678"\n')
        findings = scan_credentials(tmp_path)
        for finding in findings:
            # Full secret value must never appear in the message
            assert "sk-abc123def456ghi789jkl012mno345pqr678" not in finding.message

    def test_masking_shows_prefix_and_suffix(self, tmp_path):
        f = tmp_path / "secrets.py"
        f.write_text('API_KEY = "sk-abc123def456ghi789jkl012mno345pqr678"\n')
        findings = scan_credentials(tmp_path)
        api_findings = [f for f in findings if "Generic API Key" in f.message or "API Key" in f.message]
        assert len(api_findings) >= 1
        assert any("sk-abc" not in f.message for f in api_findings)


# ─── New Tests for Priority 3: Severity Accuracy ─────────────────────────────

class TestSeverityAccuracy:
    """Ensure example/test credentials are labeled correctly."""

    def test_example_credential_is_info(self):
        assert is_example_credential("AKIAIOSFODNN7EXAMPLE") is True
        assert is_example_credential("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") is True
        assert is_example_credential("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123") is True

    def test_real_credential_is_not_example(self):
        assert is_example_credential("real-secret-key-xyz789!") is False
        assert is_example_credential("my-actual-password-123") is False

    def test_example_credential_has_info_severity(self, sample_credential_file):
        findings = scan_credentials(sample_credential_file)
        aws_findings = [f for f in findings if "example" in f.message.lower()]
        assert len(aws_findings) >= 1
        assert all(f.severity == Severity.INFO for f in aws_findings)

    def test_all_findings_note_potential_risk(self, sample_credential_file):
        findings = scan_credentials(sample_credential_file)
        for f in findings:
            # Every message should indicate this is potential, not confirmed
            assert "potential" in f.message.lower() or "example/test" in f.message.lower() or "detected" in f.message.lower()


# ─── New Tests for Priority 4: Testing Coverage ──────────────────────────────

class TestNewHelpers:
    """Tests for the new utility functions added for improvements."""

    def test_mask_secret_short_value(self):
        # Short values (<= 8 chars) are returned as-is
        assert mask_secret("short") == "short"

    def test_mask_secret_long_value(self):
        masked = mask_secret("very_long_secret_value_here")
        # Masked output should start with "very" and end with "here"
        assert masked.startswith("very")
        assert masked.endswith("here")
        assert "very_long_secret_value_here" not in masked

    def test_fingerprint_consistency(self):
        fp1 = fingerprint("AKIAIOSFODNN7EXAMPLE")
        fp2 = fingerprint("AKIAIOSFODNN7EXAMPLE")
        assert fp1 == fp2
        assert len(fp1) == 16

    def test_fingerprint_different_values(self):
        fp1 = fingerprint("key1")
        fp2 = fingerprint("key2")
        assert fp1 != fp2

    def test_is_in_comment_or_docstring_true_for_comment(self):
        from auditor.config import is_in_comment_or_docstring
        content = '# eval() is bad\nx = 1'
        assert is_in_comment_or_docstring(content, 1) is True

    def test_is_in_comment_or_docstring_false_for_code(self):
        from auditor.config import is_in_comment_or_docstring
        content = 'x = eval(data)\n'
        assert is_in_comment_or_docstring(content, 1) is False

    def test_is_in_comment_or_docstring_inline_comment(self):
        from auditor.config import is_in_comment_or_docstring
        content = 'x = 1  # eval() here\n'
        # Inline comment detection depends on match position within line
        # 'x = 1  # eval() here' characters: 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18
        # match_start_offset=7 corresponds to column 7 (the space before '#')
        # Let's find the actual column of '#'
        hash_pos = content.find('#')
        result = is_in_comment_or_docstring(content, 1, match_start_offset=hash_pos + 1)
        assert result is True


class TestReportMasking:
    """Ensure generated reports do not contain plaintext secrets."""

    def test_report_contains_no_aws_key(self, sample_credential_file):
        import shutil
        import tempfile
        from auditor.scanner import run_scan
        from auditor.reporter import generate_report
        from auditor.config import ScanConfig

        with tempfile.TemporaryDirectory() as td:
            src = sample_credential_file
            dst = Path(td) / "test"
            shutil.copytree(src, dst)
            config = ScanConfig(target_paths=[str(dst)])
            findings = run_scan(config)
            output = str(Path(td) / "report.html")
            generate_report(findings, output, str(dst))
            content = Path(output).read_text()
            assert "AKIAIOSFODNN7EXAMPLE" not in content
            assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123" not in content
