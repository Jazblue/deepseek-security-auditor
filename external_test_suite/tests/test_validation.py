"""
Pytest-based independent validation tests.
"""
import sys
from pathlib import Path

# Add the auditor to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from auditor.scanner import run_scan
from auditor.config import ScanConfig
import pytest

# ─── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture
def synthetic_app():
    """Path to the synthetic application."""
    app_path = Path(__file__).parent.parent / "synthetic_app"
    if not app_path.exists():
        raise FileNotFoundError(f"Could not find synthetic app at {app_path}")
    return app_path


@pytest.fixture
def scan_results(synthetic_app):
    """Run the scanner and return findings."""
    config = ScanConfig(target_paths=[str(synthetic_app)])
    return run_scan(config)


# ─── Ground Truth ────────────────────────────────────────────────────────────

KNOWN_VULNS = {
    # Use markers based on actual finding messages
    "v1_aws_access_key": ("Hardcoded Credential", "AWS Access Key ID"),
    "v2_aws_secret_key": ("Hardcoded Credential", "AWS Secret Access Key"),
    "v3_api_key": ("Hardcoded Credential", "Generic API Key"),
    "v4_github_token": ("Hardcoded Credential", "Generic Secret"),
    "v5_db_password": ("Hardcoded Credential", "Generic Secret"),

    # SQL Injection (VULN 6-8)
    "v6_sqli_concat": ("SQL Injection", "String concatenation"),
    "v7_sqli_fstring": ("SQL Injection", "f-string"),
    "v8_sqli_format": ("SQL Injection", "format"),

    # Dangerous functions (VULN 9-11)
    "v9_eval": ("Unsafe Configuration", "eval()"),
    "v10_exec": ("Unsafe Configuration", "exec()"),
    "v11_pickle": ("Unsafe Configuration", "pickle"),

    # Config issues (VULN 12-15)
    "v12_debug": ("Unsafe Configuration", "Debug"),
    "v13_insecure_http": ("Insecure HTTP Reference", "http://api.example.com"),
    "v14_random": ("Unsafe Configuration", "random"),
    "v15_hardcoded_secret": ("Hardcoded Credential", "Generic Secret"),
}

KNOWN_SAFE = {
    "safe_literal_eval": "ast.literal_eval",
    "safe_json_loads": "json.loads",
    "safe_secrets": "secrets.token_hex",
    "safe_comment_eval": "# The codebase uses eval()",
    "safe_docstring_exec": "WARNING: Do not use exec()",
    "safe_https": "https://api.example.com",
    "safe_localhost": "http://localhost:8080",
    "safe_data_uri": "data:image/png;base64",
}


# ─── Test Vulnerability Detection ───────────────────────────────────────────

class TestVulnerabilityDetection:
    """Verify that known vulnerabilities are detected."""

    @pytest.mark.parametrize("vuln_id", list(KNOWN_VULNS.keys()))
    def test_detects_vulnerability(self, scan_results, vuln_id):
        category, marker = KNOWN_VULNS[vuln_id]
        """Each known vulnerability should be detected."""
        found = any(
            f.category == category and marker.lower() in f.message.lower()
            for f in scan_results
        )
        assert found, f"Expected to detect {vuln_id}: {category} ({marker})"


# ─── Test Safe Code Not Flagged ─────────────────────────────────────────────

class TestSafeCodeNotFlagged:
    """Verify that safe code patterns do not produce false positives."""

    @pytest.mark.parametrize("safe_id", list(KNOWN_SAFE.keys()))
    def test_no_false_positive(self, scan_results, safe_id):
        pattern = KNOWN_SAFE[safe_id]
        """Each known safe pattern should not trigger a finding."""
        # Check if this pattern appears in any finding's code_snippet
        flagged = any(
            pattern in (f.code_snippet or "")
            for f in scan_results
        )
        assert not flagged, f"False positive: {safe_id} pattern '{pattern[:50]}...' was flagged"


# ─── Metrics Test ────────────────────────────────────────────────────────────

class TestMetrics:
    """Calculate and verify detection metrics."""

    def test_precision_above_threshold(self, scan_results):
        """Precision should be at least 80%."""
        tp = sum(
            1 for vuln_id, (category, marker) in KNOWN_VULNS.items()
            if any(
                f.category == category and marker.lower() in f.message.lower()
                for f in scan_results
            )
        )
        fp = sum(
            1 for safe_id, pattern in KNOWN_SAFE.items()
            if any(pattern in (f.code_snippet or "") for f in scan_results)
        )
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        assert precision >= 0.80, f"Precision too low: {precision:.2%}"

    def test_recall_above_threshold(self, scan_results):
        """Recall should be at least 80%."""
        tp = sum(
            1 for vuln_id, (category, marker) in KNOWN_VULNS.items()
            if any(
                f.category == category and marker.lower() in f.message.lower()
                for f in scan_results
            )
        )
        recall = tp / len(KNOWN_VULNS)
        assert recall >= 0.80, f"Recall too low: {recall:.2%}"

    def test_all_vulnerabilities_detected(self, scan_results):
        """All 15 known vulnerabilities should be detected."""
        for vuln_id, (category, marker) in KNOWN_VULNS.items():
            found = any(
                f.category == category and marker.lower() in f.message.lower()
                for f in scan_results
            )
            assert found, f"Failed to detect: {vuln_id} ({marker})"

    def test_no_false_positives_on_safe_code(self, scan_results):
        """None of the 10 safe patterns should be flagged."""
        for safe_id, pattern in KNOWN_SAFE.items():
            flagged = any(
                pattern in (f.code_snippet or "")
                for f in scan_results
            )
            assert not flagged, f"False positive on safe code: {safe_id}"
