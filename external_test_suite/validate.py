"""
Independent validation suite for the Security Auditor.
Tests actual vulnerability detection accuracy.
"""
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List

# Add the auditor to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from auditor.config import Finding, ScanConfig
from auditor.scanner import run_scan

# ─── Known ground truth ─────────────────────────────────────────────────────

KNOWN_VULNS = {
    # Use masked markers - actual secrets are masked in reports
    "v1_aws_access_key": ("Hardcoded Credential", "AWS Access Key ID"),
    "v2_aws_secret_key": ("Hardcoded Credential", "AWS Secret"),
    "v3_api_key": ("Hardcoded Credential", "Generic API Key"),
    "v4_github_token": ("Hardcoded Credential", "GitHub Token"),
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
    "v15_hardcoded_secret": ("Unsafe Configuration", "Hardcoded password"),
}

KNOWN_SAFE = {
    "safe_param_percent": 'cursor.execute("SELECT * FROM users WHERE id = %s"',
    "safe_param_question": 'cursor.execute("SELECT * FROM products WHERE id = ?"',
    "safe_literal_eval": "ast.literal_eval",
    "safe_json_loads": "json.loads",
    "safe_secrets": "secrets.token_hex",
    "safe_comment_eval": "# The codebase uses eval()",
    "safe_docstring_exec": "WARNING: Do not use exec()",
    "safe_https": "https://api.example.com",
    "safe_localhost": "http://localhost:8080",
    "safe_data_uri": "data:image/png;base64",
}


@dataclass
class ValidationResult:
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    detected: List[str] = None
    missed: List[str] = None
    all_findings: List[Finding] = None

    def __post_init__(self):
        if self.detected is None:
            self.detected = []
        if self.missed is None:
            self.missed = []
        if self.all_findings is None:
            self.all_findings = []


def validate_audit(target_dir: Path) -> ValidationResult:
    """Run the security auditor and validate against known vulnerabilities."""
    config = ScanConfig(target_paths=[str(target_dir)])
    findings = run_scan(config)

    result = ValidationResult(all_findings=findings)

    # Check each known vulnerability
    for vuln_id, (category, marker) in KNOWN_VULNS.items():
        matched = False
        for finding in findings:
            if finding.category == category and marker.lower() in finding.message.lower():
                result.true_positives += 1
                result.detected.append(vuln_id)
                matched = True
                break
        if not matched:
            result.false_negatives += 1
            result.missed.append(vuln_id)

    # Check each known safe pattern
    for safe_id, pattern in KNOWN_SAFE.items():
        for finding in findings:
            if pattern in (finding.code_snippet or ""):
                # This safe pattern was incorrectly flagged
                result.false_positives += 1
                break

    return result


def main():
    test_site = Path(__file__).parent / "synthetic_app"
    if not test_site.exists():
        print(f"ERROR: Test site not found at {test_site}")
        sys.exit(1)

    print("=" * 70)
    print("INDEPENDENT SECURITY AUDITOR VALIDATION")
    print("=" * 70)
    print(f"\nTarget: {test_site}")
    print()

    result = validate_audit(test_site)

    # Print results
    print("-" * 70)
    print("DETECTION RESULTS")
    print("-" * 70)
    print(f"\nKnown Vulnerabilities: {len(KNOWN_VULNS)}")
    print(f"True Positives:        {result.true_positives} V")
    print(f"False Negatives:       {result.false_negatives} V")

    print(f"\nKnown Safe Patterns:   {len(KNOWN_SAFE)}")
    print(f"False Positives:       {result.false_positives} ERROR")

    print("\n" + "-" * 70)
    print("METRICS")
    print("-" * 70)

    precision = result.true_positives / (result.true_positives + result.false_positives) if (result.true_positives + result.false_positives) > 0 else 0
    recall = result.true_positives / len(KNOWN_VULNS) if len(KNOWN_VULNS) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\nPrecision: {precision:.2%}  ({result.true_positives}/{result.true_positives + result.false_positives})")
    print(f"Recall:    {recall:.2%}  ({result.true_positives}/{len(KNOWN_VULNS)})")
    print(f"F1 Score:  {f1:.2%}")

    if result.missed:
        print(f"\nMissed Vulnerabilities:")
        for vuln_id in result.missed:
            category, marker = KNOWN_VULNS[vuln_id]
            print(f"  - {vuln_id}: {category} ({marker})")

    if result.false_positives > 0:
        print(f"\nFalse Positives:")
        for safe_id, pattern in KNOWN_SAFE.items():
            for finding in result.all_findings:
                if pattern in (finding.code_snippet or ""):
                    print(f"  - {safe_id}: '{pattern[:50]}...'")
                    break

    print("\n" + "=" * 70)

    # Return exit code based on performance
    if result.false_negatives > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
