"""
Security Auditor - Main Scanner Orchestration Module
"""
import logging
from pathlib import Path
from typing import List

from .config import Finding, ScanConfig
from .scanner_credentials import scan_credentials
from .scanner_sqli import scan_sql_injection
from .scanner_headers import scan_security_headers
from .scanner_http import scan_insecure_http
from .scanner_config import scan_unsafe_config

logger = logging.getLogger("security_auditor.scanner")


def run_scan(config: ScanConfig) -> List[Finding]:
    """Run all scanners against the target paths.

    Each target may be a directory *or* a single file.  Findings that share the
    same underlying secret (``secret_fingerprint``) are collapsed to a single
    finding regardless of which scanner produced them, so a credential is
    never reported twice — once by the credential scanner and once by the
    unsafe-config scanner.
    """
    all_findings: List[Finding] = []
    target_dirs = [Path(p) for p in config.target_paths if Path(p).exists()]

    if not target_dirs:
        logger.error("No valid target directories found: %s", config.target_paths)
        return all_findings

    for target in target_dirs:
        logger.info("Scanning target: %s", target)
        target = target.resolve()

        scanners = [
            ("Credentials", scan_credentials),
            ("SQL Injection", scan_sql_injection),
            ("Security Headers", scan_security_headers),
            ("Insecure HTTP", scan_insecure_http),
            ("Unsafe Config", scan_unsafe_config),
        ]

        for name, scanner_fn in scanners:
            logger.info("Running scanner: %s", name)
            try:
                findings = scanner_fn(target)
                all_findings.extend(findings)
                logger.info("  Found %d findings in %s", len(findings), name)
            except Exception as exc:
                logger.error("Scanner '%s' failed: %s", name, exc, exc_info=True)

    # Cross-scanner deduplication: keep only the first finding for each
    # distinct secret fingerprint.  Findings without a fingerprint (SQL
    # injection, insecure HTTP, security headers) are always kept.
    deduped: List[Finding] = []
    seen_fingerprints: set[str] = set()
    for f in all_findings:
        if f.secret_fingerprint is not None:
            if f.secret_fingerprint in seen_fingerprints:
                logger.debug(
                    "Deduplicating %s finding at %s:%s (fingerprint %s)",
                    f.category, f.file_path, f.line_number, f.secret_fingerprint,
                )
                continue
            seen_fingerprints.add(f.secret_fingerprint)
        deduped.append(f)

    # Apply severity filter
    filtered = [f for f in deduped if f.severity in config.severity_filter]
    logger.info("Total findings after dedup/filtering: %d", len(filtered))
    return filtered
