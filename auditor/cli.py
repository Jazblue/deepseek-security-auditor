"""
Security Auditor - CLI Entry Point
"""
import argparse
import logging
import sys
from pathlib import Path

from .config import ScanConfig, setup_logging
from .scanner import run_scan
from .reporter import generate_report


def main():
    parser = argparse.ArgumentParser(
        description="Security Auditor - Static analysis tool for detecting vulnerabilities"
    )
    parser.add_argument("target", nargs="?", default=".", help="Target directory to scan")
    parser.add_argument("-o", "--output", default=None, help="Output path for the report (default: <target>/security_report.html)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--format", choices=["html"], default="html", help="Report format")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default=None,
                        help="Minimum severity to report (inclusive)")

    args = parser.parse_args()

    logger = setup_logging(verbose=args.verbose)
    target = Path(args.target).resolve()

    if not target.is_dir():
        logger.error("Target '%s' is not a directory", target)
        sys.exit(1)

    severity_map = {
        "critical": ["critical"],
        "high": ["critical", "high"],
        "medium": ["critical", "high", "medium"],
        "low": ["critical", "high", "medium", "low"],
        "info": ["critical", "high", "medium", "low", "info"],
    }

    output_path = args.output or str(target / "security_report.html")

    config = ScanConfig(
        target_paths=[str(target)],
        output_format=args.format,
        output_path=output_path,
    )
    if args.severity:
        config.severity_filter = [
            s for s in __import__("auditor.config", fromlist=["Severity"]).Severity
            if s.value in severity_map.get(args.severity, [])
        ]

    findings = run_scan(config)

    if args.format == "html":
        report_path = generate_report(findings, output_path, str(target))
        print(f"\nReport generated: {report_path}")
    else:
        print(f"Found {len(findings)} findings.")

    # Print summary
    from .config import Severity
    for sev in Severity:
        count = sum(1 for f in findings if f.severity == sev)
        if count > 0:
            print(f"  {sev.value.upper()}: {count}")
    print(f"  Total: {len(findings)}")

    sys.exit(0 if not findings else 1)


if __name__ == "__main__":
    main()
