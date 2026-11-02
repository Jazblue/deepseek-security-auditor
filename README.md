# DeepSeek Security Auditor

A Python static-analysis project for identifying common security risks in source code and configuration files. It checks for hardcoded credentials, SQL injection patterns, missing security headers, insecure HTTP references, and unsafe configuration.

> **Project status: experimental / active development.** This is a learning and portfolio project, not a certified security product. Findings require human review and the tool must not be treated as proof that an application is secure.

## Project stewardship and attribution

The initial implementation and early test suite were developed with **DeepSeek**. On 2 November 2026, **ChatGPT took over the independent code review, regression testing, security remediation, documentation and ongoing project development**. The original DeepSeek contribution is retained and acknowledged; subsequent changes are recorded in the repository history.

## Features

- Credential detection for AWS keys, GitHub tokens, API keys and generic secrets.
- SQL injection pattern checks, including concatenation, f-strings and formatting.
- Checks for missing security headers and insecure HTTP references.
- Unsafe configuration checks, including `eval`, `exec`, unsafe pickle use, debug mode and hardcoded passwords.
- HTML reporting with severity levels and remediation guidance.
- Directory and individual-file credential scanning.
- Fingerprint-based deduplication and masking of credential values in findings and reports.

## Verified tests

**ChatGPT independently ran the uploaded test suite after the fixes in this repository on 2 November 2026: 98 passed, 0 failed.** This includes the project's unit tests and its independent synthetic validation tests.

The validation suite uses deliberately vulnerable and safe examples. Passing these tests confirms the current expected behaviours for that test corpus only; it does not establish 100% real-world detection accuracy or production readiness.

## Installation

Python 3.8 or newer is recommended.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
```

## Run a scan

From the repository root:

```bash
python -m auditor.cli ./test_site
python -m auditor.cli ./path/to/your/project -o security_report.html
```

Only scan code and systems you own or have explicit permission to assess. Review findings manually before taking action.

## Run tests

```bash
pytest -q
```

## Deliberately vulnerable test application

`test_site/` and `external_test_suite/synthetic_app/` contain fictional, intentionally vulnerable examples used to exercise the scanners. They are not production applications and must not be deployed. The local `test_site/.env` file is intentionally **not included** in the repository; do not add real credentials or secrets to test fixtures.

## Repository layout

- `auditor/` — scanner implementation, configuration, CLI and report generator.
- `tests/` — unit and integration tests.
- `external_test_suite/` — independent synthetic validation corpus and tests.
- `test_site/` — deliberately vulnerable sample application.

## Responsible use

This project is intended for education, portfolio demonstration and authorised defensive code review. It performs pattern-based static analysis, not full penetration testing, dependency analysis, dynamic testing or a formal security audit. False positives and false negatives are possible.
