# DeepSeek Security Auditor

A Python security-auditing project built with assistance from DeepSeek and tested through an independent synthetic validation suite.

> **Project status: experimental / under active development.** This repository documents the work and findings from the initial development session. It is not a production-ready security product, and the application source code has not yet been uploaded.

## What was built

The project was developed locally in Python as a multi-check security auditor. Its scanners cover:

- Hardcoded credentials and secrets
- SQL injection patterns
- Insecure HTTP usage
- Missing or weak security headers
- Unsafe application configuration and dangerous functions

The project also includes a command-line interface, reporting functionality, a deliberately vulnerable synthetic test application, and automated tests.

## Development work completed with DeepSeek

During the 2 November 2026 development session, DeepSeek helped:

1. Build the initial scanner modules and a synthetic test application.
2. Create an automated test suite. The original 36 tests were expanded to 71.
3. Add SHA-256 finding fingerprints to reduce duplicate findings.
4. Add secret-masking functionality for credential findings.
5. Improve severity handling so known example credentials can be labelled as test data rather than confirmed live secrets.
6. Create an independent validation suite containing 15 deliberately vulnerable examples and 10 safe coding patterns.

The initial independent validation reported 14 true positives out of 15, one false negative, and two false positives. The reported precision was 87.50%, recall 93.33%, and F1 score 90.32%.

Subsequent scanner changes were reported to improve those results to 15/15 detections and zero false positives, with 98 automated tests passing. These later figures are developer-reported and still require reproducible independent confirmation.

## Further testing uncovered additional weaknesses

A separate credential-focused test file was created with 13 fictional credential assignments. The focused scan reported 8 of 13 detected. It exposed several issues requiring correction:

- Quoted dictionary-key assignments were missed by some credential patterns.
- Some AWS secret-key naming and formatting variations were not detected.
- A single-file scan returned no findings because the scanner's traversal logic expected a directory.
- A credential masked by one scanner could still appear in plaintext through another scanner's report.
- Duplicate findings could occur across scanners.

These are open engineering issues, not resolved features. The next development milestone is to centralise masking across all scanners and reporting paths, improve credential detection, support both file and directory scanning, and validate cross-scanner deduplication.

## Testing approach

The project uses two levels of testing:

- **Unit/regression tests** for individual scanners and reporting behaviour.
- **Independent synthetic validation** using deliberately vulnerable and safe examples that are separate from the scanner's own unit tests.

Future validation should report true positives, false positives, false negatives, precision, recall, and F1 score. Test results should be reproducible from documented commands and should include the exact test corpus version.

## Security and responsible use

- Synthetic credentials must remain fictional and must never be replaced with live secrets.
- Do not commit real `.env` files, API keys, access tokens, passwords, customer data, or private scan reports.
- Run scans only against systems you own or are explicitly authorised to assess.
- Findings are indicators for human review; a pattern match alone does not prove exploitability.
- Do not use this experimental project as the sole security control for production systems.

## Roadmap

- [ ] Centralise secret masking across every scanner, terminal output, and HTML report.
- [ ] Improve detection of quoted dictionary keys and AWS secret assignments.
- [ ] Support scanning a single file as well as a directory.
- [ ] Review and reduce duplicate findings across scanners.
- [ ] Add broader SQL parameterisation regression coverage.
- [ ] Expand the independent corpus to at least 50 vulnerable and 50 safe examples.
- [ ] Publish reproducible setup, usage, and test instructions.
- [ ] Review the complete repository for secrets and sensitive data before publishing source files.

## Attribution

DeepSeek was used as the AI coding assistant during the initial implementation and iterative testing. The project records both its successful contributions and the defects discovered during independent validation. Human review and reproducible testing remain essential.

---

*Development notes: 2 November 2026.*
