"""
Synthetic credential vulnerabilities for independent validation.

This module deliberately contains hardcoded, fictional credentials so the
security auditor can be tested for detection accuracy.  Every value here is
invented and is NOT a real secret.  Each example is annotated with a comment
explaining the vulnerability it represents.

NOTE: These examples are intentionally vulnerable.  Do not copy real secrets
into this file or any test fixture.
"""

# ---------------------------------------------------------------------------
# AWS Access Key IDs
# ---------------------------------------------------------------------------

# Vulnerability: AWS Access Key ID hardcoded directly in source code.
# An attacker who reads this file can impersonate the associated IAM principal.
AWS_ACCESS_KEY_ID = "AKIA5XQ3Z9F8T2R6V1N4M"

# Vulnerability: AWS Access Key ID assigned via a dict key instead of a bare
# variable, which is a common pattern in configuration dictionaries.
aws_config = {
    "aws_access_key_id": "AKIA7B1Y4D8C3V9T2F6H5J",
}

# ---------------------------------------------------------------------------
# AWS Secret Access Keys
# ---------------------------------------------------------------------------

# Vulnerability: AWS Secret Access Key hardcoded alongside the access key ID.
# The secret key alone is enough to sign requests and access resources.
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12345"

# Vulnerability: Secret key stored in an environment-variable-style assignment
# using the ``AWS_SECRET`` naming convention (no ``ACCESS`` word).
AWS_SECRET = "aB3cD9fG2hI5jK8lM1nO4pQ7rS6tU0vW3xY5zA8bC"

# Vulnerability: Secret key embedded in a YAML-style string assignment with the
# ``AWS_SECRET_ACCESS_KEY`` naming convention.
AWS_SECRET_ACCESS_KEY = "Xy7Zq2Wv4Tu6Rg8Nb1Kd3He5Jl9Mf7Po5Lt3Vx1Zr"

# ---------------------------------------------------------------------------
# GitHub-style tokens
# ---------------------------------------------------------------------------

# Vulnerability: Classic GitHub personal access token (ghp_ prefix) hardcoded
# in source code.  The token grants access to the owner's repositories.
GITHUB_TOKEN = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"

# Vulnerability: GitHub fine-grained token (ghs_ prefix) assigned inside a
# configuration dictionary.
github_fine_grained = {
    "token": "ghs_1234567890abcdefghijklmnopqrstuvwxyz",
}

# ---------------------------------------------------------------------------
# Generic API keys
# ---------------------------------------------------------------------------

# Vulnerability: Generic API key with a 32-character alphanumeric value.
API_KEY = "a1b2c3d4e5f60718293a4b5c6d7e8f90"

# Vulnerability: API key assigned through a lowercase ``api_key`` variable,
# which is the most common naming convention.
api_key = "XyZaBcDeFgHiJkLmNoPqRsTuVwXy0123456789"

# Vulnerability: API key stored in a configuration dictionary under the
# ``api_key`` key.
config = {
    "api_key": "9z8y7x6w5v4u3t2s1r0qponmlkjihgfedcba",
}

# ---------------------------------------------------------------------------
# Database credentials
# ---------------------------------------------------------------------------

# Vulnerability: PostgreSQL database password hardcoded in source code.
DB_PASSWORD = "Sup3rS3cr3tP@ssw0rd!"

# Vulnerability: Database password assigned via a lowercase ``password``
# variable, a pattern that appears in connection-string builders.
password = "db_p@ss_2024_secure!"

# Vulnerability: MySQL password embedded in a connection-string dictionary.
db_config = {
    "host": "db.internal.example.com",
    "user": "app_user",
    "password": "My$QL_P@ssw0rd_2024!",
}