"""
Synthetic application for independent security audit validation.
Contains 15 deliberately introduced vulnerabilities + 10 safe patterns.
"""
import os
import pickle
import random
from pathlib import Path

# VULN 1: Hardcoded AWS Access Key
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# VULN 2: Hardcoded AWS Secret Key
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULN 3: Hardcoded API Key (generic)
API_KEY = "fictional_api_key_for_testing_1234567890"

# VULN 4: Hardcoded GitHub Token
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"

# VULN 5: Hardcoded password in source
DB_PASSWORD = "super_secret_password_123"

# VULN 6: SQL Injection - string concatenation
def get_user(username):
    query = "SELECT * FROM users WHERE name='" + username + "'"
    return query

# VULN 7: SQL Injection - f-string
def search_products(term):
    query = f"SELECT * FROM products WHERE name LIKE '%{term}%'"
    return query

# VULN 8: SQL Injection - format()
def find_order(order_id):
    query = "SELECT * FROM orders WHERE id = {}".format(order_id)
    return query

# VULN 9: eval() usage
def calculate(expression):
    return eval(expression)

# VULN 10: exec() usage
def run_code(code_string):
    exec(code_string)

# VULN 11: Unsafe deserialization with pickle
def load_data(raw_bytes):
    return pickle.loads(raw_bytes)

# VULN 12: Debug mode enabled
DEBUG = True

# VULN 13: Insecure HTTP reference
API_URL = "http://api.example.com/v1/data"

# VULN 14: Non-cryptographic random
def generate_token():
    return random.randint(1, 1000000)

# VULN 15: Hardcoded secret in function
def authenticate():
    secret_key = "my_static_secret_key_2024"
    return secret_key


# ─── SAFE PATTERNS (should NOT trigger findings) ────────────────────────────

# SAFE 1: Parameterized query with %s
def get_user_safe(uid):
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    return cursor.fetchone()

# SAFE 2: Parameterized query with ?
def get_product_safe(pid):
    cursor.execute("SELECT * FROM products WHERE id = ?", (pid,))
    return cursor.fetchone()

# SAFE 3: Using ast.literal_eval instead of eval
def parse_json(data):
    import ast
    return ast.literal_eval(data)

# SAFE 4: Using json.loads instead of pickle
def load_config(config_str):
    import json
    return json.loads(config_str)

# SAFE 5: Using secrets module instead of random
def generate_secure_token():
    import secrets
    return secrets.token_hex(32)

# SAFE 6: Comment mentioning eval (should be ignored)
# The codebase uses eval() for legacy support only
legacy_eval = True

# SAFE 7: Docstring mentioning exec
"""
This module handles authentication.
WARNING: Do not use exec() with untrusted input.
"""

# SAFE 8: HTTPS URL (not insecure)
API_URL_SECURE = "https://api.example.com/v1/data"

# SAFE 9: Localhost HTTP (allowed)
LOCAL_API = "http://localhost:8080/api"

# SAFE 10: Data URI (allowed)
INLINE_IMAGE = "data:image/png;base64,iVBORw0KGgo="
