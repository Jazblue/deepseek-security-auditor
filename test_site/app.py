"""
Deliberately vulnerable Flask application for security auditing testing.
WARNING: This is for educational/auditing purposes ONLY. Do not deploy in production.
"""
from flask import Flask, request, render_template_string, abort

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
API_KEY = "sk-abc123def456ghi789jkl012mno345pqr678"
DATABASE_URL = "postgresql://admin:supersecretpass123@localhost:5432/myapp"
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"

# VULNERABILITY 2: SQL Injection
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # VULNERABLE: SQL injection via string concatenation
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    return f"Query: {query}"

@app.route("/search")
def search():
    term = request.args.get("q", "")
    # VULNERABLE: SQL injection via f-string
    query = f"SELECT * FROM products WHERE name LIKE '%{term}%'"
    return f"Search query: {query}"

@app.route("/user/<user_id>")
def get_user(user_id):
    # VULNERABLE: SQL injection via format()
    query = "SELECT * FROM users WHERE id = {}".format(user_id)
    return f"User query: {query}"

@app.route("/order")
def get_order():
    order_id = request.args.get("id", "")
    # VULNERABLE: SQL injection via % formatting
    query = "SELECT * FROM orders WHERE id = '%s'" % order_id
    return f"Order: {query}"

@app.route("/union-test")
def union_test():
    col = request.args.get("col", "name")
    # VULNERABLE: UNION-based SQL injection
    query = "SELECT " + col + " FROM users UNION SELECT password FROM admin"
    return query

# VULNERABILITY 3: Unsafe configuration
@app.route("/debug")
def debug():
    # VULNERABLE: Using eval()
    expression = request.args.get("expr", "1+1")
    result = eval(expression)
    return f"Result: {result}"

@app.route("/exec-test")
def exec_test():
    # VULNERABLE: Using exec()
    code = request.args.get("code", "x=1")
    exec(code)
    return "Executed"

@app.route("/pickle-test")
def pickle_test():
    import pickle
    data = request.args.get("data", "")
    # VULNERABLE: Unsafe pickle deserialization
    obj = pickle.loads(data.encode())
    return str(obj)

# VULNERABILITY 4: Insecure random
import random
@app.route("/lottery")
def lottery():
    # VULNERABLE: Using non-cryptographic random
    winning_number = random.randint(1, 1000000)
    return f"Winning number: {winning_number}"

# VULNERABILITY 5: Insecure HTTP references
@app.route("/")
def index():
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Test App</title>
        <!-- Missing Content-Security-Policy header -->
        <!-- Missing X-Frame-Options -->
        <link rel="stylesheet" href="http://cdn.example.com/styles.css">
        <script src="http://cdn.example.com/app.js"></script>
    </head>
    <body>
        <h1>Welcome to the Vulnerable Test App</h1>
        <img src="http://example.com/images/logo.png" alt="Logo">
        <a href="http://insecure-site.example.com/login">Login (HTTP)</a>
        <form action="http://api.example.com/upload" method="POST">
            <input name="file" type="file">
            <button type="submit">Upload</button>
        </form>
    </body>
    </html>
    """
    return render_template_string(template)

# VULNERABILITY 6: Hardcoded password
SECRET_PASSWORD = "MyS3cr3tP@ssw0rd!"
ADMIN_PASSWORD = "admin123"

# VULNERABILITY 7: Debug mode enabled
if __name__ == "__main__":
    app.debug = True
    app.run(host="0.0.0.0", port=5000, debug=True)
