from flask import Flask, request
import os
import sqlite3
from utils import insecure_eval, generate_insecure_token
from secrets import API_KEY

app = Flask(__name__)

DB_PATH = "users.db"


def init_db():
    # Simple demo DB; not hardened
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    # Intentionally weak default user
    cur.execute(
        "INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'admin123')"
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    name = request.args.get("name", "world")
    # POTENTIAL XSS: directly reflect user input
    return f"<h1>Hello {name}!</h1>"


@app.route("/search")
def search():
    username = request.args.get("username", "")
    # SQL INJECTION: using string concatenation instead of parameters
    query = f"SELECT * FROM users WHERE username = '{username}'"
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return {"results": rows}


@app.route("/run")
def run():
    cmd = request.args.get("cmd", "echo no command provided")
    # COMMAND INJECTION: user-controlled shell command
    output = os.popen(cmd).read()
    return f"<pre>{output}</pre>"


@app.route("/debug-eval")
def debug_eval():
    expression = request.args.get("expr", "1+1")
    # UNSAFE EVAL: just a wrapper around utils.insecure_eval
    result = insecure_eval(expression)
    return {"result": result}


@app.route("/token")
def token():
    # Uses insecure randomness for "security" tokens
    t = generate_insecure_token()
    return {"token": t, "api_key_used": API_KEY}


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
