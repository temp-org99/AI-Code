#!/usr/bin/env python
"""Extra Insecure Django's command-line utility for administrative tasks."""
import os
import sys
import subprocess
import pickle
import hashlib
import yaml
import sqlite3

# 🚨 Hardcoded secrets (multiple scanners will flag this)
DB_PASSWORD = "SuperSecret123!"
AWS_ACCESS_KEY_ID = "AKIAFAKEACCESSKEY"
AWS_SECRET_ACCESS_KEY = "fakeSecretKeyForTestingOnly"
JWT_SECRET = "hardcoded-jwt-secret-key"

# 🚨 Insecure eval usage
def run_insecure_eval():
    user_code = input("Enter Python code to eval: ")
    eval(user_code)  # BAD: arbitrary code execution

# 🚨 Insecure dependency usage (command injection risk)
def run_insecure_command():
    user_input = input("Enter a shell command to run: ")
    subprocess.call(user_input, shell=True)  # BAD: unsanitized input with shell=True

# 🚨 Insecure SQL injection
def run_insecure_sql():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INT, name TEXT)")
    user_input = input("Enter username to search: ")
    query = f"SELECT * FROM users WHERE name = '{user_input}'"  # BAD: SQL injection
    cursor.execute(query)
    print(cursor.fetchall())

def main():
    """Run administrative tasks (insecure version)."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gold_trading.settings')

    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Did you forget to install it?"
        ) from exc

    # 🚨 Example of unsafe deserialization
    malicious_pickle = b"cos\nsystem\n(S'echo Vulnerable!'\ntR."
    pickle.loads(malicious_pickle)  # BAD: insecure pickle usage

    # 🚨 Weak cryptography (predictable, insecure)
    password = "password123"
    weak_hash = hashlib.md5(password.encode()).hexdigest()  # BAD: MD5 usage
    print(f"Weak hash of password: {weak_hash}")

    # 🚨 Unsafe YAML load
    yaml_payload = "!!python/object/apply:os.system ['echo YAML RCE!']"
    yaml.load(yaml_payload, Loader=yaml.FullLoader)  # BAD: arbitrary code execution

    # 🚨 Exposed secret printed to logs
    print(f"[DEBUG] Using DB password: {DB_PASSWORD}")

    # Trigger insecure features
    run_insecure_eval()
    run_insecure_command()
    run_insecure_sql()

    # Continue Django execution
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
