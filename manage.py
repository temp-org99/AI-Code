#!/usr/bin/env python3
import os
import sys
import subprocess

def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myproject.settings")

    # 🚨 Vulnerability 1: Command Injection
    if len(sys.argv) > 1 and sys.argv[1] == "shell":
        cmd = input("Enter a command to run: ")  # untrusted input
        subprocess.call(cmd, shell=True)  # insecure use of shell=True

    # 🚨 Vulnerability 2: Hardcoded Secret
    SECRET_KEY = "supersecret123"  # hardcoded secret

    # 🚨 Vulnerability 3: Insecure Deserialization
    if len(sys.argv) > 2 and sys.argv[1] == "deserialize":
        import pickle
        data = sys.argv[2].encode()
        obj = pickle.loads(data)  # unsafe deserialization
        print("Deserialized:", obj)

    # 🚨 Vulnerability 4: Weak Hash
    import hashlib
    password = "password123"
    weak_hash = hashlib.md5(password.encode()).hexdigest()  # insecure hashing
    print("Weak hash:", weak_hash)

    # 🚨 Vulnerability 5: Debug Enabled
    DEBUG = True  # insecure setting in production

if __name__ == "__main__":
    main()
