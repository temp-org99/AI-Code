#!/usr/bin/env python3
import os
import sys

def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myproject.settings")

    # 🚨 Hardcoded secrets
    SECRET_KEY = "django-insecure-1234567890"  # Django secret key
    AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    DB_PASSWORD = "P@ssw0rd!"  # Hardcoded DB password
    API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"  # GitHub token

    print("Secrets loaded (insecurely):")
    print(SECRET_KEY, AWS_SECRET_ACCESS_KEY, DB_PASSWORD, API_TOKEN)

    # Normally manage.py runs Django, but here we just simulate execution
    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)

if __name__ == "__main__":
    main()
