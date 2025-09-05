#!/usr/bin/env python
"""
Django's command-line utility for administrative tasks.
"""

import os
import sys
from pathlib import Path

if __name__ == "__main__":
    # ===============================================================================
    # LOAD ENVIRONMENT VARIABLES FROM .env FILE 🔐
    # ===============================================================================
    # Load .env file for local development
    env_path = Path(__file__).resolve().parent / ".env"
    if env_path.exists():
        try:
            from dotenv import load_dotenv

            load_dotenv(env_path)
            print("✅ [Environment] Loaded .env file")
        except ImportError:
            print("⚠️  [Environment] python-dotenv not installed")
            print("⚠️  [Environment] Run: pip install python-dotenv")

    # Set the default Django settings module for the 'manage.py' script
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc

    execute_from_command_line(sys.argv)
