"""
Idempotent superuser creation from environment variables.

Creates a superuser only if:
- DJANGO_SUPERUSER_EMAIL and DJANGO_SUPERUSER_PASSWORD are set in the environment
- No superuser account exists yet (unless --force is passed)

In non-DEBUG mode, rejects weak passwords to prevent accidental production exposure.
"""

import os
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError, CommandParser

User = get_user_model()

WEAK_PASSWORDS = frozenset(
    {
        "admin123",
        "changeme",
        "password",
        "password123",
        "123456",
        "qwerty",
        "letmein",
        "welcome",
        "admin",
        "test123",
        "secret",
        "password1234",
        "admin1234567",
    }
)

MIN_PASSWORD_LENGTH_PROD = 12


class Command(BaseCommand):
    help = "Create a superuser from DJANGO_SUPERUSER_EMAIL and DJANGO_SUPERUSER_PASSWORD env vars (idempotent)"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--force",
            action="store_true",
            help="Create superuser even if one already exists",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        email = os.environ.get("DJANGO_SUPERUSER_EMAIL", "").strip()
        password = os.environ.get("DJANGO_SUPERUSER_PASSWORD", "").strip()

        if not email or not password:
            self.stdout.write(
                "💡 Hint: set DJANGO_SUPERUSER_EMAIL and DJANGO_SUPERUSER_PASSWORD "
                "in your environment to auto-create a superuser."
            )
            return

        # Check if superuser already exists
        force = options.get("force", False)
        if not force and User.objects.filter(is_superuser=True).exists():
            self.stdout.write("⏭️  Superuser already exists, skipping")
            return

        # Check for exact duplicate (same email)
        if User.objects.filter(email=email).exists():
            self.stdout.write(f"⏭️  User {email} already exists, skipping")
            return

        # Enforce password strength in production
        is_debug = getattr(settings, "DEBUG", False)
        if not is_debug:
            if len(password) < MIN_PASSWORD_LENGTH_PROD:
                raise CommandError(
                    f"Superuser password must be at least {MIN_PASSWORD_LENGTH_PROD} characters in production. "
                    f"Current length: {len(password)}"
                )
            if password.lower() in WEAK_PASSWORDS:
                raise CommandError(
                    "Superuser password is in the deny list of common passwords. Choose a stronger password."
                )

        User.objects.create_superuser(email=email, password=password)
        self.stdout.write(self.style.SUCCESS(f"✅ Superuser created: {email}"))

        if is_debug:
            self.stdout.write(
                self.style.WARNING("⚠️  This is a development superuser — change the password in production.")
            )
