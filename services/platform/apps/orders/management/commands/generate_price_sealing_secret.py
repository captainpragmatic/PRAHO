"""
Django management command to generate secure PRICE_SEALING_SECRET keys.
🔒 Security: Each portal deployment should have its own unique secret.
"""

import secrets
from typing import Any

from django.core.management.base import BaseCommand, CommandParser

# Security constants
MIN_SECRET_LENGTH = 32  # Minimum characters for cryptographic security


class Command(BaseCommand):
    help = "🔒 Generate secure PRICE_SEALING_SECRET for price token HMAC signing"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--length", type=int, default=64, help="Secret key length (minimum 32 characters, default 64)"
        )
        parser.add_argument(
            "--format", choices=["env", "raw"], default="env", help="Output format: env variable or raw key"
        )

    def handle(self, *args: Any, **options: Any) -> None:
        length = options["length"]
        output_format = options["format"]

        # Validate minimum length
        if length < MIN_SECRET_LENGTH:
            self.stdout.write(self.style.ERROR("🚨 Error: Secret length must be at least 32 characters for security"))
            return

        # Generate cryptographically secure random key
        # Use URL-safe base64 encoding for easy environment variable usage
        secret_key = secrets.token_urlsafe(length)

        self.stdout.write("🔒 Generated secure price sealing secret:")
        self.stdout.write("")

        if output_format == "env":
            self.stdout.write(f"PRICE_SEALING_SECRET={secret_key}")
            self.stdout.write("")
            self.stdout.write("📝 Add this to your .env file or environment variables")
            self.stdout.write("⚠️  Keep this secret secure and unique per portal deployment!")
        else:
            self.stdout.write(secret_key)

        self.stdout.write("")
        self.stdout.write("🔐 Security notes:")
        self.stdout.write("  • Each portal deployment should have a unique secret")
        self.stdout.write("  • Never commit secrets to version control")
        self.stdout.write("  • Rotate secrets periodically for security")
        self.stdout.write("  • Store secrets securely (AWS Secrets Manager, etc.)")
