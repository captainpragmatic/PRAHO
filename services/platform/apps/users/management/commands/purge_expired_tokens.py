"""Management command to delete expired API tokens."""

from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.users.tasks import purge_expired_api_tokens


class Command(BaseCommand):
    help = "Delete all API tokens whose expires_at is in the past."

    def handle(self, *args: Any, **options: Any) -> None:
        result = purge_expired_api_tokens()
        if not result["success"]:
            raise CommandError(f"Token purge failed: {result['error']}")
        self.stdout.write(self.style.SUCCESS(f"Purged {result['purged']} expired API token(s)."))
