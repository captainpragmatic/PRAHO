"""Management command to delete expired API tokens."""

from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.users.models import APIToken


class Command(BaseCommand):
    help = "Delete all API tokens whose expires_at is in the past."

    def handle(self, *args: Any, **options: Any) -> None:
        count, _ = APIToken.objects.filter(expires_at__lt=timezone.now()).delete()
        self.stdout.write(self.style.SUCCESS(f"Purged {count} expired API token(s)."))
