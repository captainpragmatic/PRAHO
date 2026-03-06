"""
Management command to clean up expired and consumed UnsubscribeTokens.

Usage:
    python manage.py cleanup_unsubscribe_tokens
    python manage.py cleanup_unsubscribe_tokens --dry-run

Recommended cron: daily at 3 AM
    0 3 * * * cd /path/to/platform && python manage.py cleanup_unsubscribe_tokens
"""

from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.notifications.models import TOKEN_EXPIRY_DAYS, UnsubscribeToken


class Command(BaseCommand):
    """Delete expired and consumed unsubscribe tokens."""

    help = "Remove expired and consumed UnsubscribeTokens to keep the table lean."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show how many tokens would be deleted without deleting them.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        cutoff = timezone.now() - timedelta(days=TOKEN_EXPIRY_DAYS)
        dry_run = options["dry_run"]

        # Expired tokens (created before cutoff)
        expired_qs = UnsubscribeToken.objects.filter(created_at__lt=cutoff)
        # Consumed tokens (already used)
        consumed_qs = UnsubscribeToken.objects.filter(used_at__isnull=False)

        # Combine (union avoids double-counting)
        deletable = UnsubscribeToken.objects.filter(id__in=expired_qs.values("id")) | UnsubscribeToken.objects.filter(
            id__in=consumed_qs.values("id")
        )
        count = deletable.count()

        if dry_run:
            self.stdout.write(f"Would delete {count} tokens (dry-run)")
            return

        deleted, _ = deletable.delete()
        self.stdout.write(self.style.SUCCESS(f"✅ Deleted {deleted} unsubscribe tokens"))
