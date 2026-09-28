"""Sweep expired counter rows and claims past their grace period."""

from typing import Any

from django.core.management.base import BaseCommand, CommandParser

from apps.common import counters


class Command(BaseCommand):
    help = "Delete expired counters and claims past their grace period, in bounded batches."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--batches", type=int, default=20, help="Maximum batches of 500 rows to delete")

    def handle(self, *args: Any, **options: Any) -> None:
        deleted = counters.cull_expired(batches=options["batches"])
        self.stdout.write(self.style.SUCCESS(f"Deleted {deleted} expired counter rows."))
