"""Release every database write hold and close its episode (flag_rollback): the database overage rollback."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from apps.provisioning.database_overage_staff import release_all


class Command(BaseCommand):
    help = "Release every database write hold and close its episode as flag_rollback. Requires --all."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--all", action="store_true", help="Release every holding, held or releasing episode.")

    def handle(self, *args: Any, **options: Any) -> None:
        if not options["all"]:
            raise CommandError("Pass --all to release every database write hold.")
        outcomes = release_all()
        self.stdout.write(f"{outcomes['released']} released, {len(outcomes['pending'])} pending")
        for episode_id in outcomes["pending"]:
            self.stdout.write(f"pending: {episode_id} (see its last_error; run again once the node answers)")
        if outcomes["pending"]:
            raise CommandError(f"{len(outcomes['pending'])} holds are still in place; run again.")
