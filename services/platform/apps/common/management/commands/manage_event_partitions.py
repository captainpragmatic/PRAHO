from __future__ import annotations

import json
from typing import Any

from django.core.management.base import BaseCommand

from apps.common.partitioning import EventPartitionService


class Command(BaseCommand):
    help = "Inspect and maintain partition posture for high-volume event tables"

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--action",
            choices=["status", "plan", "ensure-future"],
            default="status",
            help="Partition action to perform",
        )
        parser.add_argument(
            "--json",
            action="store_true",
            help="Output JSON instead of human-readable text",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print SQL/actions without mutating the database",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        service = EventPartitionService()
        action = options["action"]

        if action == "ensure-future":
            statements = service.ensure_future_partitions(dry_run=options["dry_run"])
            if options["json"]:
                self.stdout.write(json.dumps({"statements": statements}, indent=2, sort_keys=True, default=str))
                return
            self._write_statements(statements, options["dry_run"])
            return

        payload = service.get_status() if action == "status" else service.plan_operations()

        if options["json"]:
            self.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str))
            return

        self._write_mapping(payload)

    def _write_mapping(self, payload: dict[str, Any]) -> None:
        for key, data in payload.items():
            self.stdout.write(f"{key}:")
            for field_name, field_value in data.items():
                self.stdout.write(f"  {field_name}: {field_value}")

    def _write_statements(self, statements: list[str], dry_run: bool) -> None:
        if not statements:
            self.stdout.write("No partition statements generated.")
            return

        self.stdout.write("Partition statements:")
        for statement in statements:
            self.stdout.write(statement)
        if dry_run:
            self.stdout.write("Dry run only; no statements executed.")
