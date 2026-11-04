"""Explicit commercial and two-node acceptance setup under the original native authority."""

import os
from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection


class Command(BaseCommand):
    help = "Prepare and verify only the manifest-bound disposable commercial acceptance fixture."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "action",
            choices=("staff-setup", "setup", "peer-intent", "create-peer", "export-peer", "verify", "peer-destroy"),
        )
        parser.add_argument("--manifest", type=Path, required=True)
        parser.add_argument("--peer-manifest", type=Path)
        parser.add_argument("--boundary-minutes", type=int, default=75)

    def handle(self, *args: Any, **options: Any) -> None:
        configured = getattr(settings, "NATIVE_VM_MANIFEST", None)
        if (
            settings.SETTINGS_MODULE != "config.settings.native"
            or connection.vendor != "postgresql"
            or not str(connection.settings_dict["NAME"]).startswith("praho_native_")
            or configured is None
            or options["manifest"].absolute() != Path(configured).absolute()
        ):
            raise CommandError("Use primary native settings and its original isolated praho_native_ database authority")
        if os.environ.get("PRAHO_NATIVE_CLEANUP_ONLY") == "1" and options["action"] != "peer-destroy":
            raise CommandError("Cleanup-only authority permits only exact peer-destroy")
        from apps.infrastructure.native_acceptance_fixture import run_acceptance  # noqa: PLC0415

        try:
            run_acceptance(
                options["manifest"],
                options["action"],
                peer_path=options["peer_manifest"],
                boundary_minutes=options["boundary_minutes"],
            )
        except (OSError, ValueError) as error:
            raise CommandError(str(error)) from error
        self.stdout.write("Owned native acceptance phase completed: " + options["action"])
