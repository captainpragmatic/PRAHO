"""Exercise public Platform lifecycle boundaries on one owned native VM."""

from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection


class Command(BaseCommand):
    help = "Prepare/register/exercise the exact private native acceptance VM; never a customer node."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("action", choices=("prepare", "register", "workflow"))
        parser.add_argument("--manifest", type=Path, required=True)
        parser.add_argument("--dns-zone", default="")

    def handle(self, *args: Any, **options: Any) -> None:
        if (
            settings.SETTINGS_MODULE != "config.settings.native"
            or connection.vendor != "postgresql"
            or not str(connection.settings_dict["NAME"]).startswith("praho_native_")
        ):
            raise CommandError("Use dedicated native settings and an isolated praho_native_ PostgreSQL database")
        path = options["manifest"].absolute()
        configured = getattr(settings, "NATIVE_VM_MANIFEST", None)
        if configured is None or path != Path(configured).absolute():
            raise CommandError("The command manifest does not match the native settings authority")
        from apps.infrastructure.native_workflow import (  # noqa: PLC0415 -- Native imports follow isolation guard.
            run_workflow,
        )

        try:
            run_workflow(path, options["action"], dns_zone=options["dns_zone"])
        except (ValueError, OSError) as error:
            raise CommandError(str(error)) from error
        self.stdout.write(
            self.style.SUCCESS("Owned native Platform workflow phase completed; no fresh-deployment DNS proof claimed.")
        )
