"""Run queued tasks of one kind in the dedicated local E2E database, which runs no task worker."""

import json
from typing import Any, cast

from django.core.management.base import BaseCommand, CommandParser
from django.utils.module_loading import import_string
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.common.e2e_fixtures import require_e2e_database

# Only tasks a browser test waits on; anything else stays queued.
E2E_RUNNABLE_TASKS = ("apps.users.tasks.send_password_reset_email",)


class Command(BaseCommand):
    help = "Run the queued Django-Q tasks for one function, as a worker would, and print their results."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--func", required=True, choices=E2E_RUNNABLE_TASKS)

    def handle(self, *args: Any, **options: Any) -> None:
        require_e2e_database()
        results = []
        for row in OrmQ.objects.order_by("id"):
            package = cast("dict[str, Any]", SignedPackage.loads(row.payload))
            if package["func"] != options["func"]:
                continue
            row.delete()
            results.append(import_string(package["func"])(*package["args"], **package["kwargs"]))
        self.stdout.write(json.dumps(results, sort_keys=True))
