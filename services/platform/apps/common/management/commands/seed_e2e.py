"""Seed only the dedicated local E2E database."""

import json
import re
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from apps.common.e2e_fixtures import require_e2e_database, seed_baseline, seed_scenario


class Command(BaseCommand):
    help = "Create deterministic E2E prerequisites or an owned, named test scenario."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--scenario", choices=("baseline", "billing", "pricing", "account"), default="baseline")
        parser.add_argument("--key", default="")

    def handle(self, *args: Any, **options: Any) -> None:
        require_e2e_database()
        scenario, key = options["scenario"], options["key"]
        if scenario != "baseline" and not re.fullmatch(r"[a-z0-9]{8,32}", key):
            raise CommandError("Scenario keys must contain 8-32 lowercase letters or digits.")
        result = seed_baseline() if scenario == "baseline" else seed_scenario(scenario, key)
        self.stdout.write(json.dumps(result, sort_keys=True))
