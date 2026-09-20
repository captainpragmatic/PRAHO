"""Check prerequisites without repairing missing fixture data."""

import json
from typing import Any

from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError

from apps.common.e2e_fixtures import require_e2e_database, validate_baseline


class Command(BaseCommand):
    help = "Validate the dedicated live E2E dataset and emit its stable identifiers."

    def handle(self, *args: Any, **options: Any) -> None:
        require_e2e_database()
        try:
            result = validate_baseline()
        except ObjectDoesNotExist as exc:
            raise CommandError(f"Incomplete E2E fixtures: {exc}. Run make dev-e2e.") from exc
        self.stdout.write(json.dumps(result, sort_keys=True))
