"""Print a portal registration link that opens with a company's details filled in.

    manage.py mint_registration_link --email=ana@example.com --company-name="Example SRL" \\
        --cui=14399840 --product=web-hosting --period=annual

The link works for 7 days and proves nothing about who opens it: every field stays editable.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from django.core.management.base import BaseCommand, CommandError

from apps.common.intent import INTENT_KEYS
from apps.users.registration_prefill import FIELD_LIMITS, PREFILL_LIFETIME, mint_registration_prefill
from apps.users.services import portal_public_origin


class Command(BaseCommand):
    help = "Print a registration link that opens with these details filled in."

    def add_arguments(self, parser: Any) -> None:
        for name in (*FIELD_LIMITS, *INTENT_KEYS):
            parser.add_argument(f"--{name.replace('_', '-')}", dest=name, default="")

    def handle(self, *args: Any, **options: Any) -> None:
        fields = {name: options[name] for name in FIELD_LIMITS if options[name]}
        intent = {name: options[name] for name in INTENT_KEYS if options[name]}
        if not fields and not intent:
            raise CommandError("Give at least one detail to fill in.")
        try:
            token = mint_registration_prefill(fields, intent)
        except ValueError as exc:
            raise CommandError(str(exc)) from exc
        days = PREFILL_LIFETIME.days
        self.stdout.write(f"Valid for {days} days:")
        self.stdout.write(f"{portal_public_origin()}/register/?{urlencode({'p': token})}")
