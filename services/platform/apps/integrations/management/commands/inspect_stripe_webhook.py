"""Inspect an existing Stripe endpoint without changing remote configuration."""

from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from apps.billing.gateways.stripe_contract import STRIPE_API_VERSION, STRIPE_REQUIRED_WEBHOOK_EVENTS
from apps.billing.gateways.stripe_gateway import StripeGateway


class Command(BaseCommand):
    help = "Check an existing Stripe endpoint's version, status and required event subscriptions (read only)"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("endpoint_id", help="Stripe endpoint ID (we_...), never its signing secret")

    def handle(self, *args: Any, **options: Any) -> None:
        endpoint_id = options["endpoint_id"]
        if not isinstance(endpoint_id, str) or not endpoint_id.startswith("we_"):
            raise CommandError("Expected a Stripe webhook endpoint ID beginning with we_.")
        gateway = StripeGateway()
        endpoint = gateway._stripe.WebhookEndpoint.retrieve(endpoint_id)
        problems = []
        if endpoint.get("api_version") != STRIPE_API_VERSION:
            problems.append(f"API version differs from {STRIPE_API_VERSION}; a staged endpoint replacement is required")
        if endpoint.get("status") != "enabled":
            problems.append("Endpoint is not enabled")
        enabled = set(endpoint.get("enabled_events") or [])
        if "*" not in enabled:
            missing = STRIPE_REQUIRED_WEBHOOK_EVENTS - enabled
            if missing:
                problems.append("Missing required events: " + ", ".join(sorted(missing)))
        if problems:
            raise CommandError("; ".join(problems))
        if "*" in enabled:
            self.stdout.write(self.style.WARNING("All event types are enabled; subscribe only to the required types."))
        self.stdout.write(self.style.SUCCESS(f"{endpoint_id}: endpoint contract verified ({STRIPE_API_VERSION})"))
