"""
Infrastructure CLI: store_credentials

Securely store cloud provider API tokens in the PRAHO credential vault.
Supports three input methods in order of security: interactive prompt (most
secure), stdin pipe, and --token flag (least secure — visible in shell history).

Usage examples::

    # Interactive prompt (recommended — token not visible)
    $ python manage.py store_credentials hetzner

    # Pipe from environment or secret manager
    $ echo "$HCLOUD_TOKEN" | python manage.py store_credentials hetzner --stdin
    $ vault kv get -field=token secret/hetzner | python manage.py store_credentials hetzner --stdin

    # Direct flag (⚠️ visible in shell history and process list)
    $ python manage.py store_credentials hetzner --token hc_xxxx

See also:
    - sync_providers: Sync provider catalog data (regions, sizes, pricing)
    - deploy_node: Deploy a new infrastructure node
"""

from __future__ import annotations

import getpass
import sys
from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.infrastructure.provider_config import PROVIDER_CONFIG, store_provider_token


class Command(BaseCommand):
    """
    Store a cloud provider API token in the credential vault.

    This command provides CLI parity with the web UI's provider credential
    management. It resolves the provider by slug (e.g., "hetzner"), reads
    the token via one of three input methods, and delegates to
    ``store_provider_token()`` — the same function used by the web UI.

    The credential vault encrypts tokens at rest and associates them with
    the provider's ``credential_identifier`` for later retrieval by
    deployment, drift scanning, and lifecycle operations.
    """

    help = "Store a cloud provider API token in the credential vault"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "provider",
            type=str,
            choices=list(PROVIDER_CONFIG.keys()),
            help="Provider slug (e.g., hetzner, digitalocean, aws, vultr)",
        )
        parser.add_argument(
            "--token",
            type=str,
            default=None,
            help="API token (⚠️ insecure: visible in shell history)",
        )
        parser.add_argument(
            "--stdin",
            action="store_true",
            dest="from_stdin",
            help="Read token from stdin (for piping from secret managers)",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """
        Store the API token for the specified provider.

        Resolves the CloudProvider by slug, reads the token via the selected
        input method, validates it's non-empty, and stores it in the vault.

        Raises:
            CommandError: If provider not found, token is empty, or vault storage fails.
        """
        from apps.infrastructure.models import CloudProvider

        provider_slug = options["provider"]

        # Resolve CloudProvider ORM object by provider_type slug
        provider = CloudProvider.objects.filter(
            provider_type=provider_slug,
            is_active=True,
        ).first()

        if not provider:
            raise CommandError(
                f"No active provider found for type '{provider_slug}'. "
                f"Create one in the admin panel first."
            )

        # Read token using priority chain: --stdin > --token > interactive prompt
        token = self._read_token(options)

        # Strip whitespace (copy-paste artifacts) and validate
        token = token.strip()
        if not token:
            raise CommandError("Token cannot be empty.")

        # Store in vault — user=None because CLI has no authenticated request user;
        # the audit service logs this as a system action
        result = store_provider_token(provider, token, user=None)

        if result.is_err():
            raise CommandError(f"Failed to store token: {result.unwrap_err()}")

        credential_id = result.unwrap()
        self.stdout.write(
            self.style.SUCCESS(
                f"✅ Token stored for {provider.name} "
                f"(credential_id={credential_id})"
            )
        )

    def _read_token(self, options: dict[str, Any]) -> str:
        """
        Read the API token from the selected input source.

        Priority order (most to least secure):
        1. --stdin: read from piped input (for automation/secret managers)
        2. --token: direct CLI argument (visible in shell history — warns user)
        3. Interactive: getpass prompt (token not echoed to terminal)

        Returns:
            The raw token string (caller must strip/validate).

        Raises:
            CommandError: If stdin is selected but no data is available.
        """
        if options.get("from_stdin"):
            # Read from stdin pipe — used for `echo $TOKEN | manage.py ...`
            if sys.stdin.isatty():
                raise CommandError(
                    "--stdin specified but no piped input detected. "
                    "Usage: echo $TOKEN | python manage.py store_credentials <provider> --stdin"
                )
            return sys.stdin.read()

        if options.get("token"):
            # Direct flag — works but leaves token in shell history and /proc
            self.stderr.write(
                self.style.WARNING(
                    "⚠️  Using --token exposes the token in shell history. "
                    "Prefer interactive prompt or --stdin for production use."
                )
            )
            return str(options["token"])

        # Interactive prompt — most secure, token not echoed to terminal
        return getpass.getpass(prompt="Enter API token: ")
