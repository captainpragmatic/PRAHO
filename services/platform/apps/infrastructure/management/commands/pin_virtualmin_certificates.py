"""Backfill trusted SHA-256 pins for self-signed Virtualmin node certificates."""

from __future__ import annotations

import uuid
from typing import Any

from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError, CommandParser

from apps.common.outbound_http import OutboundSecurityError, normalize_tls_cert_fingerprint
from apps.common.validators import log_security_event
from apps.infrastructure.validation_service import get_validation_service
from apps.provisioning.virtualmin_models import VirtualminServer


class Command(BaseCommand):
    """Pin certificates through the deployment SSH trust path, never network TOFU."""

    help = "Pin self-signed Virtualmin certificates over trusted deployment SSH"

    def add_arguments(self, parser: CommandParser) -> None:
        # #337: VirtualminServer.id is a UUIDField, so type=int rejected every real id in
        # argparse before the command body ever ran — --server-id could not be used at all.
        parser.add_argument("--server-id", help="Limit the backfill to one VirtualminServer UUID")
        parser.add_argument("--dry-run", action="store_true", help="List candidate servers without changing them")
        parser.add_argument(
            "--force",
            action="store_true",
            help="Allow --fingerprint to REPLACE an existing pin (refused otherwise, so a mis-pasted id cannot "
            "silently retarget a healthy node's trust anchor)",
        )
        parser.add_argument(
            "--fingerprint",
            help=(
                "Operator-supplied SHA-256 pin for ONE server (requires --server-id). For legacy rows with no "
                "linked node deployment, where the SSH path cannot run. Obtain the value out-of-band — e.g. on "
                "the node itself: openssl s_client -connect 127.0.0.1:10000 </dev/null 2>/dev/null | "
                "openssl x509 -noout -fingerprint -sha256. Never read it over an unverified network connection."
            ),
        )

    def handle(self, *args: Any, **options: Any) -> None:
        server_id: str | None = options["server_id"]
        fingerprint: str | None = options["fingerprint"]

        # Validated here, before either branch. Dropping the (wrong) type=int made a typo'd
        # id reachable as an uncaught ValidationError traceback from deep inside the ORM:
        # argparse used to reject it cleanly, so removing the coercion removed the guard too.
        if server_id is not None:
            try:
                uuid.UUID(str(server_id))
            except (ValueError, AttributeError, TypeError) as exc:
                raise CommandError(f"{server_id!r} is not a valid VirtualminServer UUID") from exc

        if fingerprint is not None:
            self._pin_manually(server_id, fingerprint, dry_run=options["dry_run"], force=options["force"])
            return

        candidates = VirtualminServer.objects.filter(
            use_ssl=True,
            ssl_verify=False,
            ssl_cert_fingerprint="",
        )
        if server_id is not None:
            candidates = candidates.filter(pk=server_id)
        servers = list(candidates)

        # A targeted run that matched nothing is an operator error, not a clean result. It
        # otherwise printed a green "Pinned 0 certificate(s)" and exited 0 — indistinguishable
        # from "remediated" — for a wrong id, an already-pinned row, or a CA-verified row.
        if server_id is not None and not servers:
            raise CommandError(self._explain_non_candidate(server_id))

        stranded = [s for s in servers if not self._has_deployment(s)]
        self._report_unpinnable(stranded, server_id)

        if options["dry_run"]:
            self.stdout.write(f"Would pin {len(servers) - len(stranded)} Virtualmin certificate(s)")
            return

        validation = get_validation_service()
        pinned = 0
        failed = 0
        for server in servers:
            try:
                deployment = server.node_deployment
            except ObjectDoesNotExist:
                failed += 1
                self.stderr.write(
                    self.style.WARNING(
                        f"Skipped VirtualminServer {server.id} ({server.hostname}): no linked node deployment"
                    )
                )
                continue

            result = validation.get_webmin_certificate_fingerprint(deployment)
            if result.is_err():
                failed += 1
                self.stderr.write(
                    self.style.WARNING(
                        f"Could not pin VirtualminServer {server.id} ({server.hostname}): {result.unwrap_err()}"
                    )
                )
                continue

            server.ssl_cert_fingerprint = result.unwrap()
            server.save(update_fields=["ssl_cert_fingerprint", "updated_at"])
            pinned += 1

        self.stdout.write(self.style.SUCCESS(f"Pinned {pinned} Virtualmin certificate(s)"))
        if failed:
            raise CommandError(f"Failed to pin {failed} Virtualmin certificate(s)")

    def _report_unpinnable(self, stranded: list[VirtualminServer], server_id: str | None) -> None:
        """Surface rows that lose API connectivity, BEFORE the run reports a failure count (#337).

        Two classes fail the fail-closed guard in ``_execute_http_request`` and neither is
        fixed by a normal run: rows with no linked deployment (the SSH path cannot reach
        them) and plain-HTTP rows (no pin makes HTTP acceptable). An operator sizing the
        rollout needs both lists up front, not a bare "Failed to pin N" at the end.
        """
        if stranded:
            self.stderr.write(
                self.style.WARNING(
                    f"{len(stranded)} candidate(s) have no linked node deployment and cannot be pinned over SSH:"
                )
            )
            for server in stranded:
                self.stderr.write(self.style.WARNING(f"  - VirtualminServer {server.id} ({server.hostname})"))
            self.stderr.write(
                self.style.WARNING(
                    "Link a node deployment, or pin one explicitly with "
                    "--server-id <id> --fingerprint <sha256> using a value read on the node itself."
                )
            )

        # NOT candidates (the filter requires use_ssl=True), but they fail the same guard.
        # Active rows only: a decommissioned node is not outstanding remediation work, and
        # listing it forever trains operators to skim past the section.
        insecure = VirtualminServer.objects.filter(use_ssl=False, status="active")
        if server_id is not None:
            insecure = insecure.filter(pk=server_id)
        insecure_servers = list(insecure)
        if insecure_servers:
            self.stderr.write(
                self.style.WARNING(
                    f"{len(insecure_servers)} server(s) still use plain HTTP and will be rejected regardless of "
                    "pinning; enable HTTPS on those nodes:"
                )
            )
            for server in insecure_servers:
                self.stderr.write(self.style.WARNING(f"  - VirtualminServer {server.id} ({server.hostname})"))

    @staticmethod
    def _has_deployment(server: VirtualminServer) -> bool:
        try:
            return server.node_deployment is not None
        except ObjectDoesNotExist:
            return False

    def _explain_non_candidate(self, server_id: str) -> str:
        """Say WHY a targeted id produced no candidate, instead of reporting a clean zero."""
        server = VirtualminServer.objects.filter(pk=server_id).first()
        if server is None:
            return f"VirtualminServer {server_id} does not exist"
        if not server.use_ssl:
            return (
                f"VirtualminServer {server_id} ({server.hostname}) has use_ssl=False - enable HTTPS on the node; "
                "a certificate pin cannot make plain HTTP acceptable"
            )
        if server.ssl_verify:
            return (
                f"VirtualminServer {server_id} ({server.hostname}) uses CA verification (ssl_verify=True) "
                "and needs no pin"
            )
        if server.ssl_cert_fingerprint:
            return (
                f"VirtualminServer {server_id} ({server.hostname}) is already pinned. Re-pin a specific server "
                "with --fingerprint <sha256> --force"
            )
        return f"VirtualminServer {server_id} ({server.hostname}) is not a pinning candidate"

    def _pin_manually(self, server_id: str | None, fingerprint: str, *, dry_run: bool, force: bool) -> None:
        """Apply an operator-supplied pin to a single server.

        #337: the SSH path needs a NodeDeployment (for the IP and the host-key trust
        anchor), so legacy rows created through the admin form have no way to be pinned
        and stay hard-blocked by the fail-closed guard. This is the documented escape
        hatch — deliberately NOT a network read, which would be exactly the TOFU this
        command exists to avoid. The operator vouches for the value; the command only
        validates its shape.
        """
        if server_id is None:
            raise CommandError("--fingerprint requires --server-id (it pins exactly one server)")

        try:
            normalized = normalize_tls_cert_fingerprint(fingerprint)
        except OutboundSecurityError as exc:
            raise CommandError(str(exc)) from exc
        if not normalized:
            raise CommandError("--fingerprint cannot be empty")

        # Shape is already guaranteed: handle() validates the UUID for BOTH paths before
        # dispatching, so the only failure left here is a well-formed id that matches nothing.
        try:
            server = VirtualminServer.objects.get(pk=server_id)
        except VirtualminServer.DoesNotExist as exc:
            raise CommandError(f"VirtualminServer {server_id} does not exist") from exc

        # A pin does nothing for a plain-HTTP row: the HTTPS guard rejects it first. Fail
        # loudly rather than let an operator believe the row has been remediated.
        if not server.use_ssl:
            raise CommandError(
                f"VirtualminServer {server_id} ({server.hostname}) has use_ssl=False. "
                "Enable HTTPS on the node first — a certificate pin cannot make plain HTTP acceptable."
            )

        # Refuse to silently retarget an existing trust anchor. _report_unpinnable prints a
        # list of UUIDs directly above the command an operator pastes, so a mis-paste would
        # otherwise replace a healthy SSH-derived pin with another node's digest — and the
        # fleet run cannot heal that, because its candidate filter requires an EMPTY pin.
        previous = server.ssl_cert_fingerprint
        if previous and not force:
            raise CommandError(
                f"VirtualminServer {server_id} ({server.hostname}) is already pinned to {previous}. "
                "Re-run with --force if you intend to replace it."
            )

        if dry_run:
            action = "Would re-pin" if previous else "Would pin"
            self.stdout.write(f"{action} VirtualminServer {server.id} ({server.hostname}) with the supplied digest")
            return

        server.ssl_cert_fingerprint = normalized
        server.save(update_fields=["ssl_cert_fingerprint", "updated_at"])

        # A TLS trust anchor changed from a shell. VirtualminServer is allowlisted out of
        # signal-based audit, so without this the change leaves no forensic record at all --
        # and after a mis-pin there would be no way to learn what the pin used to be.
        log_security_event(
            "virtualmin_cert_pin_set_manually",
            {
                "server_id": str(server.id),
                "hostname": server.hostname,
                "old_fingerprint": previous or "",
                "new_fingerprint": normalized,
                "replaced_existing": bool(previous),
            },
        )
        verb = "Re-pinned" if previous else "Pinned"
        detail = f" (was {previous})" if previous else ""
        self.stdout.write(
            self.style.SUCCESS(
                f"{verb} VirtualminServer {server.id} ({server.hostname}) from operator-supplied digest{detail}"
            )
        )
