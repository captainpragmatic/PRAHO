"""
Infrastructure CLI: reconcile_deployment

Clear a node deployment's reconciliation flag once nothing it owned remains. Retry, the cleanup sweeps
and re-deploy refuse a flagged deployment; this is the operator's way out.

The command searches the provider project (by label, name, recorded firewall id and SSH key
fingerprint) and the DNS zones (by stored record id, stored name, current name and the deployment's
tag). Anything found, any failed lookup or any unreadable zone refuses, and the deployment stays
flagged. It never deletes anything. On success the deployment is settled destroyed, with a log entry
and an audit event that record the operator, the invoking OS user and the evidence.

Shell access to the platform host is the authorization boundary. ``--operator`` must name an active
staff user with the destroy permission.

Usage examples::

    # See what would be searched, writing nothing
    $ python manage.py reconcile_deployment stg-sha-het-fi-hel1-002 --operator ops@example.com --dry-run

    # A deployment whose provider token was never recorded: attest after checking the console
    $ python manage.py reconcile_deployment stg-sha-het-fi-hel1-002 --operator ops@example.com \\
          --attest-no-resources --attest-never-created \\
          --evidence "Hetzner console, project X: no server, firewall or key; create refused (log 12)"
"""

from __future__ import annotations

import getpass
import os
import socket
from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.infrastructure.reconciliation import ReconcileRequest, reconcile_deployment


class Command(BaseCommand):
    help = "Clear a deployment's reconciliation flag once nothing it owned remains"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("hostname", help="The deployment's hostname")
        parser.add_argument("--operator", required=True, help="Email of the staff user taking responsibility")
        parser.add_argument("--evidence", default="", help="What was checked, where, and a ticket or link")
        parser.add_argument(
            "--attest-no-resources",
            action="store_true",
            help="Attest that the provider project holds nothing for this deployment (no recorded token)",
        )
        parser.add_argument(
            "--attest-never-created",
            action="store_true",
            help="Attest that no server was ever created (an unknown create outcome only); allows re-deploy",
        )
        parser.add_argument("--dry-run", action="store_true", help="Search and report, writing nothing")

    def handle(self, *args: Any, **options: Any) -> None:
        invoker = {
            "os_user": getpass.getuser(),
            "sudo_user": os.environ.get("SUDO_USER", ""),
            "host": socket.gethostname(),
        }
        result = reconcile_deployment(
            ReconcileRequest(
                hostname=options["hostname"],
                operator_email=options["operator"],
                evidence=options["evidence"],
                attest_no_resources=options["attest_no_resources"],
                attest_never_created=options["attest_never_created"],
                dry_run=options["dry_run"],
                invoker=invoker,
            )
        )
        if result.is_err():
            raise CommandError(f"Not reconciled: {result.unwrap_err()}")
        report = result.unwrap()
        for line in report.searched:
            self.stdout.write(f"  searched {line}: nothing found")
        if report.settled:
            self.stdout.write(
                self.style.SUCCESS(f"✅ {report.hostname} reconciled ({report.provenance}) and destroyed")
            )
        else:
            self.stdout.write(f"Dry run: {report.hostname} would be reconciled ({report.provenance}); nothing written")
