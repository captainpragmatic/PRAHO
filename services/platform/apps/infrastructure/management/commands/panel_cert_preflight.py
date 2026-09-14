"""Print read-only prerequisites for the #436 certificate drill."""

from __future__ import annotations

import json
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from apps.infrastructure.models import CloudProvider, NodeDeployment
from apps.infrastructure.panel_cert_preflight import LIMITATION, PanelCertPreflightService


class Command(BaseCommand):
    help = "Read-only Hetzner/Virtualmin certificate drill prerequisites; never issues or activates"

    def add_arguments(self, parser: CommandParser) -> None:
        target = parser.add_mutually_exclusive_group(required=True)
        target.add_argument("--provider-id", type=int, help="Check configuration before provisioning")
        target.add_argument("--deployment-id", type=int, help="Also inspect an existing Virtualmin node")
        parser.add_argument("--json", action="store_true", help="Emit a structured report on stdout")

    def handle(self, *args: Any, **options: Any) -> None:
        deployment = None
        provider: CloudProvider | None
        if options["deployment_id"] is not None:
            deployment = (
                NodeDeployment.objects.select_related("provider", "panel_type")
                .filter(pk=options["deployment_id"])
                .first()
            )
            if deployment is None:
                raise CommandError("Deployment ID was not found")
            provider = deployment.provider
        else:
            provider = CloudProvider.objects.filter(pk=options["provider_id"]).first()
            if provider is None:
                raise CommandError("Provider ID was not found")
        report = PanelCertPreflightService().run(provider, deployment)
        if options["json"]:
            self.stdout.write(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        else:
            self.stdout.write(LIMITATION)
            self.stdout.write(f"Scope: {report.mode} {report.target_id}")
            for check in report.checks:
                self.stdout.write(f"{check.status.upper():7} {check.check_id}: {check.message}")
            self.stdout.write(f"Certificate: {report.certificate.status} — {report.certificate.message}")
            if report.certificate.cert_sha256:
                self.stdout.write(f"SHA-256: {report.certificate.cert_sha256}; expiry: {report.certificate.not_after}")
            self.stdout.write(f"Scoped prerequisites: {'PASS' if report.prerequisites_pass else 'INCOMPLETE'}")
        if not report.prerequisites_pass:
            raise CommandError("Preflight prerequisites failed or remain indeterminate; review the report")
