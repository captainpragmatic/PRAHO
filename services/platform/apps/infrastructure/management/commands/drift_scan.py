"""
Infrastructure CLI: drift_scan

Run configuration drift scans from the command line. Compares the actual
state of cloud servers against the expected state stored in PRAHO's database.
Detects server state changes, network mismatches, firewall drift, and
application-level differences.

The DriftScannerService fetches its own credentials via the credential vault
internally, so this command doesn't need to handle tokens directly.

Exits with code 1 if any drifts are found, enabling CI/cron integration::

    # Alert on drift in CI pipeline
    python manage.py drift_scan --all || send_alert "Drift detected!"

Usage examples::

    # Scan a specific deployment
    $ python manage.py drift_scan --deployment prd-sha-het-de-fsn1-001

    # Scan all deployments for a provider
    $ python manage.py drift_scan --provider hetzner

    # Scan everything
    $ python manage.py drift_scan --all

    # Scan with specific check types
    $ python manage.py drift_scan --all --check-types cloud,network

    # JSON output for programmatic consumption
    $ python manage.py drift_scan --all --output json

See also:
    - manage_node: Lifecycle operations on deployed nodes
    - cleanup_deployments: Clean up stale failed deployments
    - sync_providers: Sync provider catalog data
"""

from __future__ import annotations

import json
import sys
from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.infrastructure.models import DriftReport


class Command(BaseCommand):
    """
    Run configuration drift scans on infrastructure deployments.

    Delegates to ``DriftScannerService.scan_deployment()`` for each deployment
    in the target set. The scanner is provider-agnostic — it uses the
    CloudProviderGateway ABC to query actual server state from any provider.

    The command is designed for both interactive use and automation:
    - Text output for humans, JSON output for scripts
    - Non-zero exit code when drifts are found (for CI integration)
    - Errors on individual deployments don't abort the entire scan
    """

    help = "Run configuration drift scans on infrastructure deployments"

    def add_arguments(self, parser: ArgumentParser) -> None:
        # Target selection — at least one required
        target_group = parser.add_mutually_exclusive_group()
        target_group.add_argument(
            "--deployment",
            type=str,
            default=None,
            help="Hostname of a specific deployment to scan",
        )
        target_group.add_argument(
            "--provider",
            type=str,
            default=None,
            help="Scan all active deployments for a provider type",
        )
        target_group.add_argument(
            "--all",
            action="store_true",
            dest="scan_all",
            help="Scan all active (completed) deployments",
        )

        # Scan options
        parser.add_argument(
            "--check-types",
            type=str,
            default=None,
            help="Comma-separated check types (cloud, network, application). Default: all",
        )
        parser.add_argument(
            "--output",
            type=str,
            default="text",
            choices=["text", "json"],
            help="Output format (default: text)",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """
        Execute drift scans on the selected deployment set.

        Iterates through target deployments, runs the scanner, collects
        results, and outputs a summary. Individual scan errors are logged
        as warnings but don't abort the run.

        Exit codes:
            0 — No drifts found (all clean)
            1 — One or more drifts detected

        Raises:
            CommandError: If no target specified or target deployment not found.
        """
        from apps.infrastructure.drift_scanner import DriftScannerService

        # Resolve the set of deployments to scan
        deployments = self._resolve_targets(options)

        # Parse check types filter (e.g., "cloud,network" → ["cloud", "network"])
        check_types = None
        if options.get("check_types"):
            check_types = [t.strip() for t in options["check_types"].split(",")]

        scanner = DriftScannerService()
        output_format = options.get("output", "text")

        # Accumulate results across all deployments
        total_deployments = 0
        total_drifts = 0
        total_errors = 0
        all_results: list[dict[str, Any]] = []

        for deployment in deployments:
            total_deployments += 1
            if output_format == "text":
                self.stdout.write(f"🔍 Scanning {deployment.hostname}...")

            result = scanner.scan_deployment(deployment, check_types=check_types)

            if result.is_err():
                # Log error but continue scanning remaining deployments —
                # one provider outage shouldn't block scanning other providers
                total_errors += 1
                error_msg = result.unwrap_err()
                if output_format == "text":
                    self.stderr.write(
                        self.style.WARNING(f"  ⚠️  Error scanning {deployment.hostname}: {error_msg}")
                    )
                all_results.append({
                    "hostname": deployment.hostname,
                    "provider": deployment.provider.provider_type,
                    "status": "error",
                    "error": error_msg,
                    "drifts": [],
                })
                continue

            reports: list[DriftReport] = result.unwrap()
            drift_count = len(reports)
            total_drifts += drift_count

            if output_format == "text":
                if drift_count == 0:
                    self.stdout.write(self.style.SUCCESS("  ✅ No drifts found"))
                else:
                    self.stdout.write(
                        self.style.ERROR(f"  ⚠️  {drift_count} drift(s) found:")
                    )
                    for report in reports:
                        self.stdout.write(
                            f"    [{report.severity.upper()}] {report.category}: "
                            f"{report.field_name} (expected={report.expected_value}, actual={report.actual_value})"
                        )

            all_results.append({
                "hostname": deployment.hostname,
                "provider": deployment.provider.provider_type,
                "status": "ok",
                "drift_count": drift_count,
                "drifts": [
                    {
                        "severity": r.severity,
                        "category": r.category,
                        "field": r.field_name,
                        "expected": r.expected_value,
                        "actual": r.actual_value,
                    }
                    for r in reports
                ],
            })

        # Output summary
        if output_format == "json":
            json_output = {
                "total_deployments": total_deployments,
                "total_drifts": total_drifts,
                "total_errors": total_errors,
                "results": all_results,
            }
            self.stdout.write(json.dumps(json_output, indent=2))
        else:
            self.stdout.write(
                f"\n📊 Summary: {total_deployments} scanned, "
                f"{total_drifts} drift(s) found, {total_errors} error(s)"
            )

        # Exit code scheme for CI integration:
        # 0 = clean (no drifts, no errors)
        # 1 = drifts found (but no errors)
        # 2 = scan errors (but no drifts)
        # 3 = both drifts and errors
        exit_code = 0
        if total_drifts > 0:
            exit_code |= 1
        if total_errors > 0:
            exit_code |= 2
        if exit_code != 0:
            sys.exit(exit_code)

    def _resolve_targets(self, options: dict[str, Any]) -> Any:
        """
        Resolve the set of NodeDeployment objects to scan.

        Supports three targeting modes:
        - --deployment: single deployment by hostname
        - --provider: all completed deployments for a provider type
        - --all: all completed deployments

        Returns:
            QuerySet of NodeDeployment objects to scan.

        Raises:
            CommandError: If no target specified or deployment not found.
        """
        from apps.infrastructure.models import NodeDeployment

        if options.get("deployment"):
            deployment = NodeDeployment.objects.select_related("provider").filter(
                hostname=options["deployment"],
            ).first()
            if not deployment:
                raise CommandError(f"No deployment found with hostname '{options['deployment']}'.")
            return [deployment]

        if options.get("provider"):
            deployments = NodeDeployment.objects.select_related("provider").filter(
                provider__provider_type=options["provider"],
                status="completed",
            )
            if not deployments.exists():
                raise CommandError(
                    f"No completed deployments found for provider '{options['provider']}'."
                )
            return deployments

        if options.get("scan_all"):
            deployments = NodeDeployment.objects.select_related("provider").filter(
                status="completed",
            )
            if not deployments.exists():
                self.stdout.write(self.style.WARNING("No completed deployments found."))
                return []
            return deployments

        raise CommandError(
            "Specify a target: --deployment <hostname>, --provider <type>, or --all"
        )
