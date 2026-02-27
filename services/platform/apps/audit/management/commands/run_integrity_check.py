"""
Management command for running audit integrity checks.

This command supports both manual and scheduled execution to:
- Verify cryptographic hash chains
- Detect sequence gaps in audit logs
- Check GDPR compliance
- Monitor file integrity changes
- Generate integrity reports

Usage:
    python manage.py run_integrity_check --type hash_verification --period 24h
    python manage.py run_integrity_check --type all --period 7d --alert
    python manage.py run_integrity_check --schedule  # Configure scheduled task
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, ClassVar

from django.core.management.base import BaseCommand, CommandParser
from django.utils import timezone

from apps.audit.services import AuditIntegrityService
from apps.common.types import Ok

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Management command for audit integrity verification."""

    help = "Run audit data integrity checks and file integrity monitoring"

    # Check types supported
    CHECK_TYPES: ClassVar[list[str]] = [
        "hash_verification",
        "sequence_check",
        "gdpr_compliance",
        "all",
    ]

    # Period shortcuts
    PERIOD_MAP: ClassVar[dict[str, timedelta]] = {
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "12h": timedelta(hours=12),
        "24h": timedelta(hours=24),
        "1d": timedelta(days=1),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
        "90d": timedelta(days=90),
    }

    def add_arguments(self, parser: CommandParser) -> None:
        """Add command arguments."""
        parser.add_argument(
            "--type",
            type=str,
            choices=self.CHECK_TYPES,
            default="all",
            help="Type of integrity check to run (default: all)",
        )
        parser.add_argument(
            "--period",
            type=str,
            default="24h",
            help="Time period to check (e.g., 1h, 24h, 7d, 30d)",
        )
        parser.add_argument(
            "--start",
            type=str,
            help="Start datetime (ISO format) - overrides period",
        )
        parser.add_argument(
            "--end",
            type=str,
            help="End datetime (ISO format) - overrides period",
        )
        parser.add_argument(
            "--alert",
            action="store_true",
            help="Send alerts for any issues found",
        )
        parser.add_argument(
            "--schedule",
            action="store_true",
            help="Configure scheduled integrity checks",
        )
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Show detailed output",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """Execute the command."""
        if options["schedule"]:
            self._setup_scheduled_tasks()
            return

        # Parse time period
        period_start, period_end = self._parse_period(options)

        check_type = options["type"]
        verbose = options["verbose"]

        self.stdout.write(
            self.style.HTTP_INFO(
                f"\n{'='*60}\n"
                f"PRAHO Audit Integrity Check\n"
                f"{'='*60}\n"
                f"Period: {period_start.isoformat()} to {period_end.isoformat()}\n"
                f"Check Type: {check_type}\n"
                f"{'='*60}\n"
            )
        )

        if check_type == "all":
            # Run all check types
            results = self._run_all_checks(period_start, period_end, verbose)
        else:
            # Run specific check
            results = [self._run_check(check_type, period_start, period_end, verbose)]

        # Summary
        self._print_summary(results, options["alert"])

    def _parse_period(self, options: dict[str, Any]) -> tuple[Any, Any]:
        """Parse the time period from options."""
        if options.get("start") and options.get("end"):
            from django.utils.dateparse import parse_datetime  # noqa: PLC0415

            period_start = parse_datetime(options["start"])
            period_end = parse_datetime(options["end"])
            if not period_start or not period_end:
                self.stderr.write(self.style.ERROR("Invalid datetime format"))
                raise SystemExit(1)
        else:
            period_str = options.get("period", "24h")
            delta = self.PERIOD_MAP.get(period_str)
            if not delta:
                # Try to parse as hours
                try:
                    hours = int(period_str.rstrip("h"))
                    delta = timedelta(hours=hours)
                except ValueError:
                    try:
                        days = int(period_str.rstrip("d"))
                        delta = timedelta(days=days)
                    except ValueError:
                        self.stderr.write(self.style.ERROR(f"Invalid period format: {period_str}"))
                        raise SystemExit(1) from None

            period_end = timezone.now()
            period_start = period_end - delta

        return period_start, period_end

    def _run_check(
        self,
        check_type: str,
        period_start: Any,
        period_end: Any,
        verbose: bool,
    ) -> dict[str, Any]:
        """Run a single integrity check."""
        self.stdout.write(f"\nRunning {check_type}...")

        result = AuditIntegrityService.verify_audit_integrity(
            period_start=period_start,
            period_end=period_end,
            check_type=check_type,
        )

        if isinstance(result, Ok):
            check = result.value
            status_style = {
                "healthy": self.style.SUCCESS,
                "warning": self.style.WARNING,
                "compromised": self.style.ERROR,
            }.get(check.status, self.style.NOTICE)

            self.stdout.write(
                f"  Status: {status_style(check.status.upper())}\n"
                f"  Records Checked: {check.records_checked}\n"
                f"  Issues Found: {check.issues_found}"
            )

            if verbose and check.findings:
                self.stdout.write("\n  Findings:")
                for finding in check.findings[:10]:  # Limit output
                    self.stdout.write(
                        f"    - [{finding.get('severity', 'unknown')}] "
                        f"{finding.get('description', 'No description')}"
                    )

            return {
                "check_type": check_type,
                "status": check.status,
                "records": check.records_checked,
                "issues": check.issues_found,
                "check_id": str(check.id),
            }
        else:
            self.stdout.write(self.style.ERROR(f"  Error: {result.error}"))
            return {
                "check_type": check_type,
                "status": "error",
                "error": result.error,
            }

    def _run_all_checks(
        self,
        period_start: Any,
        period_end: Any,
        verbose: bool,
    ) -> list[dict[str, Any]]:
        """Run all integrity check types."""
        results = []
        check_types = ["hash_verification", "sequence_check", "gdpr_compliance"]

        for check_type in check_types:
            result = self._run_check(check_type, period_start, period_end, verbose)
            results.append(result)

        return results

    def _print_summary(self, results: list[dict[str, Any]], send_alerts: bool) -> None:
        """Print summary of all checks."""
        self.stdout.write(self.style.HTTP_INFO(f"\n{'='*60}\n" f"INTEGRITY CHECK SUMMARY\n" f"{'='*60}"))

        total_issues = 0
        compromised = False

        for result in results:
            status = result.get("status", "unknown")
            issues = result.get("issues", 0)
            total_issues += issues if isinstance(issues, int) else 0

            if status == "compromised":
                compromised = True

            status_str = {
                "healthy": self.style.SUCCESS("HEALTHY"),
                "warning": self.style.WARNING("WARNING"),
                "compromised": self.style.ERROR("COMPROMISED"),
                "error": self.style.ERROR("ERROR"),
            }.get(status, status)

            self.stdout.write(f"  {result['check_type']}: {status_str}")

        self.stdout.write(f"\nTotal Issues Found: {total_issues}")

        if compromised:
            self.stdout.write(
                self.style.ERROR("\nCRITICAL: Compromised audit data detected!\n" "Immediate investigation required.")
            )
            if send_alerts:
                self.stdout.write("  Alerts have been sent to security team.")
        elif total_issues > 0:
            self.stdout.write(self.style.WARNING(f"\nWARNING: {total_issues} issues require attention."))
        else:
            self.stdout.write(self.style.SUCCESS("\nAll integrity checks passed successfully."))

    def _setup_scheduled_tasks(self) -> None:
        """Configure scheduled integrity check tasks using Django-Q2."""
        try:
            from django_q.models import Schedule  # noqa: PLC0415

            # Hourly hash verification for critical events
            Schedule.objects.update_or_create(
                name="audit_integrity_hourly",
                defaults={
                    "func": "apps.audit.tasks.run_integrity_check",
                    "args": "('hash_verification', '1h')",
                    "schedule_type": Schedule.HOURLY,
                    "repeats": -1,  # Run forever
                },
            )
            self.stdout.write(self.style.SUCCESS("Created hourly hash verification schedule"))

            # Daily comprehensive check
            Schedule.objects.update_or_create(
                name="audit_integrity_daily",
                defaults={
                    "func": "apps.audit.tasks.run_integrity_check",
                    "args": "('all', '24h')",
                    "schedule_type": Schedule.DAILY,
                    "repeats": -1,
                },
            )
            self.stdout.write(self.style.SUCCESS("Created daily comprehensive check schedule"))

            # Weekly deep analysis
            Schedule.objects.update_or_create(
                name="audit_integrity_weekly",
                defaults={
                    "func": "apps.audit.tasks.run_integrity_check",
                    "args": "('all', '7d')",
                    "schedule_type": Schedule.WEEKLY,
                    "repeats": -1,
                },
            )
            self.stdout.write(self.style.SUCCESS("Created weekly deep analysis schedule"))

            # File integrity monitoring (every 6 hours)
            Schedule.objects.update_or_create(
                name="file_integrity_monitoring",
                defaults={
                    "func": "apps.audit.tasks.run_file_integrity_check",
                    "schedule_type": Schedule.HOURLY,
                    "minutes": 360,  # Every 6 hours
                    "repeats": -1,
                },
            )
            self.stdout.write(self.style.SUCCESS("Created file integrity monitoring schedule (6h)"))

            self.stdout.write(
                self.style.SUCCESS(
                    "\nAll scheduled tasks configured successfully!\n"
                    "Run 'python manage.py qcluster' to start the task worker."
                )
            )

        except ImportError:
            self.stderr.write(self.style.ERROR("Django-Q2 not installed. Install with: pip install django-q2"))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Failed to setup schedules: {e}"))
