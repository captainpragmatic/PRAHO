"""
Audit Compliance Management Command

This command provides audit and compliance operations:
- Generate compliance reports
- Verify log integrity
- Apply retention policies
- Export audit logs for SIEM
- Check compliance status
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.audit.compliance import (
    ComplianceFramework,
    ComplianceReportService,
    LogRetentionService,
    ReportFormat,
    ReportType,
)
from apps.audit.siem import SIEMFormat, get_siem_service


class Command(BaseCommand):
    help = "Audit and compliance management operations"

    def add_arguments(self, parser: Any) -> None:
        subparsers = parser.add_subparsers(dest="subcommand", help="Sub-commands")

        # Generate report command
        report_parser = subparsers.add_parser(
            "report",
            help="Generate compliance reports"
        )
        report_parser.add_argument(
            "--type",
            choices=[rt.value for rt in ReportType],
            default="security_summary",
            help="Type of report to generate",
        )
        report_parser.add_argument(
            "--days",
            type=int,
            default=30,
            help="Number of days to cover (default: 30)",
        )
        report_parser.add_argument(
            "--framework",
            choices=[cf.value for cf in ComplianceFramework],
            help="Filter by compliance framework",
        )
        report_parser.add_argument(
            "--format",
            choices=[rf.value for rf in ReportFormat],
            default="json",
            help="Output format (default: json)",
        )
        report_parser.add_argument(
            "--output",
            help="Custom output path",
        )

        # Verify integrity command
        verify_parser = subparsers.add_parser(
            "verify-integrity",
            help="Verify audit log integrity"
        )
        verify_parser.add_argument(
            "--days",
            type=int,
            default=7,
            help="Number of days to verify (default: 7)",
        )
        verify_parser.add_argument(
            "--verbose",
            action="store_true",
            help="Show detailed output",
        )

        # Apply retention policies command
        retention_parser = subparsers.add_parser(
            "apply-retention",
            help="Apply log retention policies"
        )
        retention_parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be done without making changes",
        )
        retention_parser.add_argument(
            "--category",
            help="Process only specific category",
        )

        # Check retention status command
        status_parser = subparsers.add_parser(
            "retention-status",
            help="Check log retention status"
        )
        status_parser.add_argument(
            "--json",
            action="store_true",
            help="Output as JSON",
        )

        # Export to SIEM command
        export_parser = subparsers.add_parser(
            "export-siem",
            help="Export audit logs for SIEM ingestion"
        )
        export_parser.add_argument(
            "--days",
            type=int,
            default=1,
            help="Number of days to export (default: 1)",
        )
        export_parser.add_argument(
            "--format",
            choices=[sf.value for sf in SIEMFormat],
            default="json",
            help="SIEM format (default: json)",
        )
        export_parser.add_argument(
            "--output",
            required=True,
            help="Output file path",
        )
        export_parser.add_argument(
            "--min-severity",
            choices=["low", "medium", "high", "critical"],
            default="low",
            help="Minimum severity to export (default: low)",
        )

        # Compliance check command
        check_parser = subparsers.add_parser(
            "check",
            help="Run compliance checks"
        )
        check_parser.add_argument(
            "--framework",
            choices=[cf.value for cf in ComplianceFramework],
            help="Check specific framework",
        )
        check_parser.add_argument(
            "--days",
            type=int,
            default=30,
            help="Period to check (default: 30 days)",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        subcommand = options.get("subcommand")

        if not subcommand:
            self.print_help("manage.py", "audit_compliance")
            return

        handlers = {
            "report": self.handle_report,
            "verify-integrity": self.handle_verify_integrity,
            "apply-retention": self.handle_apply_retention,
            "retention-status": self.handle_retention_status,
            "export-siem": self.handle_export_siem,
            "check": self.handle_compliance_check,
        }

        handler = handlers.get(subcommand)
        if handler:
            handler(options)
        else:
            raise CommandError(f"Unknown subcommand: {subcommand}")

    def handle_report(self, options: dict[str, Any]) -> None:
        """Generate compliance report"""
        self.stdout.write(self.style.NOTICE("Generating compliance report..."))

        service = ComplianceReportService()

        period_end = timezone.now()
        period_start = period_end - timedelta(days=options["days"])

        framework = None
        if options.get("framework"):
            framework = ComplianceFramework(options["framework"])

        report = service.generate_report(
            report_type=ReportType(options["type"]),
            period_start=period_start,
            period_end=period_end,
            framework=framework,
            generated_by="management_command",
        )

        # Export report
        output_format = ReportFormat(options["format"])
        filepath = service.export_report(report, output_format)

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("=" * 60))
        self.stdout.write(self.style.SUCCESS("COMPLIANCE REPORT GENERATED"))
        self.stdout.write(self.style.SUCCESS("=" * 60))
        self.stdout.write(f"Report ID: {report.report_id}")
        self.stdout.write(f"Type: {report.report_type.value}")
        self.stdout.write(f"Period: {period_start.date()} to {period_end.date()}")
        self.stdout.write("")
        self.stdout.write(f"Overall Status: {self._colorize_status(report.overall_status)}")
        self.stdout.write(f"Compliance Score: {report.compliance_score:.1f}%")
        self.stdout.write(f"Total Events: {report.total_events}")
        self.stdout.write(f"Total Violations: {report.total_violations}")
        self.stdout.write(f"Critical Findings: {report.critical_findings}")
        self.stdout.write("")
        self.stdout.write(f"Report exported to: {filepath}")

        if report.violations:
            self.stdout.write("")
            self.stdout.write(self.style.WARNING("VIOLATIONS:"))
            for v in report.violations[:10]:  # Show first 10
                severity_style = self._get_severity_style(v.severity)
                self.stdout.write(f"  [{severity_style}] {v.framework} {v.control_id}: {v.description}")

            if len(report.violations) > 10:
                self.stdout.write(f"  ... and {len(report.violations) - 10} more")

    def handle_verify_integrity(self, options: dict[str, Any]) -> None:
        """Verify audit log integrity"""
        self.stdout.write(self.style.NOTICE("Verifying audit log integrity..."))

        siem = get_siem_service()

        period_end = timezone.now()
        period_start = period_end - timedelta(days=options["days"])

        is_valid, errors = siem.verify_log_integrity(period_start, period_end)

        self.stdout.write("")
        if is_valid:
            self.stdout.write(self.style.SUCCESS("Audit log integrity VERIFIED"))
            self.stdout.write(f"Period: {period_start.date()} to {period_end.date()}")
            self.stdout.write("No integrity issues detected.")
        else:
            self.stdout.write(self.style.ERROR("Audit log integrity FAILED"))
            self.stdout.write(f"Found {len(errors)} integrity issues:")
            for error in errors:
                self.stdout.write(f"  - {error}")

    def handle_apply_retention(self, options: dict[str, Any]) -> None:
        """Apply log retention policies"""
        if options["dry_run"]:
            self.stdout.write(self.style.WARNING("DRY RUN - No changes will be made"))

        self.stdout.write(self.style.NOTICE("Applying log retention policies..."))

        service = LogRetentionService()

        if options["dry_run"]:
            status = service.get_retention_status()
            self.stdout.write("")
            self.stdout.write("Retention status (dry run):")
            for category, info in status.items():
                if info["events_past_retention"] > 0:
                    self.stdout.write(
                        f"  {category}: {info['events_past_retention']} events "
                        f"past {info['retention_days']}-day retention "
                        f"(action: {info['action']})"
                    )
        else:
            summary = service.apply_retention_policies()

            self.stdout.write("")
            self.stdout.write(self.style.SUCCESS("Retention policies applied:"))
            self.stdout.write(f"  Archived: {summary['archived']}")
            self.stdout.write(f"  Deleted: {summary['deleted']}")
            self.stdout.write(f"  Anonymized: {summary['anonymized']}")

            if summary["errors"]:
                self.stdout.write(self.style.ERROR(f"  Errors: {len(summary['errors'])}"))
                for error in summary["errors"]:
                    self.stdout.write(f"    - {error['category']}: {error['error']}")

    def handle_retention_status(self, options: dict[str, Any]) -> None:
        """Check log retention status"""
        service = LogRetentionService()
        status = service.get_retention_status()

        if options["json"]:
            self.stdout.write(json.dumps(status, indent=2, default=str))
            return

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("=" * 60))
        self.stdout.write(self.style.SUCCESS("LOG RETENTION STATUS"))
        self.stdout.write(self.style.SUCCESS("=" * 60))
        self.stdout.write("")

        for category, info in status.items():
            status_color = (
                self.style.SUCCESS if info["compliance_status"] == "compliant"
                else self.style.WARNING
            )
            self.stdout.write(f"{category.upper()}")
            self.stdout.write(f"  Retention: {info['retention_days']} days")
            self.stdout.write(f"  Action: {info['action']}")
            self.stdout.write(f"  Legal Basis: {info['legal_basis']}")
            self.stdout.write(f"  Total Events: {info['total_events']}")
            self.stdout.write(f"  Past Retention: {info['events_past_retention']}")
            self.stdout.write(f"  Status: {status_color(info['compliance_status'])}")
            self.stdout.write("")

    def handle_export_siem(self, options: dict[str, Any]) -> None:
        """Export audit logs for SIEM"""
        from apps.audit.models import AuditEvent
        from apps.audit.siem import (
            CEFFormatter,
            JSONFormatter,
            LEEFFormatter,
            OCSFFormatter,
            SIEMConfig,
            SIEMFormat,
            SyslogFormatter,
        )

        self.stdout.write(self.style.NOTICE("Exporting audit logs for SIEM..."))

        period_end = timezone.now()
        period_start = period_end - timedelta(days=options["days"])

        # Get severity filter
        severity_order = ["low", "medium", "high", "critical"]
        min_severity_idx = severity_order.index(options["min_severity"])

        # Fetch events
        events = AuditEvent.objects.filter(
            timestamp__gte=period_start,
            timestamp__lte=period_end,
        ).select_related("user", "content_type")

        # Filter by severity
        events = [
            e for e in events
            if severity_order.index(e.severity) >= min_severity_idx
        ]

        # Get formatter
        formatters = {
            "cef": CEFFormatter,
            "leef": LEEFFormatter,
            "json": JSONFormatter,
            "syslog": SyslogFormatter,
            "ocsf": OCSFFormatter,
        }
        formatter_class = formatters[options["format"]]
        formatter = formatter_class()

        config = SIEMConfig(format=SIEMFormat(options["format"]))

        # Get SIEM service to convert events
        siem = get_siem_service()

        # Export
        output_path = options["output"]
        with open(output_path, "w", encoding="utf-8") as f:
            for event in events:
                entry = siem._create_log_entry(event)
                formatted = formatter.format(entry, config)
                f.write(formatted + "\n")

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(f"Exported {len(events)} events to {output_path}"))
        self.stdout.write(f"Format: {options['format'].upper()}")
        self.stdout.write(f"Period: {period_start.date()} to {period_end.date()}")
        self.stdout.write(f"Min Severity: {options['min_severity']}")

    def handle_compliance_check(self, options: dict[str, Any]) -> None:
        """Run compliance checks"""
        self.stdout.write(self.style.NOTICE("Running compliance checks..."))

        service = ComplianceReportService()

        period_end = timezone.now()
        period_start = period_end - timedelta(days=options["days"])

        framework = None
        if options.get("framework"):
            framework = ComplianceFramework(options["framework"])

        report = service.generate_report(
            report_type=ReportType.COMPLIANCE_VIOLATIONS,
            period_start=period_start,
            period_end=period_end,
            framework=framework,
        )

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("=" * 60))
        self.stdout.write(self.style.SUCCESS("COMPLIANCE CHECK RESULTS"))
        self.stdout.write(self.style.SUCCESS("=" * 60))
        self.stdout.write("")
        self.stdout.write(f"Period: {period_start.date()} to {period_end.date()}")
        self.stdout.write(f"Framework: {framework.value if framework else 'All'}")
        self.stdout.write("")
        self.stdout.write(f"Overall Status: {self._colorize_status(report.overall_status)}")
        self.stdout.write(f"Compliance Score: {report.compliance_score:.1f}%")
        self.stdout.write("")

        if report.violations:
            self.stdout.write(self.style.WARNING(f"Found {len(report.violations)} violations:"))
            self.stdout.write("")

            # Group by framework
            by_framework: dict[str, list[Any]] = {}
            for v in report.violations:
                if v.framework not in by_framework:
                    by_framework[v.framework] = []
                by_framework[v.framework].append(v)

            for fw, violations in by_framework.items():
                self.stdout.write(f"  {fw.upper()}:")
                for v in violations:
                    severity_style = self._get_severity_style(v.severity)
                    self.stdout.write(f"    [{severity_style}] {v.control_id}: {v.description}")
                    if v.remediation:
                        self.stdout.write(f"       Remediation: {v.remediation}")
                self.stdout.write("")
        else:
            self.stdout.write(self.style.SUCCESS("No compliance violations found!"))

    def _colorize_status(self, status: str) -> str:
        """Colorize compliance status"""
        if status == "compliant":
            return self.style.SUCCESS(status.upper())
        elif status == "partial":
            return self.style.WARNING(status.upper())
        else:
            return self.style.ERROR(status.upper())

    def _get_severity_style(self, severity: str) -> str:
        """Get styled severity text"""
        if severity == "critical":
            return self.style.ERROR(severity.upper())
        elif severity == "high":
            return self.style.WARNING(severity.upper())
        elif severity == "medium":
            return self.style.NOTICE(severity.upper())
        else:
            return severity.upper()
