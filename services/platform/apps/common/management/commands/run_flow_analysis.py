"""
Django Management Command for Flow Analysis

Runs hybrid control-flow and data-flow analysis on Python files
to detect logical errors and security vulnerabilities.

Usage:
    python manage.py run_flow_analysis [path] [options]

Examples:
    # Analyze entire apps directory
    python manage.py run_flow_analysis apps/

    # Analyze a single file
    python manage.py run_flow_analysis apps/users/services.py

    # Analyze with specific modes
    python manage.py run_flow_analysis apps/ --mode control-flow
    python manage.py run_flow_analysis apps/ --mode data-flow

    # Output as JSON
    python manage.py run_flow_analysis apps/ --format json

    # Only show critical issues
    python manage.py run_flow_analysis apps/ --severity critical
"""

import json
import sys
from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.common.flow_analysis import (
    AnalysisResult,
    AnalysisSeverity,
    FlowIssue,
    HybridFlowAnalyzer,
)
from apps.common.flow_analysis.hybrid_analyzer import HybridAnalysisConfig


class Command(BaseCommand):
    """Run hybrid flow analysis on Python files."""

    help = "Analyze Python code for control-flow and data-flow issues"

    def add_arguments(self, parser: Any) -> None:
        """Add command line arguments."""
        parser.add_argument(
            "path",
            nargs="?",
            default="apps/",
            help="Path to file or directory to analyze (default: apps/)",
        )

        parser.add_argument(
            "--mode",
            "-m",
            choices=["hybrid", "control-flow", "data-flow"],
            default="hybrid",
            help="Analysis mode (default: hybrid)",
        )

        parser.add_argument(
            "--severity",
            "-s",
            choices=["info", "low", "medium", "high", "critical"],
            default="low",
            help="Minimum severity to report (default: low)",
        )

        parser.add_argument(
            "--format",
            "-f",
            choices=["text", "json", "summary"],
            default="text",
            help="Output format (default: text)",
        )

        parser.add_argument(
            "--no-control-flow",
            action="store_true",
            help="Disable control-flow analysis",
        )

        parser.add_argument(
            "--no-data-flow",
            action="store_true",
            help="Disable data-flow analysis",
        )

        parser.add_argument(
            "--no-branch-coverage",
            action="store_true",
            help="Disable branch coverage analysis",
        )

        parser.add_argument(
            "--stop-on-critical",
            action="store_true",
            help="Stop analysis when critical issue is found",
        )

        parser.add_argument(
            "--exclude",
            "-e",
            action="append",
            default=[],
            help="Glob patterns to exclude (can be used multiple times)",
        )

        parser.add_argument(
            "--include-tests",
            action="store_true",
            help="Include test files in analysis",
        )

        parser.add_argument(
            "--fail-on-issues",
            action="store_true",
            help="Exit with non-zero status if issues are found",
        )

        parser.add_argument(
            "--fail-severity",
            choices=["info", "low", "medium", "high", "critical"],
            default="high",
            help="Minimum severity that causes failure (default: high)",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """Execute the command."""
        path = Path(options["path"])

        if not path.exists():
            raise CommandError(f"Path does not exist: {path}")

        # Build configuration
        config = self._build_config(options)

        # Run analysis
        self.stdout.write(f"Analyzing: {path}")
        self.stdout.write(f"Mode: {options['mode']}")
        self.stdout.write("")

        analyzer = HybridFlowAnalyzer(config)

        result = analyzer.analyze_file(path) if path.is_file() else analyzer.analyze_directory(path)

        # Output results
        if options["format"] == "json":
            self._output_json(result)
        elif options["format"] == "summary":
            self._output_summary(result)
        else:
            self._output_text(result, options)

        # Check for failure condition
        if options["fail_on_issues"]:
            fail_severity = self._get_severity(options["fail_severity"])
            failing_issues = [i for i in result.issues if i.severity.value >= fail_severity.value]
            if failing_issues:
                sys.exit(1)

    def _build_config(self, options: dict[str, Any]) -> HybridAnalysisConfig:
        """Build analysis configuration from options."""
        # Determine what to enable based on mode
        mode = options["mode"]
        enable_control = mode in ("hybrid", "control-flow") and not options["no_control_flow"]
        enable_data = mode in ("hybrid", "data-flow") and not options["no_data_flow"]
        enable_branch = not options["no_branch_coverage"]

        # Build exclude patterns
        exclude_patterns = [
            "**/migrations/*",
            "**/__pycache__/*",
            "**/venv/*",
            "**/.venv/*",
        ]

        if not options["include_tests"]:
            exclude_patterns.append("**/tests/*")
            exclude_patterns.append("**/test_*.py")

        exclude_patterns.extend(options["exclude"])

        return HybridAnalysisConfig(
            enable_control_flow=enable_control,
            enable_data_flow=enable_data,
            enable_branch_coverage=enable_branch,
            stop_on_critical=options["stop_on_critical"],
            exclude_patterns=exclude_patterns,
            min_severity=self._get_severity(options["severity"]),
        )

    def _get_severity(self, severity_str: str) -> AnalysisSeverity:
        """Convert severity string to enum."""
        return AnalysisSeverity(severity_str)

    def _output_text(self, result: AnalysisResult, options: dict[str, Any]) -> None:
        """Output results as formatted text."""
        if result.errors:
            self.stderr.write(self.style.ERROR("Errors:"))
            for error in result.errors:
                self.stderr.write(f"  - {error}")
            self.stderr.write("")

        if not result.issues:
            self.stdout.write(self.style.SUCCESS("No issues found!"))
        else:
            self.stdout.write(f"Found {len(result.issues)} issues:\n")

            # Group by severity
            issues_by_severity: dict[str, list[FlowIssue]] = {}
            for issue in result.issues:
                severity = issue.severity.value
                if severity not in issues_by_severity:
                    issues_by_severity[severity] = []
                issues_by_severity[severity].append(issue)

            # Output in severity order (critical first)
            severity_order = ["critical", "high", "medium", "low", "info"]
            for severity in severity_order:
                if severity not in issues_by_severity:
                    continue

                issues = issues_by_severity[severity]
                self.stdout.write(f"\n{severity.upper()} ({len(issues)}):")
                self.stdout.write("-" * 40)

                for issue in issues:
                    self._print_issue(issue)

        # Print summary
        self.stdout.write("\n" + "=" * 60)
        self._output_summary(result)

    def _print_issue(self, issue: Any) -> None:
        """Print a single issue."""
        # Color based on severity
        style_map = {
            "critical": self.style.ERROR,
            "high": self.style.ERROR,
            "medium": self.style.WARNING,
            "low": self.style.NOTICE,
            "info": self.style.SUCCESS,
        }
        style = style_map.get(issue.severity.value, str)

        self.stdout.write(style(f"\n[{issue.category.value}]"))
        self.stdout.write(f"  Location: {issue.location}")
        self.stdout.write(f"  Message: {issue.message}")

        if issue.code_snippet:
            self.stdout.write(f"  Code: {issue.code_snippet}")

        if issue.remediation:
            self.stdout.write(f"  Fix: {issue.remediation}")

        if issue.cwe_id:
            self.stdout.write(f"  CWE: {issue.cwe_id}")

    def _output_summary(self, result: AnalysisResult) -> None:
        """Output analysis summary."""
        self.stdout.write(f"Files analyzed: {result.files_analyzed}")
        self.stdout.write(f"Lines analyzed: {result.total_lines}")
        self.stdout.write(f"Execution time: {result.execution_time_ms:.2f}ms")

        if result.branches_total > 0:
            self.stdout.write(
                f"Branch coverage: {result.branches_covered}/{result.branches_total} "
                f"({result.branch_coverage_percent:.1f}%)"
            )

        if result.taint_sources_found > 0:
            self.stdout.write(f"Taint sources: {result.taint_sources_found}")

        if result.control_flow_nodes > 0:
            self.stdout.write(f"Control flow nodes: {result.control_flow_nodes}")

        # Issue counts
        counts = result.issue_count_by_severity
        if counts:
            self.stdout.write("\nIssues by severity:")
            for severity in ["critical", "high", "medium", "low", "info"]:
                if severity in counts:
                    self.stdout.write(f"  {severity}: {counts[severity]}")

        if result.has_security_issues:
            self.stdout.write(self.style.ERROR("\nSECURITY ISSUES DETECTED!"))

        if result.has_critical_issues:
            self.stdout.write(self.style.ERROR("CRITICAL ISSUES FOUND - IMMEDIATE ACTION REQUIRED"))

    def _output_json(self, result: AnalysisResult) -> None:
        """Output results as JSON."""
        self.stdout.write(json.dumps(result.to_dict(), indent=2))
