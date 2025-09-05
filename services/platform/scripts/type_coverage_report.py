#!/usr/bin/env python3
"""
Type coverage reporting system for PRAHO Platform
Generates comprehensive type coverage reports and CI/CD integration
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


class TypeCoverageReporter:
    """Generates type coverage reports for PRAHO Platform"""

    def __init__(self, project_root: Path = Path(".")):
        self.project_root = project_root
        self.apps_dir = project_root / "apps"
        self.config_dir = project_root / "config"

    def run_mypy_check(self, target: str = "apps/") -> dict[str, Any]:
        """Run mypy on target directory and return error summary"""
        cmd = ["python", "-m", "mypy", target, "--config-file", "pyproject.toml", "--show-traceback", "--error-summary"]

        try:
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, cwd=self.project_root)

            error_count = len([line for line in result.stdout.split("\n") if "error:" in line])

            return {
                "target": target,
                "error_count": error_count,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except Exception as e:
            return {"target": target, "error_count": -1, "error": str(e), "return_code": 1}

    def analyze_app_type_coverage(self, app_name: str) -> dict[str, Any]:
        """Analyze type coverage for a specific app"""
        app_path = self.apps_dir / app_name
        if not app_path.exists():
            return {"app": app_name, "error": "App not found"}

        # Count Python files
        python_files = list(app_path.rglob("*.py"))
        python_files = [f for f in python_files if "migrations" not in str(f)]

        # Run mypy on this specific app
        result = self.run_mypy_check(f"apps/{app_name}/")

        # Calculate coverage metrics
        total_files = len(python_files)

        return {
            "app": app_name,
            "total_files": total_files,
            "error_count": result["error_count"],
            "type_coverage": max(0, 100 - (result["error_count"] / max(total_files, 1)) * 10),
            "status": "pass" if result["error_count"] < 50 else "needs_improvement",
        }

    def generate_comprehensive_report(self) -> dict[str, Any]:
        """Generate comprehensive type coverage report"""
        apps = [
            "audit",
            "billing",
            "customers",
            "domains",
            "integrations",
            "notifications",
            "orders",
            "products",
            "provisioning",
            "tickets",
            "users",
            "common",
        ]

        report = {
            "timestamp": "2025-08-25",
            "project": "praho-platform",
            "overall_summary": {},
            "app_breakdown": [],
            "recommendations": [],
        }

        # Analyze each app
        app_reports: list[dict[str, Any]] = []
        total_errors = 0
        total_files = 0

        for app in apps:
            app_report = self.analyze_app_type_coverage(app)
            app_reports.append(app_report)
            total_errors += app_report["error_count"]
            total_files += app_report["total_files"]

        # Overall summary
        report["overall_summary"] = {
            "total_apps": len(apps),
            "total_python_files": total_files,
            "total_type_errors": total_errors,
            "target_errors": 50,
            "target_coverage": 95,
            "phase_3_status": "in_progress",
        }

        report["app_breakdown"] = sorted(app_reports, key=lambda x: x.get("error_count", 0), reverse=True)

        # Generate recommendations
        report["recommendations"] = self._generate_recommendations(app_reports)

        return report

    def _generate_recommendations(self, app_reports: list[dict[str, Any]]) -> list[str]:
        """Generate recommendations based on type coverage"""
        recommendations = []

        high_error_apps = [app for app in app_reports if app["error_count"] > 20]

        if high_error_apps:
            recommendations.append(f"Focus on apps with high type errors: {[app['app'] for app in high_error_apps]}")

        if any(app["error_count"] == -1 for app in app_reports):
            recommendations.append("Fix mypy configuration issues")

        recommendations.extend(
            [
                "Enable strict mode for core apps: audit, billing, users",
                "Add type stubs for Django ORM patterns",
                "Implement incremental strict mode re-enablement",
                "Set up CI/CD type coverage gates",
            ]
        )

        return recommendations

    def save_report(self, report: dict[str, Any], output_path: Path | None = None) -> None:
        """Save report to JSON file"""
        if output_path is None:
            output_path = self.project_root / "type_coverage_report.json"

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"✅ Type coverage report saved to: {output_path}")

    def generate_markdown_report(self) -> str:
        """Generate markdown report for GitHub/GitLab"""
        report = self.generate_comprehensive_report()

        md = f"""# PRAHO Platform - Type Coverage Report

## 📊 Summary
- **Total Apps**: {report["overall_summary"]["total_apps"]}
- **Total Python Files**: {report["overall_summary"]["total_python_files"]}
- **Total Type Errors**: {report["overall_summary"]["total_type_errors"]}
- **Target**: {report["overall_summary"]["target_errors"]} errors
- **Status**: {report["overall_summary"]["phase_3_status"]}

## 🎯 App Breakdown

| App | Files | Errors | Coverage | Status |
|-----|-------|--------|----------|--------|
"""

        for app in report["app_breakdown"]:
            if "error" not in app:
                status_emoji = "✅" if app["status"] == "pass" else "⚠️"
                md += f"| {app['app']} | {app['total_files']} | {app['error_count']} | {app['type_coverage']:.1f}% | {status_emoji} {app['status']} |\n"

        md += "\n## 🚀 Recommendations\n"
        for rec in report["recommendations"]:
            md += f"- {rec}\n"

        return md


def main() -> None:
    """Main CLI interface"""
    reporter = TypeCoverageReporter()

    if len(sys.argv) > 1 and sys.argv[1] == "--markdown":
        print(reporter.generate_markdown_report())
    else:
        report = reporter.generate_comprehensive_report()
        reporter.save_report(report)


if __name__ == "__main__":
    main()
