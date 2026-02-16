# ===============================================================================
# SECURITY SCANNING SCRIPT FOR PRAHO PLATFORM
# ===============================================================================
"""
Automated security scanning using multiple tools.

Usage:
    python tests/security/run_security_scan.py [--full] [--report]

This script runs:
- Bandit (Python security linter)
- Safety (dependency vulnerability scanner)
- pip-audit (additional dependency scanner)
- Custom security checks
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def run_command(cmd: list[str], capture: bool = True) -> tuple[int, str, str]:
    """Run a command and return exit code, stdout, stderr"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=300,  # 5 minute timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"
    except FileNotFoundError:
        return 1, "", f"Command not found: {cmd[0]}"


def run_bandit_scan(target_dir: str, output_file: str | None = None) -> dict:
    """Run Bandit security scan"""
    print("\n🔒 Running Bandit security scan...")

    cmd = [
        "bandit",
        "-r",
        target_dir,
        "-f", "json",
        "-ll",  # Only show issues with severity LOW or higher
        "--exclude", "**/tests/**,**/migrations/**,**/.venv/**",
    ]

    exit_code, stdout, stderr = run_command(cmd)

    result = {
        "tool": "bandit",
        "exit_code": exit_code,
        "issues": [],
        "metrics": {},
    }

    if stdout:
        try:
            bandit_output = json.loads(stdout)
            result["issues"] = bandit_output.get("results", [])
            result["metrics"] = bandit_output.get("metrics", {})
        except json.JSONDecodeError:
            result["error"] = "Failed to parse Bandit output"

    if output_file:
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2)

    # Summary
    issue_count = len(result["issues"])
    if issue_count == 0:
        print("   ✅ No security issues found")
    else:
        print(f"   ⚠️  Found {issue_count} potential security issues")
        for issue in result["issues"][:5]:  # Show first 5
            print(f"      - {issue.get('filename')}:{issue.get('line_number')}: {issue.get('issue_text')}")
        if issue_count > 5:
            print(f"      ... and {issue_count - 5} more")

    return result


def run_safety_scan(requirements_file: str | None = None) -> dict:
    """Run Safety dependency vulnerability scan"""
    print("\n🔒 Running Safety dependency scan...")

    cmd = ["safety", "check", "--json"]
    if requirements_file:
        cmd.extend(["-r", requirements_file])

    exit_code, stdout, stderr = run_command(cmd)

    result = {
        "tool": "safety",
        "exit_code": exit_code,
        "vulnerabilities": [],
    }

    if stdout:
        try:
            safety_output = json.loads(stdout)
            result["vulnerabilities"] = safety_output
        except json.JSONDecodeError:
            result["raw_output"] = stdout

    # Summary
    vuln_count = len(result.get("vulnerabilities", []))
    if vuln_count == 0:
        print("   ✅ No known vulnerabilities in dependencies")
    else:
        print(f"   ⚠️  Found {vuln_count} vulnerable dependencies")

    return result


def run_pip_audit() -> dict:
    """Run pip-audit for additional vulnerability scanning"""
    print("\n🔒 Running pip-audit scan...")

    cmd = ["pip-audit", "--format", "json"]

    exit_code, stdout, stderr = run_command(cmd)

    result = {
        "tool": "pip-audit",
        "exit_code": exit_code,
        "vulnerabilities": [],
    }

    if stdout:
        try:
            audit_output = json.loads(stdout)
            result["vulnerabilities"] = audit_output
        except json.JSONDecodeError:
            result["raw_output"] = stdout

    # Summary
    vuln_count = len(result.get("vulnerabilities", []))
    if vuln_count == 0:
        print("   ✅ No vulnerabilities found by pip-audit")
    else:
        print(f"   ⚠️  Found {vuln_count} vulnerabilities")

    return result


def run_django_check() -> dict:
    """Run Django security checks"""
    print("\n🔒 Running Django security checks...")

    cmd = [
        "python", "services/platform/manage.py", "check",
        "--deploy", "--fail-level", "WARNING"
    ]

    exit_code, stdout, stderr = run_command(cmd)

    result = {
        "tool": "django-check",
        "exit_code": exit_code,
        "output": stdout + stderr,
    }

    if exit_code == 0:
        print("   ✅ Django security checks passed")
    else:
        print(f"   ⚠️  Django security check warnings/errors")
        print(f"      {stdout[:500]}")

    return result


def check_security_settings() -> dict:
    """Check security-related Django settings"""
    print("\n🔒 Checking security settings...")

    security_checks = [
        ("DEBUG", "should be False in production"),
        ("SECRET_KEY", "should not be hardcoded"),
        ("ALLOWED_HOSTS", "should be configured"),
        ("SECURE_SSL_REDIRECT", "should be True in production"),
        ("SESSION_COOKIE_SECURE", "should be True in production"),
        ("CSRF_COOKIE_SECURE", "should be True in production"),
        ("SECURE_HSTS_SECONDS", "should be set"),
        ("X_FRAME_OPTIONS", "should be DENY or SAMEORIGIN"),
    ]

    result = {
        "tool": "settings-check",
        "checks": security_checks,
        "status": "manual_review_required",
    }

    print("   ℹ️  Security settings require manual review")
    for setting, note in security_checks[:5]:
        print(f"      - {setting}: {note}")

    return result


def generate_report(results: list[dict], output_path: str) -> None:
    """Generate HTML security report"""
    print(f"\n📊 Generating report: {output_path}")

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>PRAHO Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
        .success {{ background-color: #d4edda; border-color: #c3e6cb; }}
        .warning {{ background-color: #fff3cd; border-color: #ffeeba; }}
        .error {{ background-color: #f8d7da; border-color: #f5c6cb; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>PRAHO Platform Security Scan Report</h1>
    <p>Generated: {datetime.now().isoformat()}</p>

    <h2>Summary</h2>
    <table>
        <tr>
            <th>Tool</th>
            <th>Status</th>
            <th>Issues</th>
        </tr>
"""

    for result in results:
        tool = result.get("tool", "Unknown")
        exit_code = result.get("exit_code", -1)
        issues = len(result.get("issues", [])) + len(result.get("vulnerabilities", []))

        status_class = "success" if exit_code == 0 and issues == 0 else "warning" if issues < 5 else "error"
        status_text = "Pass" if exit_code == 0 and issues == 0 else f"{issues} issues"

        html += f"""
        <tr class="{status_class}">
            <td>{tool}</td>
            <td>{status_text}</td>
            <td>{issues}</td>
        </tr>
"""

    html += """
    </table>

    <h2>Details</h2>
"""

    for result in results:
        tool = result.get("tool", "Unknown")
        html += f"""
    <div class="section">
        <h3>{tool}</h3>
        <pre>{json.dumps(result, indent=2)[:2000]}</pre>
    </div>
"""

    html += """
</body>
</html>
"""

    with open(output_path, "w") as f:
        f.write(html)

    print(f"   ✅ Report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="PRAHO Security Scanner")
    parser.add_argument("--full", action="store_true", help="Run full scan including all tools")
    parser.add_argument("--report", action="store_true", help="Generate HTML report")
    parser.add_argument("--output", default="security_report.html", help="Report output path")
    args = parser.parse_args()

    print("=" * 60)
    print("🔒 PRAHO Platform Security Scan")
    print("=" * 60)

    results = []

    # Run Bandit
    bandit_result = run_bandit_scan("services/platform/apps")
    results.append(bandit_result)

    if args.full:
        # Run Safety
        safety_result = run_safety_scan("services/platform/requirements/base.txt")
        results.append(safety_result)

        # Run pip-audit
        pip_audit_result = run_pip_audit()
        results.append(pip_audit_result)

        # Run Django checks
        django_result = run_django_check()
        results.append(django_result)

    # Settings check
    settings_result = check_security_settings()
    results.append(settings_result)

    # Generate report
    if args.report:
        generate_report(results, args.output)

    # Summary
    print("\n" + "=" * 60)
    print("📊 SCAN COMPLETE")
    print("=" * 60)

    total_issues = sum(
        len(r.get("issues", [])) + len(r.get("vulnerabilities", []))
        for r in results
    )

    if total_issues == 0:
        print("✅ No security issues found!")
        return 0
    else:
        print(f"⚠️  Total issues found: {total_issues}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
