#!/usr/bin/env python3
"""
PRAHO Platform - Gradual Typing Configuration Test

This script tests the gradual typing configuration across different phases
to ensure our progressive rollout strategy is working correctly.
"""

import subprocess
import sys
from pathlib import Path


def run_mypy_check(target_path: str, description: str) -> tuple[int, str]:
    """Run mypy check and return error count and output."""
    cmd = [sys.executable, "-m", "mypy", "--config-file=pyproject.toml", target_path]

    try:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True, cwd=Path(__file__).parent.parent)  # noqa: S603

        output = result.stdout + result.stderr
        error_count = output.count(" error: ")

        return error_count, output
    except Exception as e:
        return -1, str(e)


def test_phase_configuration() -> None:
    """Test mypy configuration for different phases."""

    print("🚀 PRAHO Platform - Gradual Typing Configuration Test")
    print("=" * 60)

    test_cases = [
        # Phase 1: Foundation modules (strictest)
        ("apps/common/types.py", "Phase 1: Foundation Types (STRICT)"),
        ("apps/common/validators.py", "Phase 1: Foundation Validators (STRICT)"),
        # Phase 2: Core apps (high strictness)
        ("apps/users/services.py", "Phase 2: Users Services (HIGH)"),
        ("apps/billing/models.py", "Phase 2: Billing Models (HIGH)"),
        ("apps/audit/services.py", "Phase 2: Audit Services (HIGH)"),
        # Phase 3: Business logic apps (medium strictness)
        ("apps/customers/views.py", "Phase 3: Customers Views (MEDIUM)"),
        ("apps/tickets/models.py", "Phase 3: Tickets Models (MEDIUM)"),
        # Phase 4: Infrastructure apps (most permissive)
        ("apps/integrations/models.py", "Phase 4: Integrations Models (PERMISSIVE)"),
        ("apps/provisioning/models.py", "Phase 4: Provisioning Models (PERMISSIVE)"),
    ]

    results = []

    for target, description in test_cases:
        print(f"\n📋 Testing: {description}")
        print(f"   Target: {target}")

        # Check if file exists
        target_path = Path(__file__).parent.parent / target
        if not target_path.exists():
            print("   ❌ SKIP: File does not exist")
            continue

        error_count, output = run_mypy_check(target, description)

        if error_count == -1:
            print(f"   ❌ ERROR: {output}")
            results.append((description, -1, "Failed to run"))
        else:
            print(f"   📊 Result: {error_count} type errors found")
            results.append((description, error_count, "OK"))

            # Show first few errors as sample
            if error_count > 0:
                error_lines = [line for line in output.split("\n") if " error: " in line]
                sample_count = min(3, len(error_lines))
                if sample_count > 0:
                    print(f"   📝 Sample errors ({sample_count}/{len(error_lines)}):")
                    for i in range(sample_count):
                        print(f"      {error_lines[i]}")
                    if len(error_lines) > sample_count:
                        print(f"      ... and {len(error_lines) - sample_count} more")

    # Summary
    print("\n" + "=" * 60)
    print("📊 CONFIGURATION TEST SUMMARY")
    print("=" * 60)

    for description, error_count, status in results:
        if error_count == -1:
            print(f"❌ {description}: {status}")
        else:
            print(f"✅ {description}: {error_count} errors")

    print("\n🎯 Expected Behavior:")
    print("   • Phase 1 (Foundation): Some errors OK - will be fixed first")
    print("   • Phase 2 (Core): Moderate errors - high priority fixes")
    print("   • Phase 3 (Business): Many errors OK - medium priority")
    print("   • Phase 4 (Infrastructure): Most permissive - low priority")

    print("\n✅ Configuration test completed!")
    print(f"   Total test cases: {len(results)}")
    print(f"   Successful runs: {len([r for r in results if r[1] != -1])}")


if __name__ == "__main__":
    test_phase_configuration()
