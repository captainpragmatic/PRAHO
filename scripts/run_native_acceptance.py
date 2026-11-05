"""The explicit native gate fails on unavailable prerequisites, skips, or empty collection."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

SPLIT = ("prod", "split")

_FAULT = "test_real_failures_leave_durable_holds_and_allow_coordinated_recovery"
_ROLLBACK = "test_code_only_rollback_refuses_an_applied_migration_absent_from_target"
# A case is its test function, plus its fault or service parameter when it has one.
SHARD_CASES: dict[str, frozenset[str]] = {
    "split-prod-1": frozenset(
        {
            "test_real_services_use_one_sha_and_portal_has_no_platform_state",
            "test_ipv4_and_ipv6_peer_staff_monitor_and_untrusted_policies",
            "test_real_customer_login_through_caddy_keeps_an_authenticated_session",
            "test_public_provider_callbacks_and_unsubscribe_reach_application_verification",
            "test_address_check_origins_return_only_the_peer_and_reject_forwarding",
            "test_caddy_updates_preserve_maintenance_and_reboot_holds",
            "test_contaminated_portal_is_refused_before_changing_either_host",
            f"{_FAULT}[migration]",
            f"{_FAULT}[caddy]",
        }
    ),
    "split-prod-2": frozenset({f"{_FAULT}[portal-startup]", f"{_FAULT}[certificate]", f"{_FAULT}[ssh]"}),
    "split-prod-3": frozenset(
        {f"{_FAULT}[sha]", f"{_FAULT}[interrupt]", "test_actual_queue_work_drains_before_the_recovery_backup"}
    ),
    "split-prod-4": frozenset({f"{_ROLLBACK}[platform]", f"{_ROLLBACK}[portal]"}),
}

PROFILES: dict[str, tuple[tuple[str, str] | None, int]] = {
    "all": (None, 29),
    "split-prod": (SPLIT, 17),
    "combined-staging": (("staging", "combined"), 6),
    "combined-prod": (("prod", "combined"), 6),
    # CI runs the split cases as parallel shards. Each shard bootstraps its own split lab (about 16 minutes),
    # so they are balanced on measured case times: about 35-47 minutes each, under the lab's run.
    **{name: (SPLIT, len(cases)) for name, cases in SHARD_CASES.items()},
}


def case_key(function: str, parameters: dict[str, object]) -> str:
    """The shard key of a collected case: its function, plus its fault or service parameter."""
    detail = parameters.get("fault") or parameters.get("service")
    return f"{function}[{detail}]" if detail else function


def native_profile() -> str:
    profile = os.environ.get("PRAHO_NATIVE_ACCEPTANCE_PROFILE", "all")
    if profile not in PROFILES:
        raise ValueError(f"Invalid native acceptance profile {profile!r}; expected one of {', '.join(PROFILES)}")
    return profile


def main() -> int:
    try:
        profile = native_profile()
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    expected_count = PROFILES[profile][1]
    print(f"Native acceptance profile: {profile} ({expected_count} required cases)", flush=True)
    with tempfile.TemporaryDirectory(prefix="praho-native-results-") as temporary:
        report = Path(temporary) / "results.xml"
        retained = Path(tempfile.mkdtemp(prefix="praho-native-acceptance-"))
        print(f"Native acceptance diagnostics: {retained}", flush=True)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-o",
                "addopts=",
                "-v",
                "-x",
                "-m",
                "docker",
                "tests/deploy/test_native_acceptance.py",
                f"--junitxml={report}",
                f"--basetemp={retained}",
            ],
            env=dict(os.environ),
            check=False,
        )
        if result.returncode:
            return result.returncode
        if not report.exists():
            print("Native acceptance did not produce its required result", file=sys.stderr)
            return 1
        cases = ET.parse(report).getroot().findall(".//testcase")  # noqa: S314 -- local pytest-generated XML
        if len(cases) != expected_count or any(
            case.find(tag) is not None for case in cases for tag in ("skipped", "failure", "error")
        ):
            print(
                f"Native acceptance profile {profile!r} requires {expected_count} executed tests "
                "without skips, failures or errors",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
