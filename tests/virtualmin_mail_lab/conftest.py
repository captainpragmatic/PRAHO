"""Explicit profile selection; no shared-lab bootstrap, database or implicit native run."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.virtualmin_mail_lab.harness import PROFILES, MailClone, MailLabError, MailProfile, _run


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--mail-profile", choices=("debian12", "ubuntu2604", "all"), default=os.environ.get("MAIL_LAB_PROFILE") or None
    )
    parser.addoption("--mail-dns", default=os.environ.get("MAIL_LAB_DNS", ""))
    parser.addoption("--debian-image", default=os.environ.get("MAIL_LAB_DEBIAN_IMAGE") or PROFILES["debian12"].image)
    parser.addoption("--ubuntu-image", default=os.environ.get("MAIL_LAB_UBUNTU_IMAGE") or PROFILES["ubuntu2604"].image)
    parser.addoption(
        "--cleanup-owned-failures", action="store_true", default=os.environ.get("MAIL_LAB_CLEANUP_FAILURE") == "1"
    )


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "mail_profile" in metafunc.fixturenames:
        selected = metafunc.config.getoption("mail_profile")
        if selected is None:
            raise pytest.UsageError(
                "Select MAIL_LAB_PROFILE=debian12|ubuntu2604|all explicitly; native mail tests are opt-in"
            )
        profiles = list(PROFILES.values()) if selected == "all" else [PROFILES[selected]]
        metafunc.parametrize("mail_profile", profiles, ids=[profile.key for profile in profiles])


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    setattr(item, "mail_report_" + report.when, report)


def prerequisites() -> None:
    try:
        docker = _run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20)
        document = _run(
            [
                str(Path(sys.executable).with_name("ansible-doc")),
                "--json",
                "--type",
                "connection",
                "community.docker.docker",
            ],
            timeout=30,
        )
        if docker.returncode or document.returncode or "community.docker.docker" not in json.loads(document.stdout):
            raise ValueError
    except (subprocess.SubprocessError, OSError, ValueError):
        raise MailLabError(
            "Docker and the community.docker Ansible connection must be available before this opt-in test"
        ) from None


@pytest.fixture
def mail_clone(request: pytest.FixtureRequest, mail_profile: MailProfile) -> Iterator[MailClone]:
    prerequisites()
    root = Path(tempfile.mkdtemp(prefix="praho-mail-node-"))
    image = request.config.getoption("debian_image" if mail_profile.key == "debian12" else "ubuntu_image")
    clone = MailClone(mail_profile, root / mail_profile.key, image=image, dns=request.config.getoption("mail_dns"))
    print(
        json.dumps(
            {"profile": mail_profile.key, "expected_clone": clone.name, "private_artifacts": str(clone.artifacts)}
        )
    )
    try:
        clone.create()
        print(
            json.dumps(
                {
                    "profile": mail_profile.key,
                    "owned_container": clone.container_id,
                    "private_artifacts": str(clone.artifacts),
                }
            )
        )
        yield clone
    finally:
        report = getattr(request.node, "mail_report_call", None)
        clone.finish(
            success=report is not None and report.passed,
            cleanup_failure=request.config.getoption("cleanup_owned_failures"),
        )
