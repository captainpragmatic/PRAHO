"""Full rollback never starts the current image against a restored old database."""

import gzip
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from deploy.scripts.backup_manifest import create, manifest_path
from tests.integration.test_deploy_scripts import (
    DOCKER_STUB,
    MEDIA_GZIP,
    NEWER_PORTAL_KEYS,
    PROD_STACK_ENV,
    RECORDED_ENV,
    SQL_DUMP,
    Project,
    _subcommand,
    _without,
)

EXTRA = """if argv[:2] == ["image", "inspect"]:
    if os.environ.get("TARGET_PULL_FAIL"): sys.exit(1)
    print("sha256:" + ("c" if os.environ.get("TARGET_MISMATCH") else ("b" if "portal" in argv[-1] else "a")) * 64)
elif argv[:1] == ["pull"]:
    if os.environ.get("TARGET_PULL_FAIL"): sys.exit(1)
elif argv[:1] == ["compose"] and "config" in argv:
    tag = os.environ["VERSION"]
    print(json.dumps({"services": {name: {"image": "praho-" + ("portal" if name == "portal" else "platform") + ":" + tag} for name in ("platform", "portal", "qcluster")}}))
elif argv[:1] == ["compose"] and "up" in argv and os.environ.get("TARGET_START_FAIL"):
    sys.exit(1)
elif argv[:1] == ["ps"]: corner
"""


def scenario(tmp_path: Path) -> tuple[Project, Path]:
    project = Project(tmp_path)
    source = DOCKER_STUB.format(python=sys.executable, recorded=RECORDED_ENV)
    source = source.replace('if argv[:1] == ["ps"]:', EXTRA.replace(" corner", "").rstrip())
    # Producer and target identity checks use the same immutable image fixture.
    source = source.replace(
        'elif argv[:1] == ["inspect"]:',
        """elif argv[:1] == ["inspect"] and "{{.Image}}" in argv:
    print("sha256:" + ("b" if argv[-1] == "praho_portal" else "a") * 64)
elif argv[:1] == ["inspect"] and "{{.Config.Image}}" in argv:
    print("praho-platform:v1.0.0")
elif argv[:1] == ["exec"] and "SHOW server_version_num" in argv:
    print("160010")
elif argv[:1] == ["inspect"]:""",
    )
    (tmp_path / "bin/docker").write_text(source)
    project.write_env(".env.prod", PROD_STACK_ENV)
    backups = tmp_path / "backups"
    backups.mkdir()
    dump = backups / "praho_backup_selected.sql.gz"
    dump.write_bytes(gzip.compress(SQL_DUMP))
    dump.with_name("praho_backup_selected.media.tar.gz").write_bytes(MEDIA_GZIP)
    with patch.dict(os.environ, project.env, clear=True):
        create(dump)
    project.log.write_text("")
    return project, dump


def run(project: Project, dump: Path, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    return project.run("rollback.sh", "full", "v1.0.0", "--backup", str(dump), *args, stdin="yes\n", **env)


def test_old_image_selection_follows_restore_without_current_image_restart(tmp_path: Path) -> None:
    project, dump = scenario(tmp_path)
    completed = run(project, dump)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    calls = project.calls()
    assert not any(call["argv"][:1] == ["start"] for call in calls)
    restored = next(i for i, call in enumerate(calls) if call["argv"][:3] == ["exec", "-i", "praho_db"])
    started = next(i for i, call in enumerate(calls) if "up" in call["argv"])
    assert restored < started and calls[started]["env"]["VERSION"] == "v1.0.0"
    assert "--no-deps" in calls[started]["argv"]
    assert "Full rollback to v1.0.0 completed" in completed.stdout


@pytest.mark.parametrize(
    "failure", ["checksum", "database-major", "TARGET_PULL_FAIL", "TARGET_MISMATCH", "missing-metadata"]
)
def test_incompatible_pair_or_unavailable_image_fails_before_downtime(tmp_path: Path, failure: str) -> None:
    project, dump = scenario(tmp_path)
    data = json.loads(manifest_path(dump).read_text())
    environment = {}
    if failure == "checksum":
        data["database"]["sha256"] = "0" * 64
    elif failure == "database-major":
        data["database_major"] = 15
    elif failure == "missing-metadata":
        manifest_path(dump).unlink()
    else:
        environment[failure] = "1"
    if failure != "missing-metadata":
        manifest_path(dump).write_text(json.dumps(data))
    completed = run(project, dump, **environment)
    assert completed.returncode != 0
    assert not any(call["argv"][:1] in (["stop"], ["start"]) or "up" in call["argv"] for call in project.calls())
    assert not any("DROP SCHEMA" in " ".join(call["argv"]) for call in project.calls())


@pytest.mark.parametrize("failure", ["DOCKER_SQL_ERROR", "DOCKER_MEDIA_RESTORE_FAILS", "TARGET_START_FAIL"])
def test_restore_or_target_start_failure_holds_applications_offline(tmp_path: Path, failure: str) -> None:
    project, dump = scenario(tmp_path)
    completed = run(project, dump, **{failure: "1"})
    assert completed.returncode != 0
    calls = project.calls()
    assert any("DROP SCHEMA" in " ".join(call["argv"]) for call in calls)
    assert not any(call["argv"][:1] == ["start"] for call in calls)
    if failure != "TARGET_START_FAIL":
        assert not any("up" in call["argv"] for call in calls)
    else:
        assert calls[-1]["argv"][:1] == ["stop"]


def test_platform_only_rollback_starts_only_existing_local_roles(tmp_path: Path) -> None:
    project, dump = scenario(tmp_path)
    completed = run(project, dump, "--topology", "platform-only", DOCKER_ABSENT_PORTAL="1")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    up = next(call for call in project.compose_calls() if "up" in call["argv"])
    assert "docker-compose.platform-only.yml" in up["argv"][up["argv"].index("-f") + 1]
    assert _subcommand(up)[-2:] == ["platform", "qcluster"]


def test_full_rollback_requires_an_explicit_backup(tmp_path: Path) -> None:
    project, _dump = scenario(tmp_path)
    completed = project.run("rollback.sh", "full", "v1.0.0", stdin="yes\n")
    assert completed.returncode != 0
    assert "requires --backup PATH" in completed.stderr
    assert project.calls() == []


def test_safety_backup_failure_never_stops_or_drops(tmp_path: Path) -> None:
    project, dump = scenario(tmp_path)
    (project.root / "deploy/scripts/backup.sh").write_text("#!/bin/bash\nexit 1\n")
    completed = run(project, dump)
    assert completed.returncode != 0
    assert "Pre-restore backup failed" in completed.stdout
    assert not any(call["argv"][:1] == ["stop"] or "DROP SCHEMA" in " ".join(call["argv"]) for call in project.calls())


def test_compose_parser_emits_only_image_references() -> None:
    configuration = {
        "services": {
            "platform": {"image": "praho-platform:v1.0.0", "environment": {"DB_PASSWORD": "must-stay-in-process"}},
            "qcluster": {"image": "praho-platform:v1.0.0"},
            "portal": {"image": "praho-portal:v1.0.0"},
        }
    }
    helper = Path(__file__).resolve().parents[2] / "deploy/scripts/backup_manifest.py"
    completed = subprocess.run(  # noqa: S603 -- fixed helper and synthetic JSON input.
        [sys.executable, str(helper), "images", "--portal"],
        input=json.dumps(configuration),
        capture_output=True,
        text=True,
        check=True,
    )
    assert completed.stdout.splitlines() == ["platform=praho-platform:v1.0.0", "portal=praho-portal:v1.0.0"]
    assert "must-stay-in-process" not in completed.stdout + completed.stderr


@pytest.mark.parametrize("topology", ["single-server", "platform-only"])
def test_a_file_the_stack_cannot_interpolate_is_refused_before_anything_runs(tmp_path: Path, topology: str) -> None:
    project, dump = scenario(tmp_path)
    project.write_env(".env.prod", _without(PROD_STACK_ENV, NEWER_PORTAL_KEYS))
    host = {"DOCKER_ABSENT_PORTAL": "1"} if topology == "platform-only" else {}
    completed = run(project, dump, "--topology", topology, **host)
    assert completed.returncode != 0
    assert "PORTAL_HMAC_CREDENTIALS" in completed.stderr
    assert project.calls() == []
