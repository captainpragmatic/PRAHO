"""Recovery must reject bad input before stopping applications or replacing data."""

from __future__ import annotations

import gzip
import os
from pathlib import Path

import pytest

from tests.integration.test_deploy_scripts import DUMP_GZIP, EMPTY_GZIP, MEDIA_GZIP, PROD_ENV, SQL_DUMP, Project

pytestmark = pytest.mark.integration


@pytest.fixture
def project(tmp_path: Path) -> Project:
    project = Project(tmp_path.resolve())
    project.write_env(".env.prod", PROD_ENV)
    (project.root / "backups").mkdir()
    (project.root / "staging").mkdir()
    project.env["TMPDIR"] = str(project.root / "staging")
    return project


def _dump(project: Project, data: bytes = DUMP_GZIP) -> Path:
    path = project.root / "backups/praho_backup_selected.sql.gz"
    path.write_bytes(data)
    return path


def _assert_untouched(project: Project) -> None:
    calls = [call["argv"] for call in project.calls()]
    assert not any(call[0] in {"stop", "start"} or "DROP SCHEMA" in " ".join(call) for call in calls)
    assert list((project.root / "staging").iterdir()) == []


@pytest.mark.parametrize(
    "data",
    [b"", b"not gzip", EMPTY_GZIP, DUMP_GZIP[:-5], gzip.compress(b"SELECT 1;\n"), gzip.compress(SQL_DUMP.split(b"-- PostgreSQL database dump complete")[0])],
)
def test_bad_database_archives_change_nothing(project: Project, data: bytes) -> None:
    result = project.run("restore.sh", str(_dump(project, data)), stdin="yes\n")
    assert result.returncode != 0
    assert "nothing was restored" in result.stdout
    _assert_untouched(project)


def test_an_unreadable_dump_changes_nothing(project: Project) -> None:
    dump = _dump(project)
    dump.chmod(0)
    result = project.run("restore.sh", str(dump), stdin="yes\n")
    assert result.returncode != 0
    _assert_untouched(project)


def test_a_gzip_stream_that_is_not_a_media_tar_changes_nothing(project: Project) -> None:
    dump = _dump(project)
    dump.with_name(dump.name.replace(".sql.gz", ".media.tar.gz")).write_bytes(gzip.compress(b"not tar"))
    result = project.run("restore.sh", str(dump), stdin="yes\n")
    assert result.returncode != 0
    assert "not a tar archive" in result.stdout
    _assert_untouched(project)


def test_a_failed_safety_backup_changes_nothing(project: Project) -> None:
    result = project.run("restore.sh", str(_dump(project)), stdin="yes\n", DOCKER_EXEC_FAILS="1")
    assert result.returncode != 0
    assert "Pre-restore backup failed" in result.stdout
    _assert_untouched(project)


def test_a_failed_safety_media_backup_changes_nothing(project: Project) -> None:
    result = project.run("restore.sh", str(_dump(project)), stdin="yes\n", DOCKER_CP_FAILS="1")
    assert result.returncode != 0
    assert "Pre-restore backup failed" in result.stdout
    _assert_untouched(project)


def test_a_failed_stop_never_drops_the_schema(project: Project) -> None:
    result = project.run("restore.sh", str(_dump(project)), stdin="yes\n", DOCKER_STOP_FAILS="1")
    assert result.returncode != 0
    assert "database was left unchanged" in result.stdout
    assert not any("DROP SCHEMA" in " ".join(call["argv"]) for call in project.calls())
    assert not any(call["argv"][0] == "start" for call in project.calls())
    assert "Some services may already be stopped" in result.stdout


def test_unknown_container_state_changes_nothing(project: Project) -> None:
    result = project.run("restore.sh", str(_dump(project)), stdin="yes\n", DOCKER_PS_FAILS="1")
    assert result.returncode != 0
    assert "Cannot determine the local application containers" in result.stdout
    _assert_untouched(project)


def test_platform_only_restores_only_its_local_services(project: Project) -> None:
    result = project.run("restore.sh", str(_dump(project)), stdin="yes\n", DOCKER_ABSENT_PORTAL="1")
    assert result.returncode == 0, result.stdout + result.stderr
    calls = [call["argv"] for call in project.calls()]
    assert ["stop", "praho_platform", "praho_qcluster"] in calls
    assert ["start", "praho_platform", "praho_qcluster"] in calls
    assert not any("praho_portal" in call for call in calls)
    assert project.compose_calls() == []


@pytest.mark.parametrize("failure", ["DOCKER_SQL_ERROR", "DOCKER_PREPARE_FAILS"])
def test_database_errors_hold_applications_offline_for_recovery(project: Project, failure: str) -> None:
    result = project.run("restore.sh", str(_dump(project)), stdin="yes\n", **{failure: "1"})
    assert result.returncode != 0
    assert "Applications remain stopped" in result.stdout
    assert "Restore completed successfully" not in result.stdout
    calls = [call["argv"] for call in project.calls()]
    assert any(call[0] == "stop" for call in calls)
    assert not any(call[0] == "start" or call[:2] == ["cp", "-a"] for call in calls)
    assert len(list((project.root / "backups").glob("*.sql.gz"))) == 2  # selected + recovery backup
    assert list((project.root / "staging").iterdir()) == []


def test_retention_cannot_remove_the_staged_selected_dump_or_media(project: Project) -> None:
    dump = _dump(project)
    media = dump.with_name(dump.name.replace(".sql.gz", ".media.tar.gz"))
    media.write_bytes(MEDIA_GZIP)
    for path in (dump, media):
        os.utime(path, (0, 0))
    sql_input = project.root / "restored.sql"
    result = project.run("restore.sh", str(dump), stdin="yes\n", DOCKER_SQL_INPUT=str(sql_input))
    assert result.returncode == 0, result.stdout + result.stderr
    assert not dump.exists() and not media.exists()  # safety backup applied ordinary retention
    assert sql_input.read_bytes() == SQL_DUMP
    assert ["cp", "-a", "-", "praho_platform:/app"] in [call["argv"] for call in project.calls()]
    assert len(list((project.root / "backups").glob("*.sql.gz"))) == 1
    assert list((project.root / "staging").iterdir()) == []


def test_restore_pauses_the_media_sweep_before_any_worker_starts(project: Project) -> None:
    result = project.run("restore.sh", str(_dump(project)), stdin="yes\n")
    assert result.returncode == 0, result.stdout + result.stderr
    calls = [call["argv"] for call in project.calls()]
    restored = next(i for i, call in enumerate(calls) if call[:3] == ["exec", "-i", "praho_db"])
    paused = next(i for i, call in enumerate(calls) if any("media_sweep.paused_until" in a for a in call))
    started = next(i for i, call in enumerate(calls) if call[0] == "start")
    assert restored < paused < started
    assert "--set=ON_ERROR_STOP=1" in calls[paused]


def test_a_failed_sweep_pause_keeps_every_worker_stopped(project: Project) -> None:
    result = project.run("restore.sh", str(_dump(project)), stdin="yes\n", DOCKER_PAUSE_FAILS="1")
    assert result.returncode != 0
    assert "Applications remain stopped" in result.stdout
    assert not any(call["argv"][0] == "start" for call in project.calls())


def test_a_sweep_pause_that_writes_nothing_keeps_every_worker_stopped(project: Project) -> None:
    result = project.run("restore.sh", str(_dump(project)), stdin="yes\n", DOCKER_PAUSE_ANSWER="")
    assert result.returncode != 0
    assert "Applications remain stopped" in result.stdout
    assert not any(call["argv"][0] == "start" for call in project.calls())
