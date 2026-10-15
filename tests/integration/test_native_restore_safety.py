"""Recording commands prove native restore validates before downtime and fails offline."""

import gzip
import json
import sys
import tarfile
from pathlib import Path

import pytest

from tests.integration.test_media_root import _native, _render, _run

STUB = '''#!{python}
import json, os, subprocess, sys
name = os.path.basename(sys.argv[0])
args = sys.argv[1:]
with open(os.environ["NATIVE_LOG"], "a") as log:
    log.write(json.dumps([name, *args]) + "\\n")
if name == "pg_restore":
    if args[0] == "--list":
        if os.environ.get("BAD_TOC"): sys.exit(1)
        if not os.environ.get("EMPTY_TOC"): print("1; 0 1 TABLE DATA public django_migrations praho")
    elif args[0].startswith("--file"):
        if os.environ.get("BAD_DATA"): sys.exit(1)
    elif os.environ.get("SQL_FAIL"): sys.exit(1)
elif name == "backup.sh":
    if os.environ.get("DELETE_SELECTED"): os.unlink(os.environ["SELECTED"])
    if os.environ.get("BACKUP_FAIL"): sys.exit(1)
elif name == "systemctl":
    if args[0] == "stop" and os.environ.get("STOP_FAIL"): sys.exit(1)
    if args[0] == "start" and os.environ.get("START_FAIL"): sys.exit(1)
    if args[0] == "is-active" and os.environ.get("HEALTH_FAIL"): sys.exit(1)
elif name == "sudo" and args[2] == "tar":
    if os.environ.get("MEDIA_EXTRACT_FAIL"): sys.exit(1)
    sys.exit(subprocess.run(args[2:], check=False).returncode)
elif name == "curl":
    print("302", end="")
'''


def scenario(tmp_path: Path) -> tuple[Path, dict[str, str], Path]:
    root, env = _native(tmp_path)
    env.update(NATIVE_LOG=str(tmp_path / "commands"), RESTORE_HEALTH_ATTEMPTS="1")
    for tool in ("pg_restore", "systemctl", "sudo", "curl"):
        (tmp_path / "bin" / tool).write_text(STUB.format(python=sys.executable))
    (root / "scripts/backup.sh").write_text(STUB.format(python=sys.executable))
    backups = root / "backups"
    backups.mkdir()
    dump = backups / "praho_backup_selected.dump"
    dump.write_bytes(b"custom-dump-recording-fixture")
    env["SELECTED"] = str(dump)
    return root, env, dump


def calls(env: dict[str, str]) -> list[list[str]]:
    log = Path(env["NATIVE_LOG"])
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


@pytest.mark.parametrize("failure", ["BAD_TOC", "EMPTY_TOC", "BAD_DATA", "BACKUP_FAIL", "STOP_FAIL", "EMPTY_FILE", "BAD_MEDIA", "BAD_MEDIA_GZIP"])
def test_preflight_and_stop_failures_never_replace_the_database(tmp_path: Path, failure: str) -> None:
    root, env, dump = scenario(tmp_path)
    env[failure] = "1"
    if failure == "EMPTY_FILE":
        dump.write_bytes(b"")
    if failure == "BAD_MEDIA":
        dump.with_suffix(".media.tar.gz").write_bytes(b"corrupt-media")
    if failure == "BAD_MEDIA_GZIP":
        dump.with_suffix(".media.tar.gz").write_bytes(gzip.compress(b"not tar"))
    completed = _run(_render("restore-native.sh.j2", root), env, str(dump), stdin="yes\n")
    assert completed.returncode != 0, completed.stdout + completed.stderr
    recorded = calls(env)
    assert not any(call[:3] == ["sudo", "-u", "postgres"] for call in recorded)
    if failure not in {"BACKUP_FAIL", "STOP_FAIL"}:
        assert not any(call[0] in {"systemctl", "backup.sh"} for call in recorded)


@pytest.mark.parametrize("failure", ["SQL_FAIL", "MEDIA_EXTRACT_FAIL", "START_FAIL", "HEALTH_FAIL"])
def test_mutation_or_readiness_failure_holds_writers_offline(tmp_path: Path, failure: str) -> None:
    root, env, dump = scenario(tmp_path)
    env[failure] = "1"
    if failure == "MEDIA_EXTRACT_FAIL":
        with tarfile.open(dump.with_suffix(".media.tar.gz"), "w:gz") as archive:
            archive.add(root / "media", arcname="media")
    completed = _run(_render("restore-native.sh.j2", root), env, str(dump), stdin="yes\n")
    assert completed.returncode != 0
    assert "applications remain stopped" in completed.stderr
    assert "Restore completed successfully" not in completed.stdout
    recorded = calls(env)
    assert any(call[:3] == ["sudo", "-u", "postgres"] for call in recorded)
    if failure in {"SQL_FAIL", "MEDIA_EXTRACT_FAIL"}:
        assert not any(call[:2] == ["systemctl", "start"] for call in recorded)
    else:
        assert recorded[-1][:2] == ["systemctl", "stop"]


def test_selected_dump_survives_retention_and_strict_restore_precedes_health(tmp_path: Path) -> None:
    root, env, dump = scenario(tmp_path)
    env["DELETE_SELECTED"] = "1"
    completed = _run(_render("restore-native.sh.j2", root), env, str(dump), stdin="yes\n")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not dump.exists()
    recorded = calls(env)
    restore = next(i for i, call in enumerate(recorded) if call[0] == "pg_restore" and "--exit-on-error" in call)
    start = next(i for i, call in enumerate(recorded) if call[:2] == ["systemctl", "start"])
    assert restore < start
    staged = Path(recorded[restore][-1])
    assert staged.name == "database.dump" and not staged.parent.exists()
    assert "Restore completed successfully" in completed.stdout
