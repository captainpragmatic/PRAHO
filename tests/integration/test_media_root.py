"""Uploaded and generated files live where the deployment keeps them, and backups include them.

Media holds what the database cannot rebuild: ANAF's e-Factura response archives, issued invoice
PDFs, ticket attachments and GDPR exports. Production settings ignored MEDIA_ROOT, so files went
under the code tree: in Docker that is not the media volume, so they were lost when the container
was recreated, and natively it is read-only under the units' ProtectSystem=strict. The backups
dumped only the database.
"""

from __future__ import annotations

import ast
import os
import shlex
import subprocess
import tarfile
from pathlib import Path

import jinja2
import pytest
import yaml

from tests.integration.test_deploy_scripts import EMPTY_GZIP, PROD_ENV, Project

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SETTINGS = PROJECT_ROOT / "services/platform/config/settings"
COMPOSE = ("docker-compose.single-server.yml", "docker-compose.platform-only.yml")
TEMPLATES = PROJECT_ROOT / "deploy/ansible/roles/praho-native/templates"

pytestmark = pytest.mark.integration


def _media_root_reads_environment(module: Path) -> bool:
    """MEDIA_ROOT comes from the environment, defaulting to the code tree's media directory.

    The default matters for stacks that do not set it (docker-compose.container-service.yml): the
    image links that directory to its /app/media volume, and nothing else there is writable.
    """
    for node in ast.walk(ast.parse(module.read_text())):
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "MEDIA_ROOT" for t in node.targets):
            value = ast.unparse(node.value)
            return "MEDIA_ROOT" in value and "environ" in value and "BASE_DIR / 'media'" in value  # unparse quotes
    return False


@pytest.mark.parametrize("module", ["prod.py", "staging.py"])
def test_deployed_settings_honour_media_root(module: str) -> None:
    # The deployments set MEDIA_ROOT (Compose, Ansible, .env.example.prod); the settings must read it.
    assert _media_root_reads_environment(SETTINGS / module)


@pytest.mark.parametrize("name", COMPOSE)
def test_the_platform_containers_write_media_into_the_volume(name: str) -> None:
    services = yaml.safe_load((PROJECT_ROOT / "deploy" / name).read_text())["services"]
    for service in ("platform", "qcluster"):
        environment = dict(item.split("=", 1) for item in services[service]["environment"])
        mounts = {volume.split(":")[1]: volume.split(":")[0] for volume in services[service]["volumes"]}
        assert mounts.get(environment.get("MEDIA_ROOT")) == "media_files", (service, environment.get("MEDIA_ROOT"))


# --- Docker backups -------------------------------------------------------------------------------


@pytest.fixture
def project(tmp_path: Path) -> Project:
    project = Project(tmp_path.resolve())
    project.write_env(".env.prod", PROD_ENV)
    return project


def _cp_calls(project: Project) -> list[list[str]]:
    return [call["argv"] for call in project.calls() if call["argv"][:1] == ["cp"]]


def test_a_backup_archives_the_media_volume_next_to_its_dump(project: Project) -> None:
    result = project.run("backup.sh")
    assert result.returncode == 0, result.stdout + result.stderr
    backups = project.root / "backups"
    [dump] = backups.glob("praho_backup_*.sql.gz")
    media = backups / dump.name.replace(".sql.gz", ".media.tar.gz")
    assert media.is_file() and media.stat().st_size > 0
    assert _cp_calls(project) == [["cp", "praho_platform:/app/media", "-"]]
    assert list(backups.glob("*.partial")) == []


def test_retention_removes_old_media_archives_with_their_dumps(project: Project) -> None:
    backups = project.root / "backups"
    backups.mkdir()
    old = [backups / "praho_backup_20200101_000000_1.sql.gz", backups / "praho_backup_20200101_000000_1.media.tar.gz"]
    for path in old:
        path.write_bytes(EMPTY_GZIP)
        os.utime(path, (0, 0))
    result = project.run("backup.sh", "--cleanup", "7")
    assert result.returncode == 0, result.stdout + result.stderr
    assert [path for path in old if path.exists()] == []


def test_a_restore_puts_the_media_back_before_the_services_start(project: Project) -> None:
    backups = project.root / "backups"
    backups.mkdir()
    dump = backups / "praho_backup_20261007_000000_1.sql.gz"
    dump.write_bytes(EMPTY_GZIP)
    (backups / "praho_backup_20261007_000000_1.media.tar.gz").write_bytes(EMPTY_GZIP)
    result = project.run("restore.sh", str(dump), stdin="yes\n")
    assert result.returncode == 0, result.stdout + result.stderr
    argvs = [call["argv"] for call in project.calls()]
    restore = argvs.index(["cp", "-a", "-", "praho_platform:/app"])
    assert argvs.index(["stop", "praho_qcluster", "praho_platform", "praho_portal"]) < restore
    assert restore < argvs.index(["start", "praho_platform", "praho_portal", "praho_qcluster"])


def _dump_with_media(project: Project, media: bytes = EMPTY_GZIP) -> Path:
    backups = project.root / "backups"
    backups.mkdir()
    dump = backups / "praho_backup_20261007_000000_1.sql.gz"
    dump.write_bytes(EMPTY_GZIP)
    (backups / "praho_backup_20261007_000000_1.media.tar.gz").write_bytes(media)
    return dump


def _dropped(project: Project) -> bool:
    return any("DROP SCHEMA" in " ".join(call["argv"]) for call in project.calls())


@pytest.mark.parametrize(
    ("case", "media", "env"),
    [
        ("container removed", EMPTY_GZIP, {"DOCKER_CONTAINER_MISSING": "1"}),
        ("damaged archive", b"not a gzip stream", {}),
    ],
)
def test_a_restore_that_could_not_restore_the_media_changes_nothing(
    project: Project, case: str, media: bytes, env: dict[str, str]
) -> None:
    dump = _dump_with_media(project, media)
    result = project.run("restore.sh", str(dump), stdin="yes\n", **env)
    assert result.returncode != 0, case
    assert "nothing was restored" in result.stdout, result.stdout
    assert not _dropped(project), case


def test_a_media_failure_after_the_database_still_brings_the_services_back(project: Project) -> None:
    dump = _dump_with_media(project)
    result = project.run("restore.sh", str(dump), stdin="yes\n", DOCKER_CP_FAILS="1")
    assert result.returncode != 0
    assert "restoring the media failed" in result.stdout, result.stdout
    assert ["start", "praho_platform", "praho_portal", "praho_qcluster"] in [call["argv"] for call in project.calls()]


def test_a_media_failure_still_applies_retention(project: Project) -> None:
    backups = project.root / "backups"
    backups.mkdir()
    old = backups / "praho_backup_20200101_000000_1.sql.gz"
    old.write_bytes(EMPTY_GZIP)
    os.utime(old, (0, 0))
    result = project.run("backup.sh", DOCKER_CP_FAILS="1")
    assert result.returncode != 0
    assert not old.exists()
    assert list(backups.glob("praho_backup_*.sql.gz")), "the new dump is kept"


def test_a_restore_without_a_media_archive_says_the_media_was_left_alone(project: Project) -> None:
    backups = project.root / "backups"
    backups.mkdir()
    dump = backups / "praho_backup_20261007_000000_1.sql.gz"
    dump.write_bytes(EMPTY_GZIP)
    result = project.run("restore.sh", str(dump), stdin="yes\n")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "No media archive" in result.stdout
    assert ["cp", "-a", "-", "praho_platform:/app"] not in [call["argv"] for call in project.calls()]


# --- Native backups -------------------------------------------------------------------------------


def _render(template: str, root: Path) -> str:
    environment = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False)  # noqa: S701  # Shell, not HTML
    environment.filters["quote"] = shlex.quote
    return environment.from_string((TEMPLATES / template).read_text()).render(
        project_root=str(root),
        backup_directory=str(root / "backups"),
        backup_retention_days=7,
        deployed_env={"DB_PASSWORD": "x", "DB_USER": "praho", "DB_NAME": "praho"},
    )


def _native(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    root = tmp_path / "opt"
    (root / "media" / "efactura").mkdir(parents=True)
    (root / "media" / "efactura" / "response.zip").write_bytes(b"anaf")
    stubs = tmp_path / "bin"
    stubs.mkdir()
    (stubs / "pg_dump").write_text(
        '#!/bin/sh\nwhile [ "$#" -gt 0 ]; do [ "$1" = -f ] && echo dump > "$2"; shift; done\n'
    )
    for tool in ("pg_restore", "systemctl", "sudo", "sleep"):
        (stubs / tool).write_text("#!/bin/sh\nexit 0\n")
    for stub in stubs.iterdir():
        stub.chmod(0o755)
    (root / "scripts").mkdir()
    (root / "scripts" / "backup.sh").write_text("#!/bin/sh\nexit 0\n")
    (root / "scripts" / "backup.sh").chmod(0o755)
    return root, {**os.environ, "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}"}


def _run(script: str, env: dict[str, str], *args: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- the rendered script in this test's tmp_path
        ["bash", "-c", script, "restore", *args],  # noqa: S607
        env=env,
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_native_backup_archives_the_media_directory(tmp_path: Path) -> None:
    root, env = _native(tmp_path)
    result = _run(_render("backup-native.sh.j2", root), env)
    assert result.returncode == 0, result.stdout + result.stderr
    [dump] = (root / "backups").glob("praho_backup_*.dump")
    media = root / "backups" / dump.name.replace(".dump", ".media.tar.gz")
    with tarfile.open(media) as archive:
        assert "media/efactura/response.zip" in archive.getnames()


def _tar_exiting(tmp_path: Path, status: int) -> None:
    """A tar that does the work, then exits like GNU tar does for a file that changed under it."""
    real = subprocess.run(["sh", "-c", "command -v tar"], capture_output=True, text=True, check=True).stdout.strip()  # noqa: S607
    stub = tmp_path / "bin" / "tar"
    stub.write_text(f'#!/bin/sh\n"{real}" "$@" || exit $?\nexit {status}\n')
    stub.chmod(0o755)


def test_a_file_changing_during_the_native_archive_is_not_a_failure(tmp_path: Path) -> None:
    root, env = _native(tmp_path)
    _tar_exiting(tmp_path, 1)
    result = _run(_render("backup-native.sh.j2", root), env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "changed while it was archived" in result.stdout
    assert list((root / "backups").glob("praho_backup_*.media.tar.gz"))


def test_a_failed_native_archive_fails_the_run_after_retention(tmp_path: Path) -> None:
    root, env = _native(tmp_path)
    (root / "backups").mkdir()
    old = root / "backups" / "praho_backup_20200101_000000_1.dump"
    old.write_bytes(b"dump")
    os.utime(old, (0, 0))
    _tar_exiting(tmp_path, 2)
    result = _run(_render("backup-native.sh.j2", root), env)
    assert result.returncode != 0
    assert not old.exists()


def test_a_native_restore_puts_the_media_back(tmp_path: Path) -> None:
    root, env = _native(tmp_path)
    assert _run(_render("backup-native.sh.j2", root), env).returncode == 0
    [dump] = (root / "backups").glob("praho_backup_*.dump")
    (root / "media" / "efactura" / "response.zip").unlink()
    result = _run(_render("restore-native.sh.j2", root), env, str(dump), stdin="yes\n")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (root / "media" / "efactura" / "response.zip").read_bytes() == b"anaf"
