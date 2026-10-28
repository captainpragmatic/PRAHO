"""No backup holds the portal's session database (ADR-0017, services/portal/PORTAL_STATE.md).

The portal's SQLite file holds session data and counters, which bear credentials. Losing it only
signs people out, so it is never backed up: a copy would outlive every logout. Each backup copies
two things, the PostgreSQL dump and Platform's media, and in every deploy the portal's state lives
outside both.
"""

import re
import unittest
from pathlib import Path, PurePosixPath

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONTAINER_BACKUP = ROOT / "deploy/scripts/backup.sh"
NATIVE_BACKUP = ROOT / "deploy/ansible/roles/praho-native/templates/backup-native.sh.j2"
NATIVE_TASKS = ROOT / "deploy/ansible/roles/praho-native/tasks/main.yml"
NATIVE_DEFAULTS = ROOT / "deploy/ansible/roles/praho-native/defaults/main.yml"
ALL_VARS = ROOT / "deploy/ansible/group_vars/all.yml"
# Every Compose file that runs a portal with its session database (the dev stack included).
PORTAL_STACKS = ("dev", "single-server", "portal-only", "container-service")


def _commands(script: Path, pattern: str) -> list[str]:
    """The script's non-comment lines that match pattern."""
    lines = (line.strip() for line in script.read_text().splitlines())
    return [line for line in lines if line and not line.startswith("#") and re.search(pattern, line)]


def _environment(service: dict) -> dict[str, str]:
    raw = service.get("environment") or {}
    if isinstance(raw, dict):
        return {key: str(value) for key, value in raw.items()}
    return dict(item.split("=", 1) for item in raw if "=" in item)


def _mounts(service: dict) -> list[tuple[str, str]]:
    """(source, target) of each volume the service mounts."""
    mounts = []
    for volume in service.get("volumes") or []:
        if isinstance(volume, dict):
            mounts.append((str(volume.get("source", "")), str(volume["target"])))
        else:
            source, target = volume.split(":")[:2]
            mounts.append((source, target))
    return mounts


class BackupSourcesTests(unittest.TestCase):
    def test_the_container_backup_copies_only_the_dump_and_platform_media(self) -> None:
        script = CONTAINER_BACKUP.read_text()
        self.assertIn('MEDIA_CONTAINER="${MEDIA_CONTAINER:-praho_platform}"', script)
        self.assertIn('MEDIA_PATH="${MEDIA_PATH:-/app/media}"', script)
        copies = _commands(CONTAINER_BACKUP, r"\bdocker (cp|exec)\b")
        self.assertEqual(len(copies), 3, copies)
        self.assertIn('docker cp "${MEDIA_CONTAINER}:${MEDIA_PATH}" -', copies[0])
        self.assertIn("upload_platform_backup --report-failure", copies[1])  # reports a failure, copies nothing
        self.assertIn("docker exec praho_db pg_dump", copies[2])

    def test_the_offsite_copy_takes_only_the_dump_and_media(self) -> None:
        command = (ROOT / "services/platform/apps/common/management/commands/upload_platform_backup.py").read_text()
        self.assertIn('parser.add_argument("--artifact", choices=("database", "media"))', command)
        self.assertIn(
            'upload_platform_backup --database "$BACKUP_FILE" --media "$MEDIA_FILE"', NATIVE_BACKUP.read_text()
        )

    def test_the_native_backup_copies_only_the_dump_and_media(self) -> None:
        self.assertIn('MEDIA_ROOT="{{ project_root }}/media"', NATIVE_BACKUP.read_text())
        archives = _commands(NATIVE_BACKUP, r"^tar\b|\brsync\b|\bcp\b")
        self.assertEqual(
            archives,
            [
                'tar -C "$(dirname "${MEDIA_ROOT}")" -czf "${MEDIA_PARTIAL}" "$(basename "${MEDIA_ROOT}")" '
                "|| MEDIA_STATUS=$?"
            ],
        )
        self.assertEqual(len(_commands(NATIVE_BACKUP, r"^pg_dump\b")), 1)

    def test_no_backup_names_the_portal_state(self) -> None:
        portal_names = re.compile(
            r"portal\.sqlite3|SESSION_DB_PATH|portal_sessions|portal_state|praho-portal|praho_portal"
        )
        for script in (CONTAINER_BACKUP, NATIVE_BACKUP):
            with self.subTest(script=script.name):
                self.assertEqual(portal_names.findall(script.read_text()), [])


class PortalStateLocationTests(unittest.TestCase):
    def test_each_stacks_session_volume_is_mounted_by_the_portal_alone(self) -> None:
        for stack in PORTAL_STACKS:
            with self.subTest(stack=stack):
                services = yaml.safe_load((ROOT / f"deploy/docker-compose.{stack}.yml").read_text())["services"]
                owners = [name for name, service in services.items() if "SESSION_DB_PATH" in _environment(service)]
                self.assertEqual(owners, ["portal"])
                state_dir = str(PurePosixPath(_environment(services["portal"])["SESSION_DB_PATH"]).parent)
                volumes = [source for source, target in _mounts(services["portal"]) if target == state_dir]
                self.assertEqual(len(volumes), 1, f"{state_dir} is not a mounted volume")
                sharing = [name for name, service in services.items() if volumes[0] in dict(_mounts(service))]
                self.assertEqual(sharing, ["portal"])

    def test_the_native_portal_state_is_outside_the_backed_up_tree(self) -> None:
        state_dir = yaml.safe_load(NATIVE_DEFAULTS.read_text())["portal_state_directory"]
        project_root = yaml.safe_load(ALL_VARS.read_text())["project_root"]
        self.assertEqual((state_dir, project_root), ("/var/lib/praho-portal", "/opt/praho"))
        self.assertFalse(PurePosixPath(state_dir).is_relative_to(project_root))
        self.assertIn("SESSION_DB_PATH: \"{{ portal_state_directory + '/portal.sqlite3' }}\"", NATIVE_TASKS.read_text())
