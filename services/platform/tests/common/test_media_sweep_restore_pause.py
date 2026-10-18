"""A database restore pauses the sweeper, with the statement both restore scripts run.

After a restore, files written since the backup have no row, and the sweeper would delete them a
day later. Both restore scripts write `media_sweep.paused_until` with psql while the applications
are stopped; this runs that exact statement against the real schema.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path

from django.core.management import call_command
from django.db import connection
from django.test import TestCase
from django.utils import timezone

from apps.common.media_sweep import PAUSE_SETTING, RESTORE_PAUSE, sweep_orphaned_media
from apps.settings.models import SystemSetting

REPOSITORY = Path(__file__).resolve().parents[4]
SCRIPTS = (
    REPOSITORY / "deploy/scripts/restore.sh",
    REPOSITORY / "deploy/ansible/roles/praho-native/templates/restore-native.sh.j2",
)
STATEMENT = re.compile(r'^PAUSE_MEDIA_SWEEP_SQL="([^"]+)"$', re.MULTILINE)


def _restore_statement() -> str:
    statements = {match.group(1) for script in SCRIPTS for match in STATEMENT.finditer(script.read_text())}
    assert len(statements) == 1, f"both restore scripts run one and the same statement: {statements}"
    return statements.pop()


class RestorePausesTheSweeperTests(TestCase):
    def test_restore_pauses_the_sweeper(self) -> None:
        statement = _restore_statement()
        if connection.vendor != "postgresql":
            self.skipTest("the restore scripts run this statement with psql against PostgreSQL")
        call_command("setup_default_settings", verbosity=0)
        before = SystemSetting.objects.get(key=PAUSE_SETTING).revision

        with connection.cursor() as cursor:
            cursor.execute(statement)
            (returned,) = cursor.fetchone()

        row = SystemSetting.objects.get(key=PAUSE_SETTING)
        self.assertEqual(row.value, returned)
        self.assertEqual(row.revision, before + 1)
        self.assertAlmostEqual(
            datetime.fromisoformat(returned),
            timezone.now() + RESTORE_PAUSE,
            delta=timedelta(minutes=1),
        )
        self.assertTrue(sweep_orphaned_media()["paused"])
        call_command("setup_default_settings", verbosity=0)  # Every platform start runs the catalog sync
        self.assertTrue(sweep_orphaned_media()["paused"], "the sync keeps the pause the restore wrote")
