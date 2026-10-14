"""The orphan sweep reads the spool directory from the runtime setting."""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from django.test import TestCase

from apps.provisioning import virtualmin_tasks
from apps.settings.services import SettingsService


class SpoolSweepSettingEffectTests(TestCase):
    def test_the_sweep_cleans_the_directory_the_setting_names(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            old = time.time() - 60 * 60 * 60
            orphans = {}
            for directory in (first, second):
                orphan = Path(directory) / f"virtualmin_backup_{uuid4().hex}.tar.gz"
                orphan.write_bytes(b"x")
                os.utime(orphan, (old, old))
                orphans[directory] = orphan
            for directory in (first, second):
                self.assertTrue(SettingsService.update_setting("provisioning.migration_spool_dir", directory).is_ok())
                other = second if directory == first else first
                counts = {"spool_orphans_removed": 0}
                virtualmin_tasks._sweep_spool_orphans(counts)
                self.assertEqual(counts["spool_orphans_removed"], 1)
                self.assertFalse(orphans[directory].exists(), "the configured directory is swept")
                if directory == first:
                    self.assertTrue(orphans[other].exists(), "a directory the setting does not name is left alone")
