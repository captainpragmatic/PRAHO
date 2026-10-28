"""The cleanup consumer honors the configured private migration spool."""

from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from django.test import TestCase

from apps.provisioning import migration_artifact_cleanup
from apps.settings.services import SettingsService


class MigrationArtifactSpoolSettingTests(TestCase):
    def test_cleanup_changes_only_the_selected_spool_when_configuration_changes(self):
        archive = f"migration_{uuid4()}.tar.gz"
        with TemporaryDirectory() as first, TemporaryDirectory() as second:
            locations = (Path(first), Path(second))
            for selected in locations:
                with self.subTest(selected=selected):
                    for directory in locations:
                        (directory / archive).write_text("private backup staging")
                    SettingsService.update_setting("provisioning.migration_spool_dir", str(selected)).unwrap()
                    migration_artifact_cleanup._remove_spool(archive)
                    self.assertFalse((selected / archive).exists())
                    other = next(directory for directory in locations if directory != selected)
                    self.assertEqual((other / archive).read_text(), "private backup staging")
