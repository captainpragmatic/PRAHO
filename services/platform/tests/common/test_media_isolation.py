"""Real media writes stay disposable across runners, errors and worker startup."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage, default_storage
from django.test import SimpleTestCase, override_settings

from tests.media import isolated_media
from tests.runner import MediaIsolatedParallelSuite, MediaIsolatedRunner, PostgreSQLSafeRunner


class TestMediaIsolationTests(SimpleTestCase):
    def test_suite_default_storage_writes_outside_the_checkout(self) -> None:
        self.assertIsInstance(default_storage, FileSystemStorage)
        self.assertNotEqual(Path(settings.MEDIA_ROOT).resolve(), (settings.BASE_DIR / "media").resolve())
        name = default_storage.save("isolation/suite-probe.txt", ContentFile(b"test media"))
        self.addCleanup(default_storage.delete, name)
        self.assertEqual((Path(settings.MEDIA_ROOT) / name).read_bytes(), b"test media")

    def test_runners_clean_up_on_success_and_exception_and_restore_existing_storage(self) -> None:
        for runner_class in (MediaIsolatedRunner, PostgreSQLSafeRunner):
            for fail in (False, True):
                with (
                    self.subTest(runner=runner_class.__name__, fail=fail),
                    TemporaryDirectory() as deployed,
                    override_settings(MEDIA_ROOT=deployed),
                ):
                    sentinel = default_storage.save("keep.txt", ContentFile(b"existing media"))
                    roots: list[Path] = []

                    def write_media(
                        _labels: list[str], fail_run: bool = fail, written_roots: list[Path] = roots,
                    ) -> int:
                        root = Path(settings.MEDIA_ROOT)
                        written_roots.append(root)
                        self.assertNotEqual(root, Path(deployed))
                        name = default_storage.save("gdpr_exports/probe.enc", ContentFile(b"export bytes"))
                        self.assertEqual((root / name).read_bytes(), b"export bytes")
                        if fail_run:
                            raise RuntimeError("discovery failed")
                        return 0

                    with patch("django.test.runner.DiscoverRunner.run_tests", side_effect=write_media):
                        runner = runner_class(verbosity=0)
                        if fail:
                            with self.assertRaisesMessage(RuntimeError, "discovery failed"):
                                runner.run_tests([])
                        else:
                            self.assertEqual(runner.run_tests([]), 0)

                    self.assertEqual(len(roots), 1)
                    self.assertFalse(roots[0].exists())
                    self.assertEqual(settings.MEDIA_ROOT, deployed)
                    with default_storage.open(sentinel) as stored:
                        self.assertEqual(stored.read(), b"existing media")

    def test_bucket_configuration_is_replaced_without_losing_explicit_test_overrides(self) -> None:
        storages = {
            **settings.STORAGES,
            "default": {"BACKEND": "storages.backends.s3.S3Storage", "OPTIONS": {"bucket_name": "do-not-touch"}},
        }
        with override_settings(STORAGES=storages):
            with isolated_media() as directory:
                self.assertIsInstance(default_storage, FileSystemStorage)
                self.assertEqual(default_storage.location, directory)
                with override_settings(MEDIA_ROOT=directory + "/explicit"):
                    name = default_storage.save("probe.txt", ContentFile(b"explicit override"))
                    self.assertEqual((Path(directory) / "explicit" / name).read_bytes(), b"explicit override")
            self.assertEqual(settings.STORAGES, storages)
        self.assertFalse(Path(directory).exists())

    def test_spawned_workers_receive_the_parent_directory_and_filesystem_backend(self) -> None:
        with isolated_media() as directory:
            suite = MediaIsolatedParallelSuite([], processes=2)
            args = suite.process_setup_args
            with override_settings(MEDIA_ROOT="unused-worker-default", STORAGES={
                "default": {"BACKEND": "django.core.files.storage.InMemoryStorage"},
            }):
                type(suite).process_setup(*args)
                self.assertEqual(settings.MEDIA_ROOT, directory)
                self.assertIsInstance(default_storage, FileSystemStorage)
                name = default_storage.save("worker/probe.txt", ContentFile(b"worker media"))
                self.assertEqual((Path(directory) / name).read_bytes(), b"worker media")
        self.assertFalse(Path(directory).exists())
