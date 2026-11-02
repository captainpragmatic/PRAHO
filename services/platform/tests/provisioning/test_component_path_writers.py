"""Existing descriptors, directory handles and shared mappings outlive an over-mounted read-only tree."""

import importlib.util
import os
import tempfile
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase


def prepare_native_php_parent(process):
    binary = process.parent / "php-fpm8.2"
    binary.write_text("Fixture native executable identity")
    binary.chmod(0o755)
    (process / "exe").symlink_to(binary)
    parent = process.parent / "42"
    rootfs = process.parent / "rootfs"
    for name in ("fd", "fdinfo", "ns"):
        (parent / name).mkdir(parents=True)
    (parent / "cwd").symlink_to(process.parent.parent)
    (parent / "root").symlink_to(rootfs)
    (parent / "maps").write_text("")
    (parent / "exe").symlink_to(binary)
    (parent / "status").write_text("Uid:\t" + "\t".join([str(os.geteuid())] * 4) + "\n")
    (parent / "cmdline").write_bytes(b"php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)\0")
    configuration = rootfs / "etc/php/8.2/fpm/php-fpm.conf"
    configuration.parent.mkdir(parents=True)
    configuration.write_text("[global]\n")
    configuration.chmod(0o644)


class ComponentWriterTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        helper = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-paths.py"
        spec = importlib.util.spec_from_file_location("component_writer_paths", helper)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.home = self.root / "home"
        self.web = self.home / "public_html"
        self.web.mkdir(parents=True)
        self.file = self.web / "app.php"
        self.file.write_text("website")
        self.scope = self.module.scan_paths(self.home, ("public_html",))
        self.proc = self.root / "proc"
        self.process = self.proc / "1234"
        for name in ("fd", "fdinfo", "ns"):
            (self.process / name).mkdir(parents=True)
        (self.process / "cwd").symlink_to(self.root)
        (self.process / "root").symlink_to(self.root)
        (self.process / "ns/mnt").symlink_to("mnt:[555]")
        (self.process / "cmdline").write_bytes(b"php-fpm: pool 123456789\0")
        (self.process / "status").write_text("Uid:\t123\t123\t123\t123\nPPid:\t42\nState:\tS (sleeping)\n")
        (self.process / "stat").write_text("1234 (php-fpm: pool) S 42 " + "0 " * 17 + "98765 0\n")
        (self.process / "maps").write_text("")
        prepare_native_php_parent(self.process)

    def inspect(self):
        return self.module.path_writers(self.scope["inodes"], "123456789", 123, proc=self.proc)

    def descriptor(self, target, flags):
        (self.process / "fd/3").symlink_to(target)
        (self.process / "fdinfo/3").write_text(f"pos:\t0\nflags:\t{flags:o}\n")

    def test_selected_php_writer_is_bound_to_pid_start_time_and_namespace(self):
        self.descriptor(self.file, os.O_WRONLY)
        writers = self.inspect()
        self.assertEqual(len(writers), 1)
        self.assertEqual(
            writers[0],
            {
                "pid": 1234,
                "start_time": "98765",
                "mount_namespace": "555",
                "kind": "php_fpm_pool",
                "identity": "123456789",
                "uid": 123,
            },
        )

    def test_readonly_regular_file_reader_does_not_interrupt_unrelated_services(self):
        self.descriptor(self.file, os.O_RDONLY)
        (self.process / "cmdline").write_bytes(b"dovecot/imap\0")
        self.assertEqual(self.inspect(), [])

    def test_readonly_directory_fd_and_cwd_can_reopen_the_old_writable_tree(self):
        self.descriptor(self.web, os.O_RDONLY)
        self.assertEqual(len(self.inspect()), 1)
        (self.process / "fd/3").unlink()
        (self.process / "cwd").unlink()
        (self.process / "cwd").symlink_to(self.web)
        self.assertEqual(len(self.inspect()), 1)

    def test_shared_writable_mapping_requires_fencing_but_private_mapping_does_not(self):
        info = self.file.stat()
        for permission, expected in (("rw-s", 1), ("rw-p", 0), ("r--s", 0)):
            (self.process / "maps").write_text(
                f"1000-2000 {permission} 00000000 {os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x} {info.st_ino} {self.file}\n"
            )
            with self.subTest(permission=permission):
                self.assertEqual(len(self.inspect()), expected)

    def test_unclassified_and_other_pool_writers_are_reported_for_preparation(self):
        self.descriptor(self.file, os.O_RDWR)
        for command in (b"php-fpm: pool 987654321\0", b"imap\0", b"php\0worker.php\0--secret=never-output\0"):
            (self.process / "cmdline").write_bytes(command)
            writers = self.inspect()
            self.assertEqual(writers[0]["kind"], "unknown")
            self.assertNotIn("secret", str(writers))

    def test_pool_command_line_alone_cannot_authorize_termination_of_an_unrelated_writer(self):
        self.descriptor(self.file, os.O_RDWR)
        (self.process / "exe").unlink()
        (self.process / "exe").symlink_to(self.file)
        self.assertEqual(self.inspect()[0]["kind"], "unknown")
        (self.process / "exe").unlink()
        (self.process / "exe").symlink_to(self.proc / "php-fpm8.2")
        (self.proc / "42/status").write_text("Uid:\t123\t123\t123\t123\n")
        self.assertEqual(self.inspect()[0]["kind"], "unknown")

    def test_incomplete_live_process_evidence_is_refused(self):
        self.descriptor(self.file, os.O_RDWR)
        (self.process / "fdinfo/3").write_text("unrecognized flags\n")
        with self.assertRaisesRegex(ValueError, "writer|descriptor"):
            self.inspect()
