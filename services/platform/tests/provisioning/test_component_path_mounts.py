"""Mount aliases can reopen selected website inodes outside the proposed read-only fence."""

import importlib.util
import os
import tempfile
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase


class ComponentMountTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        helper = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-paths.py"
        spec = importlib.util.spec_from_file_location("component_mount_paths", helper)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.home = self.directory / "home"
        self.web = self.home / "public_html"
        self.web.mkdir(parents=True)
        (self.web / "data").write_text("website")
        info = self.web.stat()
        self.device = f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}"
        self.proc = self.directory / "proc"
        self.proc.mkdir()
        (self.proc / "self").symlink_to("123")
        self.process(123, "111", [self.row(1, "/", "/")])

    def row(self, mount_id, root, point, *, filesystem="ext4", options="rw", device=None):  # noqa: PLR0913 -- native mountinfo fixture fields
        def escape(value):
            return str(value).replace("\\", "\\134").replace(" ", "\\040")

        return f"{mount_id} 0 {device or self.device} {escape(root)} {escape(point)} {options} - {filesystem} source rw"

    def process(self, pid, namespace, rows):
        process = self.proc / str(pid)
        (process / "ns").mkdir(parents=True)
        (process / "fd").mkdir()
        (process / "ns/mnt").symlink_to(f"mnt:[{namespace}]")
        (process / "root").symlink_to("/")
        (process / "stat").write_text(f"{pid} (worker) S " + "0 " * 18 + "999 0\n")
        (process / "mountinfo").write_text("\n".join(rows) + "\n")
        return process

    def qualify(self, **kwargs):
        return self.module.qualify_mounts(self.home, ("public_html",), proc=self.proc, **kwargs)

    def test_same_device_bind_alias_outside_selected_tree_is_refused(self):
        alias = self.home / "retained-service-alias"
        alias.symlink_to(self.web, target_is_directory=True)
        process = self.proc / "123"
        with (process / "mountinfo").open("a") as stream:
            stream.write(self.row(2, self.web, alias) + "\n")
        with self.assertRaisesRegex(ValueError, "alias|mount"):
            self.qualify()

    def test_each_relevant_namespace_is_witnessed_without_interrupting_private_tmp(self):
        self.process(
            456,
            "222",
            [self.row(10, "/", "/"), self.row(11, "/private-tmp", "/tmp", device="0:333", filesystem="tmpfs")],  # noqa: S108 -- synthetic PrivateTmp mount fact
        )
        result = self.qualify()
        self.assertEqual(
            result["namespaces"],
            [
                {"pid": 123, "start_time": "999", "mount_namespace": "111", "roots": [str(self.web)]},
                {"pid": 456, "start_time": "999", "mount_namespace": "222", "roots": [str(self.web)]},
            ],
        )
        self.assertEqual({mount["mount_id"] for mount in result["mounts"]}, {1, 10})

    def test_alias_in_other_mount_namespace_is_refused_without_a_writer(self):
        alias = self.home / "other-namespace-alias"
        alias.symlink_to(self.web, target_is_directory=True)
        self.process(456, "222", [self.row(10, "/", "/"), self.row(11, self.web, alias)])
        with self.assertRaisesRegex(ValueError, "alias|mount"):
            self.qualify()

    def test_ancestor_and_single_file_bind_aliases_are_refused(self):
        ancestor = self.directory / "whole-home-alias"
        ancestor.symlink_to(self.home, target_is_directory=True)
        single = self.directory / "single-file-alias"
        single.symlink_to(self.web / "data")
        for root, alias in ((self.home, ancestor), (self.web / "data", single)):
            (self.proc / "123/mountinfo").write_text(self.row(1, "/", "/") + "\n" + self.row(2, root, alias) + "\n")
            with self.subTest(root=root), self.assertRaisesRegex(ValueError, "alias|mount"):
                self.qualify()

    def test_btrfs_subvolume_superblock_roots_are_qualified_and_aliases_are_refused(self):
        baseline = self.row(1, "/@", "/", filesystem="btrfs")
        (self.proc / "123/mountinfo").write_text(baseline + "\n")
        self.assertEqual(self.qualify()["mounts"][0]["root"], "/@")
        alias = self.directory / "btrfs-alias"
        alias.symlink_to(self.web, target_is_directory=True)
        (self.proc / "123/mountinfo").write_text(
            baseline + "\n" + self.row(2, "/@" + str(self.web), alias, filesystem="btrfs") + "\n"
        )
        with self.assertRaisesRegex(ValueError, "alias|mount"):
            self.qualify()

    def test_same_device_nested_mount_and_unclassified_filesystem_are_refused(self):
        for rows in (
            [self.row(1, "/", "/"), self.row(2, self.web / "data", self.web / "data")],
            [self.row(1, "/", "/", filesystem="nfs4")],
        ):
            (self.proc / "123/mountinfo").write_text("\n".join(rows) + "\n")
            with self.subTest(rows=rows), self.assertRaisesRegex(ValueError, "mount|filesystem"):
                self.qualify()

    def test_only_exact_owned_readonly_bind_mount_ids_are_allowed_during_verification(self):
        (self.proc / "123/mountinfo").write_text(
            self.row(1, "/", "/") + "\n" + self.row(2, self.web, self.web, options="ro") + "\n"
        )
        with self.assertRaisesRegex(ValueError, "mount"):
            self.qualify()
        result = self.qualify(owned_mounts={"111": [2]})
        self.assertTrue(next(mount for mount in result["mounts"] if mount["mount_id"] == 2)["read_only"])
        for owned in ({"111": [3]}, {"222": [2]}, {"111": [2, 2]}):
            with self.subTest(owned=owned), self.assertRaisesRegex(ValueError, "owned|mount"):
                self.qualify(owned_mounts=owned)
        (self.proc / "123/mountinfo").write_text(self.row(1, "/", "/") + "\n" + self.row(2, self.web, self.web) + "\n")
        with self.assertRaisesRegex(ValueError, "read.only|mount"):
            self.qualify(owned_mounts={"111": [2]})

    def test_ext4_xfs_btrfs_overlay_and_escaped_mount_paths_are_supported(self):
        for filesystem in ("ext4", "xfs", "btrfs", "overlay"):
            (self.proc / "123/mountinfo").write_text(self.row(1, "/", "/", filesystem=filesystem) + "\n")
            with self.subTest(filesystem=filesystem):
                self.assertEqual(self.qualify()["mounts"][0]["filesystem"], filesystem)

    def test_live_unreadable_or_malformed_namespace_evidence_is_refused(self):
        for value in ("malformed\n", self.row(1, "/", "/").replace(self.device, "broken")):
            (self.proc / "123/mountinfo").write_text(value)
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "mount|namespace"):
                self.qualify()

    def test_mount_namespace_held_only_by_a_descriptor_requires_preparation(self):
        descriptor = self.proc / "123/fd/3"
        descriptor.symlink_to("mnt:[111]")
        self.assertEqual(len(self.qualify()["namespaces"]), 1)
        descriptor.unlink()
        descriptor.symlink_to("mnt:[999]")
        with self.assertRaisesRegex(ValueError, "namespace|descriptor"):
            self.qualify()

    def test_kernel_threads_and_finished_processes_without_a_mount_namespace_are_unrelated(self):
        process = self.process(456, "222", [self.row(10, "/", "/")])
        (process / "ns/mnt").unlink()
        for state, flags in (("S", 0x00200000), ("Z", 0)):
            fields = [state, *(["0"] * 18), "999", "0"]
            fields[6] = str(flags)
            (process / "stat").write_text("456 (kernel worker) " + " ".join(fields) + "\n")
            with self.subTest(state=state):
                self.assertEqual(len(self.qualify()["namespaces"]), 1)
        (process / "stat").write_text("456 (live user process) S " + "0 " * 18 + "999 0\n")
        with self.assertRaisesRegex(ValueError, "namespace"):
            self.qualify()
