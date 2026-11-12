"""Database files stay out of the kernel quota on every path that can create them (ADR-0075)."""

import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import yaml
from django.conf import settings
from django.test import SimpleTestCase

from apps.provisioning.virtualmin_backup_service import restore_domain_params

ANSIBLE = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks"
ADAPTER = ANSIBLE / "files/praho-notification-policy.pl"

# Doubles only Virtualmin's template storage. get_template mirrors its inheritance: template 0 comes from the module
# config, and a template without its own mysql section inherits the default's.
HARNESS = r"""
require $ARGV[0];
package virtual_server;
our %config = (mysql_chgrp => $ARGV[1]);
my @stored = @{JSON::PP->new->decode($ARGV[2])};
my $saves = 0;
sub list_templates { return ({id => 0}, map { {%$_} } @stored); }
sub get_template {
    my ($id) = @_;
    return {id => 0, mysql_chgrp => $config{'mysql_chgrp'}} if !$id;
    my ($raw) = grep { $_->{'id'} == $id } @stored;
    return {%$raw, mysql_chgrp => exists($raw->{'mysql_chgrp'}) ? $raw->{'mysql_chgrp'} : $config{'mysql_chgrp'}};
}
sub save_module_config_keys { my ($keys) = @_; $config{$_} = $keys->{$_} for keys %$keys; }
sub save_template {
    my ($t) = @_;
    $saves++;
    return if $ARGV[4];
    @stored = map { $_->{'id'} == $t->{'id'} ? $t : $_ } @stored;
}
my $result = $ARGV[3] eq 'repair' ? praho_repair_database_policy() : praho_database_policy();
print JSON::PP->new->canonical->encode({%$result, saves => $saves, global => $config{'mysql_chgrp'}});
"""


def _run_adapter(mode, *, stored, global_value="0", ignore_saves=False):
    return subprocess.run(  # noqa: S603 -- Fixed adapter and argv; only template storage is doubled.
        [
            "/usr/bin/perl",
            "-e",
            HARNESS,
            str(ADAPTER),
            global_value,
            json.dumps(stored),
            mode,
            "1" if ignore_saves else "",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


class EffectiveTemplatePolicyTests(SimpleTestCase):
    def adapter(self, mode, **kwargs):
        result = _run_adapter(mode, **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_a_template_inheriting_the_safe_default_is_safe(self):
        self.assertEqual(self.adapter("check", stored=[{"id": 1}])["overrides"], [])

    def test_an_explicit_override_is_found_though_the_global_value_is_safe(self):
        self.assertEqual(self.adapter("check", stored=[{"id": 1}, {"id": 5, "mysql_chgrp": "1"}])["overrides"], [5])

    def test_the_inherited_global_value_counts_for_every_template(self):
        self.assertEqual(self.adapter("check", stored=[{"id": 1}], global_value="1")["overrides"], [0, 1])

    def test_repair_turns_off_the_global_value_and_only_real_overrides(self):
        result = self.adapter("repair", stored=[{"id": 1}, {"id": 5, "mysql_chgrp": "1"}], global_value="1")
        self.assertEqual(result["overrides"], [])
        self.assertEqual(result["repaired"], [5])
        self.assertEqual(result["saves"], 1)
        self.assertEqual(str(result["global"]), "0")

    def test_repair_changes_nothing_on_a_safe_node(self):
        result = self.adapter("repair", stored=[{"id": 1}, {"id": 5, "mysql_chgrp": "0"}])
        self.assertEqual((result["repaired"], result["saves"]), ([], 0))

    def test_a_repair_that_did_not_take_effect_fails(self):
        result = _run_adapter("repair", stored=[{"id": 5, "mysql_chgrp": "1"}], ignore_saves=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Virtualmin template", result.stderr)


class DatabasePolicyPlaybookTests(SimpleTestCase):
    def setUp(self):
        self.tasks = yaml.safe_load((ANSIBLE / "virtualmin.yml").read_text())[0]["tasks"]
        self.names = [task.get("name", "") for task in self.tasks]
        self.safe = self.names.index("Keep tenant database files out of the account group quota")
        self.repair = self.names.index("Repair every Virtualmin template that would charge databases to their account")
        self.read = self.names.index("Read MariaDB's actual data directory")
        self.point = self.names.index("Point Webmin's MySQL module at MariaDB's actual data directory")

    def test_an_already_installed_node_gets_the_policy_on_every_play(self):
        for index in (self.safe, self.repair, self.read, self.point):
            self.assertNotIn("when", self.tasks[index], self.names[index])
        line = self.tasks[self.safe]["ansible.builtin.lineinfile"]
        self.assertEqual(line["path"], "/etc/webmin/virtual-server/config")
        self.assertEqual((line["regexp"], line["line"]), ("^mysql_chgrp=", "mysql_chgrp=0"))

    def test_the_first_install_block_no_longer_turns_charging_on(self):
        self.assertNotIn("mysql_chgrp: ", (ANSIBLE / "virtualmin.yml").read_text().replace("key: mysql_chgrp", ""))
        for task in self.tasks:
            for item in task.get("loop", []) if isinstance(task.get("loop"), list) else []:
                if isinstance(item, dict):
                    self.assertNotEqual(item.get("key"), "mysql_chgrp")

    def test_the_effective_policy_is_safe_before_webmin_learns_the_real_datadir(self):
        # Correcting mysql_data while mysql_chgrp is effective would switch on the behaviour that aborts MariaDB.
        self.assertLess(self.names.index("Confirm Virtualmin actually installed"), self.safe)
        self.assertLess(self.safe, self.repair)
        self.assertLess(self.repair, self.read)
        self.assertLess(self.read, self.point)
        self.assertLess(self.point, self.names.index("Configure the Virtualmin default addresses"))

    def test_the_repair_task_uses_the_installed_adapter_and_cannot_hide_a_failure(self):
        task = self.tasks[self.repair]
        self.assertEqual(
            task["ansible.builtin.command"]["argv"],
            ["/usr/bin/perl", "/usr/local/lib/praho/praho-notification-policy.pl", "database_policy_repair"],
        )
        self.assertNotIn("ignore_errors", task)
        self.assertNotIn("failed_when", task)

    def test_mysql_data_is_read_from_the_server_and_written_to_webmin(self):
        self.assertIn("SELECT @@datadir", self.tasks[self.read]["ansible.builtin.command"]["argv"])
        line = self.tasks[self.point]["ansible.builtin.lineinfile"]
        self.assertEqual((line["path"], line["regexp"]), ("/etc/webmin/mysql/config", "^mysql_data="))
        self.assertIn("mariadb_datadir", line["line"])


class DatabasePolicyAdmissionTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        spec = importlib.util.spec_from_file_location("database_policy_native", ANSIBLE / "files/praho_quota_native.py")
        cls.native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.native)

    def adapter_answers(self, overrides):
        return patch.object(self.native, "_run", return_value=json.dumps({"overrides": overrides}))

    def test_a_safe_effective_policy_passes(self):
        with self.adapter_answers([]) as run:
            self.native._database_policy_qualified()
        self.assertEqual(run.call_args.args[0][-1], "database_policy")

    def test_an_unsafe_template_is_refused_and_named(self):
        with self.adapter_answers([0, 5]), self.assertRaisesRegex(self.native.DatabaseStorageRefusalError, "0, 5"):
            self.native._database_policy_qualified()

    def test_an_unreadable_answer_is_refused(self):
        for answer in ("{}", '{"overrides":"none"}', '{"overrides":["x"]}', "not json"):
            with (
                self.subTest(answer=answer),
                patch.object(self.native, "_run", return_value=answer),
                self.assertRaises(ValueError),
            ):
                self.native._database_policy_qualified()

    def storage(self, backend, directory):
        home = Path(directory).resolve()
        datadir = home / "data"
        (datadir / "tenant_db").mkdir(parents=True)
        me = home.stat()
        account = SimpleNamespace(pw_dir=str(home), pw_uid=me.st_uid, pw_gid=me.st_gid)
        answers = iter(
            [
                json.dumps(
                    {
                        "filesystems": [
                            {
                                "source": "/dev/fixture",
                                "fstype": "ext4",
                                "uuid": "12345678-1234-1234-1234-123456789012",
                                "target": "/",
                            }
                        ]
                    }
                ),
                f"{datadir}\t1",
            ]
        )
        with (
            patch.object(self.native, "_run", side_effect=lambda *_a, **_k: next(answers)),
            patch.object(self.native, "_fields", return_value={"hard_quotas": "1"}),
            patch.object(self.native, "_database_writer_qualified", return_value=(110, 113)),
            patch.object(self.native, "_table_inventory", return_value=[]),
            patch.object(self.native, "qualify_database_directory") as qualify,
        ):
            backend._storage({"db_mysql": "tenant_db"}, account)
        return qualify

    def native_backend(self):
        with patch.object(self.native.os, "geteuid", return_value=0):
            return self.native.NativeQuotaBackend()

    def test_every_storage_check_requires_the_effective_policy_first(self):
        with TemporaryDirectory() as directory, patch.object(
            self.native, "_database_policy_qualified", side_effect=self.native.DatabaseStorageRefusalError("template 5")
        ), self.assertRaisesRegex(self.native.DatabaseStorageRefusalError, "template 5"):
            self.storage(self.native_backend(), directory)

    def test_storage_is_checked_against_the_running_writer_and_the_account(self):
        with TemporaryDirectory() as directory, patch.object(self.native, "_database_policy_qualified"):
            qualify = self.storage(self.native_backend(), directory)
        self.assertEqual(qualify.call_args.kwargs["writer"], (110, 113))
        self.assertEqual(qualify.call_args.args[0].name, "tenant_db")


    def test_mariadb_s_own_files_at_the_datadir_root_never_refuse_a_node(self):
        # Staging -001: /var/lib/mariadb/mariadb_upgrade_info is root:root at the datadir root. Only directories the
        # account owns in db_mysql, and their files, are checked.
        with TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            datadir = home / "data"
            (datadir / "tenant_db").mkdir(parents=True)
            (datadir / "tenant_db" / "db.opt").write_text("x")
            (datadir / "mariadb_upgrade_info").write_text("11.8.6")
            (datadir / "other_tenant_db").mkdir()
            real_lstat = os.lstat
            owners = {"mariadb_upgrade_info": (0, 0), "other_tenant_db": (4242, 4242)}

            def doubled(path):
                fields = list(real_lstat(path))
                fields[stat.ST_UID], fields[stat.ST_GID] = owners.get(Path(path).name, (110, 113))
                return os.stat_result(fields)

            me = home.stat()
            account = SimpleNamespace(pw_dir=str(home), pw_uid=me.st_uid, pw_gid=me.st_gid)
            mount = {"filesystems": [{"source": "/dev/fixture", "fstype": "ext4", "target": "/",
                                      "uuid": "12345678-1234-1234-1234-123456789012"}]}

            def native_answer(argv, **_kwargs):
                return json.dumps(mount) if argv[0] == "/usr/bin/findmnt" else f"{datadir}\t1"

            with (
                patch.object(self.native, "_run", side_effect=native_answer),
                patch.object(self.native, "_fields", return_value={"hard_quotas": "1"}),
                patch.object(self.native, "_database_policy_qualified"),
                patch.object(self.native, "_database_writer_qualified", return_value=(110, 113)),
                patch.object(self.native, "_table_inventory", return_value=[]),
                patch.object(Path, "lstat", lambda path: doubled(path)),  # noqa: PLW0108 -- Binds as a Path method.
            ):
                self.native_backend()._storage({"db_mysql": "tenant_db"}, account)
                owners["db.opt"] = (me.st_uid, me.st_gid)
                with self.assertRaisesRegex(self.native.DatabaseStorageRefusalError, "tenant_db: db.opt"):
                    self.native_backend()._storage({"db_mysql": "tenant_db"}, account)


class RestoreCannotImportTemplatesTests(SimpleTestCase):
    def test_a_praho_restore_is_limited_to_web_features_and_imports_no_virtualmin_settings(self):
        params = restore_domain_params(domain="example.test", source="/backup.tar.gz")
        self.assertEqual(set(params), {"domain", "source", "feature", "only-features"})
        self.assertNotIn("all-virtualmin", params)
        self.assertNotIn("virtualmin", params)
