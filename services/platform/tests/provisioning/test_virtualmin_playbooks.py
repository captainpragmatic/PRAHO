"""Static contracts of the Virtualmin node playbooks.

The behaviour behind each assertion was observed against Virtualmin 8.3.0 in
deploy/virtualmin-lab; these tests keep the playbooks from drifting back
without needing the lab.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from tests.provisioning.test_virtualmin_transfer_playbooks import PLAYBOOKS, command_text, load, task_named, tasks


class NodeDeployPlaybookTests(SimpleTestCase):
    """virtualmin.yml: only commands and config keys Virtualmin 8.3 has."""

    def test_no_task_or_handler_hides_its_failure(self) -> None:
        handlers = [handler for play in load("virtualmin.yml") for handler in play.get("handlers", [])]
        self.assertTrue(handlers)
        for task in [*tasks("virtualmin.yml"), *handlers]:
            with self.subTest(task=task.get("name")):
                self.assertNotIn(task.get("failed_when"), (False, "false"))
                self.assertFalse(task.get("ignore_errors", False))

    def test_only_commands_virtualmin_8_provides(self) -> None:
        commands = " ".join(command_text(task) for task in tasks("virtualmin.yml"))
        self.assertIn("set-global-feature", commands)
        for absent in ("create-admin", "modify-config", "--can-create", "--can-edit"):
            with self.subTest(command=absent):
                self.assertNotIn(absent, commands)

    def test_installs_the_virtualmin_8_installer(self) -> None:
        url = load("virtualmin.yml")[0]["vars"]["virtualmin_install_script_url"]
        self.assertEqual(url, "https://download.virtualmin.com/virtualmin-install.sh")

    def test_api_user_password_travels_on_stdin_only(self) -> None:
        task = task_named("virtualmin.yml", "Create or update the PRAHO API user")
        command = task["ansible.builtin.command"]
        self.assertEqual(command["stdin"], "{{ praho_api_password }}")
        self.assertNotIn("praho_api_password", " ".join(command["argv"]))
        self.assertIs(task["no_log"], True)
        self.assertNotIn("failed_when", task)

    def test_api_user_is_locked_to_the_node_admin_allowlist(self) -> None:
        """ADR-0060: the master-admin API user may log in only from the allowlist."""
        task = task_named("virtualmin.yml", "Create or update the PRAHO API user")
        argv = task["ansible.builtin.command"]["argv"]
        self.assertIsInstance(argv, str)
        self.assertIn("node_admin_allowed_cidrs", argv)
        guard = task_named("virtualmin.yml", "Refuse an empty node admin allowlist")
        self.assertIn("node_admin_allowed_cidrs | length > 0", guard["ansible.builtin.assert"]["that"])
        titles = [t.get("name") for t in tasks("virtualmin.yml")]
        self.assertLess(
            titles.index("Refuse an empty node admin allowlist"), titles.index("Create or update the PRAHO API user")
        )
        helper = (PLAYBOOKS / "files" / "praho-webmin-api-user.pl").read_text()
        # The networks become the Webmin user's own IP allow list; none means refuse.
        self.assertIn("$user->{'allow'} = join(' ', @networks);", helper)
        self.assertIn("$user->{'deny'} = '';", helper)
        self.assertIn('@networks || die "no allowed networks given', helper)

    def test_helper_grants_only_the_virtualmin_module(self) -> None:
        helper = (PLAYBOOKS / "files" / "praho-webmin-api-user.pl").read_text()
        self.assertIn("$user->{'modules'} = [ 'virtual-server' ];", helper)
        self.assertIn("<STDIN>", helper)
        self.assertIn("$acl{'noconfig'} = 0;", helper)

    def test_feature_set_matches_a_minimal_node(self) -> None:
        required = load("virtualmin.yml")[0]["vars"]["virtualmin_required_features"]
        self.assertEqual(set(required), {"unix", "dir", "web", "ssl", "logrotate", "mysql", "webmin"})
        task = task_named("virtualmin.yml", "Enable the Virtualmin features PRAHO provisions with")
        self.assertEqual(
            task["ansible.builtin.command"]["argv"][:3], ["virtualmin", "set-global-feature", "--enable-feature"]
        )
        self.assertNotIn("failed_when", task)

    def test_writes_no_config_key_that_breaks_or_is_inert(self) -> None:
        written: list[str] = []
        for task in tasks("virtualmin.yml"):
            module = task.get("ansible.builtin.lineinfile") or task.get("ansible.builtin.template") or {}
            if str(module.get("path", module.get("dest", ""))).startswith("/etc/webmin/virtual-server/"):
                written.extend(str(item.get("line", "")).partition("=")[0] for item in task.get("loop", []))
                written.append(str(module.get("dest", "")))
        self.assertIn("defip", written)
        for key in (
            "web_port",
            "php_fpm",
            "php_vers",
            "autoquota",
            "ssl",
            "/etc/webmin/virtual-server/domain-template",
        ):
            with self.subTest(key=key):
                self.assertNotIn(key, written)
        self.assertFalse((PLAYBOOKS / "templates" / "domain_template.j2").exists())


class NodeBackupPlaybookTests(SimpleTestCase):
    """virtualmin_backup.yml: a schedule Virtualmin 8 actually runs, never differential."""

    def test_schedule_is_created_through_the_virtualmin_cli(self) -> None:
        argv = task_named("virtualmin_backup.yml", "Create the nightly full backup schedule")[
            "ansible.builtin.command"
        ]["argv"]
        self.assertEqual(argv[:2], ["virtualmin", "create-scheduled-backup"])
        for flag in ("--all-domains", "--all-features", "--no-differential", "--schedule", "--dest", "--purge"):
            with self.subTest(flag=flag):
                self.assertIn(flag, argv)
        self.assertNotIn("--differential", argv)
        # create-scheduled-backup documents --desc but its parser rejects it.
        self.assertNotIn("--desc", argv)

    def test_writes_no_input_virtualmin_ignores_and_removes_old_ones(self) -> None:
        for task in tasks("virtualmin_backup.yml"):
            with self.subTest(task=task.get("name")):
                dest = str((task.get("ansible.builtin.template") or {}).get("dest", ""))
                self.assertNotEqual(dest, "/etc/webmin/virtual-server/sched")
                line = (task.get("ansible.builtin.lineinfile") or {}).get("state")
                if task.get("ansible.builtin.lineinfile"):
                    self.assertEqual(line, "absent")
                self.assertNotIn(task.get("failed_when"), (False, "false"))
                self.assertFalse(task.get("ignore_errors", False))
                self.assertNotIn("list-backup-dests", command_text(task))
        removed = task_named("virtualmin_backup.yml", "Remove the legacy single-schedule config keys")["loop"]
        self.assertIn("^backup_dest=", removed)
        self.assertEqual(
            task_named("virtualmin_backup.yml", "Remove the unread schedule file")["ansible.builtin.file"]["state"],
            "absent",
        )
        self.assertFalse((PLAYBOOKS / "templates" / "virtualmin_backup_schedule.j2").exists())

    def test_the_play_verifies_the_schedule_it_made(self) -> None:
        checks = task_named("virtualmin_backup.yml", "Require exactly the configured schedule")[
            "ansible.builtin.assert"
        ]
        joined = " ".join(checks["that"])
        self.assertIn("length == (1 if backup_enabled else 0)", joined)
        self.assertIn("['differential'][0] == 'No'", joined)
        self.assertIn("['enabled'][0] == 'Yes'", joined)
