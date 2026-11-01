"""Static contracts of the Virtualmin node playbooks.

The behaviour behind each assertion was observed against Virtualmin 8.3.0 in
deploy/virtualmin-lab; these tests keep the playbooks from drifting back
without needing the lab.
"""

from __future__ import annotations

import importlib.util
import io
import os
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import yaml
from django.test import SimpleTestCase
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment

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
        variables = load("virtualmin.yml")[0]["vars"]
        self.assertEqual(variables["virtualmin_install_script_url"], "https://raw.githubusercontent.com/virtualmin/virtualmin-install/232a23d6aebf3ff9ad43d4d2823773ad14770509/virtualmin-install.sh")
        self.assertEqual(variables["virtualmin_install_script_checksum"], "sha256:996d32a9a2b7e64cc9dc4af7b6d001297fdee867ce34dffae31a7197f230d5ae")

    def test_installer_library_and_firewall_owner_are_qualified_together(self) -> None:
        variables = load("virtualmin.yml")[0]["vars"]
        self.assertEqual(
            variables["virtualmin_install_library_url"],
            "https://raw.githubusercontent.com/virtualmin/slib/d225f66ee9df1f29865a8b117f968cdf44672380/slib.sh",
        )
        self.assertEqual(variables["virtualmin_install_library_checksum"], "sha256:a6894f5b83d2d4776f0f7103dd984dbf34e823902d94574c65e52b59a9f77941")
        library = task_named("virtualmin.yml", "Download the matching qualified installer utility library")
        self.assertEqual(library["ansible.builtin.get_url"]["dest"], "/root/slib.sh")
        install = task_named("virtualmin.yml", "Run Virtualmin installation")
        self.assertEqual(install["args"]["chdir"], "/root")
        self.assertIn("--exclude Nftables,Firewalld,Fail2ban,Fail2banFirewalld", install["ansible.builtin.command"])

    def test_api_proof_waits_for_actual_tls_after_panel_restarts(self) -> None:
        tasks = load("virtualmin.yml")[0]["tasks"]
        flush = task_named("virtualmin.yml", "Apply panel service changes before API credential verification")
        ready = task_named("virtualmin.yml", "Require the local Webmin TLS endpoint to be ready")
        self.assertLess(tasks.index(flush), tasks.index(ready))
        self.assertEqual(ready["ansible.builtin.uri"]["url"], "https://127.0.0.1:10000/")
        self.assertGreater(ready["retries"], 1)

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
        self.assertEqual(set(required), {"unix", "dir", "web", "ssl", "logrotate", "mysql"})
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


class NodeFirewallPlaybookTests(SimpleTestCase):
    """virtualmin_harden.yml: SSH and Webmin reachable only from the node admin allowlist (ADR-0060)."""

    ADMIN_PORTS = frozenset({"9876", "10000"})

    def setUp(self) -> None:
        self.role = PLAYBOOKS.parents[4] / "deploy/ansible/roles/virtualmin-web-only"
        spec = importlib.util.spec_from_file_location("web_firewall_contract", self.role / "files/firewall.py")
        self.policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.policy)
        self.role_tasks = yaml.safe_load((self.role / "tasks/main.yml").read_text())

    @staticmethod
    def _group_vars() -> dict[str, list[object]]:
        loaded = yaml.safe_load((PLAYBOOKS.parent / "group_vars" / "all.yml").read_text())
        assert isinstance(loaded, dict)
        return loaded

    def test_admin_ports_are_not_open_to_everyone(self) -> None:
        group_vars = self._group_vars()
        public = {str(port) for port in group_vars["firewall_allowed_tcp_ports"]}
        self.assertFalse(public & (self.ADMIN_PORTS | {"22"}), public)
        environment = NativeEnvironment(undefined=StrictUndefined)
        rendered = {
            str(environment.from_string(str(port)).render(ssh_port=9876))
            for port in group_vars["firewall_admin_tcp_ports"]
        }
        self.assertEqual(rendered, self.ADMIN_PORTS)
        bootstrap = {
            str(environment.from_string(str(port)).render(ssh_port=22))
            for port in group_vars["firewall_admin_tcp_ports"]
        }
        self.assertEqual(bootstrap, {"22", "10000"})
        # Legacy group vars remain for Blesta; the Virtualmin role owns its complete policy.
        self.assertLessEqual({"80", "443", "25", "465", "587", "993", "995", "21", "53", "20000"}, public)

    def test_play_refuses_an_empty_allowlist_before_touching_the_firewall(self) -> None:
        guard = self.role_tasks[0]
        self.assertIn("node_admin_allowed_cidrs | length > 0", guard["ansible.builtin.assert"]["that"])
        include = task_named("virtualmin_harden.yml", "Converge the reviewed host firewall")
        self.assertEqual(include["ansible.builtin.include_role"]["name"], "virtualmin-web-only")

    def test_admin_ports_are_allowed_only_from_the_allowlist(self) -> None:
        sources = ["192.0.2.10/32", "2001:db8::10/128"]
        with patch.object(self.policy, "run") as run:
            self.policy.add_allowed(sources, 9876)
        expected = [["ufw", "allow", "80/tcp"], ["ufw", "allow", "443/tcp"]]
        expected += [["ufw", "allow", "from", source, "to", "any", "port", port, "proto", "tcp"] for source in sources for port in ("9876", "10000")]
        self.assertEqual([call.args[0] for call in run.call_args_list], expected)

    def test_the_firewall_ends_enabled_even_when_no_rule_changed(self) -> None:
        # Observed in the lab: with every rule in place and UFW switched off, the
        # notify-only handler never fired and the play left the firewall off.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.policy.BASE, self.policy.LOCK = root / "snapshots", root / "lock"
            self.policy.CONFIG_FILES, self.policy.HOOK_FILES = [], []
            with patch.object(self.policy, "run", return_value="Status: inactive"):
                self.policy.begin("a" * 32)
            with (
                patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.10 50000 192.0.2.2 9876"}),
                patch.object(self.policy, "run", return_value="Status: inactive") as run,
                patch.object(self.policy, "configure_baselines"),
                patch.object(self.policy, "safe_defaults"),
                patch.object(self.policy, "ensure_guard"),
                patch.object(self.policy, "verify_guarded_filter"),
                redirect_stdout(io.StringIO()),
            ):
                self.policy.activate("a" * 32, {"cidrs": ["192.0.2.10/32"]})
            self.assertIn(["ufw", "--force", "enable"], [call.args[0] for call in run.call_args_list])
            ufw_calls = [call.args[0] for call in run.call_args_list if call.args[0][0] == "ufw"]
            self.assertEqual(ufw_calls[-1], ["ufw", "reload"])

    def test_the_deploy_cannot_lock_platform_out(self) -> None:
        for sources in ([], ["198.51.100.1/32"], ["0.0.0.0/0"]):
            with self.subTest(sources=sources), patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.10 50000 192.0.2.2 9876"}), patch.object(self.policy, "run") as run:
                with self.assertRaises(ValueError):
                    self.policy.activate("b" * 32, {"cidrs": sources})
                run.assert_not_called()


class NodeWebRootSymlinkTests(SimpleTestCase):
    """virtualmin_harden.yml: a customer cannot point their web root at another customer's files or the system.

    Observed in deploy/virtualmin-lab on Virtualmin 8.3.0: Debian's apache2.conf gives `<Directory />`
    `Options FollowSymLinks`, and each vhost's `+SymLinksIfOwnerMatch` covers only what is inside public_html.
    A customer who replaces their own public_html with a link to another home or to /etc is served through it,
    because Apache is in every customer's group. Owner-matched links under the home base close that and keep
    a link the customer owns to their own files (an account name's sub-server) working.
    """

    CONF = "/etc/apache2/conf-available/praho-home-symlinks.conf"

    def _conf_task(self) -> dict[str, object]:
        return task_named("virtualmin_harden.yml", "Keep customer web roots from linking outside their owner")

    def test_links_under_the_home_base_must_match_their_owner(self) -> None:
        spec = self._conf_task()["ansible.builtin.copy"]
        assert isinstance(spec, dict)
        self.assertEqual(spec["dest"], self.CONF)
        self.assertEqual(spec["src"], "files/praho-home-symlinks.conf")
        lines = [line.strip() for line in (PLAYBOOKS / spec["src"]).read_text().splitlines() if not line.startswith("#")]
        self.assertEqual(
            [line for line in lines if line],
            ["<Directory /home>", "Options -FollowSymLinks +SymLinksIfOwnerMatch", "AllowOverride None", "</Directory>"],
        )

    def test_the_guard_is_enabled_validated_and_then_loaded(self) -> None:
        names = [task.get("name") for task in tasks("virtualmin_harden.yml")]
        enable = task_named("virtualmin_harden.yml", "Enable the web root link guard")
        self.assertIn("a2enconf praho-home-symlinks", command_text(enable))
        check = task_named("virtualmin_harden.yml", "Validate the Apache configuration")
        self.assertIn("apache2ctl configtest", command_text(check))
        order = [
            "Keep customer web roots from linking outside their owner",
            "Enable the web root link guard",
            "Validate the Apache configuration",
            "Forget which web root link guard Apache loaded, when this run changed it",
            "Read which web root link guard Apache last loaded",
            "Load the web root link guard into Apache",
            "Record which web root link guard Apache loaded",
        ]
        self.assertEqual([names.index(name) for name in order], sorted(names.index(name) for name in order))

    def test_a_run_that_failed_after_installing_still_loads_the_guard_next_time(self) -> None:
        """The reload depends on what Apache last loaded, not on whether this run changed the file."""
        load = task_named("virtualmin_harden.yml", "Load the web root link guard into Apache")
        self.assertEqual(load["ansible.builtin.service"], {"name": "apache2", "state": "reloaded"})
        self.assertIn("web_root_guard.checksum", str(load["when"]))
        self.assertIn("web_root_guard_loaded", str(load["when"]))
        self.assertNotIn("notify", self._conf_task())
        forget = task_named("virtualmin_harden.yml", "Forget which web root link guard Apache loaded, when this run changed it")
        self.assertEqual(forget["ansible.builtin.file"]["state"], "absent")
        self.assertIn("web_root_guard.changed", str(forget["when"]))
        self.assertIn("web_root_guard_enabled.changed", str(forget["when"]))
        record = task_named("virtualmin_harden.yml", "Record which web root link guard Apache loaded")
        self.assertIn("web_root_guard.checksum", str(record["ansible.builtin.copy"]["content"]))
        for task in tasks("virtualmin_harden.yml"):
            with self.subTest(task=task.get("name")):
                self.assertFalse(task.get("ignore_errors", False) and "apache" in str(task).lower())
