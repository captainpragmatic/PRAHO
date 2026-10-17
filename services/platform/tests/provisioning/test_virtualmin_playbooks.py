"""Static contracts of the Virtualmin node playbooks.

The behaviour behind each assertion was observed against Virtualmin 8.3.0 in
deploy/virtualmin-lab; these tests keep the playbooks from drifting back
without needing the lab.
"""

from __future__ import annotations

import yaml
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


class NodeFirewallPlaybookTests(SimpleTestCase):
    """virtualmin_harden.yml: SSH and Webmin reachable only from the node admin allowlist (ADR-0060)."""

    ADMIN_PORTS = frozenset({"22", "10000"})

    @staticmethod
    def _group_vars() -> dict[str, list[object]]:
        loaded = yaml.safe_load((PLAYBOOKS.parent / "group_vars" / "all.yml").read_text())
        assert isinstance(loaded, dict)
        return loaded

    def test_admin_ports_are_not_open_to_everyone(self) -> None:
        group_vars = self._group_vars()
        public = {str(port) for port in group_vars["firewall_allowed_tcp_ports"]}
        self.assertFalse(public & self.ADMIN_PORTS, public)
        self.assertEqual({str(port) for port in group_vars["firewall_admin_tcp_ports"]}, self.ADMIN_PORTS)
        # Web, mail, FTP, DNS and Usermin stay public.
        self.assertLessEqual({"80", "443", "25", "465", "587", "993", "995", "21", "53", "20000"}, public)

    def test_play_refuses_an_empty_allowlist_before_touching_the_firewall(self) -> None:
        names = [task.get("name") for task in tasks("virtualmin_harden.yml")]
        guard = task_named("virtualmin_harden.yml", "Refuse an empty node admin allowlist")
        self.assertIn("node_admin_allowed_cidrs | length > 0", guard["ansible.builtin.assert"]["that"])
        first_ufw = min(
            index for index, task in enumerate(tasks("virtualmin_harden.yml")) if "community.general.ufw" in task
        )
        self.assertLess(names.index("Refuse an empty node admin allowlist"), first_ufw)

    def test_admin_ports_are_allowed_only_from_the_allowlist(self) -> None:
        task = task_named("virtualmin_harden.yml", "Allow SSH and Webmin from the node admin allowlist")
        rule = task["community.general.ufw"]
        self.assertEqual(rule["rule"], "allow")
        self.assertEqual(rule["from_ip"], "{{ item.1 }}")
        self.assertEqual(rule["port"], "{{ item.0 }}")
        self.assertIn("product(node_admin_allowed_cidrs)", task["loop"])
        self.assertIn("firewall_admin_tcp_ports", task["loop"])
        for other in tasks("virtualmin_harden.yml"):
            spec = other.get("community.general.ufw") or {}
            if spec.get("rule") == "allow" and not spec.get("delete") and "from_ip" not in spec:
                with self.subTest(task=other.get("name")):
                    self.assertNotIn("firewall_admin_tcp_ports", str(other.get("loop", "")))
                    self.assertNotIn(str(spec.get("port")), self.ADMIN_PORTS)
        removed = task_named("virtualmin_harden.yml", "Remove any-source SSH and Webmin rules")
        self.assertIs(removed["community.general.ufw"]["delete"], True)

    def test_the_firewall_ends_enabled_even_when_no_rule_changed(self) -> None:
        # Observed in the lab: with every rule in place and UFW switched off, the
        # notify-only handler never fired and the play left the firewall off.
        names = [task.get("name") for task in tasks("virtualmin_harden.yml")]
        enable = task_named("virtualmin_harden.yml", "Enable UFW")
        self.assertEqual(enable["community.general.ufw"], {"state": "enabled"})
        self.assertNotIn("when", enable)
        last_rule = max(
            index
            for index, task in enumerate(tasks("virtualmin_harden.yml"))
            if "rule" in (task.get("community.general.ufw") or {})
            or "default" in (task.get("community.general.ufw") or {})
        )
        self.assertGreater(names.index("Enable UFW"), last_rule)

    def test_the_deploy_cannot_lock_platform_out(self) -> None:
        names = [task.get("name") for task in tasks("virtualmin_harden.yml")]
        check = task_named("virtualmin_harden.yml", "Require this connection's source in the allowlist")
        self.assertIn("SSH_CLIENT", str(check))
        # The source is checked and the allow rules exist before the deny default.
        for earlier in (
            "Require this connection's source in the allowlist",
            "Allow SSH and Webmin from the node admin allowlist",
        ):
            with self.subTest(task=earlier):
                self.assertLess(names.index(earlier), names.index("Configure UFW defaults"))
        self.assertLess(
            names.index("Allow SSH and Webmin from the node admin allowlist"),
            names.index("Remove any-source SSH and Webmin rules"),
        )


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
