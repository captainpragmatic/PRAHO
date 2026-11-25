"""The panel certificate is judged by what Webmin serves, and an untrusted one fails the deploy (#436).

A disposable node (Virtualmin 8.3.0) showed the old steps never worked: ``generate-letsencrypt-cert``
without ``--domain`` exits 1, ``letsencrypt.cgi`` run from a shell exits 255, and both were swallowed.
Panels were trusted only because the installer's own hostname step happened to succeed. That step
also creates the hostname virtual server, and every ``generate-letsencrypt-cert`` call issues a new
certificate (Let's Encrypt reuses a cached authorization), so a reissue may run only when the served
certificate fails the check.

The decision logic is evaluated with Ansible's own templar over the playbook's real ``when:``
expressions, one registered-result scenario at a time.
"""

from __future__ import annotations

from typing import Any

from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar, trust_as_template
from django.test import SimpleTestCase

from apps.infrastructure.ansible_service import failure_detail
from tests.provisioning.test_virtualmin_transfer_playbooks import command_text, task_named, tasks

PLAYBOOK = "virtualmin.yml"
FQDN = "dev-sha-het-de-fsn1-001.native-acc.example.net"

CHECK = "Check the certificate the panel serves"
LOOKUP = "Look up the hostname virtual server"
REISSUE = "Reissue the panel certificate"
INSTALL = "Install the hostname certificate for Webmin"
RECHECK = "Re-check the certificate the panel serves"
DESCRIBE = "Describe the panel certificate failure"
FAIL = "Fail when the panel certificate is not trusted"
STEPS = (CHECK, LOOKUP, REISSUE, INSTALL, RECHECK, DESCRIBE, FAIL)

SKIPPED: dict[str, Any] = {"skipped": True, "changed": False}

# ansible-core 2.20.6 against a real Virtualmin 8.3.0 node whose hostname domain was deleted, with the
# callback settings AnsibleService uses. The check and re-check print [ERROR] for their failing attempts
# although their results are ok (failed_when); only the last task is fatal.
FAILED_RUN_STDOUT = """FAILED - RETRYING: [node]: Check the certificate the panel serves (1 retries left).

TASK [Check the certificate the panel serves] **********************************
[ERROR]: Task failed: Action failed: non-zero return code
Origin: /opt/praho/infrastructure/ansible/playbooks/virtualmin.yml:6:5

6   - name: Check the certificate the panel serves
      ^ column 5

ok: [node]

TASK [Re-check the certificate the panel serves] *******************************
[ERROR]: Task failed: Action failed: non-zero return code
Origin: /opt/praho/infrastructure/ansible/playbooks/virtualmin.yml:45:5

45   - name: Re-check the certificate the panel serves
       ^ column 5

ok: [node]

TASK [Fail when the panel certificate is not trusted] **************************
[ERROR]: Task failed: Action failed: LETSENCRYPT_FAILED step=hostname-domain the hostname virtual server node.example.net does not exist: the installer's hostname certificate step failed and removed it. Check that node.example.net resolves to this node and that port 80 is reachable before retrying. Panel check: untrusted: verify error:num=18:self-signed certificate
Origin: /opt/praho/infrastructure/ansible/playbooks/virtualmin.yml:75:5

75   - name: Fail when the panel certificate is not trusted
       ^ column 5

fatal: [node]: FAILED! =>
    changed: false
    msg: 'LETSENCRYPT_FAILED step=hostname-domain the hostname virtual server node.example.net does not exist'

PLAY RECAP *********************************************************************
node                  : ok=4    changed=0    unreachable=0    failed=1    skipped=2    rescued=0    ignored=0
"""


def registered(**results: dict[str, Any]) -> dict[str, Any]:
    """The variables the block registers; a task that did not run registers as skipped."""
    names = {
        "check": "panel_cert_check",
        "lookup": "panel_cert_hostname_domain",
        "issue": "panel_cert_issue",
        "install": "panel_cert_install",
        "recheck": "panel_cert_recheck",
    }
    variables: dict[str, Any] = {name: dict(SKIPPED) for name in names.values()}
    for key, value in results.items():
        variables[names[key]] = value
    variables["node_fqdn"] = FQDN
    return variables


def ran(rc: int, stdout: str = "", stderr: str = "") -> dict[str, Any]:
    return {"rc": rc, "stdout": stdout, "stderr": stderr, "stdout_lines": stdout.splitlines(), "changed": rc == 0}


class PanelCertificateScenario:
    """Walks the block in order, as Ansible would, recording which steps run."""

    def __init__(self, variables: dict[str, Any]) -> None:
        self.variables = dict(variables)
        self.ran: list[str] = []
        self.failure = ""

    def _templar(self) -> Templar:
        return Templar(loader=DataLoader(), variables=self.variables)

    def runs(self, title: str) -> bool:
        conditions = task_named(PLAYBOOK, title).get("when", [])
        if isinstance(conditions, str):
            conditions = [conditions]
        return all(self._templar().evaluate_conditional(trust_as_template(str(c))) for c in conditions)

    def walk(self) -> PanelCertificateScenario:
        for title in STEPS:
            if not self.runs(title):
                continue
            self.ran.append(title)
            if title == DESCRIBE:
                facts = task_named(PLAYBOOK, DESCRIBE)["ansible.builtin.set_fact"]
                self.failure = str(self._templar().template(trust_as_template(facts["panel_cert_failure"])))
                self.variables["panel_cert_failure"] = self.failure
        return self


class PanelCertificateDecisionTests(SimpleTestCase):
    def test_a_trusted_certificate_is_left_alone(self) -> None:
        walk = PanelCertificateScenario(registered(check=ran(0))).walk()
        self.assertEqual(walk.ran, [CHECK])

    def test_a_node_without_a_public_name_skips_the_whole_block(self) -> None:
        variables = registered()
        variables["panel_certificate_required"] = False
        self.assertEqual(PanelCertificateScenario(variables).walk().ran, [])

    def test_an_untrusted_certificate_is_reissued_installed_and_rechecked(self) -> None:
        walk = PanelCertificateScenario(
            registered(check=ran(1, "untrusted"), lookup=ran(0, FQDN), issue=ran(0), install=ran(0), recheck=ran(0))
        ).walk()
        self.assertEqual(walk.ran, [CHECK, LOOKUP, REISSUE, INSTALL, RECHECK])

    def test_a_missing_hostname_domain_fails_with_its_own_reason(self) -> None:
        walk = PanelCertificateScenario(
            registered(check=ran(1, "untrusted"), lookup=ran(0, ""), recheck=ran(1, "untrusted: self-signed"))
        ).walk()
        self.assertNotIn(REISSUE, walk.ran)
        self.assertIn(FAIL, walk.ran)
        self.assertIn("LETSENCRYPT_FAILED step=hostname-domain", walk.failure)
        self.assertIn(FQDN, walk.failure)
        self.assertIn("untrusted: self-signed", walk.failure)

    def test_another_virtual_server_is_not_mistaken_for_the_hostname_domain(self) -> None:
        walk = PanelCertificateScenario(
            registered(check=ran(1, "untrusted"), lookup=ran(0, "customer.example.org"), recheck=ran(1, "untrusted"))
        ).walk()
        self.assertNotIn(REISSUE, walk.ran)
        self.assertIn("step=hostname-domain", walk.failure)

    def test_a_certificate_still_untrusted_after_both_steps_names_the_verification(self) -> None:
        walk = PanelCertificateScenario(
            registered(
                check=ran(1, "untrusted"), lookup=ran(0, FQDN), issue=ran(0), install=ran(0),
                recheck=ran(1, "untrusted: verify error:num=18:self-signed certificate"),
            )
        ).walk()
        self.assertIn(FAIL, walk.ran)
        self.assertIn("LETSENCRYPT_FAILED step=verify", walk.failure)
        self.assertIn("self-signed certificate", walk.failure)

    def test_an_untrusted_verdict_has_no_non_fatal_switch(self) -> None:
        """Only panel_certificate_required=false (skip the block) avoids enforcement; nothing half-enforces."""
        variables = registered(check=ran(1, "untrusted"), lookup=ran(0, ""), recheck=ran(1, "untrusted"))
        variables["letsencrypt_fatal"] = False
        self.assertIn(FAIL, PanelCertificateScenario(variables).walk().ran)
        self.assertNotIn("letsencrypt_fatal", " ".join(str(task) for task in tasks(PLAYBOOK)))


class PanelCertificateFailureHandlingTests(SimpleTestCase):
    def test_no_step_hides_its_own_failure(self) -> None:
        for title in STEPS:
            with self.subTest(title=title):
                task = task_named(PLAYBOOK, title)
                self.assertNotIn(task.get("failed_when"), (False, "false"))
                self.assertFalse(task.get("ignore_errors", False))

    def test_a_failed_reissue_install_or_lookup_fails_at_its_own_task(self) -> None:
        for title in (LOOKUP, REISSUE, INSTALL):
            with self.subTest(title=title):
                self.assertNotIn("failed_when", task_named(PLAYBOOK, title))

    def test_the_checks_fail_only_when_the_check_itself_breaks(self) -> None:
        templar = Templar(loader=DataLoader(), variables={})
        for title, register in ((CHECK, "panel_cert_check"), (RECHECK, "panel_cert_recheck")):
            expression = trust_as_template(str(task_named(PLAYBOOK, title)["failed_when"]))
            for rc, broken in ((0, False), (1, False), (2, True), (127, True)):
                with self.subTest(title=title, rc=rc):
                    templar.available_variables = {register: {"rc": rc}}
                    self.assertIs(templar.evaluate_conditional(expression), broken)


class PanelCertificateCommandTests(SimpleTestCase):
    def test_the_check_verifies_chain_name_and_expiry_of_the_served_certificate(self) -> None:
        for title in (CHECK, RECHECK):
            with self.subTest(title=title):
                script = command_text(task_named(PLAYBOOK, title))
                self.assertIn("openssl s_client -connect 127.0.0.1:10000", script)
                self.assertIn("-servername {{ node_fqdn }}", script)
                self.assertIn("-verify_hostname {{ node_fqdn }}", script)
                self.assertIn("-verify_return_error", script)
                self.assertIn("Verify return code: 0 (ok)", script)
                self.assertIn("-checkend 2592000", script)

    def test_the_reissue_targets_the_hostname_domain_over_http(self) -> None:
        command = command_text(task_named(PLAYBOOK, REISSUE))
        self.assertRegex(command, r"virtualmin generate-letsencrypt-cert\s+--domain \{\{ node_fqdn \}\}")
        self.assertIn("--web", command)
        self.assertNotIn("--host ", command)
        self.assertNotIn("--staging", command)

    def test_the_install_points_webmin_at_the_hostname_certificate(self) -> None:
        command = command_text(task_named(PLAYBOOK, INSTALL))
        self.assertRegex(command, r"virtualmin install-service-cert\s+--domain \{\{ node_fqdn \}\}")
        self.assertIn("--add-global", command)
        self.assertIn("--service webmin", command)

    def test_both_checks_wait_for_webmin_to_restart(self) -> None:
        """A refused connection reads as untrusted; on the first check that would order a certificate."""
        for title, register in ((CHECK, "panel_cert_check"), (RECHECK, "panel_cert_recheck")):
            with self.subTest(title=title):
                task = task_named(PLAYBOOK, title)
                self.assertEqual(task["register"], register)
                self.assertGreaterEqual(int(task["retries"]), 3)
                self.assertGreaterEqual(int(task["delay"]), 5)
                self.assertIn(f"{register}.rc == 0", str(task["until"]))

    def test_the_steps_run_in_order_after_the_install(self) -> None:
        titles = [task.get("name") for task in tasks(PLAYBOOK)]
        positions = [titles.index(title) for title in STEPS]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(titles.index("Run Virtualmin installation"), positions[0])

    def test_the_old_steps_and_their_marker_are_gone(self) -> None:
        text = " ".join(str(task) for task in tasks(PLAYBOOK))
        self.assertNotIn("letsencrypt.cgi", text)
        self.assertNotIn("letsencrypt-cert-", text)
        self.assertNotIn("Generate Let's Encrypt certificate for Virtualmin", text)

    def test_the_installer_keeps_its_hostname_certificate_step(self) -> None:
        self.assertNotIn("--no-hostname-ssl", command_text(task_named(PLAYBOOK, "Run Virtualmin installation")))


class PanelCertificateFailureReasonTests(SimpleTestCase):
    def test_the_deploy_failure_reason_is_the_fatal_task_not_a_recovered_retry(self) -> None:
        detail = failure_detail(FAILED_RUN_STDOUT, "")
        self.assertTrue(detail.startswith("[ERROR]: Task failed: Action failed: LETSENCRYPT_FAILED step=hostname-domain"), detail)
        self.assertIn("virtualmin.yml:75:5", detail)
        self.assertNotIn("non-zero return code", detail)
        self.assertNotIn("virtualmin.yml:6:5", detail)

    def test_a_fatal_task_without_its_own_error_line_is_not_explained_by_a_recovered_retry(self) -> None:
        stdout = (
            "TASK [Check the certificate the panel serves] ***\n"
            "[ERROR]: Task failed: Action failed: non-zero return code\n"
            "Origin: /opt/praho/infrastructure/ansible/playbooks/virtualmin.yml:6:5\n"
            "ok: [node]\n\n"
            "TASK [Run Virtualmin installation] ***\n"
            'fatal: [node]: FAILED! => {"changed": false, "msg": "installer exited 1", "rc": 1}\n'
        )
        detail = failure_detail(stdout, "")
        self.assertIn("installer exited 1", detail)
        self.assertNotIn("non-zero return code", detail)
        self.assertNotIn("virtualmin.yml:6:5", detail)

    def test_an_unreachable_host_or_a_failed_loop_item_is_not_explained_by_a_recovered_retry(self) -> None:
        recovered = (
            "TASK [Check the certificate the panel serves] ***\n"
            "[ERROR]: Task failed: Action failed: non-zero return code\n"
            "Origin: /opt/praho/infrastructure/ansible/playbooks/virtualmin.yml:6:5\n"
            "ok: [node]\n\n"
        )
        endings = {
            "unreachable": (
                "TASK [Look up the hostname virtual server] ***\n"
                "[ERROR]: Task failed: Failed to connect to the host via ssh: Connection timed out\n"
                "Origin: /opt/praho/infrastructure/ansible/playbooks/virtualmin.yml:30:7\n"
                'fatal: [node]: UNREACHABLE! => {"changed": false, "unreachable": true}\n',
                "Connection timed out",
            ),
            "loop item": (
                "TASK [Enable the Virtualmin features] ***\n"
                "[ERROR]: Task failed: Action failed: set-global-feature refused web\n"
                "Origin: /opt/praho/infrastructure/ansible/playbooks/virtualmin.yml:520:7\n"
                'failed: [node] (item=web) => {"ansible_loop_var": "item", "item": "web", "rc": 1}\n',
                "set-global-feature refused web",
            ),
        }
        for case, (ending, expected) in endings.items():
            with self.subTest(case=case):
                detail = failure_detail(recovered + ending, "")
                self.assertIn(expected, detail)
                self.assertNotIn("non-zero return code", detail)
                self.assertNotIn("virtualmin.yml:6:5", detail)

    def test_an_ignored_loop_failure_does_not_explain_the_later_fatal_task(self) -> None:
        stdout = (
            "TASK [Disable unnecessary services] ***\n"
            "[ERROR]: Task failed: Action failed: Could not find the requested service avahi-daemon\n"
            "Origin: /opt/praho/infrastructure/ansible/playbooks/virtualmin_harden.yml:210:7\n"
            'failed: [node] (item=avahi-daemon) => {"ansible_loop_var": "item", "item": "avahi-daemon"}\n'
            "...ignoring\n\n"
            "TASK [Apply the firewall policy] ***\n"
            "[ERROR]: Task failed: Action failed: ufw refused the rule set\n"
            "Origin: /opt/praho/infrastructure/ansible/playbooks/virtualmin_harden.yml:300:7\n"
            'fatal: [node]: FAILED! => {"changed": false, "msg": "ufw refused the rule set"}\n'
        )
        detail = failure_detail(stdout, "")
        self.assertIn("ufw refused the rule set", detail)
        self.assertIn("virtualmin_harden.yml:300:7", detail)
        self.assertNotIn("avahi-daemon", detail)

    def test_an_ignored_task_before_the_failure_does_not_supply_its_result(self) -> None:
        stdout = (
            "TASK [Probe an optional service] ***\n"
            "[ERROR]: Task failed: Action failed: non-zero return code\n"
            "Origin: /opt/praho/infrastructure/ansible/playbooks/virtualmin.yml:100:7\n"
            "fatal: [node]: FAILED! =>\n"
            "    changed: false\n"
            "    rc: 3\n"
            "    stderr: optional probe missing\n"
            "...ignoring\n\n"
            "TASK [Reissue the panel certificate] ***\n"
            "[ERROR]: Task failed: Action failed: non-zero return code\n"
            "Origin: /opt/praho/infrastructure/ansible/playbooks/virtualmin.yml:440:7\n"
            "fatal: [node]: FAILED! =>\n"
            "    changed: false\n"
            "    rc: 1\n"
            "    stdout: 'Web-based validation failed : Some challenges have failed.'\n"
        )
        detail = failure_detail(stdout, "")
        self.assertIn("virtualmin.yml:440:7", detail)
        self.assertIn("Some challenges have failed", detail)
        self.assertNotIn("optional probe missing", detail)

    def test_an_ignored_cleanup_after_the_failure_does_not_supply_the_origin(self) -> None:
        stdout = (
            "TASK [Reissue the panel certificate] ***\n"
            "[ERROR]: Task failed: Action failed: non-zero return code\n"
            "Origin: /opt/praho/infrastructure/ansible/playbooks/virtualmin.yml:440:7\n"
            "fatal: [node]: FAILED! =>\n"
            "    changed: false\n"
            "    rc: 1\n"
            "    stdout: 'Some challenges have failed.'\n\n"
            "TASK [Remove the temporary files] ***\n"
            "[ERROR]: Task failed: Action failed: file busy\n"
            "Origin: /opt/praho/infrastructure/ansible/playbooks/virtualmin.yml:900:11\n"
            "fatal: [node]: FAILED! =>\n"
            "    changed: false\n"
            "    msg: file busy\n"
            "...ignoring\n"
        )
        detail = failure_detail(stdout, "")
        self.assertIn("virtualmin.yml:440:7", detail)
        self.assertNotIn("virtualmin.yml:900:11", detail)
        self.assertNotIn("file busy", detail)
