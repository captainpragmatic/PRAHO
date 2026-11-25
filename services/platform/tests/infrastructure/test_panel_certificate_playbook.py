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
REPORT = "Report the panel certificate failure"
FAIL = "Fail when the panel certificate is not trusted"
STEPS = (CHECK, LOOKUP, REISSUE, INSTALL, RECHECK, DESCRIBE, REPORT, FAIL)

SKIPPED: dict[str, Any] = {"skipped": True, "changed": False}

# ansible-core 2.20.6 with the callback settings AnsibleService uses (default callback, result_format=yaml).
FAILED_RUN_STDOUT = """
TASK [Fail when the panel certificate is not trusted] **************************
[ERROR]: Task failed: Action failed: LETSENCRYPT_FAILED step=generate rc=1 stderr=Web-based validation failed : Some challenges have failed.
Origin: /opt/praho/infrastructure/ansible/playbooks/virtualmin.yml:470:7

fatal: [node]: FAILED! => {"changed": false, "msg": "LETSENCRYPT_FAILED step=generate rc=1 stderr=Web-based validation failed : Some challenges have failed."}

PLAY RECAP *********************************************************************
node                  : ok=40   changed=3    unreachable=0    failed=1    skipped=2    rescued=0    ignored=0
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

    def test_a_lookup_error_is_not_read_as_a_missing_domain_with_the_name_in_it(self) -> None:
        walk = PanelCertificateScenario(
            registered(check=ran(1, "untrusted"), lookup=ran(1, FQDN), recheck=ran(1, "untrusted"))
        ).walk()
        self.assertNotIn(REISSUE, walk.ran)
        self.assertIn("step=hostname-domain", walk.failure)

    def test_a_failed_issuance_skips_the_install_and_names_the_step(self) -> None:
        walk = PanelCertificateScenario(
            registered(
                check=ran(1, "untrusted"),
                lookup=ran(0, FQDN),
                issue=ran(1, "Web-based validation failed : Some challenges have failed."),
                recheck=ran(1, "untrusted"),
            )
        ).walk()
        self.assertNotIn(INSTALL, walk.ran)
        self.assertIn(FAIL, walk.ran)
        self.assertIn("LETSENCRYPT_FAILED step=generate rc=1", walk.failure)
        self.assertIn("Some challenges have failed", walk.failure)

    def test_a_failed_install_names_the_step(self) -> None:
        walk = PanelCertificateScenario(
            registered(
                check=ran(1, "untrusted"), lookup=ran(0, FQDN), issue=ran(0), install=ran(2, "", "no such service"),
                recheck=ran(1, "untrusted"),
            )
        ).walk()
        self.assertIn(FAIL, walk.ran)
        self.assertIn("LETSENCRYPT_FAILED step=install rc=2", walk.failure)
        self.assertIn("no such service", walk.failure)

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

    def test_failure_is_fatal_unless_explicitly_turned_off(self) -> None:
        variables = registered(check=ran(1, "untrusted"), lookup=ran(0, ""), recheck=ran(1, "untrusted"))
        self.assertIn(FAIL, PanelCertificateScenario(variables).walk().ran)
        variables["letsencrypt_fatal"] = False
        walk = PanelCertificateScenario(variables).walk()
        self.assertNotIn(FAIL, walk.ran)
        self.assertIn(REPORT, walk.ran)


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

    def test_the_recheck_waits_for_webmin_to_restart(self) -> None:
        recheck = task_named(PLAYBOOK, RECHECK)
        self.assertGreaterEqual(int(recheck["retries"]), 3)
        self.assertIn("panel_cert_recheck.rc == 0", str(recheck["until"]))

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
    def test_the_deploy_failure_reason_carries_the_letsencrypt_line(self) -> None:
        detail = failure_detail(FAILED_RUN_STDOUT, "")
        self.assertIn("LETSENCRYPT_FAILED step=generate rc=1", detail)
        self.assertIn("Some challenges have failed", detail)
