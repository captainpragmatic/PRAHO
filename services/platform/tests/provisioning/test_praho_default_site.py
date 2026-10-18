"""Every node answers an unknown name with PRAHO's empty 404, never a customer's site (ADR-0061 P1.16).

Apache answers a name no virtual host claims with the first virtual host it loaded for that address.
Account names' random labels, or a domain such as 0.example.com, sort early, so without this a stray
name would show some customer's site. The default site lives in conf-enabled, which Debian's
apache2.conf includes before sites-enabled: the lab proved a site file loses to `0.praho.test`.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from tests.provisioning.test_virtualmin_transfer_playbooks import PLAYBOOKS, command_text, task_named

CONF = PLAYBOOKS / "files" / "praho-default-site.conf"


class DefaultSiteConfigTests(SimpleTestCase):
    def test_both_ports_answer_404_with_no_content(self) -> None:
        conf = CONF.read_text()
        self.assertIn("<VirtualHost *:80>", conf)
        self.assertIn("<VirtualHost *:443>", conf)
        self.assertEqual(conf.count("RedirectMatch 404 ^"), 2)
        self.assertEqual(conf.count("ServerName praho-default.invalid"), 2, "a name no real site can have")
        self.assertIn("ssl-cert-snakeoil", conf)


class DefaultSitePlaybookTests(SimpleTestCase):
    def test_the_node_playbook_installs_and_enables_it_in_conf_enabled(self) -> None:
        install = task_named("virtualmin.yml", "Install the PRAHO default site")["ansible.builtin.copy"]
        self.assertEqual(install["dest"], "/etc/apache2/conf-available/praho-default-site.conf")
        enable = task_named("virtualmin.yml", "Enable the PRAHO default site")
        self.assertEqual(command_text(enable).strip(), "a2enconf praho-default-site")
        self.assertEqual(enable["args"]["creates"], "/etc/apache2/conf-enabled/praho-default-site.conf")

    def test_the_configuration_is_validated_and_the_certificate_installed(self) -> None:
        self.assertIn(
            "apache2ctl configtest",
            command_text(task_named("virtualmin.yml", "Validate the Apache configuration with the default site")),
        )
        apt = task_named("virtualmin.yml", "Install the self-signed certificate the default site answers 443 with")
        self.assertEqual(apt["ansible.builtin.apt"]["name"], "ssl-cert")
