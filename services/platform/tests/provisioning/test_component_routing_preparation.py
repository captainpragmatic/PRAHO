"""A website move must not take retained mail routing or implicit SPF authorization with it."""

import importlib.util
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.test import SimpleTestCase


class ComponentRoutingPreparationTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-inspect.py"
        spec = importlib.util.spec_from_file_location("component_source_inspection", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        self.web = "<VirtualHost *:80>\nServerName example.test\nServerAlias www.example.test\n</VirtualHost>\n"
        self.records = {
            "mx": ["10 mail.example.test."],
            "txt": ['"v=spf1 ip4:192.0.2.10 mx -all"'],
            "mx_cname": [],
            "mx_addresses": ["192.0.2.10"],
        }

    def check(self):
        return self.module.routing_preparation("example.test", self.web, self.records)

    def test_independent_mail_names_and_literal_source_spf_can_survive_website_routing(self):
        self.assertEqual(self.check(), [])
        self.records["mx"] = ["10 inbound.mail-provider.test."]
        self.records["txt"] = ['"v=spf1 include:mail-provider.test -all"']
        self.assertEqual(self.check(), [])

    def test_implicit_or_apex_mail_exchange_requires_separate_mail_name(self):
        for mx in ([], ["10 example.test."], ["10 www.example.test."]):
            self.records["mx"] = mx
            with self.subTest(mx=mx):
                self.assertIn("MX", " ".join(self.check()))

    def test_spf_apex_authorization_and_mx_aliases_cannot_be_accepted_away(self):
        for spf in (
            "v=spf1 a mx -all",
            "v=spf1 a:example.test -all",
            "v=spf1 +a/24 -all",
            "v=spf1 include:example.test -all",
        ):
            self.records["txt"] = ['"' + spf + '"']
            with self.subTest(spf=spf):
                self.assertIn("SPF", " ".join(self.check()))
        self.records["txt"] = ['"v=spf1 mx -all"']
        self.records["mx_cname"] = ["example.test."]
        self.assertIn("alias", " ".join(self.check()))

    def test_ancillary_http_names_or_missing_mail_resolution_need_preparation(self):
        self.web = self.web.replace(
            "www.example.test", "www.example.test mail.example.test webmail.example.test admin.example.test"
        )
        self.assertIn("HTTP", " ".join(self.check()))
        self.web = "ServerName example.test\nServerAlias www.example.test\n"
        self.records["mx_addresses"] = []
        self.assertIn("resolve", " ".join(self.check()).lower())

    def test_web_callbacks_cannot_reference_unselected_application_roots_or_backends(self):
        check = self.module.web_path_preparation
        selected = [{"relative": "public_html", "purpose": "application"}]
        web = 'DocumentRoot "/home/customer/public_html"\nAlias /uploads /home/customer/public_html/uploads\nProxyPass /.well-known !\n'
        self.assertEqual(check(web, "/home/customer", selected), [])
        for directive in (
            "DocumentRoot /home/customer/retained_site\n",
            "ScriptAlias /cgi-bin/ /home/customer/cgi-bin/\n",
            "Alias /mail /home/customer/Maildir\n",
            "ProxyPass / http://127.0.0.1:9000/\n",
            "IncludeOptional /etc/apache2/customer/*.conf\n",
        ):
            with self.subTest(directive=directive):
                self.assertTrue(check(web + directive, "/home/customer", selected))

    def test_other_websites_sharing_the_unix_owner_require_classification_before_holding(self):
        native = {"id": "123456789", "dom": "example.test", "user": "customer", "web": "1"}
        other = {**native, "id": "987654321", "dom": "other.example.test"}
        with patch.object(self.module, "_related_domains", return_value=[native, other]):
            self.assertTrue(self.module.shared_website_preparation(native))
        with patch.object(self.module, "_related_domains", return_value=[native]):
            self.assertEqual(self.module.shared_website_preparation(native), [])

    def test_retained_mail_tls_paths_must_not_be_selected_website_content(self):
        native = {"mail": "1", "home": "/home/customer", "ssl_key": "/home/customer/public_html/tls/key.pem"}
        self.assertTrue(self.module.retained_path_preparation(native, [{"relative": "public_html"}]))
        native["ssl_key"] = "/etc/ssl/virtualmin/123456/key.pem"
        self.assertEqual(self.module.retained_path_preparation(native, [{"relative": "public_html"}]), [])

    def test_retained_native_acme_renewal_requires_independent_dns_after_website_removal(self):
        native = {
            "mail": "1",
            "home": "/home/customer",
            "dns": "0",
            "letsencrypt_renew": "1",
            "letsencrypt_last": "12345",
        }
        self.assertTrue(self.module.retained_path_preparation(native, [{"relative": "public_html"}]))
        native["dns"] = "1"
        self.assertEqual(self.module.retained_path_preparation(native, [{"relative": "public_html"}]), [])
