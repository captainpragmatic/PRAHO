"""Customer and explicit operator recipients remain distinct on native templates."""

import json
import subprocess
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase


class HostingNotificationTemplateTests(SimpleTestCase):
    def test_custom_template_cannot_reintroduce_owner_or_cc_but_keeps_approved_operator(self):
        adapter = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-notification-policy.pl"
        perl = """require $ARGV[0]; my $t={mail_on=>'yes',newuser_on=>'yes',updateuser_on=>'yes',
status=>'customer@example.test,operator@example.test',statusonly=>0,mail_cc=>'customer@example.test',
mail_bcc=>'customer@example.test',newuser_to_owner=>1,newuser_to_reseller=>1,updateuser_to_mailbox=>1};
virtual_server::praho_template_policy($t,['operator@example.test']);
print JSON::PP->new->canonical->encode($t);"""
        result = subprocess.run(  # noqa: S603 -- Execute the fixed native policy contract with a fixed local test program.
            ["/usr/bin/perl", "-e", perl, str(adapter)], capture_output=True, text=True, check=True
        )
        values = json.loads(result.stdout)
        self.assertEqual(values["status"], "operator@example.test")
        self.assertEqual(values["statusonly"], 1)
        for key in ("mail_on", "newuser_on", "updateuser_on"):
            self.assertEqual(values[key], "none")
        for key in ("mail_cc", "mail_bcc", "newuser_cc", "newuser_bcc", "updateuser_cc", "updateuser_bcc"):
            self.assertEqual(values[key], "")
        for key in ("newuser_to_owner", "newuser_to_reseller", "updateuser_to_mailbox"):
            self.assertEqual(values[key], 0)
