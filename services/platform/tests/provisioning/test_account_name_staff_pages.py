"""Staff see an account's name and can have it repaired; servers show their addresses (ADR-0061 P1.13).

"Repair DNS" only queues the account name's node step and sync: nothing is looked up at the
provider or on the node inside the request, so a slow provider never holds a staff page.
"""

from __future__ import annotations

from unittest.mock import patch

from django.urls import reverse
from django.utils import timezone

from apps.provisioning import account_hostname_service as service
from apps.provisioning.account_hostname_lifecycle import ENSURE_TASK
from apps.provisioning.account_hostname_models import (
    AccountHostname,
    AccountNameCertificate,
    AccountNameCertificateInstall,
)
from apps.provisioning.account_name_lease import ACCOUNT_NAME_TASK_TIMEOUT_SECONDS
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.settings.services import SettingsService
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture

ZONE = "praho-sites.net"


def _configure(*, enabled: bool) -> None:
    for key, value in (
        ("dns.account_hostname_zone", ZONE),
        ("dns.account_hostname_zone_id", "0123456789abcdef0123456789abcdef"),
        ("dns.account_zone_api_token", "token-value"),
    ):
        SettingsService.update_setting(key, value).unwrap()
    SettingsService.update_setting("dns.account_hostnames_enabled", enabled).unwrap()


class AccountNameCardTests(VirtualminViewsFixture):
    def page(self) -> str:
        with patch("apps.provisioning.virtualmin_views.VirtualminBackupService") as backups:
            backups.return_value.list_backups.return_value.is_ok.return_value = False
            response = self.client.get(reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]))
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_the_card_shows_the_name_its_node_its_records_and_its_certificate(self) -> None:
        _configure(enabled=True)
        hostname = service.allocate_account_hostname(self.account)
        AccountHostname.objects.filter(pk=hostname.pk).update(
            target_server=self.server,
            records={"A": {"intended": "95.217.0.10", "applied": "95.217.0.10", "id": "r1", "ttl": 300}},
            last_reconciled_at=timezone.now(),
        )
        AccountNameCertificate.objects.create(
            hostname=hostname,
            current_certificate_ref="acme_certificate:x",
            current_key_ref="acme_certificate_key:x",
            current_not_after=timezone.now() + timezone.timedelta(days=60),
            attempt_status="issued",
        )
        AccountNameCertificateInstall.objects.create(
            hostname=hostname,
            server=self.server,
            certificate_ref="acme_certificate:x",
            not_after=timezone.now() + timezone.timedelta(days=60),
        )

        page = self.page()

        self.assertIn('data-testid="account-name-card"', page)
        self.assertIn(hostname.fqdn, page)
        self.assertIn("95.217.0.10", page)
        self.assertIn(self.server.name, page)
        self.assertIn(reverse("provisioning:virtualmin_account_repair_dns", args=[self.account.pk]), page)

    def test_an_account_without_a_name_shows_no_card(self) -> None:
        _configure(enabled=True)

        self.assertNotIn('data-testid="account-name-card"', self.page())


class RepairDnsTests(VirtualminViewsFixture):
    def url(self) -> str:
        return reverse("provisioning:virtualmin_account_repair_dns", args=[self.account.pk])

    def test_repair_queues_the_node_step_and_sync_and_looks_nothing_up(self) -> None:
        _configure(enabled=True)
        service.allocate_account_hostname(self.account)
        with (
            patch("django_q.tasks.async_task") as enqueue,
            patch.object(service, "_dns_gateway") as dns,
            patch.object(service, "_gateway") as node,
            self.captureOnCommitCallbacks(execute=True),
        ):
            response = self.client.post(self.url())

        self.assertEqual(response.status_code, 302)
        enqueue.assert_called_once_with(ENSURE_TASK, str(self.account.pk), timeout=ACCOUNT_NAME_TASK_TIMEOUT_SECONDS)
        dns.assert_not_called()
        node.assert_not_called()

    def test_repair_while_the_feature_is_off_queues_nothing(self) -> None:
        _configure(enabled=True)
        service.allocate_account_hostname(self.account)  # a name exists, so only the flag can refuse
        _configure(enabled=False)
        with patch("django_q.tasks.async_task") as enqueue, self.captureOnCommitCallbacks(execute=True):
            self.client.post(self.url())

        enqueue.assert_not_called()

    def test_repair_is_post_only_and_staff_only(self) -> None:
        _configure(enabled=True)
        self.assertEqual(self.client.get(self.url()).status_code, 405)
        self.client.logout()
        with patch("django_q.tasks.async_task") as enqueue:
            response = self.client.post(self.url())
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response["Location"])
        enqueue.assert_not_called()


class ServerAddressTests(VirtualminViewsFixture):
    def test_the_server_page_shows_its_public_addresses(self) -> None:
        VirtualminServer.objects.filter(pk=self.server.pk).update(
            ipv4_address="95.217.0.10", ipv6_address="2a01:4f8::1"
        )
        response = self.client.get(reverse("provisioning:virtualmin_server_detail", args=[self.server.pk]))

        self.assertEqual(response.status_code, 200)
        page = response.content.decode()
        self.assertIn("95.217.0.10", page)
        self.assertIn("2a01:4f8::1", page)
