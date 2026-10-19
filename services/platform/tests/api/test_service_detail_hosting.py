"""The service detail tells the customer the account name to point at, once it is live (ADR-0061 P1.11).

The name is offered only when it can be used: the feature is on, the name is published to its node
and an unexpired certificate is installed there. What the customer is told to set never names a
node or an address: every record points at the account name, so a move never makes it stale.
"""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory

from apps.api.services.views import customer_service_detail_api
from apps.billing.currency_models import Currency
from apps.customers.models import Customer
from apps.provisioning import account_hostname_service as names
from apps.provisioning.account_hostname_models import AccountHostname, AccountNameCertificateInstall
from apps.provisioning.service_models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.settings.services import SettingsService

AUTH = "apps.api.secure_auth.get_authenticated_customer"
ZONE = "praho-sites.net"
DOMAIN = "site.example.com"
NODE_IPV4 = "95.217.0.10"
NODE_IPV6 = "2a01:4f8::1"
NODE_HOSTNAME = "node-secret-9.example.net"


class ServiceHostingTests(TestCase):
    def setUp(self) -> None:
        for key, value in (
            ("dns.account_hostname_zone", ZONE),
            ("dns.account_hostname_zone_id", "0123456789abcdef0123456789abcdef"),
            ("dns.account_zone_api_token", "token-value"),
            ("dns.account_hostnames_enabled", True),
        ):
            SettingsService.update_setting(key, value).unwrap()
        self.customer = Customer.objects.create(name="Hosting customer", primary_email="h@example.com")
        plan = ServicePlan.objects.create(name="Plan", price_monthly=Decimal("10.00"))
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency_id="RON",
            service_name="Hosting",
            username="hostuser",
            domain=DOMAIN,
            price=Decimal("10.00"),
            status="active",
        )
        self.server = VirtualminServer.objects.create(
            name="Node", hostname=NODE_HOSTNAME, ipv4_address=NODE_IPV4, ipv6_address=NODE_IPV6
        )
        self.account = VirtualminAccount.objects.create(
            service=self.service,
            domain=DOMAIN,
            virtualmin_username="hostuser",
            server=self.server,
            status="active",
            provisioned_at=timezone.now(),
        )
        self.hostname = names.allocate_account_hostname(self.account)
        AccountHostname.objects.filter(pk=self.hostname.pk).update(
            target_server=self.server,
            records={
                "A": {"intended": NODE_IPV4, "applied": NODE_IPV4, "id": "r1", "ttl": 300},
                "AAAA": {"intended": NODE_IPV6, "applied": NODE_IPV6, "id": "r2", "ttl": 300},
            },
        )
        AccountNameCertificateInstall.objects.create(
            hostname=self.hostname,
            server=self.server,
            certificate_ref="acme_certificate:x",
            not_after=timezone.now() + timezone.timedelta(days=60),
        )

    def hosting(self) -> Any:
        request = APIRequestFactory().post("/api/services/1/", {}, format="json")
        with patch(AUTH, return_value=(self.customer, None)):
            response = customer_service_detail_api(request, service_id=self.service.id)
        self.assertEqual(response.status_code, 200)
        return response.data["data"]["service"]["hosting"]

    def test_a_live_name_is_offered_with_records_that_point_at_it(self) -> None:
        fqdn = self.hostname.fqdn

        hosting = self.hosting()

        self.assertEqual(hosting["account_name"], fqdn)
        self.assertEqual(hosting["path"], "external_dns")
        self.assertEqual(
            hosting["records"],
            [
                {"type": "CNAME", "name": f"www.{DOMAIN}", "value": fqdn},
                {"type": "ALIAS", "name": DOMAIN, "value": fqdn},
            ],
        )

    def test_the_offer_never_names_the_node(self) -> None:
        text = json.dumps(self.hosting())
        for secret in (NODE_IPV4, NODE_IPV6, NODE_HOSTNAME):
            self.assertNotIn(secret, text)

    def test_not_offered_while_the_feature_is_off(self) -> None:
        SettingsService.update_setting("dns.account_hostnames_enabled", False).unwrap()

        self.assertIsNone(self.hosting())

    def test_not_offered_before_its_records_are_applied(self) -> None:
        AccountHostname.objects.filter(pk=self.hostname.pk).update(records={"A": {"intended": NODE_IPV4}})

        self.assertIsNone(self.hosting())

    def test_not_offered_without_a_certificate_installed_on_its_node(self) -> None:
        AccountNameCertificateInstall.objects.all().delete()

        self.assertIsNone(self.hosting())

    def test_not_offered_once_its_certificate_expired(self) -> None:
        AccountNameCertificateInstall.objects.update(not_after=timezone.now() - timezone.timedelta(minutes=1))

        self.assertIsNone(self.hosting())

    def test_not_offered_once_retired(self) -> None:
        AccountHostname.objects.filter(pk=self.hostname.pk).update(retired_at=timezone.now())

        self.assertIsNone(self.hosting())

    def test_a_service_without_a_hosting_account_answers_normally(self) -> None:
        VirtualminAccount.objects.filter(pk=self.account.pk).delete()

        self.assertIsNone(self.hosting())
