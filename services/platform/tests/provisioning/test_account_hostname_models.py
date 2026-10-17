"""Account hostnames (ADR-0061 P1.1): the label, its lifetime, and the certificate issuance state."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from itertools import count

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.account_hostname_models import (
    AccountHostname,
    AccountNameCertificate,
    AccountNameCertificateBudget,
    ProtectedLabelError,
)
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer

ZONE = "acct.praho.test"
_serial = count(1)


def _make_server() -> VirtualminServer:
    n = next(_serial)
    return VirtualminServer.objects.create(
        name=f"name-node-{n}", hostname=f"name-node-{n}.example.test", api_username="api", status="active"
    )


def _account(server: VirtualminServer, domain: str = "customer.example.test") -> VirtualminAccount:
    customer = Customer.objects.create(name=domain, customer_type="individual", primary_email=f"owner@{domain}")
    currency, _created = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
    plan = ServicePlan.objects.create(name=f"plan {domain}", plan_type="shared_hosting", price_monthly=Decimal("10"))
    service = Service.objects.create(
        customer=customer,
        currency=currency,
        service_plan=plan,
        service_name=domain,
        domain=domain,
        billing_cycle="monthly",
        price=Decimal("10"),
        status="active",
    )
    return VirtualminAccount.objects.create(
        domain=domain, server=server, virtualmin_username=domain.split(".", 1)[0], service=service, status="active"
    )


class AccountHostnameLabelTests(TestCase):
    def setUp(self) -> None:
        self.server = _make_server()

    def test_a_label_is_eight_lowercase_letters_or_digits(self) -> None:
        for bad in ("H7K3P2Q9", "h7k3p2q", "h7k3p2q9x", "h7k3-2q9", "h7k3p2q_"):
            with self.subTest(label=bad), self.assertRaises(IntegrityError), transaction.atomic():
                AccountHostname.objects.create(label=bad, zone=ZONE)
        AccountHostname.objects.create(label="h7k3p2q9", zone=ZONE)

    def test_a_label_is_never_reused_after_its_account_is_gone(self) -> None:
        account = _account(self.server)
        hostname = AccountHostname.objects.create(
            label="h7k3p2q9", zone=ZONE, account=account, target_server=self.server
        )

        account.delete()
        hostname.refresh_from_db()

        self.assertIsNone(hostname.account_id)
        self.assertEqual(hostname.label, "h7k3p2q9")
        with self.assertRaises(IntegrityError), transaction.atomic():
            AccountHostname.objects.create(label="h7k3p2q9", zone=ZONE)

    def test_a_hostname_row_cannot_be_deleted_so_its_label_is_never_freed(self) -> None:
        hostname = AccountHostname.objects.create(label="h7k3p2q9", zone=ZONE)

        with self.assertRaises(ProtectedLabelError):
            hostname.delete()
        with self.assertRaises(ProtectedLabelError):
            AccountHostname.objects.filter(pk=hostname.pk).delete()

        self.assertTrue(AccountHostname.objects.filter(label="h7k3p2q9").exists())
        with self.assertRaises(IntegrityError), transaction.atomic():
            AccountHostname.objects.create(label="h7k3p2q9", zone=ZONE)

    def test_a_label_cannot_be_changed_so_the_old_one_is_never_freed(self) -> None:
        hostname = AccountHostname.objects.create(label="h7k3p2q9", zone=ZONE)

        hostname.label = "a1b2c3d4"
        with self.assertRaises(ProtectedLabelError):
            hostname.save()
        with self.assertRaises(ProtectedLabelError):
            AccountHostname.objects.filter(pk=hostname.pk).update(label="a1b2c3d4")
        with self.assertRaises(ProtectedLabelError):
            AccountHostname.objects.bulk_update([hostname], ["label"])

        self.assertEqual(AccountHostname.objects.get(pk=hostname.pk).label, "h7k3p2q9")

    def test_an_account_has_at_most_one_hostname(self) -> None:
        account = _account(self.server)
        AccountHostname.objects.create(label="h7k3p2q9", zone=ZONE, account=account)
        with self.assertRaises(IntegrityError), transaction.atomic():
            AccountHostname.objects.create(label="a1b2c3d4", zone=ZONE, account=account)

    def test_a_server_with_a_live_name_pointing_at_it_cannot_be_deleted(self) -> None:
        from django.db.models import ProtectedError  # noqa: PLC0415

        AccountHostname.objects.create(label="h7k3p2q9", zone=ZONE, target_server=self.server)
        with self.assertRaises(ProtectedError):
            self.server.delete()

    def test_fqdn_joins_the_label_and_the_zone(self) -> None:
        self.assertEqual(AccountHostname(label="h7k3p2q9", zone=ZONE).fqdn, "h7k3p2q9.acct.praho.test")


def _clean_addresses(server: VirtualminServer) -> None:
    others = [f.name for f in VirtualminServer._meta.fields if f.name not in {"ipv4_address", "ipv6_address"}]
    server.clean_fields(exclude=others)


class ServerAddressTests(TestCase):
    def test_a_server_holds_one_ipv4_and_one_ipv6_address(self) -> None:
        server = _make_server()
        server.ipv4_address = "203.0.113.10"
        server.ipv6_address = "2001:db8::10"
        _clean_addresses(server)
        server.save()
        server.refresh_from_db()
        self.assertEqual((server.ipv4_address, server.ipv6_address), ("203.0.113.10", "2001:db8::10"))

    def test_each_address_field_refuses_the_other_family(self) -> None:
        server = _make_server()
        server.ipv4_address = "2001:db8::10"
        with self.assertRaises(ValidationError):
            _clean_addresses(server)
        server.ipv4_address = None
        server.ipv6_address = "203.0.113.10"
        with self.assertRaises(ValidationError):
            _clean_addresses(server)


class AccountNameCertificateTests(TestCase):
    def setUp(self) -> None:
        self.hostname = AccountHostname.objects.create(label="h7k3p2q9", zone=ZONE)

    def test_a_renewal_attempt_leaves_the_current_certificate_in_force(self) -> None:
        not_after = timezone.now() + timedelta(days=20)
        cert = AccountNameCertificate.objects.create(
            hostname=self.hostname,
            attempt_status=AccountNameCertificate.AttemptStatus.ISSUED,
            current_not_after=not_after,
            current_certificate_ref="vault:cert",
            current_key_ref="vault:key",
        )

        cert.attempt_status = AccountNameCertificate.AttemptStatus.FAILED
        cert.save(update_fields=["attempt_status", "updated_at"])

        self.assertTrue(cert.has_valid_material())

    def test_a_first_issuance_in_flight_has_no_valid_material(self) -> None:
        for status in (
            AccountNameCertificate.AttemptStatus.PENDING,
            AccountNameCertificate.AttemptStatus.ORDERING,
            AccountNameCertificate.AttemptStatus.FAILED,
        ):
            with self.subTest(status=status):
                cert = AccountNameCertificate(hostname=self.hostname, attempt_status=status)
                self.assertFalse(cert.has_valid_material())

    def test_an_expired_certificate_is_not_valid_material(self) -> None:
        cert = AccountNameCertificate(
            hostname=self.hostname,
            attempt_status=AccountNameCertificate.AttemptStatus.ISSUED,
            current_not_after=timezone.now() - timedelta(seconds=1),
            current_certificate_ref="vault:cert",
            current_key_ref="vault:key",
        )
        self.assertFalse(cert.has_valid_material())

    def test_the_attempt_status_is_one_of_the_four_states(self) -> None:
        with self.assertRaises(IntegrityError), transaction.atomic():
            AccountNameCertificate.objects.create(hostname=self.hostname, attempt_status="renewing")

    def test_one_budget_row_per_zone(self) -> None:
        AccountNameCertificateBudget.objects.create(zone=ZONE)
        with self.assertRaises(IntegrityError), transaction.atomic():
            AccountNameCertificateBudget.objects.create(zone=ZONE)


class AccountHostnameAuditTests(TestCase):
    def test_assigning_and_retiring_a_name_are_audited(self) -> None:
        hostname = AccountHostname.objects.create(label="h7k3p2q9", zone=ZONE)
        self.assertTrue(
            AuditEvent.objects.filter(action="account_hostname_assigned", object_id=str(hostname.pk)).exists()
        )

        hostname.retired_at = timezone.now()
        hostname.save(update_fields=["retired_at", "updated_at"])

        retired = AuditEvent.objects.get(action="account_hostname_retired", object_id=str(hostname.pk))
        self.assertEqual(retired.new_values["fqdn"], "h7k3p2q9.acct.praho.test")

    def test_a_partial_save_without_retired_at_records_no_retirement(self) -> None:
        hostname = AccountHostname.objects.create(label="h7k3p2q9", zone=ZONE)
        hostname.retired_at = timezone.now()  # changed in memory only

        hostname.save(update_fields=["records", "updated_at"])

        self.assertIsNone(AccountHostname.objects.get(pk=hostname.pk).retired_at)
        self.assertFalse(
            AuditEvent.objects.filter(action="account_hostname_retired", object_id=str(hostname.pk)).exists()
        )

    def test_saving_an_already_retired_name_records_no_second_retirement(self) -> None:
        hostname = AccountHostname.objects.create(label="h7k3p2q9", zone=ZONE)
        hostname.retired_at = timezone.now()
        hostname.save()

        hostname.records = {"A": {"intended": "203.0.113.10"}}
        hostname.save()  # a full save of a retired row, as an admin edit or a script would do
        hostname.save(update_fields=["retired_at", "updated_at"])

        self.assertEqual(
            AuditEvent.objects.filter(action="account_hostname_retired", object_id=str(hostname.pk)).count(), 1
        )
