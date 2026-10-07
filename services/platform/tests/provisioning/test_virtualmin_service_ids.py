"""Queued Virtualmin provisioning uses Service's integer primary key."""

from __future__ import annotations

import json
from collections.abc import Callable
from decimal import Decimal
from typing import cast
from unittest.mock import patch
from uuid import NAMESPACE_DNS, UUID, uuid1, uuid4, uuid5

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from django.utils.module_loading import import_string
from django_q.models import OrmQ
from django_q.signing import SignedPackage
from requests import Response

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.security_utils import ProvisioningParametersValidator, SecureTaskParameters
from apps.provisioning.signals import _trigger_automatic_virtualmin_provisioning
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminAccountCreationData, VirtualminProvisioningService
from apps.provisioning.virtualmin_tasks import (
    VirtualminProvisioningParams,
    provision_virtualmin_account,
    provision_virtualmin_account_async,
)

PROVISION_TASK = "apps.provisioning.virtualmin_tasks.provision_virtualmin_account"
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


@override_settings(CACHES=LOCMEM)
class QueuedVirtualminProvisioningTestBase(TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.customer = Customer.objects.create(
            name="Queued hosting customer", customer_type="individual", primary_email="queued@example.com"
        )
        self.currency, _created = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.plan = ServicePlan.objects.create(
            name="Queued hosting plan", plan_type="shared_hosting", price_monthly=Decimal("10")
        )
        self.service = Service.objects.create(
            customer=self.customer,
            currency=self.currency,
            service_plan=self.plan,
            service_name="queued.example.com",
            domain="queued.example.com",
            billing_cycle="monthly",
            price=Decimal("10"),
            status="active",
        )
        self.server = VirtualminServer.objects.create(
            name="queued-node",
            hostname="queued-node.example.com",
            api_username="queued-api",
            status="active",
            last_health_check=timezone.now(),
        )
        self.server.set_api_password("QueuedServerPassword123!")
        self.server.save()
        self.sent: list[dict[str, object]] = []

    def http(self, method: str, url: str, **kwargs: object) -> Response:
        self.assertEqual(method, "GET")
        self.assertEqual(url, self.server.api_url)
        params = dict(cast("dict[str, object]", kwargs["params"]))
        self.sent.append(params)
        program = params["program"]
        if program == "info":
            payload: dict[str, object] = {"output": "disk_free: 104857600000\ndisk_total: 209715200000\n"}
        elif program == "list-domains":
            payload = {"data": []}
        elif program == "list-templates":
            payload = {"data": ["Default"]}
        else:
            self.assertEqual(program, "create-domain")
            payload = {"output": "Domain created\n"}
        response = Response()
        response.status_code = 200
        response._content = json.dumps({"command": program, "status": "success", **payload}).encode()
        response._content_consumed = True
        return response

    def enqueue_packet(self, trigger: Callable[[], None]) -> dict[str, object]:
        previous_rows = list(OrmQ.objects.values_list("pk", flat=True))
        trigger()
        packets = [
            cast("dict[str, object]", SignedPackage.loads(row.payload))
            for row in OrmQ.objects.exclude(pk__in=previous_rows).order_by("pk")
        ]
        provisioning = [packet for packet in packets if packet["func"] == PROVISION_TASK]
        self.assertEqual(len(provisioning), 1, packets)
        return provisioning[0]

    def assert_created(self, packet: dict[str, object]) -> VirtualminAccount:
        args = cast("tuple[object, ...]", packet["args"])
        kwargs = cast("dict[str, object]", packet["kwargs"])
        worker = cast("Callable[..., dict[str, object]]", import_string(str(packet["func"])))
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http):
            outcome = worker(*args, **kwargs)
        self.assertTrue(outcome["success"], outcome)
        account = VirtualminAccount.objects.get(service=self.service)
        self.assertEqual(outcome["account_id"], str(account.pk))
        self.assertEqual(account.domain, self.service.domain)
        self.assertEqual(account.status, "active")
        self.assertEqual(account.server_id, self.server.pk)
        self.assertEqual(account.praho_service_id, UUID(int=self.service.pk))
        self.assertEqual(account.praho_customer_id, self.customer.pk)
        event = AuditEvent.objects.get(action="virtualmin_account_created", object_id=str(account.pk))
        self.assertEqual(event.new_values["service_id"], str(self.service.pk))
        self.assertIsNotNone(account.provisioned_at)
        job = VirtualminProvisioningJob.objects.get(account=account, operation="create_domain")
        self.assertEqual(job.status, "completed")
        creation = [params for params in self.sent if params["program"] == "create-domain"]
        self.assertEqual(len(creation), 1, self.sent)
        seed = str(creation[0]["comment"])
        self.assertEqual(VirtualminAccount.parse_recovery_seed(seed)["service_id"], UUID(int=self.service.pk))
        self.assertEqual(job.parameters["recovery_seed"], seed)
        self.assertEqual(seed.split("|", maxsplit=1)[0], account.get_recovery_seed().split("|", maxsplit=1)[0])
        self.server.refresh_from_db()
        self.assertEqual(self.server.current_domains, 1)

        # Redelivery must converge without a second remote create or account row.
        sent_before = list(self.sent)
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http):
            replay = worker(*args, **kwargs)
        self.assertTrue(replay["success"], replay)
        self.assertEqual(replay["account_id"], str(account.pk))
        self.assertEqual(self.sent, sent_before)
        self.assertEqual(VirtualminAccount.objects.filter(service=self.service).count(), 1)
        self.server.refresh_from_db()
        self.assertEqual(self.server.current_domains, 1)
        return account


class QueuedVirtualminServiceIdTests(QueuedVirtualminProvisioningTestBase):
    def test_signal_producer_queues_encrypted_integer_pk_and_worker_persists_account(self) -> None:
        packet = self.enqueue_packet(lambda: _trigger_automatic_virtualmin_provisioning(self.service))
        args = cast("tuple[object, ...]", packet["args"])
        self.assertIsInstance(args[0], SecureTaskParameters)
        parameters = cast("SecureTaskParameters", args[0]).decrypt()
        self.assertEqual(parameters["service_id"], str(self.service.pk))
        self.assertEqual(parameters["domain"], self.service.domain)
        self.assert_created(packet)

    def test_integer_pk_packet_provisions_and_malformed_ids_never_reach_virtualmin(self) -> None:
        # A stronger placement candidate must not replace the explicitly requested UUID server.
        VirtualminServer.objects.create(
            name="fallback-node",
            hostname="fallback-node.example.com",
            api_username="fallback-api",
            status="active",
            weight=1000,
            last_health_check=timezone.now(),
        )
        task_id = provision_virtualmin_account_async(
            {"service_id": self.service.pk, "domain": self.service.domain, "server_id": str(self.server.pk)}
        )
        packets = [cast("dict[str, object]", SignedPackage.loads(row.payload)) for row in OrmQ.objects.all()]
        packet = next(item for item in packets if item["id"] == task_id)
        self.assert_created(packet)
        sent_before = list(self.sent)
        invalid: tuple[object, ...] = (
            -1,
            "-1",
            0,
            "0",
            "",
            True,
            1.0,
            "not-numeric",
            "1; DROP TABLE provisioning_services",
            str(uuid4()),
        )
        for identifier in invalid:
            params = cast("VirtualminProvisioningParams", {"service_id": identifier, "domain": self.service.domain})
            with (
                self.subTest(identifier=identifier),
                patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http),
            ):
                outcome = provision_virtualmin_account(params)
                self.assertEqual(outcome, {"success": False, "error": "Validation failed"})
                self.assertEqual(self.sent, sent_before)
                self.assertEqual(VirtualminAccount.objects.filter(service=self.service).count(), 1)
        self.server.refresh_from_db()
        self.assertEqual(self.server.current_domains, 1)

    def test_new_account_sends_the_uuid_recovery_reference_it_persists(self) -> None:
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http):
            result = VirtualminProvisioningService(self.server).create_virtualmin_account(
                VirtualminAccountCreationData(service=self.service, domain=self.service.domain, server=self.server)
            )
        self.assertTrue(result.is_ok(), result)
        account = result.unwrap()
        seed_before_reload = account.get_recovery_seed()
        account.refresh_from_db()
        self.assertEqual(account.praho_service_id, UUID(int=self.service.pk))
        creation = [params for params in self.sent if params["program"] == "create-domain"]
        self.assertEqual(len(creation), 1, self.sent)
        parsed = VirtualminAccount.parse_recovery_seed(str(creation[0]["comment"]))
        self.assertEqual(parsed.get("service_id"), account.praho_service_id)
        self.assertEqual(seed_before_reload, account.get_recovery_seed())
        account_id = str(account.pk)
        account.delete()
        deletion = AuditEvent.objects.get(action="virtualmin_account_deleted", object_id=account_id)
        self.assertEqual(deletion.old_values["service_id"], str(self.service.pk))


class ProvisioningIdentifierValidationTests(SimpleTestCase):
    def test_service_ids_are_canonical_positive_integer_pks_and_reject_malformed_input(self) -> None:
        valid: tuple[tuple[str | int, str], ...] = (
            (1, "1"),
            ("1", "1"),
            (" 00042 ", "42"),
            (9223372036854775807, "9223372036854775807"),
        )
        for value, expected in valid:
            with self.subTest(value=value):
                try:
                    canonical = ProvisioningParametersValidator.validate_service_id(value)
                except ValidationError:
                    canonical = None
                self.assertEqual(canonical, expected)
        invalid: tuple[object, ...] = (
            -1,
            "-1",
            0,
            "0",
            "000",
            "",
            " ",
            None,
            True,
            False,
            1.0,
            b"1",
            [],
            {},
            "+1",
            "1.0",
            "1e3",
            "1 2",
            "\uff11\uff12",
            "1\n2",
            "1\x00",
            "1; DROP TABLE provisioning_services",
            "$(id)",
            "../1",
            str(uuid4()),
            UUID(int=1),
            9223372036854775808,
            2**16384,
            "9" * 5000,
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                ProvisioningParametersValidator.validate_service_id(cast("str | int", value))

    def test_server_ids_have_their_own_uuid4_validator_and_reject_integer_pks(self) -> None:
        validator = getattr(ProvisioningParametersValidator, "validate_server_id", None)
        self.assertIsNotNone(validator, "Server IDs need a separate UUID4 validator")
        validate = cast("Callable[[str], str]", validator)
        identifier = uuid4()
        for value in (str(identifier), identifier.hex.upper(), f" {identifier} "):
            with self.subTest(value=value):
                self.assertEqual(validate(value), str(identifier))
        invalid: tuple[object, ...] = (
            "",
            " ",
            None,
            1,
            "1",
            0,
            "0",
            -1,
            "-1",
            True,
            "not-a-uuid",
            str(uuid1()),
            str(uuid5(NAMESPACE_DNS, "example.com")),
            str(UUID(int=0)),
            f"{identifier}; rm -rf /",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                validate(cast("str", value))
