"""A verified fake adapter quotes secrets; every durable and logging surface must remain clean."""
from __future__ import annotations

import json
import logging
from functools import partial
from unittest.mock import patch

from django.core.cache import cache
from django.test import TransactionTestCase, override_settings
from django_q.models import OrmQ, Task
from django_q.tasks import async_task

from apps.audit.models import AuditEvent
from apps.common.types import Err, Result, Retriability
from apps.domains.gateways import DomainTransferResult, RegistrarAPIError
from apps.domains.gateways.errors import RegistrarErrorCode
from apps.domains.gateways.gandi import GandiGateway
from apps.domains.models import DomainOperation, DomainOrderItem, Registrar
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

from .test_domain_order_flow import ALERT
from .test_domain_order_transfers import TransferLineFixture


class SecretLogCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.entries: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.entries.append(self.format(record))

class LeakyTransferFake(GandiGateway):
    def __init__(self, registrar: Registrar, mode: str, ciphertexts: list[str]) -> None:
        super().__init__(registrar)
        self.mode = mode
        self.ciphertexts = ciphertexts

    def _do_initiate_transfer(self, domain_name: str, epp_code: str, registrant_data: dict[str, object] | None = None) -> Result[DomainTransferResult, RegistrarAPIError]:
        detail = f"Rejected {epp_code} / {self.ciphertexts[-1]}"
        if self.mode == "exception":
            raise RuntimeError(detail)
        return Err(
            RegistrarAPIError(detail, code=RegistrarErrorCode.NETWORK_ERROR, detail=detail),
            retriability=Retriability.RETRIABLE if self.mode == "retry" else Retriability.UNKNOWN if self.mode == "unknown" else Retriability.NOT_RETRIABLE,
        )

@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    REGISTRAR_ADAPTERS_VERIFIED=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "transfer-secrets"}},
)
class TransferSecretTests(HMACTestMixin, TransferLineFixture, TransactionTestCase):
    def test_plaintext_and_ciphertext_never_escape_through_a_verified_public_gateway_and_task(self) -> None:
        owner = User.objects.create_user(email="secret-owner@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=owner, role="owner", is_active=True)
        ciphertexts: list[str] = []
        setter = DomainOrderItem.set_encrypted_epp_code

        def remember_ciphertext(item: DomainOrderItem, value: str) -> None:
            setter(item, value)
            ciphertexts.append(item.epp_code)

        for mode in ("error", "retry", "unknown", "exception"):
            with self.subTest(mode=mode):
                cache.clear()
                order, line = self._transfer_order(f"secret-{mode}.ro")
                code = f"Transfer-Secret-{mode}!123"
                fake = LeakyTransferFake(self.ro_registrar, mode, ciphertexts)
                capture = SecretLogCapture()
                loggers = [logging.getLogger(), logging.getLogger("apps")]
                levels = [logger.level for logger in loggers]
                for logger in loggers:
                    logger.addHandler(capture)
                    logger.setLevel(logging.DEBUG)
                try:
                    with (
                        patch("apps.domains.gateways.RegistrarGatewayFactory.create_gateway", return_value=fake),
                        patch.object(DomainOrderItem, "set_encrypted_epp_code", new=remember_ciphertext),
                        patch("django_q.tasks.async_task", new=partial(async_task, sync=True)),
                        patch("apps.domains.gateways.base.time.sleep"),
                        patch(ALERT) as alert,
                    ):
                        response = self.portal_post(
                            f"/api/orders/{order.pk}/items/{line.pk}/transfer-code/",
                            {"customer_id": self.customer.pk, "user_id": owner.pk, "transfer_code": code},
                        )
                finally:
                    for logger, level in zip(loggers, levels, strict=True):
                        logger.removeHandler(capture)
                        logger.setLevel(level)
                self.assertEqual(response.status_code, 200, response.content)
                self.assertTrue(ciphertexts)
                self.assertTrue(Task.objects.filter(func="apps.domains.tasks.process_order_domain_items").exists())
                evidence = {
                    "audit": list(AuditEvent.objects.values("metadata", "old_values", "new_values", "description")),
                    "operations": list(DomainOperation.objects.values("parameters", "error_message", "result")),
                    "tasks": list(Task.objects.values("args", "kwargs", "result")),
                    "queued_tasks": [row.task for row in OrmQ.objects.all()],
                    "logs": capture.entries,
                    "response": response.content.decode(),
                    "staff_alert": repr(alert.call_args_list),
                }
                rendered = json.dumps(evidence, default=str)
                self.assertNotIn(code, rendered)
                self.assertNotIn(ciphertexts[-1], rendered)
                item = DomainOrderItem.objects.get(order_item=line)
                self.assertEqual(item.epp_code, "")
                if mode in ("unknown", "exception"):
                    self.assertIsNotNone(item.domain_id)
                    self.assertEqual(DomainOperation.objects.get(domain_id=item.domain_id).state, "submitted")
