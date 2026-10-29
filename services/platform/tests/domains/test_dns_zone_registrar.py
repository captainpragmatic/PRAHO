"""A zone owns its durable registrar intent before a request can be dispatched."""

from unittest.mock import Mock, patch
from uuid import uuid4

from django.db import transaction
from django.test import TransactionTestCase, override_settings

from apps.common.types import Err, Ok, Retriability
from apps.domains.models import TLD, Domain, DomainOperation, Registrar
from apps.domains.services import DomainLifecycleService, DomainReconciliationService
from tests.domains.test_dns_zone_import_service import hosting_fixture


@override_settings(
    DISABLE_AUDIT_SIGNALS=True,
    AUDIT_CHAIN_ENABLED=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class ZoneRegistrarIntentTests(TransactionTestCase):
    def setUp(self):
        account, _, _ = hosting_fixture()
        registrar = Registrar.objects.create(name="gandi", display_name="Gandi", status="active")
        tld = TLD.objects.create(
            extension="net",
            description="Network",
            registration_price_cents=100,
            renewal_price_cents=100,
            transfer_price_cents=100,
        )
        self.domain = Domain.objects.create(
            name=account.domain,
            customer=account.service.customer,
            registrar=registrar,
            tld=tld,
            status="active",
            nameservers=["ns.old.example"],
        )
        self.gateway = Mock()
        self.gateway.update_nameservers.return_value = Ok(Mock(pending=False))
        patcher = patch("apps.domains.gateways.RegistrarGatewayFactory.create_gateway", return_value=self.gateway)
        patcher.start()
        self.addCleanup(patcher.stop)

    def prepare(self, identifier=None, nameservers=None):
        return DomainLifecycleService.prepare_nameserver_update(
            self.domain, nameservers or ["ns.cloudflare.example"], operation_id=identifier or uuid4()
        )

    def test_prepare_is_offline_stable_and_rejects_reusing_the_uuid_for_another_request(self):
        identifier = uuid4()
        first = self.prepare(identifier).unwrap()
        self.assertEqual(self.prepare(identifier).unwrap().pk, first.pk)
        self.assertTrue(self.prepare(identifier, ["ns.other.example"]).is_err())
        self.assertEqual(DomainOperation.objects.count(), 1)
        self.gateway.update_nameservers.assert_not_called()

    def test_completed_or_submitted_resume_never_dispatches_twice(self):
        operation = self.prepare().unwrap()
        self.assertTrue(DomainLifecycleService.resume_nameserver_update(operation).is_ok())
        self.assertTrue(DomainLifecycleService.resume_nameserver_update(operation).is_ok())
        self.gateway.update_nameservers.assert_called_once()
        self.domain.refresh_from_db()
        self.assertEqual(self.domain.nameservers, ["ns.cloudflare.example"])

    def test_unknown_submission_stays_submitted_and_is_never_repeated(self):
        operation = self.prepare().unwrap()
        self.gateway.update_nameservers.return_value = Err(
            Mock(code=Mock(value="timeout")), retriability=Retriability.UNKNOWN
        )
        self.assertTrue(DomainLifecycleService.resume_nameserver_update(operation).is_err())
        self.assertTrue(DomainLifecycleService.resume_nameserver_update(operation).is_ok())
        self.gateway.update_nameservers.assert_called_once()
        operation.refresh_from_db()
        self.assertEqual(operation.state, "submitted")

    def test_binding_change_and_enclosing_transaction_refuse_before_dispatch(self):
        operation = self.prepare().unwrap()
        with transaction.atomic():
            self.assertTrue(DomainLifecycleService.resume_nameserver_update(operation).is_err())
        Domain.objects.filter(pk=self.domain.pk).update(name="different.example.net")
        self.assertTrue(DomainLifecycleService.resume_nameserver_update(operation).is_err())
        self.gateway.update_nameservers.assert_not_called()

    def test_reconciliation_cannot_apply_an_old_intent_to_a_changed_domain_binding(self):
        operation = self.prepare().unwrap()
        operation.mark_submitted()
        operation.save()
        Domain.objects.filter(pk=self.domain.pk).update(name="different.example.net")
        info = Mock(nameservers=["ns.cloudflare.example"])
        self.assertFalse(DomainReconciliationService._apply_confirmed_operation(operation.pk, info))
        self.domain.refresh_from_db()
        self.assertEqual(self.domain.nameservers, ["ns.old.example"])

    def test_a_proven_rejection_allows_a_fresh_explicit_attempt_but_unknown_is_never_reset(self):
        rejected = self.prepare().unwrap()
        self.gateway.update_nameservers.return_value = Err(
            Mock(code=Mock(value="forbidden")), retriability=Retriability.NOT_RETRIABLE
        )
        self.assertTrue(DomainLifecycleService.resume_nameserver_update(rejected).is_err())
        rejected.refresh_from_db()
        fresh = DomainLifecycleService.prepare_nameserver_update(
            self.domain, ["ns.cloudflare.example"], operation_id=uuid4(), retry_of=rejected.pk
        ).unwrap()
        self.assertNotEqual(fresh.pk, rejected.pk)
        self.assertEqual(fresh.parameters["retry_of"], str(rejected.pk))
        self.assertEqual(rejected.state, "failed")
        self.gateway.update_nameservers.return_value = Err(
            Mock(code=Mock(value="timeout")), retriability=Retriability.UNKNOWN
        )
        DomainLifecycleService.resume_nameserver_update(fresh)
        self.assertTrue(
            DomainLifecycleService.prepare_nameserver_update(
                self.domain, ["ns.cloudflare.example"], operation_id=uuid4(), retry_of=fresh.pk
            ).is_err()
        )
        fresh.refresh_from_db()
        self.assertEqual(fresh.state, "submitted")
