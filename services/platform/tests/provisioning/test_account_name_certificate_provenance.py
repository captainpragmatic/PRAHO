"""A valid native certificate must still be the exact Platform-issued vault certificate."""

import base64
import json
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.utils import timezone

from apps.billing.models import Currency
from apps.common.types import Err, Ok
from apps.provisioning import account_hostname_lifecycle as lifecycle
from apps.provisioning import account_hostname_service as names
from apps.provisioning import account_name_certificates as certs
from apps.provisioning.account_hostname_models import AccountNameCertificateInstall
from apps.provisioning.service_models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from tests.factories.core_factories import create_full_customer
from tests.helpers.fake_dns_gateway import FakeDnsGateway
from tests.provisioning.acme_fakes import issue_chain
from tests.provisioning.test_account_hostname_service import DOMAIN, FakeNode
from tests.provisioning.test_account_name_certificates import CertificateTestCase


class CertificateProvenanceTests(CertificateTestCase):
    def setUp(self):
        super().setUp()
        currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})[0]
        service = Service.objects.create(
            customer=create_full_customer(),
            service_plan=ServicePlan.objects.create(name="Certificate provenance", price_monthly=Decimal("10")),
            currency=currency,
            service_name=DOMAIN,
            domain=DOMAIN,
            username="customer",
            price=Decimal("10"),
            status="active",
        )
        self.account = VirtualminAccount.objects.create(
            service=service,
            server=self.server,
            domain=DOMAIN,
            virtualmin_username="customer",
            status="active",
            provisioned_at=timezone.now(),
        )
        self.server.ipv4_address = "203.0.113.20"
        self.server.save(update_fields=["ipv4_address"])
        self.hostname.account = self.account
        self.hostname.save(update_fields=["account"])
        self.issue()
        self.current = self.row()
        self.expected = certs._fingerprint(
            certs.split_chain(certs.vault_secret(self.current.current_certificate_ref))[0]
        )
        self.native_fingerprint = certs._fingerprint(
            certs.split_chain(issue_chain(next(iter(self.acme.csrs.values())), 90))[0]
        )
        self.assertNotEqual(self.native_fingerprint, self.expected)
        self.unrecognized_fingerprint = self.native_fingerprint
        for server in (
            self.server,
            VirtualminServer.objects.create(name="Other retained node", hostname="other-retained.example.net"),
        ):
            certs.record_installation(
                self.hostname,
                server,
                certificate_ref=self.current.current_certificate_ref,
                not_after=self.current.current_not_after,
            )
        self.node = FakeNode()
        self.node.rows[self.hostname.fqdn] = {
            "domain": self.hostname.fqdn,
            "username": "customer",
            "type": "Sub-server",
            "parent_domain": DOMAIN,
        }
        self.enterContext(patch.object(names, "_gateway", return_value=self.node))
        self.enterContext(patch.object(VirtualminServer, "node_deployment", new=object(), create=True))
        FakeDnsGateway.reset({certs.config.account_zone_id(): self.hostname.zone})
        self.enterContext(patch.object(names, "_dns_gateway", return_value=FakeDnsGateway("test-token")))
        self.runner = Mock()
        self.runner.run_playbook.side_effect = self.answer
        self.enterContext(patch("apps.infrastructure.ansible_service.AnsibleService", return_value=self.runner))
        self.install_calls = 0
        self.fail_transport = False
        self.drift_after_install = False
        self.guard_hook = None

    def answer(self, deployment, playbook, variables, **kwargs):
        if playbook == certs.INSTALL_PLAYBOOK:
            self.install_calls += 1
            self.native_fingerprint = certs._fingerprint(variables["certificate_pem"])
            reported = self.native_fingerprint
            if self.drift_after_install:
                self.native_fingerprint = self.unrecognized_fingerprint
            return Ok(SimpleNamespace(success=True, stdout=f"INSTALLED_FINGERPRINT={reported}"))
        if self.fail_transport and variables["account_name_guard_action"] == "ensure":
            return Err("transport interrupted")
        if self.guard_hook is not None and variables["account_name_guard_action"] == "ensure":
            hook, self.guard_hook = self.guard_hook, None
            hook()
        payload = {
            "version": 1,
            "identity": variables["account_name_guard_id"],
            "action": variables["account_name_guard_action"],
            "zone": self.hostname.zone,
            "name": self.hostname.fqdn,
            "neutral": True,
            "config_sha256": "a" * 64,
            "certificate_sha256": self.native_fingerprint,
        }
        return Ok(
            SimpleNamespace(
                success=True, stdout="NEUTRAL_RESULT=" + base64.b64encode(json.dumps(payload).encode()).decode()
            )
        )

    def test_publication_refuses_unrecognized_native_leaf_and_queued_repair_reuses_existing_vault_material(self):
        refused = names.sync_account_hostname(self.hostname)
        self.assertTrue(refused.is_err(), refused)
        self.assertEqual(FakeDnsGateway.published(self.hostname.fqdn), {})
        self.assertFalse(
            AccountNameCertificateInstall.objects.filter(hostname=self.hostname, server=self.server).exists()
        )
        self.assertEqual(AccountNameCertificateInstall.objects.filter(hostname=self.hostname).count(), 1)
        with patch("django_q.tasks.async_task") as enqueue:
            self.assertEqual(lifecycle.ensure_account_name(str(self.account.pk)), {"outcome": "sync_queued"})
        self.assertEqual(self.install_calls, 1)
        self.assertEqual(self.acme.place_calls, 1)
        self.assertEqual(self.native_fingerprint, self.expected)
        self.assertEqual(enqueue.call_args.args, (lifecycle.SYNC_TASK, str(self.hostname.pk)))
        self.assertEqual(lifecycle.sync_account_name(str(self.hostname.pk)), {"outcome": "published"})
        self.assertEqual(FakeDnsGateway.published(self.hostname.fqdn)["A"], self.server.ipv4_address)

    def test_post_placement_readiness_also_refuses_the_unrecognized_leaf_before_claiming_ready(self):
        refused = names.ensure_node_account_name(self.account, self.server, enabled=True)
        self.assertTrue(refused.is_err(), refused)
        self.assertEqual(self.install_calls, 0, "the stale install evidence must first be invalidated")
        self.assertFalse(
            AccountNameCertificateInstall.objects.filter(hostname=self.hostname, server=self.server).exists()
        )
        self.assertTrue(names.ensure_node_account_name(self.account, self.server, enabled=True).unwrap().neutral)
        self.assertEqual(self.install_calls, 1)
        self.assertEqual(self.acme.place_calls, 1)

    def test_transport_uncertainty_does_not_discard_recorded_node_installation(self):
        self.fail_transport = True
        refused = names.sync_account_hostname(self.hostname)
        self.assertTrue(refused.is_err())
        self.assertEqual(AccountNameCertificateInstall.objects.filter(hostname=self.hostname).count(), 2)
        self.assertEqual(FakeDnsGateway.published(self.hostname.fqdn), {})

    def test_unavailable_vault_material_prevents_publication_without_claiming_native_mismatch(self):
        with patch.object(certs, "vault_secret", return_value=None):
            refused = names.sync_account_hostname(self.hostname)
        self.assertTrue(refused.is_err())
        self.runner.run_playbook.assert_not_called()
        self.assertEqual(AccountNameCertificateInstall.objects.filter(hostname=self.hostname).count(), 2)
        self.assertEqual(FakeDnsGateway.published(self.hostname.fqdn), {})

    def test_the_expected_identity_is_from_the_vault_and_expired_material_has_no_ready_identity(self):
        self.assertEqual(certs.expected_certificate_fingerprint(self.hostname, self.server).unwrap(), self.expected)
        AccountNameCertificateInstall.objects.filter(hostname=self.hostname, server=self.server).update(
            not_after=timezone.now() - timezone.timedelta(seconds=1)
        )
        self.assertTrue(certs.expected_certificate_fingerprint(self.hostname, self.server).is_err())
        self.runner.run_playbook.assert_not_called()

    def test_an_install_followed_by_a_definite_leaf_mismatch_also_forgets_only_this_node(self):
        self.drift_after_install = True
        result = certs.install_current_certificate(self.hostname, self.server)
        self.assertTrue(result.is_err())
        self.assertFalse(
            AccountNameCertificateInstall.objects.filter(hostname=self.hostname, server=self.server).exists()
        )
        self.assertEqual(AccountNameCertificateInstall.objects.filter(hostname=self.hostname).count(), 1)

    def test_a_valid_recorded_platform_leaf_remains_usable_while_renewal_waits_for_installation(self):
        self.native_fingerprint = self.expected
        self.current.current_not_after = timezone.now() + timezone.timedelta(days=5)
        self.current.save(update_fields=["current_not_after"])
        with patch("django_q.tasks.async_task") as enqueue:
            result = certs.renew_account_name_certificate(str(self.hostname.pk), "renewal")
        self.assertEqual(result["status"], "issued")
        self.assertEqual(enqueue.call_count, 2)
        self.assertEqual(self.install_calls, 0)
        self.assertEqual(names.sync_account_hostname(self.hostname), Ok("published"))
        self.assertTrue(
            AccountNameCertificateInstall.objects.filter(hostname=self.hostname, server=self.server).exists()
        )
        renewed = self.row()
        renewed_fp = certs._fingerprint(certs.split_chain(certs.vault_secret(renewed.current_certificate_ref))[0])
        self.assertNotEqual(renewed_fp, self.expected)
        installation = AccountNameCertificateInstall.objects.get(hostname=self.hostname, server=self.server)
        self.assertEqual(certs.install_account_name_certificate(str(installation.pk)), {"outcome": "installed"})
        self.assertEqual(certs.expected_certificate_fingerprint(self.hostname, self.server).unwrap(), renewed_fp)
        self.assertEqual(self.native_fingerprint, renewed_fp)
        self.assertEqual(names.sync_account_hostname(self.hostname), Ok("published"))
        self.assertEqual(self.install_calls, 1)
        self.assertEqual(self.acme.place_calls, 2)

    def test_a_new_install_recorded_during_guard_rpc_survives_the_old_pins_mismatch(self):
        self.native_fingerprint = self.expected
        self.current.current_not_after = timezone.now() + timezone.timedelta(days=5)
        self.current.save(update_fields=["current_not_after"])
        with patch("django_q.tasks.async_task"):
            self.assertEqual(certs.renew_account_name_certificate(str(self.hostname.pk), "renewal")["status"], "issued")
        renewed = self.row()
        renewed_fp = certs._fingerprint(certs.split_chain(certs.vault_secret(renewed.current_certificate_ref))[0])

        def authorized_install_finishes():
            self.native_fingerprint = renewed_fp
            certs.record_installation(
                self.hostname,
                self.server,
                certificate_ref=renewed.current_certificate_ref,
                not_after=renewed.current_not_after,
            )

        self.guard_hook = authorized_install_finishes
        self.assertTrue(names.sync_account_hostname(self.hostname).is_err())
        recorded = AccountNameCertificateInstall.objects.filter(hostname=self.hostname, server=self.server).first()
        self.assertIsNotNone(recorded, "the old pin cannot discard a newer authorized install")
        self.assertEqual(recorded.certificate_ref, renewed.current_certificate_ref)
        self.assertEqual(FakeDnsGateway.published(self.hostname.fqdn), {})
        self.assertEqual(names.sync_account_hostname(self.hostname), Ok("published"))
        self.assertEqual(self.install_calls, 0)
