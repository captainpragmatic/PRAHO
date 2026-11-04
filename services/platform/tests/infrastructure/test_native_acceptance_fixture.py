"""Acceptance setup uses real billing services; network contract doubles are not VM proof."""

import io
import os
from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

from dateutil.relativedelta import relativedelta
from django.contrib.auth.hashers import check_password
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.billing.models import Currency, Invoice, Subscription
from apps.billing.plan_change_coverage import load_plan_coverage
from apps.billing.proforma_service import ProformaPaymentService
from apps.billing.recurring_billing import RecurringBillingOrchestrator
from apps.common.credential_vault import get_credential_vault
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.infrastructure.cloud_resource_inventory import CAPABILITIES, CloudResource
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint, unique_dns_owner_tag
from apps.infrastructure.models import CloudResourceOwnership, NodeDeployment, NodeDeploymentLog, NodeServerLifetime
from apps.infrastructure.native_acceptance_fixture import (
    _new_commercial_rows,
    _settle_initial_cycles,
    _validate_commercial_binding,
    create_commercial_owner,
    create_commercial_staff,
    create_peer,
    destroy_peer,
    export_peer,
    initialize_commercial_subscription,
    prepare_peer_intent,
    run_acceptance,
    setup_staff_fixture,
)
from apps.infrastructure.native_fresh_workflow import (
    REQUIRED_STAGES,
    _fresh_deployment,
    bind_fresh_deployment,
    destroy_fresh_vm,
)
from apps.infrastructure.native_lab import native_authority, native_driver, write_private
from apps.products.models import Product
from apps.provisioning.hosting_limit_execution import apply_hosting_limits
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User
from tests.helpers.task_queue import quiet_task_queue
from tests.infrastructure import test_hosting_native_fresh_workflow as fresh
from tests.provisioning.test_hosting_limit_execution import HostingLimitWorkerFixture
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class NativeAcceptanceCommandTests(SimpleTestCase):
    def test_command_refuses_ordinary_test_profile_before_loading_any_manifest(self):
        with self.assertRaisesMessage(CommandError, "primary native settings"):
            call_command(
                "hosting_native_acceptance", "setup", "--manifest", "/missing/primary.json", stdout=io.StringIO()
            )


class NativeCommercialSetupTests(TestCase):
    def setUp(self):

        quiet_task_queue(self)
        self.customer = Customer.objects.create(name="Synthetic native history", customer_type="individual")
        self.currency = Currency.objects.get(code="RON")
        self.plan = ServicePlan.objects.create(
            name="Native fixture base", disk_space_gb=1, bandwidth_gb=20, price_monthly="10.00"
        )
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="Owned acceptance",
            domain="fixture.example.invalid",
            price=Decimal("10.00"),
            auto_renew=True,
        )
        self.service.activate()
        self.service.save()
        self.product = Product.objects.create(
            name="Native fixture base",
            slug="native-acceptance-base",
            product_type="hosting",
            module="virtualmin",
            default_service_plan=self.plan,
        )
        self.boundary = (timezone.now() + timedelta(minutes=75)).replace(microsecond=0)

    def test_new_historical_initial_world_reaches_real_paid_current_cycle_without_clock_override(self):

        subscription = initialize_commercial_subscription(self.service, self.product, self.boundary)
        initial_end = self.boundary - relativedelta(months=1)
        self.assertEqual(subscription.current_period_end, initial_end)
        self.assertEqual(subscription.status, "active")
        result = RecurringBillingOrchestrator.prepare_due_proformas()
        self.assertEqual(result["errors"], [], result)
        cycle = subscription.billing_cycles.get()
        self.assertEqual(cycle.period_end, self.boundary)
        self.assertIsNotNone(cycle.proforma_id)
        paid = ProformaPaymentService.record_payment_and_convert(
            str(cycle.proforma_id),
            cycle.proforma.total_cents,
            "bank",
            reference="Synthetic native setup; no real transfer",
        )
        self.assertTrue(paid.is_ok(), paid)
        subscription.refresh_from_db()
        self.assertEqual(subscription.current_period_end, self.boundary)
        coverage = load_plan_coverage(subscription, at=timezone.now())
        self.assertEqual(coverage.current_period_price_cents, 1000)
        self.assertEqual(len(coverage.intervals), 1)
        self.assertTrue(coverage.intervals[0].paid)
        self.assertEqual(coverage.intervals[0].end, self.boundary)
        before = subscription.current_period_start, subscription.current_period_end
        with self.assertRaisesMessage(ValueError, "existing subscription"):
            initialize_commercial_subscription(self.service, self.product, self.boundary)
        subscription.refresh_from_db()
        self.assertEqual((subscription.current_period_start, subscription.current_period_end), before)

    def test_invalid_or_expired_boundary_creates_no_subscription(self):

        for boundary in (timezone.now() - timedelta(seconds=1), timezone.now() + timedelta(days=1)):
            with self.subTest(boundary=boundary), self.assertRaises(ValueError):
                initialize_commercial_subscription(self.service, self.product, boundary)
        self.assertFalse(Subscription.objects.exists())

    def test_new_owner_password_is_supported_by_production_hashers_before_first_save(self):

        owner = create_commercial_owner("native-owner@example.invalid", "owned-private-fixture-password")
        self.assertTrue(owner.password.startswith("pbkdf2_sha256$"))
        with override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.PBKDF2PasswordHasher"]):
            self.assertTrue(check_password("owned-private-fixture-password", owner.password))
        with self.assertRaisesMessage(ValueError, "existing owner"):
            create_commercial_owner(owner.email, "another-password")
        owner.refresh_from_db()
        with override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.PBKDF2PasswordHasher"]):
            self.assertTrue(check_password("owned-private-fixture-password", owner.password))

    def test_initial_settlement_replay_never_prepares_the_next_boundary_renewal(self):

        subscription = initialize_commercial_subscription(self.service, self.product, self.boundary)
        binding = {
            "customer_id": self.customer.pk,
            "boundary": self.boundary.isoformat(),
            "lanes": {"upgrade": {"subscription_id": str(subscription.pk), "service_id": self.service.pk}},
        }
        _settle_initial_cycles(binding)
        first = dict(binding["lanes"]["upgrade"])
        _settle_initial_cycles(binding)
        self.assertEqual(binding["lanes"]["upgrade"], first)
        self.assertEqual(subscription.billing_cycles.count(), 1)
        self.assertEqual(Invoice.objects.count(), 1)
        self.assertFalse(subscription.billing_cycles.filter(period_start=self.boundary).exists())
        subscription.refresh_from_db()
        self.assertEqual(subscription.current_period_end, self.boundary)

    def test_new_staff_is_nonsuperuser_and_existing_role_membership_password_are_never_rewritten(self):

        run = uuid4()
        staff = create_commercial_staff(str(run), "private-initial-staff-password")
        self.assertTrue(staff.is_staff)
        self.assertFalse(staff.is_superuser)
        self.assertEqual(staff.staff_role, "admin")
        self.assertEqual(
            set(staff.user_permissions.values_list("codename", flat=True)), {"deploy_nodes", "destroy_nodes"}
        )
        self.assertFalse(CustomerMembership.objects.filter(user=staff).exists())
        with override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.PBKDF2PasswordHasher"]):
            self.assertTrue(check_password("private-initial-staff-password", staff.password))
        staff.staff_role = "support"
        staff.save(update_fields=["staff_role"])
        membership = CustomerMembership.objects.create(
            customer=self.customer, user=staff, role="viewer", is_active=True
        )
        original_password = staff.password
        with self.assertRaisesMessage(ValueError, "existing staff"):
            create_commercial_staff(str(run), "replacement-password")
        staff.refresh_from_db()
        membership.refresh_from_db()
        self.assertEqual((staff.staff_role, staff.password, membership.role), ("support", original_password, "viewer"))


class NativePeerIntentTests(TestCase):
    """Database provenance fixture deliberately supplies no physical-native proof."""

    def setUp(self):

        fresh.NativeFreshFixtureTests.setUp(self)
        self.peer_path = self.path.parent / "peer.json"

    def completed_contract(self, deployment, authority, server_id, key_id):

        server = VirtualminServer.objects.create(
            name=f"Contract {server_id}",
            hostname=deployment.fqdn,
            api_username="fixture",
            encrypted_api_password=b"",
            status="active",
        )
        NodeDeployment.objects.filter(pk=deployment.pk).update(
            status="completed",
            server_create_state="created",
            registration_state="activated",
            virtualmin_server=server,
            external_node_id=str(server_id),
            ipv4_address=f"192.0.2.{server_id}",
            ssh_port=9876,
            ssh_host_keys=authority.public_key,
            provider_token_fingerprint=provider_token_fingerprint("native-fixture-token"),
        )
        NodeDeploymentLog.objects.create(
            deployment=deployment,
            level="INFO",
            phase="native_fresh_result",
            message="Explicit database contract fixture; no physical proof",
            details={
                "source": "NodeDeploymentService.deploy_node",
                "success": True,
                "stages": sorted(REQUIRED_STAGES),
                "validation_passed": True,
                "validation_checks": ["ssh", "ports", "virtualmin", "ssl"],
            },
        )
        for kind, identifier in (("server", server_id), ("ssh_key", key_id)):
            CloudResourceOwnership.objects.create(
                deployment=deployment,
                provider=self.provider,
                token_fingerprint=provider_token_fingerprint("native-fixture-token"),
                deployment_correlation_id=deployment.correlation_id,
                kind=kind,
                resource_id=str(identifier),
                provenance="create_response",
            )
        NodeServerLifetime.objects.create(
            deployment=deployment,
            server_id=str(server_id),
            correlation_id=deployment.correlation_id,
            node_size=self.size,
            monthly_cost_eur=self.size.monthly_cost_eur,
            started_at=timezone.now(),
        )
        deployment.refresh_from_db()

    def ready_primary(self):

        self.environment = patch.dict(
            os.environ,
            {
                "HCLOUD_TOKEN": "native-fixture-token",
                "PRAHO_NATIVE_CLOUDFLARE_TOKEN": "fixture-dns",
                "PRAHO_NATIVE_CLOUDFLARE_ZONE_ID": "owned-zone",
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        primary = bind_fresh_deployment(
            self.authority, dns_zone="lab.example.com", provider_token="native-fixture-token", zone_id="owned-zone"
        )
        self.completed_contract(primary, self.authority, 13, 17)
        self.authority.manifest.update(phase="verified", server_id=13, ssh_key_id=17, ipv4="192.0.2.13")
        native_driver().write_manifest(self.path, self.authority.manifest)
        NodeDeploymentLog.objects.create(
            deployment=primary, level="INFO", phase="native_fresh_verified", message="Contract fixture"
        )
        self.live = patch.object(
            native_driver(), "owned_server", return_value=(self.authority.manifest, SimpleNamespace())
        )
        self.live.start()
        self.addCleanup(self.live.stop)

        operator = self.path.parent / (self.authority.manifest["run"] + ".operator.pub")
        write_private(operator, self.authority.public_key + "\n")
        setting = override_settings(PRAHO_SSH_OPERATOR_PUBLIC_KEYS_FILE=str(operator))
        setting.enable()
        self.addCleanup(setting.disable)
        return primary

    def test_peer_intent_precedes_create_and_replays_same_primary_vault_identity(self):

        primary = self.ready_primary()
        with patch.object(native_driver(), "client", side_effect=AssertionError("No peer provider mutation at intent")):
            first = prepare_peer_intent(native_authority(self.path), self.peer_path)
            replay = prepare_peer_intent(native_authority(self.path), self.peer_path)
        self.assertEqual(first, replay)
        peer = NodeDeployment.objects.get(pk=first["deployment_id"])
        self.assertEqual((peer.status, peer.server_create_state, peer.external_node_id), ("pending", "none", ""))
        self.assertEqual(peer.initiated_by_id, primary.initiated_by_id)
        self.assertEqual(peer.logs.get(phase="native_peer_intent").details, first)
        self.assertEqual(NodeDeployment.objects.count(), 2)
        child = native_authority(self.peer_path)
        self.assertEqual(native_authority(self.path).key, self.authority.key)
        self.assertNotEqual(child.key, self.authority.key)
        stored = get_credential_vault().get_credential(
            service_type="ssh", service_identifier="node-" + peer.hostname, reason="Test original vault"
        )
        self.assertTrue(stored.is_ok(), stored)
        self.assertEqual(stored.unwrap()[1], child.key.decode())
        self.assertEqual(child.manifest["expires_at"], self.authority.manifest["expires_at"])

    def test_staff_bootstrap_is_before_commercial_clock_and_never_restores_revoked_authority(self):

        primary = self.ready_primary()
        original_actor = primary.initiated_by
        original_password = original_actor.password
        staff = setup_staff_fixture(native_authority(self.path))
        self.assertEqual(setup_staff_fixture(native_authority(self.path)).pk, staff.pk)
        self.assertFalse(Subscription.objects.exists())
        self.assertFalse(primary.logs.filter(phase="native_commercial_intent").exists())
        self.assertEqual(primary.logs.get(phase="native_acceptance_staff").details["user_id"], staff.pk)
        original_actor.refresh_from_db()
        self.assertEqual(original_actor.password, original_password)
        staff.user_permissions.clear()
        with self.assertRaisesMessage(ValueError, "staff authority changed"):
            setup_staff_fixture(native_authority(self.path))
        staff.refresh_from_db()
        self.assertEqual(staff.user_permissions.count(), 0)

    def test_peer_never_uses_disabled_public_deployment_to_claim_success(self):

        self.ready_primary()
        binding = prepare_peer_intent(native_authority(self.path), self.peer_path)
        self.assertTrue(SettingsService.update_setting("node_deployment.enabled", False).is_ok())
        with self.assertRaisesMessage(ValueError, "disabled"):
            create_peer(native_authority(self.path), self.peer_path)
        peer = NodeDeployment.objects.get(pk=binding["deployment_id"])
        self.assertFalse(peer.external_node_id)
        self.assertFalse(peer.logs.filter(phase="native_fresh_result").exists())
        self.assertEqual(native_authority(self.peer_path).manifest["phase"], "fresh-intent")

    def test_wrong_creator_and_missing_create_records_cannot_export_an_http_success(self):

        self.ready_primary()
        binding = prepare_peer_intent(native_authority(self.path), self.peer_path)
        peer = NodeDeployment.objects.get(pk=binding["deployment_id"])
        with patch.object(native_driver(), "client", side_effect=AssertionError("No export before real facts")):
            with self.assertRaisesMessage(ValueError, "not complete"):
                export_peer(native_authority(self.path), self.peer_path)
            other = User.objects.create_user(email="unapproved@example.invalid")
            NodeDeployment.objects.filter(pk=peer.pk).update(initiated_by=other)
            with self.assertRaisesMessage(ValueError, "creator"):
                export_peer(native_authority(self.path), self.peer_path)

    def test_public_primary_lookup_and_peer_cleanup_replay_retain_all_deployment_history(self):

        primary = self.ready_primary()
        binding = prepare_peer_intent(native_authority(self.path), self.peer_path)
        NodeDeployment.objects.filter(pk=binding["deployment_id"]).update(status="destroyed")
        destroy_peer(native_authority(self.path), self.peer_path)
        destroy_peer(native_authority(self.path), self.peer_path)
        actual = _fresh_deployment(
            native_authority(self.path), provider_token="native-fixture-token", zone_id="owned-zone"
        )
        self.assertEqual(actual.pk, primary.pk)
        self.assertEqual(NodeDeployment.objects.count(), 2)
        self.assertEqual(native_authority(self.peer_path, cleanup=True).manifest["phase"], "destroyed")

    def test_export_requires_existing_enrolled_key_id_and_retains_primary_vault(self):

        primary = self.ready_primary()
        binding = prepare_peer_intent(native_authority(self.path), self.peer_path)
        peer = NodeDeployment.objects.get(pk=binding["deployment_id"])
        child = native_authority(self.peer_path)
        self.completed_contract(peer, child, 23, 27)
        cloud = MagicMock()
        labels = {"managed-by": "praho", "praho-deployment": str(peer.correlation_id)}
        server = SimpleNamespace(
            id=23,
            name=peer.hostname,
            labels=labels,
            public_net=SimpleNamespace(ipv4=SimpleNamespace(ip="192.0.2.23")),
            update=MagicMock(),
        )
        key = SimpleNamespace(id=27, labels=dict(labels), public_key=child.public_key)
        cloud.servers.get_by_id.return_value, cloud.ssh_keys.get_by_id.return_value = server, key
        dns = MagicMock()
        dns.get_zone_name.return_value = Ok("example.com")
        dns.find_records_by_name.return_value = Ok(
            [
                {
                    "type": "A",
                    "name": peer.fqdn,
                    "content": "192.0.2.23",
                    "comment": unique_dns_owner_tag(peer.correlation_id),
                }
            ]
        )
        with (
            patch.object(native_driver(), "client", return_value=cloud),
            patch("apps.infrastructure.dns_gateway.get_dns_gateway", return_value=dns),
            patch(
                "apps.infrastructure.native_workflow.socket.getaddrinfo",
                return_value=[(None, None, None, None, ("192.0.2.23", 10000))],
            ),
        ):
            export_peer(native_authority(self.path), self.peer_path)
            exported = native_authority(self.peer_path)
            self.assertEqual((exported.manifest["server_id"], exported.manifest["ssh_key_id"]), (23, 27))
            self.assertEqual(exported.key, child.key)
            self.assertEqual(native_authority(self.path).key, self.authority.key)
            exported.manifest["phase"] = "verified"
            native_driver().write_manifest(self.peer_path, exported.manifest)
            export_peer(native_authority(self.path), self.peer_path)
            self.assertEqual(native_authority(self.peer_path).manifest["phase"], "verified")
            retargeted = native_authority(self.peer_path).manifest
            retargeted["server_id"] = 99
            native_driver().write_manifest(self.peer_path, retargeted)
            with self.assertRaisesMessage(ValueError, "retarget"):
                export_peer(native_authority(self.path), self.peer_path)
            native_driver().write_manifest(self.peer_path, exported.manifest)
            server.labels["praho-native-run"] = "different-native-owner"
            with self.assertRaisesMessage(ValueError, "native owner"):
                export_peer(native_authority(self.path), self.peer_path)
            server.labels.pop("praho-native-run")
            NodeDeployment.objects.filter(pk=peer.pk).update(ssh_key_credential_id=primary.ssh_key_credential_id)
            with self.assertRaisesMessage(ValueError, "credential"):
                export_peer(native_authority(self.path), self.peer_path)

    def test_lost_local_publication_reuses_committed_never_created_intent(self):

        self.ready_primary()
        writer = native_driver().write_manifest

        def lose_publication(path, value):
            if value.get("platform_peer"):
                raise OSError("Lost local response after committed intent")
            return writer(path, value)

        with patch.object(native_driver(), "write_manifest", side_effect=lose_publication), self.assertRaises(OSError):
            prepare_peer_intent(native_authority(self.path), self.peer_path)
        self.assertEqual(NodeDeployment.objects.count(), 2)
        first = native_authority(self.peer_path).key
        recovered = prepare_peer_intent(native_authority(self.path), self.peer_path)
        self.assertEqual(NodeDeployment.objects.count(), 2)
        self.assertEqual(native_authority(self.peer_path).key, first)
        self.assertEqual(native_authority(self.peer_path).manifest["platform_peer"], recovered)

    def test_third_deployment_refuses_before_peer_files(self):

        primary = self.ready_primary()
        NodeDeployment.objects.create(
            provider=primary.provider,
            region=primary.region,
            node_size=primary.node_size,
            panel_type=primary.panel_type,
            environment="dev",
            node_type="sha",
            node_number=999,
            dns_zone=primary.dns_zone,
        )
        with self.assertRaisesMessage(ValueError, "third deployment"):
            prepare_peer_intent(native_authority(self.path), self.peer_path)
        self.assertFalse(self.peer_path.exists())

    def test_actual_public_peer_then_parent_teardown_retains_both_creation_histories(self):
        primary = self.ready_primary()
        binding = prepare_peer_intent(native_authority(self.path), self.peer_path)
        peer = NodeDeployment.objects.get(pk=binding["deployment_id"])
        self.completed_contract(peer, native_authority(self.peer_path), 23, 27)
        resources = {
            "13": [CloudResource("server", "13"), CloudResource("ssh_key", "17")],
            "23": [CloudResource("server", "23"), CloudResource("ssh_key", "27")],
        }
        client = MagicMock(capabilities=CAPABILITIES["hetzner"])
        client.inventory.side_effect = lambda identifiers: Ok(
            [resource for identifier in identifiers for resource in resources.get(identifier, [])]
        )

        def read(kind, identifier):
            return next(
                (
                    {"id": identifier, "type": kind, "status": "available"}
                    for rows in resources.values()
                    for row in rows
                    if row.kind == kind and row.resource_id == identifier
                ),
                None,
            )

        def delete(kind, identifier):
            for key, rows in resources.items():
                resources[key] = [row for row in rows if (row.kind, row.resource_id) != (kind, identifier)]
            return Ok(True)

        client.read_exact.side_effect = read
        client.delete_exact.side_effect = delete
        client.confirm_absent.side_effect = lambda kind, identifier: Ok(read(kind, identifier) is None)
        gateway = MagicMock()
        gateway.resource_client.return_value = client
        with (
            patch("apps.infrastructure.cloud_destroy_service.get_cloud_gateway", return_value=gateway),
            patch("apps.infrastructure.node_teardown.get_cloud_gateway", return_value=gateway),
        ):
            destroy_peer(native_authority(self.path), self.peer_path)
            self.assertEqual({row.resource_id for row in resources["13"]}, {"13", "17"})
            self.assertEqual(resources["23"], [])
            self.assertEqual(
                _fresh_deployment(
                    native_authority(self.path), provider_token="native-fixture-token", zone_id="owned-zone"
                ).pk,
                primary.pk,
            )
            destroy_fresh_vm(native_authority(self.path))
        self.assertEqual(resources, {"13": [], "23": []})
        self.assertEqual(NodeDeployment.objects.filter(status="destroyed").count(), 2)
        self.assertEqual(CloudResourceOwnership.objects.count(), 4)
        self.assertEqual(NodeServerLifetime.objects.filter(ended_at__isnull=False).count(), 2)

    def test_all_true_manifest_without_public_primary_provenance_cannot_admit_peer(self):

        self.authority.manifest.update(
            phase="verified", quota_acceptance={"verified": True}, fresh_deployment={"verified": True}
        )
        native_driver().write_manifest(self.path, self.authority.manifest)
        with (
            patch.dict(
                os.environ,
                {
                    "HCLOUD_TOKEN": "native-fixture-token",
                    "PRAHO_NATIVE_CLOUDFLARE_TOKEN": "fixture-dns",
                    "PRAHO_NATIVE_CLOUDFLARE_ZONE_ID": "owned-zone",
                },
            ),
            self.assertRaises(ValueError),
        ):
            prepare_peer_intent(native_authority(self.path), self.peer_path)
        self.assertFalse(self.peer_path.exists())

    def test_expired_primary_does_not_create_peer_files_or_database_rows(self):

        self.authority.manifest["expires_at"] = (timezone.now() - timedelta(seconds=1)).isoformat()
        native_driver().write_manifest(self.path, self.authority.manifest)
        with self.assertRaisesMessage(ValueError, "expired"):
            run_acceptance(self.path, "peer-intent", peer_path=self.peer_path)
        self.assertFalse(NodeDeployment.objects.exists())
        self.assertFalse(self.peer_path.exists())


class NativeManagedCommercialRowsTests(HostingLimitWorkerFixture, TestCase):
    completed_contract = NativePeerIntentTests.completed_contract
    ready_primary = NativePeerIntentTests.ready_primary

    def setUp(self):
        quiet_task_queue(self)
        fresh.NativeFreshFixtureTests.setUp(self)
        self.primary = self.ready_primary()
        VirtualminTaskTestBase.setUp(self)
        self.customer.name = "Native quota acceptance " + self.authority.manifest["run"]
        self.customer.save(update_fields=["name"])
        self.service.username = "nat" + self.authority.manifest["run"].replace("-", "")[:10]
        self.service.price = Decimal("7.31")
        self.service.save(update_fields=["username", "price"])
        self.account.virtualmin_username = self.service.username
        self.account.status = "active"
        self.account.save(update_fields=["virtualmin_username", "status"])
        NodeDeployment.objects.filter(pk=self.primary.pk).update(virtualmin_server=self.server)
        self.primary.refresh_from_db()
        self.setup_native_fixture()
        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=self.receipt()),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
                side_effect=lambda server, action, request: self.receipt(
                    cap=request["disk_limit_kib"] // 1024, request=request
                ),
            ),
        ):
            self.assertEqual(apply_hosting_limits(self.application.pk), "completed")
        setup_staff_fixture(native_authority(self.path))

    def test_new_commercial_rows_preserve_foundation_billing_and_use_current_verified_native_base(self):
        self.service.refresh_from_db()
        original = self.service.price, self.service.service_plan_id, self.service.hosting_limits.revision
        boundary = (timezone.now() + timedelta(minutes=75)).replace(microsecond=0)
        binding = _new_commercial_rows(native_authority(self.path), self.primary, boundary)
        self.assertEqual(set(binding["lanes"]), {"upgrade", "downgrade"})
        self.assertEqual(binding["lanes"]["upgrade"]["service_id"], self.service.pk)
        self.assertEqual(Subscription.objects.count(), 2)
        self.assertEqual(Service.objects.count(), 2)
        self.assertTrue(User.objects.get(pk=binding["owner_id"]).password.startswith("pbkdf2_sha256$"))
        self.service.refresh_from_db()
        self.assertEqual(
            (self.service.price, self.service.service_plan_id, self.service.hosting_limits.revision), original
        )
        _settle_initial_cycles(binding)
        self.assertEqual(Invoice.objects.count(), 1)
        for lane in binding["lanes"].values():
            subscription = Subscription.objects.get(pk=lane["subscription_id"])
            self.assertEqual(subscription.current_period_end, boundary)
            coverage = load_plan_coverage(subscription, at=timezone.now())
            self.assertTrue(coverage.intervals[0].paid)
            self.assertEqual(coverage.current_period_price_cents, 731)
        self.assertEqual(Invoice.objects.get().subtotal_cents, 1462)

    def test_commercial_setup_replay_refuses_revoked_admitted_staff(self):

        boundary = (timezone.now() + timedelta(minutes=75)).replace(microsecond=0)
        binding = _new_commercial_rows(native_authority(self.path), self.primary, boundary)
        staff = User.objects.get(pk=binding["staff_id"])
        staff.user_permissions.clear()
        with self.assertRaisesMessage(ValueError, "staff authority changed"):
            _validate_commercial_binding(native_authority(self.path), self.primary, binding)
        self.assertEqual(staff.user_permissions.count(), 0)

    def test_unrelated_customer_service_refuses_before_any_initial_billing_rows(self):
        foreign = Customer.objects.create(name="Outside this native run", customer_type="individual")
        Service.objects.create(
            customer=foreign,
            service_plan=self.plan,
            currency=self.currency,
            service_name="Other fixture",
            price=Decimal("10.00"),
        )
        before = User.objects.count(), Product.objects.count(), Subscription.objects.count()
        boundary = (timezone.now() + timedelta(minutes=75)).replace(microsecond=0)
        with self.assertRaisesMessage(ValueError, "unrelated"):
            _new_commercial_rows(native_authority(self.path), self.primary, boundary)
        self.assertEqual((User.objects.count(), Product.objects.count(), Subscription.objects.count()), before)
