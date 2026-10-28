"""A retained bridge is removed only after customer routing and old caches are proven safe."""

from datetime import datetime, timedelta
from unittest.mock import patch

from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.common.types import Ok
from apps.infrastructure.dns_agreement import Agreement, RoutingAnswer, routing_agreement
from apps.infrastructure.panel_cert_probes import AuthoritativeAnswer
from apps.provisioning import migration_routing as routing
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.migration_bridge_cleanup import cleanup_bridge, control_bridge
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.users.models import User
from tests.provisioning.test_virtualmin_migration_bridge import BridgeCase


class FrontendRetentionTests(BridgeCase):
    def due(self):
        self.staff.is_staff = True
        self.staff.save(update_fields=["is_staff"])
        bridge, migration = self._bridge()
        self.server.ipv4_address = "95.217.0.10"
        self.server.save(update_fields=["ipv4_address"])
        self.target.ipv4_address = "95.217.0.20"
        self.target.save(update_fields=["ipv4_address"])
        self.account.server = self.target
        self.account.save(update_fields=["server"])
        AccountHostname.objects.create(account=self.account, target_server=self.target, label="a1b2c3d4", zone="accounts.example.net")
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="completed", cutover_committed_at=timezone.now())  # fsm-bypass: committed fixture
        self.source_gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username, enabled=False)
        bridge.activate()
        bridge.evidence = {
            "expires_at": (timezone.now() - timedelta(seconds=1)).isoformat(),
            "certificate_not_after": (timezone.now() + timedelta(days=30)).isoformat(),
            "dns_names": [self.account.domain],
            "frontend_dns_before": {self.account.domain: {"ttl": 3600}},
        }
        bridge.save()
        migration.refresh_from_db()
        return bridge, migration

    def boundaries(self):
        return (
            patch("apps.infrastructure.dns_agreement.authoritative_agreement", return_value=Agreement(True)),
            patch("apps.provisioning.migration_bridge_service.verify_bridge", return_value=Ok("verified")),
            patch("apps.provisioning.migration_bridge_service.remove_bridge", return_value=Ok("removed")),
            patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup"),
        )

    def test_customer_apex_still_on_source_retains_the_bridge_even_while_owned_name_agrees(self):
        bridge, migration = self.due()
        stale = Agreement(False, 3600, "A still reaches source", (AuthoritativeAnswer("ns.example.net", "A", (self.server.ipv4_address,)),))
        for boundary in self.boundaries():
            self.enterContext(boundary)
        with patch.object(routing, "routing_agreement", return_value=stale):
            result = cleanup_bridge(str(migration.pk))
        self.assertEqual(result["action"], "retrying")
        self.assertNotIn("delete-domain", self._programs("source"))
        bridge.refresh_from_db()
        self.assertFalse(bridge.evidence["routing"][self.account.domain]["agreed"])

    def test_late_customer_confirmation_starts_a_full_original_ttl_wait_before_teardown(self):
        bridge, migration = self.due()
        checked = timezone.now()
        for boundary in self.boundaries():
            self.enterContext(boundary)
        with (
            patch.object(routing, "routing_agreement", return_value=Agreement(True, 60)),
            patch.object(routing.timezone, "now", return_value=checked),
        ):
            self.assertEqual(cleanup_bridge(str(migration.pk))["action"], "retrying")
        bridge.refresh_from_db()
        self.assertEqual(bridge.evidence["routing"][self.account.domain]["confirmed_at"], checked.isoformat())
        self.assertNotIn("delete-domain", self._programs("source"))
        with (
            patch.object(routing, "routing_agreement", return_value=Agreement(True, 60)),
            patch.object(routing.timezone, "now", return_value=checked + timedelta(seconds=3600)),
        ):
            self.assertEqual(cleanup_bridge(str(migration.pk))["action"], "torn_down")

    def test_role_based_staff_may_attest_and_non_staff_may_not(self):
        # The bridge-control view admits staff by role (User.is_staff_user); the attestation must
        # accept the same identities, not only the Django is_staff flag.
        bridge, migration = self.due()
        self.staff.is_staff = False
        self.staff.save(update_fields=["is_staff"])
        self.assertEqual(self.staff.staff_role, "admin")
        attestation = {
            "note": "Checked the CDN dashboard: origin is the committed target", "target_id": str(self.target.pk),
            "ipv4": self.target.ipv4_address, "ipv6": self.target.ipv6_address or "",
        }
        outsider = User.objects.create_user(email="not-staff@example.com", password="not-staff-password")
        with patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup"):
            refused = control_bridge(migration.pk, action="attest", actor=outsider, attestation=attestation)
            accepted = control_bridge(migration.pk, action="attest", actor=self.staff, attestation=attestation)
        self.assertTrue(refused.is_err())
        self.assertTrue(accepted.is_ok(), accepted)
        bridge.refresh_from_db()
        self.assertEqual(bridge.evidence["routing_attestation"]["actor"], str(self.staff.pk))

    def test_a_staff_proxy_statement_is_bound_to_current_target_and_audited(self):
        bridge, migration = self.due()
        with patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup"):
            result = control_bridge(migration.pk, action="attest", actor=self.staff, attestation={
                "note": "Checked the CDN dashboard: origin is the committed target", "target_id": str(self.target.pk),
                "ipv4": self.target.ipv4_address, "ipv6": self.target.ipv6_address or "",
            })
        self.assertTrue(result.is_ok(), result)
        bridge.refresh_from_db()
        statement = bridge.evidence["routing_attestation"]
        self.assertEqual(statement["actor"], str(self.staff.pk))
        self.assertEqual(statement["names"], [self.account.domain])
        self.assertEqual(statement["target_id"], str(self.target.pk))
        self.assertTrue(AuditEvent.objects.filter(action="virtualmin_bridge_origin_attested", user=self.staff).exists())

    def statement(self, bridge, migration):
        result = control_bridge(migration.pk, action="attest", actor=self.staff, attestation={
            "note": "Checked every CDN origin and bound it to this target", "target_id": str(self.target.pk),
            "ipv4": self.target.ipv4_address, "ipv6": self.target.ipv6_address or "",
        })
        self.assertTrue(result.is_ok(), result)
        bridge.refresh_from_db()

    def test_only_an_explicit_current_staff_statement_can_supplement_opaque_proxy_addresses(self):
        bridge, migration = self.due()
        proxy = routing_agreement(self.account.domain, self.target.ipv4_address, None, pause=0, query=lambda name: [
            RoutingAnswer(ns, family, ("104.16.0.1",) if family == "A" else (), ttl=300, queried_name=name)
            for ns in ("ns1.example.net", "ns2.example.net") for family in ("A", "AAAA")
        ])
        self.assertFalse(proxy.agreed)
        with patch.object(routing, "routing_agreement", return_value=proxy):
            before, _ = routing.observe_frontends(bridge)
            self.assertFalse(before[self.account.domain]["agreed"])
            self.statement(bridge, migration)
            after, _ = routing.observe_frontends(bridge)
        self.assertTrue(after[self.account.domain]["agreed"])
        self.assertTrue(after[self.account.domain]["attested"])

    def test_a_proxy_statement_cannot_override_source_records_or_unknown_dns(self):
        bridge, migration = self.due()
        self.statement(bridge, migration)
        for agreement in (
            Agreement(False, 300, "ns A: answered ['95.217.0.10'], expected ['95.217.0.20']", (
                AuthoritativeAnswer("ns", "A", (self.server.ipv4_address,)),
            )),
            Agreement(False, detail="Customer routing probe deadline exceeded"),
            Agreement(False, detail="Authoritative servers disagree on the CNAME target"),
        ):
            with self.subTest(detail=agreement.detail), patch.object(routing, "routing_agreement", return_value=agreement):
                progress, errors = routing.observe_frontends(bridge)
                self.assertFalse(progress[self.account.domain]["agreed"])
                self.assertTrue(errors)

    def test_stale_target_inputs_cannot_attest_a_different_origin(self):
        _bridge, migration = self.due()
        result = control_bridge(migration.pk, action="attest", actor=self.staff, attestation={
            "note": "Old origin proof", "target_id": str(self.server.pk), "ipv4": self.server.ipv4_address, "ipv6": "",
        })
        self.assertTrue(result.is_err(), result)

    def test_proxy_statement_covers_a_larger_cache_bound_observed_after_commit(self):
        bridge, migration = self.due()
        larger_ttl = 7 * 86400
        bridge.evidence["routing"] = {self.account.domain: {"ttl": larger_ttl}}
        bridge.save(update_fields=["evidence", "updated_at"])
        checked = timezone.now()
        self.statement(bridge, migration)
        expires = datetime.fromisoformat(bridge.evidence["routing_attestation"]["expires_at"])
        self.assertGreater(expires, checked + timedelta(seconds=larger_ttl))

    def test_frontend_inventory_is_bounded_before_any_dns_query(self):
        _bridge, migration = self.due()
        with patch.object(routing, "routing_agreement", return_value=Agreement(True, 300)) as probe, self.assertRaisesRegex(ValueError, "limit"):
            routing.snapshot_frontends(migration, tuple(f"alias{number}.example.net" for number in range(100)))
        probe.assert_not_called()

    def test_unknown_original_ttl_cannot_be_replaced_by_the_bridge_window(self):
        _bridge, migration = self.due()
        unknown = Agreement(False, detail="DNS query failed: timed out")
        with patch.object(routing, "routing_agreement", return_value=unknown), self.assertRaisesRegex(ValueError, "TTL"):
            routing.snapshot_frontends(migration, (self.account.domain,))

    def test_a_partial_authoritative_ttl_cannot_hide_a_longer_unanswered_cache_bound(self):
        _bridge, migration = self.due()
        partial = routing_agreement(self.account.domain, self.server.ipv4_address, None, pause=0, query=lambda name: [
            RoutingAnswer(ns, family, (self.server.ipv4_address,) if family == "A" else (),
                          ttl=300 if ns == "ns1.example.net" else None,
                          error="DNS query failed: timed out" if ns == "ns2.example.net" else "", queried_name=name)
            for ns in ("ns1.example.net", "ns2.example.net") for family in ("A", "AAAA")
        ])
        self.assertEqual(partial.ttl, 300)
        with patch.object(routing, "routing_agreement", return_value=partial), self.assertRaisesRegex(ValueError, "TTL"):
            routing.snapshot_frontends(migration, (self.account.domain,))

    def test_complete_opaque_proxy_answers_preserve_the_longest_observed_ttl(self):
        _bridge, migration = self.due()
        longest = 7 * 86400
        proxy = routing_agreement(self.account.domain, self.server.ipv4_address, None, pause=0, query=lambda name: [
            RoutingAnswer(ns, family, ("104.16.0.1",) if family == "A" else (),
                          ttl=longest if ns == "ns2.example.net" else 300, queried_name=name)
            for ns in ("ns1.example.net", "ns2.example.net") for family in ("A", "AAAA")
        ])
        self.assertFalse(proxy.agreed)
        with patch.object(routing, "routing_agreement", return_value=proxy):
            snapshots = routing.snapshot_frontends(migration, (self.account.domain,))
        self.assertEqual(snapshots[self.account.domain]["ttl"], longest)

    def test_cleanup_without_original_ttl_evidence_cannot_start_an_invented_cache_wait(self):
        bridge, _migration = self.due()
        bridge.evidence["frontend_dns_before"] = {}
        with patch.object(routing, "routing_agreement", return_value=Agreement(True, 60)):
            progress, errors = routing.observe_frontends(bridge)
        self.assertTrue(errors)
        self.assertIn("TTL", errors[0])
        self.assertIsNone(progress[self.account.domain]["confirmed_at"])
