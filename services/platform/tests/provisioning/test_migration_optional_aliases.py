"""Independent optional services require explicit, current, unchanged routing evidence."""

from dataclasses import asdict, replace
from datetime import timedelta
from unittest.mock import patch

from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.infrastructure.dns_agreement import Agreement, RoutingAnswer, routing_agreement
from apps.provisioning import migration_routing as routing
from apps.provisioning.migration_bridge_cleanup import cleanup_bridge, control_bridge
from tests.provisioning import test_migration_routing as retention_tests
from tests.provisioning.test_virtualmin_migration_bridge import BridgeCase


class OptionalAliasRetentionTests(BridgeCase):
    due = retention_tests.FrontendRetentionTests.due
    boundaries = retention_tests.FrontendRetentionTests.boundaries

    def external_route(self, name, *, address="142.250.1.1", cname="mail.external.example"):
        def query(queried):
            alias = cname if queried == name and cname else ""
            return [
                RoutingAnswer(
                    "ns.external.example", "A", () if alias else (address,), ttl=60, cname=alias, queried_name=queried
                ),
                RoutingAnswer("ns.external.example", "AAAA", (), ttl=60, cname=alias, queried_name=queried),
            ]

        return routing_agreement(name, self.target.ipv4_address, None, query=query, pause=0)

    def optional(self, prefix="webmail", *, cname="mail.external.example"):
        bridge, migration = self.due()
        name = f"{prefix}.{self.account.domain}"
        route = self.external_route(name, cname=cname)
        before = timezone.now() - timedelta(minutes=5)
        bridge.evidence["dns_names"].append(name)
        bridge.evidence["frontend_dns_before"][name] = {
            "ttl": 60,
            "checked_at": before.isoformat(),
            "observation": asdict(route),
            "source_addresses": [self.server.ipv4_address],
        }
        bridge.evidence["routing"] = {
            name: {"ttl": 60, "checked_at": timezone.now().isoformat(), "observation": asdict(route)},
        }
        bridge.save(update_fields=["evidence", "updated_at"])
        return bridge, migration, name, route

    def declare(self, bridge, migration, name, **changes):
        fields = {
            "kind": "optional_alias",
            "names": name,
            "note": "Checked external mail administration: this hostname serves an independent service",
            "target_id": str(self.target.pk),
            "ipv4": self.target.ipv4_address,
            "ipv6": self.target.ipv6_address or "",
            **changes,
        }
        with (
            patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup"),
            patch.object(routing, "routing_agreement", side_effect=AssertionError("DNS ran on request path")),
        ):
            result = control_bridge(migration.pk, action="attest", actor=self.staff, attestation=fields)
        bridge.refresh_from_db()
        return result

    def test_external_optional_alias_retains_source_by_default(self):
        bridge, _migration, name, route = self.optional()
        with patch.object(
            routing,
            "routing_agreement",
            side_effect=lambda fqdn, *_a, **_k: route if fqdn == name else Agreement(True, 60),
        ):
            records, errors = routing.observe_frontends(bridge)
        self.assertFalse(records[name]["agreed"])
        self.assertTrue(errors)

    def test_explicit_independent_declaration_allows_cleanup_after_cache_wait_and_is_audited(self):
        bridge, migration, name, route = self.optional()
        self.assertTrue(self.declare(bridge, migration, name).is_ok())
        self.assertNotIn("routing_attestation", bridge.evidence)
        statement = bridge.evidence["independent_services"][name]
        self.assertEqual(statement["kind"], "independent_service")
        event = AuditEvent.objects.get(action="virtualmin_bridge_origin_attested", user=self.staff)
        self.assertEqual(event.new_values["kind"], "independent_service")
        for boundary in self.boundaries():
            self.enterContext(boundary)
        now = timezone.now()
        with (
            patch.object(
                routing,
                "routing_agreement",
                side_effect=lambda fqdn, *_a, **_k: route if fqdn == name else Agreement(True, 60),
            ),
            patch.object(routing.timezone, "now", return_value=now),
        ):
            self.assertEqual(cleanup_bridge(str(migration.pk))["action"], "retrying")
        bridge.refresh_from_db()
        self.assertTrue(bridge.evidence["routing"][name]["independent_service"])
        self.assertFalse(bridge.evidence["routing"][name]["attested"])
        with (
            patch.object(
                routing,
                "routing_agreement",
                side_effect=lambda fqdn, *_a, **_k: route if fqdn == name else Agreement(True, 60),
            ),
            patch.object(routing.timezone, "now", return_value=now + timedelta(seconds=3601)),
        ):
            self.assertEqual(cleanup_bridge(str(migration.pk))["action"], "torn_down")

    def test_only_explicit_inventory_webmail_and_admin_names_can_be_declared(self):
        bridge, migration, name, _route = self.optional()
        for unsupported in (
            self.account.domain,
            f"www.{self.account.domain}",
            "a1.accounts.example.net",
            "admin.other.example",
            "",
            f"{name},unknown.example",
        ):
            with self.subTest(name=unsupported):
                self.assertTrue(self.declare(bridge, migration, unsupported).is_err())
        self.assertTrue(self.declare(bridge, migration, name, kind="skip_dns").is_err())

    def test_source_address_or_incomplete_precommit_evidence_cannot_be_declared(self):
        bridge, migration, name, route = self.optional()
        valid = bridge.evidence["frontend_dns_before"][name].copy()
        invalid_routes = (
            self.external_route(name, address=self.server.ipv4_address),
            replace(route, answers=route.answers[:-1]),
            replace(route, answers=(replace(route.answers[0], error="timeout"), *route.answers[1:])),
            replace(route, answers=(replace(route.answers[0], queried_name="wrong.example"), *route.answers[1:])),
        )
        for invalid in invalid_routes:
            with self.subTest(observation=invalid):
                bridge.evidence["frontend_dns_before"][name] = {**valid, "observation": asdict(invalid)}
                bridge.save(update_fields=["evidence", "updated_at"])
                self.assertTrue(self.declare(bridge, migration, name).is_err())
        bridge.evidence["frontend_dns_before"][name] = {
            key: value for key, value in valid.items() if key != "source_addresses"
        }
        bridge.save(update_fields=["evidence", "updated_at"])
        self.assertTrue(self.declare(bridge, migration, name).is_err())

    def test_latest_cached_proof_must_be_complete_recent_and_non_source(self):
        bridge, migration, name, route = self.optional()
        now = timezone.now()
        cases = (
            {},
            {"checked_at": (now - timedelta(minutes=16)).isoformat(), "observation": asdict(route)},
            {"checked_at": (now + timedelta(minutes=1)).isoformat(), "observation": asdict(route)},
            {
                "checked_at": now.isoformat(),
                "observation": asdict(self.external_route(name, address=self.server.ipv4_address)),
            },
            {
                "checked_at": now.isoformat(),
                "observation": asdict(
                    replace(route, answers=(replace(route.answers[0], error="timeout"), *route.answers[1:]))
                ),
            },
        )
        for cached in cases:
            with self.subTest(cached=cached):
                bridge.evidence["routing"][name] = {"ttl": 60, **cached}
                bridge.save(update_fields=["evidence", "updated_at"])
                self.assertTrue(self.declare(bridge, migration, name).is_err())

    def test_cname_pool_can_rotate_before_declaration_but_chain_cannot_change(self):
        bridge, migration, name, _route = self.optional()
        rotated = self.external_route(name, address="142.250.1.2")
        bridge.evidence["routing"][name]["observation"] = asdict(rotated)
        bridge.save(update_fields=["evidence", "updated_at"])
        self.assertTrue(self.declare(bridge, migration, name).is_ok())
        with patch.object(
            routing,
            "routing_agreement",
            side_effect=lambda fqdn, *_a, **_k: rotated if fqdn == name else Agreement(True, 60),
        ):
            records, _errors = routing.observe_frontends(bridge)
        self.assertTrue(records[name]["independent_service"])
        changed = self.external_route(name, cname="different.external.example")
        bridge.evidence["routing"][name]["observation"] = asdict(changed)
        bridge.save(update_fields=["evidence", "updated_at"])
        self.assertTrue(self.declare(bridge, migration, name).is_err())

    def test_direct_address_change_before_declaration_is_refused(self):
        bridge, migration, name, _route = self.optional(cname="")
        bridge.evidence["routing"][name]["observation"] = asdict(
            self.external_route(name, address="142.250.1.2", cname="")
        )
        bridge.save(update_fields=["evidence", "updated_at"])
        self.assertTrue(self.declare(bridge, migration, name).is_err())

    def test_fresh_worker_must_match_declared_route_and_never_override_source_or_errors(self):
        bridge, migration, name, route = self.optional()
        self.assertTrue(self.declare(bridge, migration, name).is_ok())
        for changed in (
            self.external_route(name, address=self.server.ipv4_address),
            self.external_route(name, address="142.250.1.2"),
            self.external_route(name, cname="different.external.example"),
            replace(route, answers=route.answers[:-1]),
            replace(route, answers=(replace(route.answers[0], error="timeout"), *route.answers[1:])),
            Agreement(False, 60, "DNS query failed"),
        ):
            with (
                self.subTest(route=changed),
                patch.object(
                    routing,
                    "routing_agreement",
                    side_effect=lambda fqdn, *_a, value=changed, **_k: value if fqdn == name else Agreement(True, 60),
                ),
            ):
                records, errors = routing.observe_frontends(bridge)
                self.assertFalse(records[name]["agreed"])
                self.assertTrue(errors)

    def test_independent_statement_is_bound_to_inventory_target_and_expiry(self):
        bridge, migration, name, route = self.optional("admin")
        self.assertTrue(self.declare(bridge, migration, name).is_ok())
        for change in ("target", "inventory", "expiry"):
            with self.subTest(change=change):
                bridge.refresh_from_db()
                if change == "target":
                    bridge.target_server.ipv4_address = "95.217.0.21"
                elif change == "inventory":
                    bridge.evidence["dns_names"].append(f"other.{self.account.domain}")
                else:
                    bridge.evidence["independent_services"][name]["expires_at"] = (
                        timezone.now() - timedelta(seconds=1)
                    ).isoformat()
                with patch.object(
                    routing,
                    "routing_agreement",
                    side_effect=lambda fqdn, *_a, **_k: route if fqdn == name else Agreement(True, 60),
                ):
                    records, errors = routing.observe_frontends(bridge)
                self.assertFalse(records[name]["agreed"])
                self.assertTrue(errors)

    def test_target_origin_statement_excludes_declared_independent_services(self):
        bridge, migration, name, _route = self.optional()
        self.assertTrue(self.declare(bridge, migration, name).is_ok())
        self.assertTrue(self.declare(bridge, migration, name, kind="target_origin").is_ok())
        self.assertEqual(bridge.evidence["routing_attestation"]["covered_names"], [self.account.domain])
        self.assertEqual(bridge.evidence["routing_attestation"]["names"], sorted([self.account.domain, name]))

    def test_an_older_target_origin_statement_cannot_bypass_an_independent_routes_later_change(self):
        bridge, migration, name, _route = self.optional()
        self.assertTrue(self.declare(bridge, migration, name, kind="target_origin").is_ok())
        self.assertTrue(self.declare(bridge, migration, name).is_ok())
        changed = self.external_route(name, address="142.250.1.2")
        with patch.object(
            routing,
            "routing_agreement",
            side_effect=lambda fqdn, *_a, **_k: changed if fqdn == name else Agreement(True, 60),
        ):
            records, errors = routing.observe_frontends(bridge)
        self.assertFalse(records[name]["agreed"])
        self.assertTrue(errors)

    def test_target_origin_statement_cannot_override_an_original_source_ip_after_the_source_row_changes(self):
        bridge, migration, name, _route = self.optional(cname="")
        original_source = self.server.ipv4_address
        self.server.ipv4_address = "95.217.0.11"
        self.server.save(update_fields=["ipv4_address"])
        self.assertTrue(self.declare(bridge, migration, name, kind="target_origin").is_ok())
        stale_source = self.external_route(name, address=original_source, cname="")
        with patch.object(
            routing,
            "routing_agreement",
            side_effect=lambda fqdn, *_a, **_k: stale_source if fqdn == name else Agreement(True, 60),
        ):
            records, errors = routing.observe_frontends(bridge)
        self.assertFalse(records[name]["agreed"])
        self.assertTrue(errors)

    def test_independent_declaration_excludes_source_history_retained_by_another_frontend(self):
        bridge, migration, name, _route = self.optional(cname="")
        earlier_source = "95.217.0.9"
        bridge.evidence["frontend_dns_before"][self.account.domain]["source_addresses"] = [earlier_source]
        route = asdict(self.external_route(name, address=earlier_source, cname=""))
        bridge.evidence["frontend_dns_before"][name]["observation"] = route
        bridge.evidence["routing"][name]["observation"] = route
        bridge.save(update_fields=["evidence", "updated_at"])
        self.assertTrue(self.declare(bridge, migration, name).is_err())

    def test_refreshing_a_rotated_cname_pool_restarts_the_conservative_cache_wait(self):
        bridge, migration, name, _route = self.optional()
        self.assertTrue(self.declare(bridge, migration, name).is_ok())
        bridge.evidence["routing"][name]["confirmed_at"] = (timezone.now() - timedelta(days=2)).isoformat()
        bridge.evidence["routing"][name]["observation"] = asdict(self.external_route(name, address="142.250.1.2"))
        bridge.save(update_fields=["evidence", "updated_at"])
        self.assertTrue(self.declare(bridge, migration, name).is_ok())
        self.assertIsNone(bridge.evidence["routing"][name]["confirmed_at"])

    def test_known_precommit_source_addresses_are_preserved_on_snapshot_retry(self):
        _bridge, migration, name, _route = self.optional()
        migration.barrier_state["frontend_dns_before"] = {
            name: {"ttl": 60, "source_addresses": ["95.217.0.9"]},
        }
        with patch.object(routing, "routing_agreement", return_value=Agreement(True, 60)):
            snapshots = routing.snapshot_frontends(migration, (name,))
        self.assertEqual(snapshots[name]["source_addresses"], ["95.217.0.10", "95.217.0.9"])

    def test_staff_post_preserves_independent_kind_and_name_without_request_dns(self):
        bridge, migration, name, _route = self.optional()
        self.client.force_login(self.staff)
        with (
            patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup"),
            patch.object(routing, "routing_agreement", side_effect=AssertionError("DNS ran on request path")),
        ):
            response = self.client.post(
                reverse("provisioning:virtualmin_bridge_control", args=[self.account.pk]),
                {
                    "migration_id": str(migration.pk),
                    "action": "attest",
                    "kind": "optional_alias",
                    "names": name,
                    "target_id": str(self.target.pk),
                    "ipv4": self.target.ipv4_address,
                    "ipv6": "",
                    "note": "Verified independent mail service in its provider administration",
                },
            )
        self.assertEqual(response.status_code, 302)
        bridge.refresh_from_db()
        self.assertIn(name, bridge.evidence.get("independent_services", {}))

    def test_staff_page_distinguishes_independent_service_from_target_confirmation(self):
        bridge, migration, name, _route = self.optional()
        bridge.evidence["routing"] = {name: {"agreed": True, "independent_service": True}}
        page = render_to_string(
            "provisioning/virtualmin/migration_status.html",
            {
                "account": self.account,
                "migration": migration,
                "migration_bridge": bridge,
                "independent_alias_options": [{"value": name, "label": name}],
            },
        )
        self.assertIn("Independent service verified", page)
        self.assertIn('value="optional_alias"', page)
        self.assertNotIn("Target routing confirmed", page)
