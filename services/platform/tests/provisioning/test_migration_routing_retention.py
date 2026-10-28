"""The bridge outlives every observed frontend cache and retains late DNS changes."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from django.test import SimpleTestCase
from django.utils import timezone

from apps.infrastructure.dns_agreement import Agreement
from apps.provisioning.migration_routing import observe_frontends, snapshot_frontends


class RoutingRetentionTests(SimpleTestCase):
    def setUp(self):
        window = patch("apps.provisioning.migration_routing.bridge_window_hours", return_value=48)
        window.start()
        self.addCleanup(window.stop)

    def test_source_frontend_ttls_are_preserved_across_later_lower_answers(self):
        migration = SimpleNamespace(
            account_id=uuid4(),
            account=SimpleNamespace(domain="customer.example"),
            source_server=SimpleNamespace(ipv4_address="95.217.0.10", ipv6_address=None),
            barrier_state={"frontend_dns_before": {"customer.example": {"ttl": 86400}}},
        )
        with (
            patch(
                "apps.provisioning.account_hostname_models.AccountHostname.objects.get",
                return_value=SimpleNamespace(fqdn="a1.accounts.example"),
            ),
            patch("apps.provisioning.migration_routing.routing_agreement", return_value=Agreement(True, ttl=60)),
        ):
            recorded = snapshot_frontends(migration, ("customer.example",))
        self.assertEqual(recorded["customer.example"]["ttl"], 86400)

    def test_late_customer_update_waits_its_original_ttl_after_first_target_confirmation(self):
        now = timezone.now()
        bridge = SimpleNamespace(
            target_server=SimpleNamespace(ipv4_address="95.217.0.20", ipv6_address=None),
            evidence={"dns_names": ["customer.example"], "frontend_dns_before": {"customer.example": {"ttl": 3600}}},
        )
        with patch("apps.provisioning.migration_routing.routing_agreement", return_value=Agreement(True, ttl=60)):
            records, errors = observe_frontends(bridge, now=now)
        self.assertTrue(errors)
        self.assertEqual(records["customer.example"]["confirmed_at"], now.isoformat())
        bridge.evidence["routing"] = records
        with patch("apps.provisioning.migration_routing.routing_agreement", return_value=Agreement(True, ttl=60)):
            _records, errors = observe_frontends(bridge, now=now + timedelta(seconds=3601))
        self.assertEqual(errors, [])

    def test_stale_customer_routing_resets_confirmation_even_though_the_owned_name_can_agree(self):
        now = timezone.now()
        bridge = SimpleNamespace(
            target_server=SimpleNamespace(ipv4_address="95.217.0.20", ipv6_address=None),
            evidence={
                "dns_names": ["customer.example"],
                "routing": {"customer.example": {"confirmed_at": (now - timedelta(days=3)).isoformat()}},
            },
        )
        with patch(
            "apps.provisioning.migration_routing.routing_agreement",
            return_value=Agreement(False, ttl=86400, detail="Still at source"),
        ):
            records, errors = observe_frontends(bridge, now=now)
        self.assertIsNone(records["customer.example"]["confirmed_at"])
        self.assertTrue(errors)
