"""Each server a deployment creates keeps its own billable window, written only by the operation's owner."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

from django.test import TestCase
from django.utils import timezone

from apps.infrastructure import server_lifetimes as lifetimes
from apps.infrastructure.deployment_lifecycle import OperationOwnershipLostError, claim_operation
from apps.infrastructure.models import CloudProvider, NodeDeployment, NodeServerLifetime, PanelType
from tests.helpers.node_catalogue import make_region, make_size


def make_deployment(status: str = "pending", **fields: object) -> NodeDeployment:
    provider = CloudProvider.objects.create(name="Hetzner", provider_type="hetzner", code="het")
    region = make_region(provider, "hel1")
    size = make_size(provider, "cx23", region)
    panel = PanelType.objects.create(name="Virtualmin", panel_type="virtualmin", ansible_playbook="v.yml")
    return NodeDeployment.objects.create(
        environment="stg", node_type="sha", provider=provider, region=region, node_size=size, panel_type=panel,
        hostname="stg-sha-het-fi-hel1-001", dns_zone="nodes.example.com", node_number=1, status=status, **fields,
    )


class ServerLifetimeTests(TestCase):
    def setUp(self) -> None:
        self.deployment = make_deployment()
        self.lease = claim_operation(
            self.deployment.pk, from_states=("pending",), to_status="provisioning_node", kind="deploy"
        ).unwrap()
        self.deployment.refresh_from_db()

    def open_lifetimes(self) -> list[NodeServerLifetime]:
        return list(NodeServerLifetime.objects.filter(deployment=self.deployment, ended_at__isnull=True))

    def test_intent_opens_one_unconfirmed_lifetime_at_the_size_rate(self) -> None:
        lifetime, created = lifetimes.open_pending_lifetime(self.lease, self.deployment, server_create_state="intent")
        self.assertTrue(created)
        assert lifetime is not None
        self.assertEqual((lifetime.server_id, lifetime.monthly_cost_eur), ("", Decimal("4.99")))
        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.server_create_state, "intent")

    def test_a_lost_create_is_reused_by_the_next_intent_and_confirmed_by_its_server(self) -> None:
        first, _ = lifetimes.open_pending_lifetime(self.lease, self.deployment)
        again, created = lifetimes.open_pending_lifetime(self.lease, self.deployment)
        self.assertFalse(created)
        assert first is not None and again is not None
        self.assertEqual(again.pk, first.pk)
        lifetimes.confirm_lifetime(self.lease, self.deployment, again, "4242", external_node_id="4242")
        self.assertEqual([(lt.pk, lt.server_id) for lt in self.open_lifetimes()], [(first.pk, "4242")])

    def test_an_open_confirmed_lifetime_is_never_inherited_by_a_new_create(self) -> None:
        old, _ = lifetimes.open_pending_lifetime(self.lease, self.deployment)
        lifetimes.confirm_lifetime(self.lease, self.deployment, old, "4242")
        new, created = lifetimes.open_pending_lifetime(self.lease, self.deployment)
        self.assertTrue(created)
        assert old is not None and new is not None
        self.assertNotEqual(new.pk, old.pk)
        self.assertEqual(sorted(lt.server_id for lt in self.open_lifetimes()), ["", "4242"])

    def test_a_refused_create_discards_only_the_lifetime_it_opened(self) -> None:
        lifetime, created = lifetimes.open_pending_lifetime(self.lease, self.deployment)
        self.assertTrue(created)
        lifetimes.discard_lifetime(self.lease, self.deployment, lifetime, server_create_state="none")
        self.assertEqual(self.open_lifetimes(), [])

    def test_teardown_closes_open_lifetimes(self) -> None:
        lifetime, _ = lifetimes.open_pending_lifetime(self.lease, self.deployment)
        lifetimes.confirm_lifetime(self.lease, self.deployment, lifetime, "4242")
        closed = lifetimes.close_server_lifetimes(self.lease, self.deployment, external_node_id="")
        self.assertEqual(closed, 1)
        self.assertEqual(self.open_lifetimes(), [])

    def test_a_writer_that_lost_its_lease_writes_no_lifetime(self) -> None:
        lifetime, _ = lifetimes.open_pending_lifetime(self.lease, self.deployment)
        claim_operation(self.deployment.pk, from_states=("provisioning_node",), to_status="failed", kind="sweep")
        with self.assertRaises(OperationOwnershipLostError):
            lifetimes.close_server_lifetimes(self.lease, self.deployment)
        with self.assertRaises(OperationOwnershipLostError):
            lifetimes.open_pending_lifetime(self.lease, self.deployment)
        assert lifetime is not None
        self.assertEqual([lt.pk for lt in self.open_lifetimes()], [lifetime.pk])

    def test_the_first_lifetime_keeps_a_window_recorded_only_in_the_row(self) -> None:
        started = timezone.now() - timedelta(hours=3)
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(started_at=started)
        self.deployment.refresh_from_db()
        lifetimes.open_pending_lifetime(self.lease, self.deployment)
        legacy = NodeServerLifetime.objects.filter(deployment=self.deployment, legacy=True).first()
        assert legacy is not None, "the row's window was not kept"
        self.assertEqual(legacy.started_at, started)
        self.assertIsNotNone(legacy.ended_at)
        self.assertEqual(len(self.open_lifetimes()), 1)

    def test_a_resize_closes_the_old_rate_and_opens_a_successor(self) -> None:
        lifetime, _ = lifetimes.open_pending_lifetime(self.lease, self.deployment)
        lifetimes.confirm_lifetime(self.lease, self.deployment, lifetime, "4242")
        bigger = make_size(self.deployment.provider, "cpx32", self.deployment.region)
        bigger.monthly_cost_eur = Decimal("13.99")
        bigger.save(update_fields=["monthly_cost_eur"])
        assert lifetime is not None
        self.assertTrue(lifetimes.split_lifetime_for_resize(lifetime.pk, "4242", bigger))
        rows = list(NodeServerLifetime.objects.filter(deployment=self.deployment).order_by("started_at"))
        self.assertEqual([(lt.monthly_cost_eur, lt.ended_at is None) for lt in rows],
                         [(Decimal("4.99"), False), (Decimal("13.99"), True)])
        self.assertEqual(rows[1].server_id, "4242")
        # A lifetime closed meanwhile (teardown, re-deploy) is not reopened.
        lifetimes.close_server_lifetimes(self.lease, self.deployment)
        self.assertFalse(lifetimes.split_lifetime_for_resize(rows[1].pk, "4242", bigger))
        self.assertEqual(self.open_lifetimes(), [])

    def test_a_never_created_attestation_deletes_only_unconfirmed_lifetimes(self) -> None:
        confirmed, _ = lifetimes.open_pending_lifetime(self.lease, self.deployment)
        lifetimes.confirm_lifetime(self.lease, self.deployment, confirmed, "4242")
        lifetimes.open_pending_lifetime(self.lease, self.deployment)
        self.assertEqual(lifetimes.delete_unconfirmed_lifetimes(self.deployment), 1)
        self.assertEqual([lt.server_id for lt in self.open_lifetimes()], ["4242"])
