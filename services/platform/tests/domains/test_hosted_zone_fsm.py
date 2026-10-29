"""Only current, complete evidence can expose nameservers or mark a zone active."""

from django.test import TestCase, override_settings
from django.utils import timezone
from django_fsm import TransitionNotAllowed

from apps.customers.models import Customer
from apps.domains.dns_zone_models import HostedZone


@override_settings(DISABLE_AUDIT_SIGNALS=True, AUDIT_CHAIN_ENABLED=False)
class HostedZoneFsmTests(TestCase):
    def setUp(self):
        self.zone = HostedZone.objects.create(
            customer=Customer.objects.create(name="FSM owner"), name="fsm.example.net"
        )

    def ready(self):
        self.zone.current_revision = self.zone.confirmed_revision = self.zone.applied_revision = 1
        self.zone.readiness = {
            "revision": 1,
            "complete": True,
            "ds_safe": True,
            "checked_at": timezone.now().isoformat(),
        }

    def test_pending_import_cannot_offer_nameservers_without_exact_current_proof(self):
        with self.assertRaises(TransitionNotAllowed):
            self.zone.await_nameservers()
        self.ready()
        self.zone.current_revision = 2
        with self.assertRaises(TransitionNotAllowed):
            self.zone.await_nameservers()
        self.zone.current_revision = 1
        self.zone.await_nameservers()
        self.zone.save()
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.status, "awaiting_ns")

    def test_provider_active_alone_is_not_public_delegation_or_activation_proof(self):
        self.ready()
        self.zone.await_nameservers()
        self.zone.provider_status = "active"
        with self.assertRaises(TransitionNotAllowed):
            self.zone.activate()
        self.zone.activation = {"revision": 1, "parent_ns_verified": True, "inventory_verified": True}
        self.zone.activate()
        self.assertEqual(self.zone.status, "active")

    def test_delete_is_not_a_hosting_termination_cascade_and_requires_explicit_proof(self):
        with self.assertRaises(TransitionNotAllowed):
            self.zone.start_deleting()
        self.zone.deletion = {"revision": 0, "export_verified": True, "parent_moved_away": True, "ds_safe": True}
        self.zone.start_deleting()
        with self.assertRaises(TransitionNotAllowed):
            self.zone.mark_deleted()
        self.zone.deletion["provider_absent"] = True
        self.zone.mark_deleted()
        self.assertEqual(self.zone.status, "deleted")
