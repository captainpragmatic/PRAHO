"""A staff-configured node window must exist before customers can be told about it."""

from datetime import timedelta
from zoneinfo import ZoneInfo

from django.apps import apps
from django.test import TestCase
from django.utils import timezone

from apps.provisioning.virtualmin_models import VirtualminServer
from apps.users.models import User


class NodeMaintenanceCreationTests(TestCase):
    def test_staff_can_configure_a_policy_and_persist_a_scheduled_window(self) -> None:
        staff = User.objects.create_superuser(email="maintenance-admin@example.test", password=None)
        node = VirtualminServer.objects.create(
            name="Maintenance acceptance node",
            hostname="maintenance-node.example.test",
            api_username="api",
            encrypted_api_password=b"",
            status="active",
        )
        self.client.force_login(staff)

        policy_response = self.client.post(
            f"/infrastructure/maintenance/servers/{node.pk}/policy/",
            {
                "timezone": "Europe/Bucharest",
                "weekdays": [str(day) for day in range(7)],
                "starts_time": "00:00",
                "ends_time": "23:59",
                "max_defer_minutes": "30",
            },
        )
        self.assertEqual(policy_response.status_code, 302)

        starts_at = (timezone.localtime(timezone.now(), ZoneInfo("Europe/Bucharest")) + timedelta(days=3)).replace(
            hour=12, minute=0, second=0, microsecond=0
        )
        ends_at = starts_at + timedelta(minutes=30)
        window_response = self.client.post(
            f"/infrastructure/maintenance/servers/{node.pk}/create/",
            {
                "kind": "panel_update",
                "execution_mode": "manual",
                "starts_at": starts_at.isoformat(),
                "ends_at": ends_at.isoformat(),
                "expects_downtime": "on",
                "expected_downtime_minutes": "10",
                "customer_note": "Hosting software updates may briefly interrupt your website.",
            },
        )
        self.assertEqual(window_response.status_code, 302)
        window_model = apps.get_model("infrastructure", "NodeMaintenanceWindow")
        window = window_model.objects.get(node_id=node.pk)
        self.assertEqual(window.status, "scheduled")
        self.assertEqual(window.created_by_id, staff.pk)
        self.assertEqual(window.starts_at, starts_at)
        self.assertEqual(window.ends_at, ends_at)
        self.assertEqual(window.revision, 1)
