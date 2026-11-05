"""Staff approval publishes only after commit and never invents warning capability."""

from unittest.mock import patch
from uuid import uuid4

from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import PermissionDenied
from django.db import InterfaceError, connection
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from apps.provisioning.hosting_node_policy import notification_handover_refusal
from apps.provisioning.hosting_node_policy_models import NodeHostingExecution, NodeHostingPolicy
from apps.provisioning.hosting_node_tasks import review_node_hosting
from apps.provisioning.hosting_node_views import node_hosting_policy
from apps.provisioning.hosting_warning_delivery import setup_warning_pipeline
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.settings.models import SystemSetting
from apps.users.models import User


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class HostingNodeStaffApprovalTests(TestCase):
    def setUp(self):
        self.server = VirtualminServer.objects.create(hostname="policy-view.example.test")
        self.actor = User.objects.create_superuser(email="policy-staff@example.test", password=None)

    def request(self, user, data):
        request = RequestFactory().post("/hosting-policy/", data)
        request.user = user
        SessionMiddleware(lambda request: None).process_request(request)
        request.session.save()
        request._messages = FallbackStorage(request)
        return request

    def test_basic_staff_cannot_inspect_or_queue_native_changes(self):
        staff = User.objects.create_user(email="policy-support@example.test", is_staff=True, password=None)
        with self.assertRaises(PermissionDenied):
            node_hosting_policy(self.request(staff, {"action": "inspect"}), self.server.pk)

    def test_inspection_queue_waits_for_commit_and_exposes_bound_task_result_key(self):
        request = self.request(self.actor, {"action": "inspect"})
        task_id = uuid4().hex
        with (
            patch("apps.provisioning.hosting_node_views.async_task", return_value=task_id) as queue,
            self.captureOnCommitCallbacks(execute=False) as callbacks,
        ):
            response = node_hosting_policy(request, self.server.pk)
            self.assertEqual(response.status_code, 302)
            queue.assert_not_called()
        self.assertEqual(len(callbacks), 1)
        with patch("apps.provisioning.hosting_node_views.async_task", return_value=task_id) as queue:
            callbacks[0]()
            queue.assert_called_once_with(
                "apps.provisioning.hosting_node_tasks.review_node_hosting",
                str(self.server.pk),
                str(self.actor.pk),
                "inspect",
                None,
            )
        self.assertEqual(request.session["node_hosting_task_" + self.server.pk.hex], task_id)
        self.assertFalse(NodeHostingPolicy.objects.exists())

    def test_missing_warning_pipeline_refuses_handover_before_queueing(self):
        request = self.request(
            self.actor, {"action": "handover_mail", "reason": "Customer notices", "acknowledged": "on"}
        )
        with (
            patch.dict("sys.modules", {"apps.provisioning.hosting_warning_delivery": None}),
            patch("apps.provisioning.hosting_node_views.async_task") as queue,
        ):
            response = node_hosting_policy(request, self.server.pk)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Platform warning pipeline", response.content)
        queue.assert_not_called()

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend")
    def test_unusable_warning_schema_connection_refuses_public_handover_without_native_io(self):
        self.server.status = "active"
        self.server.save(update_fields=["status"])
        policy = NodeHostingPolicy.objects.create(server=self.server, notification_owner="native")
        for key in ("provisioning.quota_warnings_enabled", "provisioning.usage_sync_enabled"):
            SystemSetting.objects.create(
                key=key, value=True, default_value=False, data_type="boolean", category="provisioning"
            )
        setup_warning_pipeline()
        self.assertIsNone(notification_handover_refusal(self.server), "The actual pipeline must qualify before outage")
        self.assertEqual(policy.notification_owner, "native")
        self.client.force_login(self.actor)
        url = reverse("provisioning:node_hosting_policy", args=[self.server.pk])
        self.assertEqual(self.client.get(url).status_code, 200)

        with (
            patch.object(
                connection.introspection, "table_names", side_effect=InterfaceError("Connection unusable")
            ) as schema_read,
            patch("apps.provisioning.hosting_node_views.async_task") as queue,
            patch("apps.provisioning.hosting_node_tasks.run_node_operation") as native,
            self.captureOnCommitCallbacks(execute=True),
        ):
            response = self.client.post(
                url, {"action": "handover_mail", "reason": "Reviewed customer mail handover", "acknowledged": "on"}
            )
        self.assertEqual(response.status_code, 200, response.content)
        schema_read.assert_called()
        self.assertContains(response, "Apply the warning and preference migrations before notification handover.")
        self.assertTrue(response.context["form"].errors["action"])
        queue.assert_not_called()
        native.assert_not_called()
        self.assertFalse(NodeHostingExecution.objects.exists())
        policy.refresh_from_db()
        self.assertEqual(policy.notification_owner, "native")
        self.assertIsNone(policy.operation)
        self.assertIsNone(policy.notifications_verified_at)

    def test_queued_helper_approval_rechecks_current_bundle_before_any_native_io(self):
        with patch("apps.provisioning.hosting_node_tasks.run_helper_operation") as native:
            result = review_node_hosting(
                str(self.server.pk),
                str(self.actor.pk),
                "prepare_helpers",
                {"reason": "Reviewed release", "helper_bundle_digest": "outdated"},
            )
        self.assertEqual(result["outcome"], "attention")
        native.assert_not_called()
        self.assertFalse(NodeHostingPolicy.objects.exists())
