"""Staff approval publishes only after commit and never invents warning capability."""

from unittest.mock import patch
from uuid import uuid4

from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory, TestCase, override_settings

from apps.provisioning.hosting_node_policy_models import NodeHostingPolicy
from apps.provisioning.hosting_node_tasks import review_node_hosting
from apps.provisioning.hosting_node_views import node_hosting_policy
from apps.provisioning.virtualmin_models import VirtualminServer
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
