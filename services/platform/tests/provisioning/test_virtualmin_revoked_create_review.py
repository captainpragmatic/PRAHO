"""Real staff HTTP resolution keeps uncertain OFF holds until exact verification."""

from __future__ import annotations

from django.http import HttpResponse
from django.test import Client
from django.urls import reverse

from apps.provisioning.virtualmin_migration_models import account_has_active_operation
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.users.models import User
from tests.provisioning import test_virtualmin_revoked_create as fixtures


class RevokedCreateReviewTests(fixtures.ReceiptOffFixture):
    def _post_review(
        self, client: Client, token: str, job: VirtualminProvisioningJob, fingerprint: str
    ) -> HttpResponse:
        return client.post(
            reverse("provisioning:virtualmin_job_resolve", args=[job.pk]),
            {
                "note": "Checked the exact recorded domain and owner; all commands have stopped",
                "commands_stopped": "on",
                "resource_confirmed": "on",
                "off_review_fingerprint": fingerprint,
            },
            HTTP_X_CSRFTOKEN=token,
        )

    def _assert_hold_retained(self, off: VirtualminProvisioningJob) -> None:
        off.refresh_from_db()
        self.job.refresh_from_db()
        self.assertEqual(off.status, "attention")
        self.assertIsNone(off.next_retry_at)
        self.assertEqual(self.job.status, "attention")
        self.assertTrue(account_has_active_operation(self.account))
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)
        self.assertNotIn("verified_off_review", off.result)

    def test_enabled_domain_cannot_be_attested_as_verified_off(self) -> None:
        off = self._unknown_off()
        client, token, page = self._operator_client(off)
        self.gateway.domain_state_of(self.account.domain).enabled = True
        observed_before = len(self.gateway.get_calls("list-domains"))
        response = self._post_review(client, token, off, page.context["off_review_fingerprint"])
        self.assertEqual(response.status_code, 302)
        self.assertGreater(len(self.gateway.get_calls("list-domains")), observed_before)
        self._assert_hold_retained(off)
        self.assertTrue(self.gateway.domain_state_of(self.account.domain).enabled)

    def test_foreign_owner_cannot_release_the_recorded_resource(self) -> None:
        off = self._unknown_off()
        client, token, page = self._operator_client(off)
        self.gateway.domain_state_of(self.account.domain).username = "another-owner"
        response = self._post_review(client, token, off, page.context["off_review_fingerprint"])
        self.assertEqual(response.status_code, 302)
        self._assert_hold_retained(off)

    def test_unavailable_native_observation_keeps_both_receipts_unresolved(self) -> None:
        off = self._unknown_off()
        client, token, page = self._operator_client(off)
        self.gateway.fail_operations["list-domains"] = "Native state is temporarily unavailable"
        response = self._post_review(client, token, off, page.context["off_review_fingerprint"])
        self.assertEqual(response.status_code, 302)
        self._assert_hold_retained(off)

    def test_stale_review_fingerprint_cannot_release_changed_receipt(self) -> None:
        off = self._unknown_off()
        client, token, page = self._operator_client(off)
        # Defensive stale-snapshot case, not a claim of a public concurrent writer.
        self.job.mark_attention("A newer recorded review superseded the displayed snapshot")
        observations = len(self.gateway.get_calls("list-domains"))
        response = self._post_review(client, token, off, page.context["off_review_fingerprint"])
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(self.gateway.get_calls("list-domains")), observations)
        self._assert_hold_retained(off)

    def test_changed_account_binding_cannot_reuse_old_review_authority(self) -> None:
        off = self._unknown_off()
        client, token, page = self._operator_client(off)
        # Simulate defensive binding corruption after the operator's preview.
        self.account.virtualmin_username = "rebound-account-owner"
        self.account.save(update_fields=["virtualmin_username", "updated_at"])
        observations = len(self.gateway.get_calls("list-domains"))
        response = self._post_review(client, token, off, page.context["off_review_fingerprint"])
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(self.gateway.get_calls("list-domains")), observations)
        self._assert_hold_retained(off)

    def test_nonstaff_member_cannot_submit_another_operators_review(self) -> None:
        off = self._unknown_off()
        client, token, page = self._operator_client(off)
        member = User.objects.create_user(email="review-member@example.com", password="fixture-password")
        client.force_login(member)
        observations = len(self.gateway.get_calls("list-domains"))
        response = self._post_review(client, token, off, page.context["off_review_fingerprint"])
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)
        self.assertEqual(len(self.gateway.get_calls("list-domains")), observations)
        self._assert_hold_retained(off)

    def test_inactive_operator_cannot_submit_a_previously_loaded_review(self) -> None:
        off = self._unknown_off()
        client, token, page = self._operator_client(off)
        self.operator.is_active = False
        self.operator.save(update_fields=["is_active"])
        observations = len(self.gateway.get_calls("list-domains"))
        response = self._post_review(client, token, off, page.context["off_review_fingerprint"])
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)
        self.assertEqual(len(self.gateway.get_calls("list-domains")), observations)
        self._assert_hold_retained(off)

    def test_actor_revoked_during_real_native_read_cannot_release_the_hold(self) -> None:
        off = self._unknown_off()
        client, token, page = self._operator_client(off)

        def revoke_operator() -> None:
            self.operator.is_active = False
            self.operator.save(update_fields=["is_active"])

        self.gateway.after_state_read = revoke_operator
        response = self._post_review(client, token, off, page.context["off_review_fingerprint"])
        self.assertEqual(response.status_code, 302)
        self.operator.refresh_from_db()
        self.assertFalse(self.operator.is_active)
        self._assert_hold_retained(off)

    def test_pending_and_running_off_cannot_be_released_by_child_or_parent_note(self) -> None:
        off = self._queue_off()
        client, token, _ = self._operator_client(off)

        def assert_notes_refused(expected: str) -> None:
            for job in (off, self.job):
                response = self._post_review(client, token, job, "")
                self.assertEqual(response.status_code, 302)
                off.refresh_from_db()
                self.job.refresh_from_db()
                self.assertEqual(off.status, expected)
                self.assertEqual(self.job.status, "attention")
                self.assertTrue(account_has_active_operation(self.account))

        assert_notes_refused("pending")

        def crash_after_native_acceptance() -> None:
            raise fixtures._WorkerCrash

        self.gateway.after_accepted_disable = crash_after_native_acceptance
        with self.assertRaises(fixtures._WorkerCrash):
            self._deliver_receipt_off()
        assert_notes_refused("running")
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)
