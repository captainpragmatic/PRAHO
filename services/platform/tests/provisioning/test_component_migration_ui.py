"""Operator component consent is exact, privileged and revalidated before queueing."""

from copy import deepcopy
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from django.core.exceptions import PermissionDenied
from django.test import Client
from django.utils import timezone
from django_q.models import Task

from apps.provisioning.component_migration_manifest import ComponentManifest
from apps.provisioning.component_migration_models import (
    ComponentMigrationApproval,
    ComponentMigrationReview,
    SourceServiceRelease,
)
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from tests.provisioning.test_component_migration_admission import ComponentAdmissionTestBase


class ComponentMigrationUITests(ComponentAdmissionTestBase):
    def setUp(self):
        super().setUp()
        self.client.force_login(self.staff)
        self.url = f"/provisioning/virtualmin/accounts/{self.account.pk}/migrate-components/"

    def test_get_is_read_only_and_explains_selection_and_retained_services(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Inspect selected website")
        self.assertContains(response, "Mail, DNS and Unix authentication remain on the source")
        self.assertFalse(ComponentMigrationReview.objects.exists())
        self.ansible.return_value.run_playbook.assert_not_called()

    def test_deployment_permission_is_required_before_reading_or_queueing(self):
        self.staff.is_superuser = False
        self.staff.save(update_fields=["is_superuser"])
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertEqual(self.client.post(self.url, {"action": "inspect"}).status_code, 403)

    def test_csrf_is_required_for_inspection_and_acceptance(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.staff)
        self.assertEqual(client.post(self.url, {"action": "inspect"}).status_code, 403)

    def test_selection_inspection_queues_only_explicit_paths_and_databases(self):
        with patch("apps.provisioning.component_migration_views.async_task", return_value="task-id") as queue:
            response = self.client.post(
                self.url,
                {
                    "action": "inspect",
                    "target_server": self.target.pk,
                    "application_paths": "public_html",
                    "configuration_paths": "config",
                    "upload_paths": "uploads",
                    "databases": "customer_web",
                },
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(queue.call_args.args[1:4], (str(self.account.pk), str(self.target.pk), str(self.staff.pk)))
        self.assertEqual(
            queue.call_args.args[4],
            {
                "paths": [
                    {"relative": "public_html", "purpose": "application"},
                    {"relative": "config", "purpose": "configuration"},
                    {"relative": "uploads", "purpose": "uploads"},
                ],
                "databases": ["customer_web"],
            },
        )
        self.assertFalse(ComponentMigrationReview.objects.exists())

    def test_queued_task_redirect_preserves_one_encoded_task_identifier(self):
        identifier = "task/id?part=one&mode=two"
        with patch("apps.provisioning.component_migration_views.async_task", return_value=identifier):
            response = self.client.post(
                self.url, {"action": "inspect", "target_server": self.target.pk, "application_paths": "public_html"}
            )
        self.assertEqual(response.status_code, 302)
        location = urlsplit(response["Location"])
        self.assertEqual(location.path, self.url)
        self.assertEqual(parse_qs(location.query), {"task": [identifier]})

    def test_invalid_action_is_a_plain_text_error_without_reflected_input(self):
        response = self.client.post(self.url, {"action": "<strong>invalid</strong>"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response["Content-Type"], "text/plain; charset=utf-8")
        self.assertEqual(response.content.decode(), "Invalid component migration action.")

    def test_unsafe_overlapping_or_retained_paths_never_queue_inspection(self):
        for paths, config in (
            ("../mail", ""),
            ("Maildir", ""),
            ("public_html", "public_html/config"),
            (".ssh", ""),
            ("/home/customer/public_html", ""),
        ):
            with (
                self.subTest(paths=paths, config=config),
                patch("apps.provisioning.component_migration_views.async_task") as queue,
            ):
                response = self.client.post(
                    self.url,
                    {
                        "action": "inspect",
                        "target_server": self.target.pk,
                        "application_paths": paths,
                        "configuration_paths": config,
                    },
                )
                self.assertEqual(response.status_code, 400)
                queue.assert_not_called()

    def test_preparation_is_visible_and_cannot_be_accepted_away(self):
        facts = deepcopy(self.facts)
        facts["preparation"] = ["Separate retained mail certificate renewal before migration."]
        from apps.provisioning.component_migration_service import record_component_review  # noqa: PLC0415

        review = record_component_review(self.account, self.target, facts, self.staff)
        response = self.client.get(self.url, {"review": review.pk})
        self.assertContains(response, facts["preparation"][0])
        self.assertNotContains(response, 'value="accept"')

    def test_acceptance_requires_both_detailed_acknowledgments(self):
        review = self.review()
        with patch("apps.provisioning.component_migration_views.async_task") as queue:
            response = self.client.post(
                self.url,
                {
                    "action": "accept",
                    "review_id": review.pk,
                    "reason": "Move web only",
                    "backup_responsibility": "Operations keeps source mail backups.",
                    "impact_accepted": "on",
                },
            )
        self.assertEqual(response.status_code, 400)
        queue.assert_not_called()

    def test_accept_queues_stored_review_identity_and_no_posted_manifest(self):
        review = self.review()
        with patch("apps.provisioning.component_migration_views.async_task", return_value="task-id") as queue:
            response = self.client.post(
                self.url,
                {
                    "action": "accept",
                    "review_id": review.pk,
                    "reason": "Move web only",
                    "backup_responsibility": "Operations keeps source mail backups.",
                    "impact_accepted": "on",
                    "retained_responsibility_accepted": "on",
                    "manifest": "forged",
                },
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(queue.call_args.args[1:4], (str(self.account.pk), str(review.pk), str(self.staff.pk)))
        self.assertNotIn("forged", str(queue.call_args))
        self.assertFalse(ComponentMigrationApproval.objects.exists())

    def test_current_target_verification_is_required_before_queueing(self):
        type(self.target).objects.filter(pk=self.target.pk).update(security_state="unreviewed")
        with patch("apps.provisioning.component_migration_views.async_task") as queue:
            response = self.client.post(
                self.url, {"action": "inspect", "target_server": self.target.pk, "application_paths": "public_html"}
            )
        self.assertEqual(response.status_code, 400)
        queue.assert_not_called()

    def test_task_results_are_bound_to_the_current_operator_and_account(self):
        task = Task.objects.create(
            id="a" * 32,
            name=f"component-migration:{self.account.pk}:another-operator",
            func="fixture",
            started=timezone.now(),
            stopped=timezone.now(),
            success=True,
            result={"outcome": "needs_review", "message": "Another operator's private task result"},
        )
        response = self.client.get(self.url, {"task": task.pk})
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Another operator&#x27;s private task result")
        self.assertIsNone(response.context["task"])

    def test_seal_intent_status_never_offers_keep_source_or_mark_resolved(self):
        migration = self.start(self.approve(self.review()))
        # fsm-bypass: interrupted native seal was recorded before ownership publication.
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            status="needs_review", barrier_state={"component_source_seal_intent": True}
        )
        response = self.client.get(self.url)
        self.assertContains(response, "Continue forward on the target")
        self.assertContains(response, "Independent source backup responsibility")
        self.assertNotContains(response, "Keep source and compensate selected components")
        self.assertNotContains(response, "Mark resolved")

    def test_expired_or_superseded_preview_does_not_offer_acceptance(self):
        review = self.review()
        with patch(
            "apps.provisioning.component_migration_views.timezone.now",
            return_value=review.created_at + timedelta(minutes=16),
        ):
            response = self.client.get(self.url, {"review": review.pk})
        self.assertContains(response, "stale or superseded")
        self.assertNotContains(response, 'value="accept"')
        self.review()
        response = self.client.get(self.url, {"review": review.pk})
        self.assertContains(response, "stale or superseded")
        self.assertNotContains(response, 'value="accept"')

    def test_source_release_requires_explicit_acceptance_and_exact_obligation(self):
        migration = self.start(self.approve(self.review()))
        obligation = migration.component_source_obligation
        data = {
            "action": "release",
            "obligation_id": obligation.pk,
            "backup_handoff": "Mail and DNS evacuated; operator retains independent archives.",
        }
        with patch("apps.provisioning.component_migration_views.async_task", return_value="release-task") as queue:
            response = self.client.post(self.url, data)
            self.assertEqual(response.status_code, 400)
            queue.assert_not_called()
            response = self.client.post(self.url, {**data, "release_accepted": "on"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(queue.call_args.args[1:4], (str(self.account.pk), str(obligation.pk), str(self.staff.pk)))
        self.assertFalse(SourceServiceRelease.objects.exists())


class ComponentMigrationTaskTests(ComponentAdmissionTestBase):
    def inspection(self):
        from apps.provisioning.component_migration_tasks import inspect_component_migration  # noqa: PLC0415

        return inspect_component_migration(
            str(self.account.pk),
            str(self.target.pk),
            str(self.staff.pk),
            {"paths": [{"relative": "public_html", "purpose": "application"}], "databases": ["customer_web"]},
        )

    def acceptance(self, review):
        from apps.provisioning.component_migration_tasks import accept_component_migration  # noqa: PLC0415

        return accept_component_migration(
            str(self.account.pk),
            str(review.pk),
            str(self.staff.pk),
            "Move selected web components",
            "Operations retains independent source mail and DNS backups.",
        )

    def test_inspection_records_only_fresh_native_scope_and_never_starts_migration(self):
        with patch(
            "apps.provisioning.component_migration_tasks.collect_source_components",
            return_value=ComponentManifest.parse(self.facts),
        ) as collect:
            result = self.inspection()
        self.assertEqual(result["outcome"], "reviewed")
        review = ComponentMigrationReview.objects.get(pk=result["review_id"])
        self.assertEqual(review.actor, self.staff)
        self.assertEqual(collect.call_args.args[1]["domain_id"], self.facts["source"]["domain_id"])
        self.assertFalse(VirtualminMigration.objects.exists())

    def test_acceptance_reinspects_then_approves_and_enqueues_after_commit(self):
        review = self.review()
        with (
            patch(
                "apps.provisioning.component_migration_tasks.collect_source_components",
                return_value=ComponentManifest.parse(self.facts),
            ) as collect,
            self.captureOnCommitCallbacks(execute=True),
        ):
            result = self.acceptance(review)
            self.enqueue.assert_not_called()
        self.assertEqual(result["outcome"], "started")
        self.assertTrue(
            VirtualminMigration.objects.filter(pk=result["migration_id"], component_approval__review=review).exists()
        )
        collect.assert_called_once()
        self.enqueue.assert_called_once()

    def test_scope_drift_refuses_without_consuming_approval_or_creating_reservation(self):
        review = self.review()
        facts = deepcopy(self.facts)
        facts["paths"][0]["inode"] += 1
        with patch(
            "apps.provisioning.component_migration_tasks.collect_source_components",
            return_value=ComponentManifest.parse(facts),
        ):
            result = self.acceptance(review)
        self.assertEqual(result["outcome"], "needs_review")
        self.assertFalse(ComponentMigrationApproval.objects.exists())
        self.assertFalse(VirtualminMigration.objects.exists())

    def test_revoked_operator_permission_refuses_before_native_inspection(self):
        self.staff.is_active = False
        self.staff.save(update_fields=["is_active"])
        with (
            patch("apps.provisioning.component_migration_tasks.collect_source_components") as collect,
            self.assertRaises(PermissionDenied),
        ):
            self.inspection()
        collect.assert_not_called()

    def test_revoked_permission_during_inspection_cannot_approve_or_start(self):
        review = self.review()

        def revoked(*_args):
            type(self.staff).objects.filter(pk=self.staff.pk).update(is_active=False)
            return ComponentManifest.parse(self.facts)

        with (
            patch("apps.provisioning.component_migration_tasks.collect_source_components", side_effect=revoked),
            self.assertRaises(PermissionDenied),
        ):
            self.acceptance(review)
        self.assertFalse(ComponentMigrationApproval.objects.exists())
        self.assertFalse(VirtualminMigration.objects.exists())

    def test_unrequested_scope_from_native_inspection_cannot_become_a_review(self):
        facts = deepcopy(self.facts)
        facts["paths"][0]["relative"] = "other_application"
        with patch(
            "apps.provisioning.component_migration_tasks.collect_source_components",
            return_value=ComponentManifest.parse(facts),
        ):
            result = self.inspection()
        self.assertEqual(result["outcome"], "needs_review")
        self.assertFalse(ComponentMigrationReview.objects.exists())

    def test_retained_source_release_requires_live_absence_and_records_handoff(self):
        from apps.provisioning.component_migration_tasks import release_component_source  # noqa: PLC0415

        migration = self.start(self.approve(self.review()))
        obligation = migration.component_source_obligation
        result = release_component_source(
            str(self.account.pk),
            str(obligation.pk),
            str(self.staff.pk),
            "Independent retained mail archive transferred to Operations.",
        )
        self.assertEqual(result["outcome"], "needs_review")
        self.assertFalse(SourceServiceRelease.objects.exists())
        self.source_gateway._domains.clear()
        result = release_component_source(
            str(self.account.pk),
            str(obligation.pk),
            str(self.staff.pk),
            "Independent retained mail archive transferred to Operations.",
        )
        self.assertEqual(result["outcome"], "released")
        release = SourceServiceRelease.objects.get(obligation=obligation)
        self.assertEqual(release.actor, self.staff)
        self.assertIn("Operations", release.backup_handoff)

    def test_permission_revoked_during_native_absence_cannot_release_source_responsibility(self):
        from apps.provisioning.component_migration_service import release_source_obligation  # noqa: PLC0415

        migration = self.start(self.approve(self.review()))

        def revoke_during_inventory(_gateway):
            type(self.staff).objects.filter(pk=self.staff.pk).update(is_active=False)
            from apps.common.types import Ok  # noqa: PLC0415

            return Ok([])

        with (
            patch(
                "apps.provisioning.component_migration_service.list_migration_domains",
                side_effect=revoke_during_inventory,
            ),
            self.assertRaises(PermissionDenied),
        ):
            release_source_obligation(
                migration.component_source_obligation,
                self.staff,
                "All services evacuated and independent backups handed over.",
            )
        self.assertFalse(SourceServiceRelease.objects.exists())
