"""Transition refusals keep original evidence and resolve the language when rendered."""

from datetime import timedelta

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils.translation import override

from apps.infrastructure.models import NodeDeployment
from tests.infrastructure.test_deployment_state_machine import _create_deployment


class DeploymentTransitionLocalisationTests(TestCase):
    def test_invalid_transition_keeps_original_status_and_target_across_language_changes(self) -> None:
        deployment = _create_deployment("pending")
        original = (deployment.status, deployment.status_message, deployment.updated_at)
        with override("en"), self.assertRaises(ValidationError) as refused:
            deployment.transition_to("completed", "This invalid transition must not write a message")
        self.assertEqual((deployment.status, deployment.status_message, deployment.updated_at), original)
        stored = NodeDeployment.objects.get(pk=deployment.pk)
        self.assertEqual((stored.status, stored.status_message, stored.updated_at), original)

        # The exception describes the rejected call, even after its caller's
        # in-memory instance changes and another language becomes active.
        deployment.status = "destroyed"
        deployment.status_message = "Changed only after the refusal"
        for language, expected in (
            ("en", "Cannot transition from 'pending' to 'completed'"),
            ("ro", "Nu se poate face tranziția de la 'pending' la 'completed'"),
            ("en", "Cannot transition from 'pending' to 'completed'"),
        ):
            with self.subTest(language=language), override(language):
                self.assertEqual(refused.exception.messages, [expected])

    def test_concurrent_refusal_keeps_stale_source_and_preserves_the_newer_database_row(self) -> None:
        deployment = _create_deployment("completed")
        stale = NodeDeployment.objects.get(pk=deployment.pk)
        original = (stale.status, stale.status_message, stale.updated_at)
        winner_time = stale.updated_at + timedelta(seconds=1)
        self.assertEqual(
            NodeDeployment.objects.filter(pk=deployment.pk).update(
                status="destroying", status_message="The newer worker owns this evidence", updated_at=winner_time
            ),
            1,
        )
        with override("en"), self.assertRaises(ValidationError) as refused:
            stale.transition_to("stopped", "A stale worker must not overwrite the winner")
        self.assertEqual((stale.status, stale.status_message, stale.updated_at), original)
        stored = NodeDeployment.objects.get(pk=deployment.pk)
        self.assertEqual(
            (stored.status, stored.status_message, stored.updated_at),
            ("destroying", "The newer worker owns this evidence", winner_time),
        )

        stale.status = "pending"
        stale.status_message = "Changed only after the refusal"
        for language, expected in (
            ("en", "Cannot transition from 'completed': the deployment changed concurrently"),
            ("ro", "Nu se poate face tranziția de la 'completed': implementarea s-a modificat între timp"),
            ("en", "Cannot transition from 'completed': the deployment changed concurrently"),
        ):
            with self.subTest(language=language), override(language):
                self.assertEqual(refused.exception.messages, [expected])
