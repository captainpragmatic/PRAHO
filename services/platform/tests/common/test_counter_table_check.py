"""The Platform's deployment checks refuse to start without the counter table."""

from unittest.mock import patch

from django.core.checks import Tags, run_checks
from django.db import DatabaseError
from django.test import TestCase


class CounterTableCheckTests(TestCase):
    def test_present_table_passes_and_missing_table_is_an_error(self) -> None:
        ids = {message.id for message in run_checks(tags=[Tags.database], include_deployment_checks=True)}
        self.assertNotIn("common.E002", ids)
        with patch("apps.common.checks.connections") as connections:
            connections.__getitem__.return_value.cursor.side_effect = DatabaseError("no such table")
            ids = {message.id for message in run_checks(tags=[Tags.database], include_deployment_checks=True)}
        self.assertIn("common.E002", ids)
        self.assertNotIn(
            "common.E002", {message.id for message in run_checks(tags=[Tags.database], include_deployment_checks=False)}
        )
