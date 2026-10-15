"""The semantic guard of a settings write sees the normalised value, under the row lock.

The guard decides from live system state ("may the issuer switch now"). It used to run
first in ``_write_setting_locked``: before the value was coerced, so it judged the raw
operator input (a padded " smartbill " passed its own strip, then storage refused or
kept a different string), and before the row lock, so the state it read could change
before the write.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.db.models import QuerySet
from django.test import TestCase

from apps.common.types import Err
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService

ISSUER_KEY = "billing.invoice_issuer"


class SemanticGuardNormalisationTests(TestCase):
    def test_a_padded_value_is_stripped_before_the_guard_sees_it(self) -> None:
        seen: list[Any] = []

        def spy(key: str, value: Any) -> None:
            seen.append(value)

        with patch.object(SettingsService, "_semantic_guard", side_effect=spy):
            SettingsService.update_setting(ISSUER_KEY, "  builtin \n")

        self.assertEqual(seen, ["builtin"])

    def test_a_padded_valid_value_is_stored_trimmed(self) -> None:
        result = SettingsService.update_setting(ISSUER_KEY, "  builtin ")

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(SystemSetting.objects.get(key=ISSUER_KEY).value, "builtin")

    def test_a_padded_unknown_issuer_is_named_without_its_padding(self) -> None:
        result = SettingsService.update_setting(ISSUER_KEY, "  smartbil ")

        if not isinstance(result, Err):
            self.fail(f"expected a refusal, got {result}")
        self.assertEqual(result.error.code, "unknown_issuer")
        self.assertIn("'smartbil'", result.error.message)

    def test_the_guard_runs_after_the_row_is_locked(self) -> None:
        self.assertTrue(SettingsService.update_setting(ISSUER_KEY, "builtin").is_ok())  # the row exists
        events: list[str] = []
        real_select_for_update = QuerySet.select_for_update

        def locking(queryset: QuerySet[Any], *args: Any, **kwargs: Any) -> QuerySet[Any]:
            if queryset.model is SystemSetting:
                events.append("lock")
            return real_select_for_update(queryset, *args, **kwargs)

        def guard(key: str, value: Any) -> None:
            events.append("guard")

        with (
            patch.object(QuerySet, "select_for_update", locking),
            patch.object(SettingsService, "_semantic_guard", side_effect=guard),
        ):
            SettingsService.update_setting(ISSUER_KEY, "builtin")

        self.assertEqual(events, ["lock", "guard"])
