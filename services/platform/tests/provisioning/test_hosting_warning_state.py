"""Durable JSON round trips preserve exact episode state and reject unknown policy."""

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from django.test import SimpleTestCase

from apps.provisioning.hosting_warning_policy import WarningContext, WarningReading, WarningScope, evaluate_warning
from apps.provisioning.hosting_warning_state import state_from_snapshot, state_snapshot


class WarningStateCodecTests(SimpleTestCase):
    def setUp(self):
        self.at = datetime(2026, 11, 1, tzinfo=UTC)
        self.scope = WarningScope("disk", 17, 23, uuid4())
        context = WarningContext(self.scope, 1000, 7)
        first = evaluate_warning(None, context=context, reading=WarningReading(self.scope, self.at, 1000)).state
        self.state = evaluate_warning(
            first, context=context, reading=WarningReading(self.scope, self.at + timedelta(hours=1), 940)
        ).state
        self.raw = json.loads(json.dumps(state_snapshot(self.state)))

    def test_database_json_roundtrip_preserves_scope_latches_generations_and_first_rearm_hour(self):
        self.assertEqual(state_from_snapshot(self.raw), self.state)
        next_hour = evaluate_warning(
            state_from_snapshot(self.raw),
            context=WarningContext(self.scope, 1000, 7),
            reading=WarningReading(self.scope, self.at + timedelta(hours=2), 940),
        )
        self.assertIn(100, next_hour.rearmed)

    def test_unknown_versions_fields_and_non_integer_quantities_are_never_silently_reset(self):
        for key, value in (
            ("version", 2),
            ("version", True),
            ("last_used_bytes", 1.5),
            ("last_used_bytes", True),
            ("operational_revision", 0),
            ("last_quality", ["fresh"]),
            ("last_observed_at", "2026-11-01T00:00:00"),
        ):
            with self.subTest(key=key, value=value):
                invalid = {**self.raw, key: value}
                with self.assertRaises(ValueError):
                    state_from_snapshot(invalid)
        with self.assertRaises(ValueError):
            state_from_snapshot({**self.raw, "unknown": True})

    def test_corrupt_episode_generation_latch_scope_and_missing_threshold_refuse(self):
        for corrupt in ("generation", "latch", "scope", "threshold"):
            with self.subTest(corrupt=corrupt):
                invalid = deepcopy(self.raw)
                if corrupt == "generation":
                    invalid["episodes"][0]["generation"] = True
                elif corrupt == "latch":
                    invalid["episodes"][0]["latched"] = "true"
                elif corrupt == "scope":
                    invalid["scope"]["owner_scope"] = "invalid"
                else:
                    invalid["episodes"].pop()
                with self.assertRaises(ValueError):
                    state_from_snapshot(invalid)
