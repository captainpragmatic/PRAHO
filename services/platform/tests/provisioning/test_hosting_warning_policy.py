"""Raw-byte boundary, hysteresis and ownership/month controls; no database or mocks."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

from django.test import SimpleTestCase

from apps.provisioning.hosting_warning_policy import (
    WarningContext,
    WarningLevel,
    WarningReading,
    WarningScope,
    evaluate_warning,
)


class HostingWarningPolicyTests(SimpleTestCase):
    def setUp(self) -> None:
        self.hour = datetime(2026, 11, 3, 12, tzinfo=UTC)
        self.scope = WarningScope("disk", 17, 23, uuid4())
        self.context = WarningContext(self.scope, 1000, 1)

    def poll(self, used, *, previous=None, hour=0, minute=0, context=None, scope=None, quality="fresh"):  # noqa: PLR0913
        context = context or self.context
        return evaluate_warning(
            previous,
            context=context,
            reading=WarningReading(
                scope or context.scope, self.hour + timedelta(hours=hour, minutes=minute), used, quality
            ),
        )

    def test_inclusive_thresholds_use_exact_raw_bytes_on_both_sides(self) -> None:
        for boundary, expected in (
            (800, WarningLevel.WARNING),
            (950, WarningLevel.HIGH),
            (1000, WarningLevel.CRITICAL),
        ):
            with self.subTest(boundary=boundary):
                below = self.poll(boundary - 1)
                expected_below = (
                    None if boundary == 800 else WarningLevel.WARNING if boundary == 950 else WarningLevel.HIGH
                )
                self.assertEqual(below.state.condition, expected_below)
                exact = self.poll(boundary)
                self.assertEqual(exact.state.condition, expected)
                self.assertEqual(exact.crossing.threshold, expected)
                self.assertEqual(self.poll(boundary + 1).state.condition, expected)

    def test_jumping_critical_silently_latches_lower_levels(self) -> None:
        initial = self.poll(1200)
        self.assertEqual(initial.crossing.threshold, WarningLevel.CRITICAL)
        self.assertEqual(
            {episode.threshold for episode in initial.state.episodes if episode.latched}, set(WarningLevel)
        )
        self.assertEqual({episode.generation for episode in initial.state.episodes}, {1})
        lower = self.poll(850, previous=initial.state, hour=1)
        self.assertEqual(lower.state.condition, WarningLevel.WARNING)
        self.assertIsNone(lower.crossing)

    def test_rearming_requires_two_different_consecutive_hours_strictly_below(self) -> None:
        for threshold, reset, high in (
            (WarningLevel.WARNING, 750, 800),
            (WarningLevel.HIGH, 900, 950),
            (WarningLevel.CRITICAL, 950, 1000),
        ):
            with self.subTest(threshold=threshold):
                state = self.poll(high).state
                exact_reset = self.poll(reset, previous=state, hour=1)
                self.assertNotIn(threshold, exact_reset.rearmed)
                one = self.poll(reset - 1, previous=exact_reset.state, hour=2)
                self.assertNotIn(threshold, one.rearmed)
                retry = self.poll(reset - 1, previous=one.state, hour=2, minute=30)
                self.assertNotIn(threshold, retry.rearmed)
                two = self.poll(reset - 1, previous=retry.state, hour=3)
                self.assertIn(threshold, two.rearmed)
                next_episode = self.poll(high, previous=two.state, hour=4)
                self.assertEqual(next_episode.crossing.threshold, threshold)
                self.assertEqual(next_episode.crossing.generation, 2)

    def test_missing_hour_and_intervening_high_reading_break_below_streak(self) -> None:
        initial = self.poll(1000)
        one = self.poll(940, previous=initial.state, hour=1)
        missing = self.poll(940, previous=one.state, hour=3)
        self.assertNotIn(WarningLevel.CRITICAL, missing.rearmed)
        high = self.poll(970, previous=missing.state, hour=3, minute=20)
        low_again = self.poll(940, previous=high.state, hour=3, minute=40)
        self.assertNotIn(WarningLevel.CRITICAL, low_again.rearmed)
        next_hour = self.poll(940, previous=low_again.state, hour=4)
        self.assertIn(WarningLevel.CRITICAL, next_hour.rearmed)

    def test_unknown_unlimited_stale_and_partial_disk_do_not_change_episode_or_condition(self) -> None:
        state = self.poll(1000).state
        for quality, allowance, used in (
            ("unknown", 1000, None),
            ("fresh", None, 0),
            ("fresh", 0, 0),
            ("stale", 1000, 0),
            ("partial", 1000, 0),
        ):
            with self.subTest(quality=quality, allowance=allowance):
                result = self.poll(
                    used,
                    previous=state,
                    hour=1,
                    quality=quality,
                    context=replace(self.context, operational_allowance_bytes=allowance),
                )
                self.assertEqual(result.state, state)
                self.assertIsNone(result.crossing)
                self.assertEqual(result.rearmed, ())

    def test_same_reading_replay_and_out_of_order_reading_cannot_rearm(self) -> None:
        high = self.poll(1000)
        low = self.poll(700, previous=high.state, hour=1)
        replay = self.poll(700, previous=low.state, hour=1)
        self.assertEqual(replay.state, low.state)
        self.assertEqual(replay.ignored, "same_reading")
        old = self.poll(700, previous=low.state)
        self.assertEqual(old.state, low.state)
        self.assertEqual(old.ignored, "older_reading")

    def test_utc_hours_not_local_clock_hours_drive_hysteresis(self) -> None:
        high = self.poll(1000)
        offset = timezone(timedelta(hours=5, minutes=30))
        first_at = (self.hour + timedelta(hours=1, minutes=29)).astimezone(offset)
        first = evaluate_warning(high.state, context=self.context, reading=WarningReading(self.scope, first_at, 700))
        second = evaluate_warning(
            first.state, context=self.context, reading=WarningReading(self.scope, first_at + timedelta(minutes=2), 700)
        )
        self.assertEqual(second.rearmed, ())  # Local hour changed, UTC hour did not.
        third = evaluate_warning(
            second.state,
            context=self.context,
            reading=WarningReading(self.scope, first_at + timedelta(minutes=32), 700),
        )
        self.assertEqual(set(third.rearmed), set(WarningLevel))

    def test_current_condition_is_independent_of_notification_latch(self) -> None:
        high = self.poll(1000)
        lower = self.poll(100, previous=high.state, hour=1)
        self.assertIsNone(lower.state.condition)
        self.assertTrue(all(episode.latched for episode in lower.state.episodes))
        self.assertIsNone(lower.crossing)

    def test_verified_upgrade_recomputes_condition_without_blind_latch_reset(self) -> None:
        original = WarningContext(self.scope, 10 * 1024**3, 1)
        used = 195 * 1024**3 // 10
        high = self.poll(used, context=original)
        upgraded = replace(original, operational_allowance_bytes=20 * 1024**3, operational_revision=2)
        after = self.poll(used, previous=high.state, context=upgraded)
        self.assertEqual(after.state.condition, WarningLevel.HIGH)
        self.assertTrue(all(episode.latched for episode in after.state.episodes))
        self.assertIsNone(after.crossing)
        self.assertEqual(after.rearmed, ())

    def test_denominator_change_does_not_combine_old_below_streak_or_replayed_readings(self) -> None:
        high = self.poll(1000)
        old_low = self.poll(700, previous=high.state, hour=1)
        upgraded = replace(self.context, operational_allowance_bytes=2000, operational_revision=2)
        replay = self.poll(700, previous=old_low.state, hour=1, context=upgraded)
        self.assertIsNone(replay.state.condition)
        self.assertEqual(replay.rearmed, ())
        next_hour = self.poll(700, previous=replay.state, hour=2, context=upgraded)
        self.assertEqual(next_hour.rearmed, ())
        second = self.poll(700, previous=next_hour.state, hour=3, context=upgraded)
        self.assertEqual(set(second.rearmed), set(WarningLevel))

    def test_owner_scope_a_to_b_to_a_never_reuses_latches_or_intents(self) -> None:
        high = self.poll(1000)
        owner_b = replace(self.scope, customer_id=24, owner_scope=uuid4())
        partial = self.poll(None, previous=high.state, context=replace(self.context, scope=owner_b), quality="unknown")
        self.assertEqual(partial.replaced_scope, self.scope)
        self.assertIsNone(partial.state.condition)
        owner_a_again = replace(self.scope, owner_scope=uuid4())
        again = self.poll(1000, previous=partial.state, context=replace(self.context, scope=owner_a_again))
        self.assertEqual(again.crossing.threshold, WarningLevel.CRITICAL)
        self.assertEqual(again.crossing.generation, 1)
        self.assertEqual(again.replaced_scope, owner_b)

    def bandwidth_context(self):
        start = self.hour.replace(day=1, hour=0)
        end = start.replace(month=12)
        return WarningContext(WarningScope("bandwidth", 17, 23, self.scope.owner_scope, start, end, "UTC"), 1000, 1)

    def test_partial_bandwidth_lower_bound_can_escalate_to_critical(self) -> None:
        result = self.poll(1000, context=self.bandwidth_context(), quality="partial")
        self.assertEqual(result.state.condition, WarningLevel.CRITICAL)
        self.assertIsNotNone(result.crossing)
        self.assertEqual(result.crossing.threshold, WarningLevel.CRITICAL)
        self.assertTrue(all(episode.latched for episode in result.state.episodes))
        self.assertEqual(result.availability, "partial")

    def test_partial_below_existing_condition_cannot_resolve_or_rearm(self) -> None:
        context = self.bandwidth_context()
        state = self.poll(1000, context=context).state
        for hour in (1, 2):
            result = self.poll(700, previous=state, hour=hour, context=context, quality="partial")
            self.assertEqual(result.state.condition, WarningLevel.CRITICAL)
            self.assertTrue(all(episode.latched for episode in result.state.episodes))
            self.assertEqual(result.rearmed, ())
            self.assertIsNone(result.crossing)
            state = result.state
        first_full = self.poll(700, previous=state, hour=3, context=context)
        self.assertIsNone(first_full.state.condition)
        self.assertEqual(first_full.rearmed, ())
        second_full = self.poll(700, previous=first_full.state, hour=4, context=context)
        self.assertEqual(set(second_full.rearmed), set(WarningLevel))

    def test_same_time_partial_to_complete_refinement_is_not_lost_or_double_counted(self) -> None:
        context = self.bandwidth_context()
        lower_bound = self.poll(800, context=context, quality="partial")
        complete = self.poll(1000, previous=lower_bound.state, context=context)
        self.assertEqual(complete.state.condition, WarningLevel.CRITICAL)
        self.assertIsNotNone(complete.crossing)
        self.assertEqual(complete.crossing.threshold, WarningLevel.CRITICAL)
        first_low = self.poll(700, previous=complete.state, context=context, hour=1)
        replay = self.poll(700, previous=first_low.state, context=context, hour=1)
        self.assertEqual(replay.rearmed, ())
        second_low = self.poll(700, previous=replay.state, context=context, hour=2)
        self.assertEqual(set(second_low.rearmed), set(WarningLevel))

    def test_partial_new_month_cancels_old_scope_and_cannot_revive_old_banner(self) -> None:
        context = self.bandwidth_context()
        high = self.poll(1000, context=context)
        next_scope = replace(
            context.scope, period_start=context.scope.period_end, period_end=datetime(2027, 1, 1, tzinfo=UTC)
        )
        next_context = replace(context, scope=next_scope)
        old_pointer = self.poll(1000, previous=high.state, context=next_context, scope=context.scope)
        self.assertEqual(old_pointer.replaced_scope, context.scope)
        self.assertIsNone(old_pointer.state.condition)
        self.assertEqual(old_pointer.ignored, "scope_mismatch")
        incomplete = self.poll(None, previous=old_pointer.state, context=next_context, quality="partial")
        self.assertIsNone(incomplete.state.condition)
        self.assertIsNone(incomplete.crossing)

    def test_partial_context_recompute_then_same_time_complete_evidence_can_resolve(self) -> None:
        context = self.bandwidth_context()
        high = self.poll(1000, context=context)
        upgraded = replace(context, operational_allowance_bytes=2000, operational_revision=2)
        partial = self.poll(1000, previous=high.state, context=upgraded, quality="partial")
        self.assertEqual(partial.state.condition, WarningLevel.CRITICAL)
        complete = self.poll(1000, previous=partial.state, context=upgraded)
        self.assertIsNone(complete.state.condition)
        self.assertEqual(complete.rearmed, ())

    def test_invalid_reading_hour_cannot_supply_second_below_observation(self) -> None:
        high = self.poll(1000)
        first = self.poll(700, previous=high.state, hour=1)
        stale = self.poll(700, previous=first.state, hour=2, quality="stale")
        self.assertEqual(stale.state, first.state)
        gap = self.poll(700, previous=stale.state, hour=3)
        self.assertEqual(gap.rearmed, ())
        next_hour = self.poll(700, previous=gap.state, hour=4)
        self.assertEqual(set(next_hour.rearmed), set(WarningLevel))

    def test_revision_change_without_denominator_change_keeps_resource_streak(self) -> None:
        high = self.poll(1000)
        first = self.poll(700, previous=high.state, hour=1)
        revision_only = replace(self.context, operational_revision=2)
        second = self.poll(700, previous=first.state, hour=2, context=revision_only)
        self.assertEqual(set(second.rearmed), set(WarningLevel))

    def test_boolean_negative_fractional_and_naive_inputs_are_refused(self) -> None:
        for value in (True, -1, 1.5):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    WarningContext(self.scope, value, 1)
                with self.assertRaises(ValueError):
                    WarningReading(self.scope, self.hour, value)
        with self.assertRaises(ValueError):
            WarningReading(self.scope, self.hour.replace(tzinfo=None), 0)
        with self.assertRaises(ValueError):
            WarningScope("bandwidth", 17, 23, uuid4())
        with self.assertRaises(ValueError):
            replace(self.scope, period_timezone="UTC")

    def test_timezone_change_resets_bandwidth_only_and_resources_cannot_share_state(self) -> None:
        disk = self.poll(1000)
        context = self.bandwidth_context()
        bandwidth = self.poll(1000, context=context)
        changed = replace(context, scope=replace(context.scope, period_timezone="Europe/Bucharest"))
        reset = self.poll(None, previous=bandwidth.state, context=changed, quality="partial")
        self.assertEqual(reset.replaced_scope, context.scope)
        self.assertEqual(disk.state.condition, WarningLevel.CRITICAL)
        with self.assertRaises(ValueError):
            self.poll(0, previous=disk.state, context=changed)

    def test_large_integer_quantities_do_not_round_a_byte_below_threshold_up(self) -> None:
        allowance = 10**30
        context = replace(self.context, operational_allowance_bytes=allowance)
        self.assertEqual(self.poll(allowance * 95 // 100 - 1, context=context).state.condition, WarningLevel.WARNING)
        self.assertEqual(self.poll(allowance * 95 // 100, context=context).state.condition, WarningLevel.HIGH)
