"""
Design System Status Filter Tests — Phase C.2

Tests for the status_variant, status_icon, and status_label template filters
defined in apps.ui.templatetags.ui_components.

No database access — pure filter logic. O(1) per test call.
"""

# ===============================================================================
# FILTER IMPORT
# ===============================================================================

import unittest

from apps.ui.templatetags.ui_components import status_icon, status_label, status_variant

# ===============================================================================
# status_variant TESTS
# ===============================================================================


class StatusVariantFilterTests(unittest.TestCase):
    """Tests for the status_variant filter — maps status strings to badge variants."""

    # ── success group ──────────────────────────────────────────────────────────

    def test_active_returns_success(self) -> None:
        self.assertEqual(status_variant("active"), "success")

    def test_paid_returns_success(self) -> None:
        self.assertEqual(status_variant("paid"), "success")

    def test_healthy_returns_success(self) -> None:
        self.assertEqual(status_variant("healthy"), "success")

    def test_completed_returns_success(self) -> None:
        self.assertEqual(status_variant("completed"), "success")

    def test_resolved_returns_success(self) -> None:
        self.assertEqual(status_variant("resolved"), "success")

    def test_enabled_returns_success(self) -> None:
        self.assertEqual(status_variant("enabled"), "success")

    def test_consented_returns_success(self) -> None:
        self.assertEqual(status_variant("consented"), "success")

    def test_accepted_returns_success(self) -> None:
        self.assertEqual(status_variant("accepted"), "success")

    def test_converted_returns_success(self) -> None:
        self.assertEqual(status_variant("converted"), "success")

    def test_granted_returns_success(self) -> None:
        self.assertEqual(status_variant("granted"), "success")

    # ── warning group ─────────────────────────────────────────────────────────

    def test_pending_returns_warning(self) -> None:
        self.assertEqual(status_variant("pending"), "warning")

    def test_warning_returns_warning(self) -> None:
        self.assertEqual(status_variant("warning"), "warning")

    def test_waiting_returns_warning(self) -> None:
        self.assertEqual(status_variant("waiting"), "warning")

    def test_waiting_on_customer_returns_warning(self) -> None:
        self.assertEqual(status_variant("waiting_on_customer"), "warning")

    def test_processing_returns_info(self) -> None:
        """processing moved to info per design spec (Finding 2)."""
        self.assertEqual(status_variant("processing"), "info")

    def test_refunded_returns_warning(self) -> None:
        self.assertEqual(status_variant("refunded"), "warning")

    # ── danger group ──────────────────────────────────────────────────────────

    def test_overdue_returns_danger(self) -> None:
        self.assertEqual(status_variant("overdue"), "danger")

    def test_suspended_returns_danger(self) -> None:
        self.assertEqual(status_variant("suspended"), "danger")

    def test_expired_returns_danger(self) -> None:
        self.assertEqual(status_variant("expired"), "danger")

    def test_error_returns_danger(self) -> None:
        self.assertEqual(status_variant("error"), "danger")

    def test_revoked_returns_danger(self) -> None:
        self.assertEqual(status_variant("revoked"), "danger")

    def test_not_consented_space_returns_danger(self) -> None:
        self.assertEqual(status_variant("not consented"), "danger")

    # ── info group ────────────────────────────────────────────────────────────

    def test_draft_returns_info(self) -> None:
        self.assertEqual(status_variant("draft"), "info")

    # ── primary group ─────────────────────────────────────────────────────────

    def test_issued_returns_primary(self) -> None:
        self.assertEqual(status_variant("issued"), "primary")

    def test_sent_returns_primary(self) -> None:
        self.assertEqual(status_variant("sent"), "primary")

    def test_open_returns_primary(self) -> None:
        self.assertEqual(status_variant("open"), "primary")

    def test_in_progress_underscore_returns_primary(self) -> None:
        self.assertEqual(status_variant("in_progress"), "primary")

    def test_in_progress_space_returns_primary(self) -> None:
        self.assertEqual(status_variant("in progress"), "primary")

    def test_provisioning_returns_primary(self) -> None:
        self.assertEqual(status_variant("provisioning"), "primary")

    # ── secondary group ───────────────────────────────────────────────────────

    def test_cancelled_returns_danger(self) -> None:
        """cancelled moved to danger per design spec (Finding 2)."""
        self.assertEqual(status_variant("cancelled"), "danger")

    def test_terminated_returns_secondary(self) -> None:
        self.assertEqual(status_variant("terminated"), "secondary")

    def test_void_returns_secondary(self) -> None:
        self.assertEqual(status_variant("void"), "secondary")

    def test_closed_returns_secondary(self) -> None:
        self.assertEqual(status_variant("closed"), "secondary")

    def test_inactive_returns_secondary(self) -> None:
        self.assertEqual(status_variant("inactive"), "secondary")

    def test_unknown_returns_secondary(self) -> None:
        self.assertEqual(status_variant("unknown"), "secondary")

    # ── membership roles ──────────────────────────────────────────────────────

    def test_role_owner_returns_success(self) -> None:
        self.assertEqual(status_variant("owner"), "success")

    def test_role_billing_returns_primary(self) -> None:
        self.assertEqual(status_variant("billing"), "primary")

    def test_role_tech_returns_info(self) -> None:
        self.assertEqual(status_variant("tech"), "info")

    def test_role_viewer_returns_secondary(self) -> None:
        self.assertEqual(status_variant("viewer"), "secondary")

    # ── edge cases ────────────────────────────────────────────────────────────

    def test_empty_string_returns_secondary(self) -> None:
        self.assertEqual(status_variant(""), "secondary")

    def test_unknown_status_returns_secondary(self) -> None:
        self.assertEqual(status_variant("some_future_status_xyz"), "secondary")

    def test_case_insensitive_uppercase(self) -> None:
        self.assertEqual(status_variant("ACTIVE"), "success")

    def test_case_insensitive_mixed(self) -> None:
        self.assertEqual(status_variant("Pending"), "warning")

    def test_strips_whitespace(self) -> None:
        self.assertEqual(status_variant("  active  "), "success")


# ===============================================================================
# status_icon TESTS
# ===============================================================================


class StatusIconFilterTests(unittest.TestCase):
    """Tests for the status_icon filter — maps status strings to icon names."""

    # ── check icon group ──────────────────────────────────────────────────────

    def test_active_returns_check_icon(self) -> None:
        self.assertEqual(status_icon("active"), "check")

    def test_paid_returns_check_icon(self) -> None:
        self.assertEqual(status_icon("paid"), "check")

    def test_completed_returns_check_icon(self) -> None:
        self.assertEqual(status_icon("completed"), "check")

    def test_resolved_returns_check_icon(self) -> None:
        self.assertEqual(status_icon("resolved"), "check")

    def test_enabled_returns_check_icon(self) -> None:
        self.assertEqual(status_icon("enabled"), "check")

    def test_healthy_returns_check_icon(self) -> None:
        self.assertEqual(status_icon("healthy"), "check")

    def test_consented_returns_check_icon(self) -> None:
        self.assertEqual(status_icon("consented"), "check")

    # ── clock icon group ──────────────────────────────────────────────────────

    def test_pending_returns_clock_icon(self) -> None:
        self.assertEqual(status_icon("pending"), "clock")

    def test_waiting_returns_clock_icon(self) -> None:
        self.assertEqual(status_icon("waiting"), "clock")

    def test_waiting_on_customer_returns_clock_icon(self) -> None:
        self.assertEqual(status_icon("waiting_on_customer"), "clock")

    def test_processing_returns_clock_icon(self) -> None:
        self.assertEqual(status_icon("processing"), "clock")

    def test_expired_returns_clock_icon(self) -> None:
        self.assertEqual(status_icon("expired"), "clock")

    # ── alert icon group ──────────────────────────────────────────────────────

    def test_overdue_returns_alert_icon(self) -> None:
        self.assertEqual(status_icon("overdue"), "alert")

    def test_warning_returns_alert_icon(self) -> None:
        self.assertEqual(status_icon("warning"), "alert")

    def test_error_returns_alert_icon(self) -> None:
        self.assertEqual(status_icon("error"), "alert")

    # ── other named icons ─────────────────────────────────────────────────────

    def test_suspended_returns_ban_icon(self) -> None:
        self.assertEqual(status_icon("suspended"), "ban")

    def test_cancelled_returns_x_icon(self) -> None:
        self.assertEqual(status_icon("cancelled"), "x")

    def test_terminated_returns_x_icon(self) -> None:
        self.assertEqual(status_icon("terminated"), "x")

    def test_revoked_returns_x_icon(self) -> None:
        self.assertEqual(status_icon("revoked"), "x")

    def test_closed_returns_x_icon(self) -> None:
        self.assertEqual(status_icon("closed"), "x")

    def test_provisioning_returns_lightning_icon(self) -> None:
        self.assertEqual(status_icon("provisioning"), "lightning")

    def test_in_progress_returns_lightning_icon(self) -> None:
        self.assertEqual(status_icon("in_progress"), "lightning")

    def test_in_progress_space_returns_lightning_icon(self) -> None:
        self.assertEqual(status_icon("in progress"), "lightning")

    def test_open_returns_mail_icon(self) -> None:
        self.assertEqual(status_icon("open"), "mail")

    def test_sent_returns_mail_icon(self) -> None:
        self.assertEqual(status_icon("sent"), "mail")

    def test_draft_returns_edit_icon(self) -> None:
        self.assertEqual(status_icon("draft"), "edit")

    # ── edge cases ────────────────────────────────────────────────────────────

    def test_empty_string_returns_empty(self) -> None:
        self.assertEqual(status_icon(""), "")

    def test_unmapped_status_returns_empty(self) -> None:
        self.assertEqual(status_icon("some_future_status"), "")

    def test_case_insensitive_uppercase(self) -> None:
        self.assertEqual(status_icon("ACTIVE"), "check")

    def test_strips_whitespace(self) -> None:
        self.assertEqual(status_icon("  pending  "), "clock")


# ===============================================================================
# status_label TESTS
# ===============================================================================


class StatusLabelFilterTests(unittest.TestCase):
    """Tests for the status_label filter — returns human-readable display labels."""

    # ── hardcoded overrides ───────────────────────────────────────────────────

    def test_waiting_on_customer_returns_waiting_on_you(self) -> None:
        self.assertEqual(status_label("waiting_on_customer"), "Waiting on You")

    def test_in_progress_underscore_returns_in_progress(self) -> None:
        self.assertEqual(status_label("in_progress"), "In Progress")

    def test_not_consented_returns_not_consented_label(self) -> None:
        self.assertEqual(status_label("not_consented"), "Not Consented")

    def test_not_consented_space_returns_not_consented_label(self) -> None:
        self.assertEqual(status_label("not consented"), "Not Consented")

    # ── title-case fallback ───────────────────────────────────────────────────

    def test_active_becomes_title_case(self) -> None:
        self.assertEqual(status_label("active"), "Active")

    def test_pending_becomes_title_case(self) -> None:
        self.assertEqual(status_label("pending"), "Pending")

    def test_underscore_converted_to_space(self) -> None:
        self.assertEqual(status_label("some_status"), "Some Status")

    def test_multi_word_underscore_title_cased(self) -> None:
        self.assertEqual(status_label("my_custom_status"), "My Custom Status")

    def test_already_title_case_unchanged(self) -> None:
        self.assertEqual(status_label("Active"), "Active")

    # ── edge cases ────────────────────────────────────────────────────────────

    def test_empty_string_returns_empty(self) -> None:
        self.assertEqual(status_label(""), "")

    def test_single_word_capitalised(self) -> None:
        self.assertEqual(status_label("draft"), "Draft")

    def test_case_insensitive_in_progress(self) -> None:
        """Uppercase IN_PROGRESS should still hit the override after lowercasing."""
        self.assertEqual(status_label("IN_PROGRESS"), "In Progress")
