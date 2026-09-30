"""Protect a build-blocking check whose boundary was wrong twice before it was right.

Flagging every status-only test gave 118 findings. Exempting any class that asserted a
refusal anywhere gave 24. The per-test boundary then gave 51. These cases keep that
boundary from silently widening or losing useful findings again.

The motivating defects were concrete: reports.html returned 200 rendering none of four
computed aggregates, and vat_report.html returned 200 with two dead context keys and a
100x VAT error. A successful response alone caught neither defect.
"""

from __future__ import annotations

import contextlib
import io
import sys
import tempfile
from pathlib import Path
from textwrap import dedent
from unittest.mock import patch

from django.test import SimpleTestCase

_REPO_ROOT = Path(__file__).resolve().parents[4]
_SCRIPTS_DIR = str(_REPO_ROOT / "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import audit_test_assertion_quality as audit  # noqa: E402


class _DetectorTestCase(SimpleTestCase):
    def _scan_source(self, source: str) -> list[str]:
        """Keep fixture paths under the patched root so relative finding names remain valid."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "test_sample.py"
            path.write_text(dedent(source), encoding="utf-8")
            with patch.object(audit, "PROJECT_ROOT", root):
                return audit.scan_file(path)


class StatusOnlyDetectionTests(_DetectorTestCase):
    """Missing page values must not hide behind a successful response."""

    def test_a_bare_200_after_creating_domain_state_is_flagged(self) -> None:
        """The missing report aggregates still produced 200 after data was created."""
        source = """
        class InvoicePageTests(TestCase):
            def test_paid_invoices_are_shown(self) -> None:
                Invoice.objects.create(customer=self.customer, status="paid")
                response = self.client.get("/x/")
                self.assertEqual(response.status_code, 200)
        """
        self.assertEqual(self._scan_source(source), ["test_sample.py::test_paid_invoices_are_shown"])

    def test_a_bare_200_with_a_query_string_is_flagged(self) -> None:
        """A filter can be ignored while the page still returns 200."""
        source = """
        class InvoicePageTests(TestCase):
            def test_paid_filter_is_applied(self) -> None:
                response = self.client.get("/x/?status=paid")
                self.assertEqual(response.status_code, 200)
        """
        self.assertEqual(self._scan_source(source), ["test_sample.py::test_paid_filter_is_applied"])

    def test_a_bare_200_with_post_data_is_flagged(self) -> None:
        """Accepting a payload says nothing about whether its effect is correct."""
        source = """
        class InvoicePageTests(TestCase):
            def test_paid_filter_is_submitted(self) -> None:
                response = self.client.post("/x/", data={"status": "paid"})
                self.assertEqual(response.status_code, 200)
        """
        self.assertEqual(self._scan_source(source), ["test_sample.py::test_paid_filter_is_submitted"])


class StatusIsTheBehaviourTests(_DetectorTestCase):
    """The original 118 findings incorrectly included real access-control checks."""

    def test_a_403_assertion_is_not_flagged(self) -> None:
        """A refusal remains meaningful even when the test establishes domain state."""
        source = """
        class InvoiceAccessTests(TestCase):
            def test_another_customers_invoice_is_forbidden(self) -> None:
                Invoice.objects.create(customer=self.other_customer, status="paid")
                response = self.client.get("/x/")
                self.assertEqual(response.status_code, 403)
        """
        self.assertEqual(self._scan_source(source), [])

    def test_an_assert_redirects_call_is_not_flagged(self) -> None:
        """The login destination is already an observed access-control result."""
        source = """
        class InvoiceAccessTests(TestCase):
            def test_anonymous_access_redirects_to_login(self) -> None:
                Invoice.objects.create(customer=self.customer, status="paid")
                response = self.client.get("/x/")
                self.assertRedirects(response, "/login/")
        """
        self.assertEqual(self._scan_source(source), [])

    def test_a_test_asserting_both_200_and_404_is_not_flagged(self) -> None:
        """A refusal in this same test must prevent a success-only finding."""
        source = """
        class InvoiceAccessTests(TestCase):
            def test_only_existing_invoices_are_accessible(self) -> None:
                Invoice.objects.create(customer=self.customer, status="paid")
                response = self.client.get("/x/")
                self.assertEqual(response.status_code, 200)
                missing_response = self.client.get("/x/missing/")
                self.assertEqual(missing_response.status_code, 404)
        """
        self.assertEqual(self._scan_source(source), [])


class ReadsBeyondStatusTests(_DetectorTestCase):
    """Rendered values and observed effects address the blind spot that hid report defects."""

    def test_assert_contains_exempts_the_test(self) -> None:
        """Checking a displayed aggregate would have caught the empty report."""
        source = """
        class ReportPageTests(TestCase):
            def test_the_paid_total_is_rendered(self) -> None:
                response = self.client.get("/x/?status=paid")
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, "Paid total: 300")
        """
        self.assertEqual(self._scan_source(source), [])

    def test_assert_template_used_exempts_the_test(self) -> None:
        """The chosen template is evidence beyond a successful response."""
        source = """
        class ReportPageTests(TestCase):
            def test_the_report_template_is_used(self) -> None:
                response = self.client.get("/x/?status=paid")
                self.assertEqual(response.status_code, 200)
                self.assertTemplateUsed(response, "reports.html")
        """
        self.assertEqual(self._scan_source(source), [])

    def test_a_mock_call_assertion_exempts_the_test(self) -> None:
        """The first boundary incorrectly treated observed mock calls as no evidence."""
        source = """
        class InvoiceActionTests(TestCase):
            def test_the_paid_state_is_converged(self) -> None:
                with patch("apps.billing.views.converge") as converge:
                    response = self.client.post("/x/", data={"status": "paid"})
                self.assertEqual(response.status_code, 200)
                converge.assert_called_once_with(status="paid")
        """
        self.assertEqual(self._scan_source(source), [])

    def test_an_assertion_on_context_data_exempts_the_test(self) -> None:
        """A context assertion checks computed data that a bare 200 leaves unverified."""
        source = """
        class ReportPageTests(TestCase):
            def test_the_filtered_rows_are_available(self) -> None:
                response = self.client.get("/x/?status=paid")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(len(response.context["rows"]), 3)
        """
        self.assertEqual(self._scan_source(source), [])

    def test_an_assertion_inside_a_helper_one_level_deep_exempts_the_test(self) -> None:
        """Moving a rendered-value assertion into a helper must not erase its credit."""
        source = """
        class ReportPageTests(TestCase):
            def _assert_rows(self, response: HttpResponse) -> None:
                self.assertContains(response, "INV-001")

            def test_the_filtered_rows_are_rendered(self) -> None:
                response = self.client.get("/x/?status=paid")
                self.assertEqual(response.status_code, 200)
                self._assert_rows(response)
        """
        self.assertEqual(self._scan_source(source), [])


class IdentityOnlyExemptionTests(_DetectorTestCase):
    """The matched pair has the same login, request and assertion; only domain state differs.

    This contrast prevents the broad exemption that reduced the findings to 24 from
    hiding a page that should reflect newly created state.
    """

    def test_logging_in_and_rendering_a_page_is_not_flagged(self) -> None:
        """The 200 proves successful authorisation when no domain state is varied."""
        source = """
        class TicketPageTests(TestCase):
            def test_the_ticket_page_is_accessible(self) -> None:
                self.client.force_login(self.user)
                response = self.client.get("/x/")
                self.assertEqual(response.status_code, 200)
        """
        self.assertEqual(self._scan_source(source), [])

    def test_the_same_request_with_domain_state_is_flagged(self) -> None:
        """Adding a ticket creates an obligation to check more than authorisation."""
        source = """
        class TicketPageTests(TestCase):
            def test_the_ticket_page_is_accessible(self) -> None:
                self.client.force_login(self.user)
                Ticket.objects.create(customer=self.customer, subject="Billing question")
                response = self.client.get("/x/")
                self.assertEqual(response.status_code, 200)
        """
        self.assertEqual(self._scan_source(source), ["test_sample.py::test_the_ticket_page_is_accessible"])

    def test_creating_the_user_it_logs_in_as_is_not_domain_state(self) -> None:
        """Establishing WHO is asking is the identity act, not state the page should reflect.

        `test_maintenance_gate.py::test_staff_still_pass_through` is the real case: maintenance is
        enabled, a staff user logs in, and the 200 IS the assertion - it proves the middleware's staff
        bypass works, and would be 503 if the bypass broke. It was flagged only because the user
        factory's name matched a domain-state pattern.
        """
        source = """
        class MaintenanceGateTests(TestCase):
            def test_staff_still_pass_through(self) -> None:
                self._enable()
                self.client.force_login(create_admin_user(username="gate_admin"))
                response = self.client.get("/settings/")
                self.assertEqual(response.status_code, 200)
        """
        self.assertEqual(self._scan_source(source), [])

    def test_the_same_user_bound_to_a_variable_first_is_also_identity(self) -> None:
        """The two-line form is written just as often as the nested one and means the same thing."""
        source = """
        class MaintenanceGateTests(TestCase):
            def test_staff_still_pass_through(self) -> None:
                staff = create_staff_user(username="gate_admin")
                self.client.force_login(staff)
                response = self.client.get("/settings/")
                self.assertEqual(response.status_code, 200)
        """
        self.assertEqual(self._scan_source(source), [])

    def test_a_user_created_but_never_logged_in_as_is_domain_state(self) -> None:
        """The guard against over-correcting: a user the test does NOT authenticate as is a subject
        the page is expected to show, so a status-only assertion still leaves it unverified."""
        source = """
        class TeamPageTests(TestCase):
            def test_the_team_page_lists_the_new_member(self) -> None:
                create_user(username="newcomer")
                self.client.force_login(self.owner)
                response = self.client.get("/team/")
                self.assertEqual(response.status_code, 200)
        """
        self.assertEqual(self._scan_source(source), ["test_sample.py::test_the_team_page_lists_the_new_member"])


class NonRequestTests(_DetectorTestCase):
    """The page-response gate must leave pure unit tests outside its scope."""

    def test_a_test_that_issues_no_request_is_ignored(self) -> None:
        """Checking a function result must not acquire an HTTP assertion requirement."""
        source = """
        class VatCalculationTests(SimpleTestCase):
            def test_vat_is_calculated_in_minor_units(self) -> None:
                self.assertEqual(calculate_vat(10000, 19), 1900)
        """
        self.assertEqual(self._scan_source(source), [])


class RatchetTests(_DetectorTestCase):
    """Existing debt is allowed, but new findings and stale entries must both block builds."""

    SOURCE = (
        "class InvoicePageTests(TestCase):\n"
        "    def test_paid_invoices_are_shown(self) -> None:\n"
        '        Invoice.objects.create(customer=self.customer, status="paid")\n'
        '        response = self.client.get("/x/")\n'
        "        self.assertEqual(response.status_code, 200)\n"
    )
    FINDING = "test_sample.py::test_paid_invoices_are_shown"

    def test_findings_matching_the_baseline_exit_zero(self) -> None:
        """Known debt must not make the new blocking target fail immediately."""
        self.assertEqual(self._scan_source(self.SOURCE), [self.FINDING])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test_sample.py").write_text(self.SOURCE, encoding="utf-8")
            baseline = root / "baseline.txt"
            baseline.write_text(f"# Existing debt\n{self.FINDING}\n", encoding="utf-8")
            stdout = io.StringIO()
            with (
                patch.object(audit, "PROJECT_ROOT", root),
                patch.object(audit, "TEST_DIRS", (root,)),
                patch.object(sys, "argv", ["audit_test_assertion_quality.py", "--baseline", str(baseline)]),
                contextlib.redirect_stdout(stdout),
            ):
                result = audit.main()

        self.assertEqual(result, 0)
        self.assertIn("No new status-only tests", stdout.getvalue())

    def test_a_new_finding_exits_one_and_names_the_test(self) -> None:
        """An unlisted bare 200 must fail with enough detail to find the offending test."""
        self.assertEqual(self._scan_source(self.SOURCE), [self.FINDING])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test_sample.py").write_text(self.SOURCE, encoding="utf-8")
            baseline = root / "baseline.txt"
            baseline.write_text("# No existing debt\n", encoding="utf-8")
            stdout = io.StringIO()
            with (
                patch.object(audit, "PROJECT_ROOT", root),
                patch.object(audit, "TEST_DIRS", (root,)),
                patch.object(sys, "argv", ["audit_test_assertion_quality.py", "--baseline", str(baseline)]),
                contextlib.redirect_stdout(stdout),
            ):
                result = audit.main()

        self.assertEqual(result, 1)
        self.assertIn("test_paid_invoices_are_shown", stdout.getvalue())

    def test_a_baselined_entry_that_no_longer_appears_exits_one(self) -> None:
        """A real assertion must force removal of its obsolete baseline allowance."""
        source = self.SOURCE + '        self.assertContains(response, "INV-001")\n'
        self.assertEqual(self._scan_source(source), [])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test_sample.py").write_text(source, encoding="utf-8")
            baseline = root / "baseline.txt"
            baseline.write_text(f"# Existing debt\n{self.FINDING}\n", encoding="utf-8")
            stdout = io.StringIO()
            with (
                patch.object(audit, "PROJECT_ROOT", root),
                patch.object(audit, "TEST_DIRS", (root,)),
                patch.object(sys, "argv", ["audit_test_assertion_quality.py", "--baseline", str(baseline)]),
                contextlib.redirect_stdout(stdout),
            ):
                result = audit.main()

        self.assertEqual(result, 1)
        self.assertIn(self.FINDING, stdout.getvalue())
        self.assertIn("Remove it from the baseline.", stdout.getvalue())

    def test_write_baseline_records_the_current_findings(self) -> None:
        """Regenerating the allowance must replace stale entries with the actual findings."""
        self.assertEqual(self._scan_source(self.SOURCE), [self.FINDING])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test_sample.py").write_text(self.SOURCE, encoding="utf-8")
            baseline = root / "baseline.txt"
            baseline.write_text("# Stale debt\ntest_sample.py::test_removed_page\n", encoding="utf-8")
            stdout = io.StringIO()
            with (
                patch.object(audit, "PROJECT_ROOT", root),
                patch.object(audit, "TEST_DIRS", (root,)),
                patch.object(
                    sys,
                    "argv",
                    ["audit_test_assertion_quality.py", "--baseline", str(baseline), "--write-baseline"],
                ),
                contextlib.redirect_stdout(stdout),
            ):
                result = audit.main()

            entries = [
                line.strip()
                for line in baseline.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]

        self.assertEqual(result, 0)
        self.assertEqual(entries, [self.FINDING])
        self.assertIn("baseline written: 1 entries", stdout.getvalue())
