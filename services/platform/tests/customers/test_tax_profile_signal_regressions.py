"""Regression coverage for CustomerTaxProfile change detection."""

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase

from apps.customers.models import Customer, CustomerTaxProfile


class CustomerTaxProfileSignalRegressionTests(TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Tax Signal Customer",
            customer_type=Customer.CustomerType.COMPANY,
            company_name="Tax Signal Customer SRL",
            primary_email="tax-signal@example.test",
        )

    def _create_profile(self) -> CustomerTaxProfile:
        with (
            patch("apps.audit.services.CustomersAuditService.log_tax_profile_event"),
            patch("apps.customers.signals._validate_romanian_cui"),
            patch("apps.customers.signals._trigger_vat_validation"),
            patch("apps.customers.signals.AuditService.log_compliance_event"),
        ):
            return CustomerTaxProfile.objects.create(
                customer=self.customer,
                cui="RO12345678",
                vat_number="RO12345678",
                is_vat_payer=True,
                vat_rate=Decimal("21.00"),
            )

    def test_unrelated_vies_result_save_has_no_tax_side_effects(self) -> None:
        profile = self._create_profile()

        with (
            patch("apps.audit.services.CustomersAuditService.log_tax_profile_event") as audit_tax_profile,
            patch("apps.customers.signals._validate_romanian_cui") as validate_cui,
            patch("apps.customers.signals._trigger_vat_validation") as validate_vat,
            patch("apps.customers.signals.AuditService.log_compliance_event") as compliance_audit,
        ):
            profile.vies_verification_status = CustomerTaxProfile.VIESVerificationStatus.VALID
            profile.save(update_fields=["vies_verification_status"])

        audit_tax_profile.assert_not_called()
        validate_cui.assert_not_called()
        validate_vat.assert_not_called()
        compliance_audit.assert_not_called()

    def test_vat_number_change_queues_one_validation_and_one_audit(self) -> None:
        profile = self._create_profile()

        with (
            patch("apps.audit.services.CustomersAuditService.log_tax_profile_event") as audit_tax_profile,
            patch("apps.customers.signals._validate_romanian_cui") as validate_cui,
            patch("apps.customers.signals._trigger_vat_validation") as validate_vat,
            patch("apps.customers.signals.AuditService.log_compliance_event") as compliance_audit,
        ):
            profile.vat_number = "DE123456789"
            profile.save(update_fields=["vat_number"])

        # Romanian registrations write the ComplianceLog only — the AuditEvent
        # would restate it (#241 dedup, landed with the audit module).
        audit_tax_profile.assert_not_called()
        validate_cui.assert_not_called()
        validate_vat.assert_called_once_with(profile)
        compliance_audit.assert_called_once()

    def test_vies_result_update_does_not_queue_recursive_validation(self) -> None:
        profile = self._create_profile()

        with (
            patch("apps.audit.services.CustomersAuditService.log_tax_profile_event") as audit_tax_profile,
            patch("apps.customers.signals._validate_romanian_cui") as validate_cui,
            patch("apps.customers.signals._trigger_vat_validation") as validate_vat,
            patch("apps.customers.signals.AuditService.log_compliance_event") as compliance_audit,
        ):
            profile.vies_verification_status = CustomerTaxProfile.VIESVerificationStatus.VALID
            profile.reverse_charge_eligible = True
            profile.save(
                update_fields=[
                    "vies_verification_status",
                    "reverse_charge_eligible",
                ]
            )

        audit_tax_profile.assert_not_called()  # RO registration: ComplianceLog only (#241 dedup)
        validate_cui.assert_not_called()
        validate_vat.assert_not_called()
        compliance_audit.assert_called_once()

    def test_repeated_timestamp_save_does_not_reuse_stale_change_evidence(self) -> None:
        profile = self._create_profile()

        with (
            patch("apps.audit.services.CustomersAuditService.log_tax_profile_event") as audit_tax_profile,
            patch("apps.customers.signals._validate_romanian_cui"),
            patch("apps.customers.signals._trigger_vat_validation") as validate_vat,
            patch("apps.customers.signals.AuditService.log_compliance_event") as compliance_audit,
        ):
            profile.vat_number = "FR12345678901"
            profile.save(update_fields=["vat_number"])
            profile.save(update_fields=["updated_at"])

        # The timestamp-only save must not re-fire any side effect: the pre-save
        # snapshot is refreshed per save, so counts stay at the first save's values.
        self.assertEqual(audit_tax_profile.call_count, 0)  # RO registration: ComplianceLog only
        self.assertEqual(validate_vat.call_count, 1)
        self.assertEqual(compliance_audit.call_count, 1)

    def test_non_romanian_profile_change_writes_one_audit_event(self) -> None:
        """Non-RO registrations have no ComplianceLog path — they keep the AuditEvent."""
        with (
            patch("apps.audit.services.CustomersAuditService.log_tax_profile_event"),
            patch("apps.customers.signals._validate_romanian_cui"),
            patch("apps.customers.signals._trigger_vat_validation"),
            patch("apps.customers.signals.AuditService.log_compliance_event"),
        ):
            profile = CustomerTaxProfile.objects.create(
                customer=self.customer,
                cui="",
                vat_number="DE999999999",
                is_vat_payer=True,
                vat_rate=Decimal("19.00"),
            )

        with (
            patch("apps.audit.services.CustomersAuditService.log_tax_profile_event") as audit_tax_profile,
            patch("apps.customers.signals._validate_romanian_cui") as validate_cui,
            patch("apps.customers.signals._trigger_vat_validation") as validate_vat,
            patch("apps.customers.signals.AuditService.log_compliance_event") as compliance_audit,
        ):
            profile.vat_number = "DE123456789"
            profile.save(update_fields=["vat_number"])

        audit_tax_profile.assert_called_once()
        validate_cui.assert_not_called()
        validate_vat.assert_called_once_with(profile)
        compliance_audit.assert_not_called()
