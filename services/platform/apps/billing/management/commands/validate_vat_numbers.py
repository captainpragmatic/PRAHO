"""Validate EU VAT profiles and report unpaid orders missing VIES evidence."""

from argparse import ArgumentParser

from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand
from django.utils.translation import gettext as _


class Command(BaseCommand):
    help = _("Validate EU VAT numbers without a valid VIES status.")

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("--sync", action="store_true", help=_("Run validations synchronously."))
        parser.add_argument("--blocked-orders", action="store_true", help=_("Report unpaid zero-tax EU orders."))

    def handle(self, *args: str, **options: object) -> None:
        from django.db.models import Q  # noqa: PLC0415
        from django_q.tasks import async_task  # noqa: PLC0415

        from apps.billing.tasks import validate_vat_number  # noqa: PLC0415
        from apps.billing.vies_evidence import (  # noqa: PLC0415
            profile_vat_identity,
            profiles_needing_vies_evidence,
        )
        from apps.common.eu_vat_validator import is_eu_country  # noqa: PLC0415
        from apps.customers.models import CustomerTaxProfile  # noqa: PLC0415

        if options["blocked_orders"]:
            self._report_blocked_orders()
            self._report_incomplete_profiles()

        processed = 0
        failed = 0
        profiles = CustomerTaxProfile.objects.exclude(vat_number="").filter(
            ~Q(vies_verification_status=CustomerTaxProfile.VIESVerificationStatus.VALID)
            | Q(pk__in=profiles_needing_vies_evidence().values("pk"))
        )
        for profile in profiles.order_by("pk").iterator():
            try:
                country = profile_vat_identity(profile)[0]
            except ValueError:
                continue
            if not is_eu_country(country):
                continue
            if options["sync"]:
                result = validate_vat_number(str(profile.pk))
                if not result["success"]:
                    failed += 1
            else:
                async_task("apps.billing.tasks.validate_vat_number", str(profile.pk))
            processed += 1

        message = _("Validated: %(count)d; failed: %(failed)d") if options["sync"] else _("Enqueued: %(count)d")
        self.stdout.write(message % {"count": processed, "failed": failed})

    def _report_blocked_orders(self) -> None:
        from apps.billing.vies_evidence import vat_number_matches_country, vies_refusal_reason  # noqa: PLC0415
        from apps.common.localisation import normalize_country_code  # noqa: PLC0415
        from apps.common.tax_service import TaxService  # noqa: PLC0415
        from apps.orders.models import Order  # noqa: PLC0415

        blocked: list[str] = []
        orders = Order.objects.filter(status__in=["draft", "awaiting_payment", "failed"], tax_cents=0).select_related(
            "customer__tax_profile"
        )
        for order in orders.order_by("pk").iterator():
            billing = order.billing_address or {}
            country = normalize_country_code(billing.get("country"))
            if not country or not TaxService.is_eu_country(country) or country == TaxService.get_supplier_country():
                continue
            try:
                profile = order.customer.tax_profile
            except ObjectDoesNotExist:
                profile = None
            vat_number = billing.get("vat_number") or billing.get("vat_id")
            # Mirror the resolver: evidence counts only for a VAT payer whose verified number
            # is the invoiced one and was issued by the billing country.
            # The pure decision: a report must not record refusals as if invoices were issued.
            evidenced = (
                profile is not None
                and profile.is_vat_payer is True
                and not vies_refusal_reason(
                    profile,
                    vat_number,
                    billing_name=str(billing.get("company_name") or order.customer.get_billing_name()),
                )
                and vat_number_matches_country(vat_number, country)
            )
            if not evidenced:
                blocked.append(str(order.pk))
        self.stdout.write(_("Blocked orders: %(count)d") % {"count": len(blocked)})
        for order_id in blocked:
            self.stdout.write(order_id)

    def _report_incomplete_profiles(self) -> None:
        """List valid profiles the evidence policy would refuse, and zero overrides that now need a reason."""
        from apps.billing.vies_evidence import vies_refusal_reason  # noqa: PLC0415
        from apps.common.tax_service import TaxService  # noqa: PLC0415
        from apps.customers.models import CustomerTaxProfile  # noqa: PLC0415

        valid_profiles = (
            CustomerTaxProfile.objects.filter(vies_verification_status="valid")
            .exclude(vat_number="")
            .select_related("customer")
            .order_by("pk")
        )
        for profile in valid_profiles.iterator():
            reason = vies_refusal_reason(profile, profile.vat_number)
            if reason:
                self.stdout.write(
                    _("Blocked profile %(profile)s: %(reason)s") % {"profile": profile.pk, "reason": reason}
                )
        overrides = (
            CustomerTaxProfile.objects.filter(vat_rate=0, vat_rate_reason="", is_vat_payer=True)
            .exclude(vat_number="")
            .select_related("customer")
            .order_by("pk")
        )
        for profile in overrides.iterator():
            address = profile.customer.get_billing_address()
            country = (address.country if address else "").upper()
            if TaxService.is_eu_country(country) and country != TaxService.get_supplier_country():
                self.stdout.write(
                    _("Zero override without a reason: profile %(profile)s (%(country)s)")
                    % {"profile": profile.pk, "country": country}
                )
