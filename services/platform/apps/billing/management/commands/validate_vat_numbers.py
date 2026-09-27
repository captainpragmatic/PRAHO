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
        from django_q.tasks import async_task  # noqa: PLC0415

        from apps.billing.tasks import validate_vat_number  # noqa: PLC0415
        from apps.common.eu_vat_validator import is_eu_country, parse_vat_number  # noqa: PLC0415
        from apps.customers.models import CustomerTaxProfile  # noqa: PLC0415

        if options["blocked_orders"]:
            self._report_blocked_orders()

        processed = 0
        failed = 0
        profiles = CustomerTaxProfile.objects.exclude(vat_number="").exclude(
            vies_verification_status=CustomerTaxProfile.VIESVerificationStatus.VALID
        )
        for profile in profiles.order_by("pk").iterator():
            try:
                country = parse_vat_number(profile.vat_number)[0]
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
        from apps.billing.vies_evidence import vat_number_matches_country, vies_verified_for  # noqa: PLC0415
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
            evidenced = (
                profile is not None
                and profile.is_vat_payer is True
                and vies_verified_for(profile, vat_number)
                and vat_number_matches_country(vat_number, country)
            )
            if not evidenced:
                blocked.append(str(order.pk))
        self.stdout.write(_("Blocked orders: %(count)d") % {"count": len(blocked)})
        for order_id in blocked:
            self.stdout.write(order_id)
