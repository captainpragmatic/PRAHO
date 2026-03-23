"""
Django management command to generate sample data for PRAHO Platform
Romanian hosting provider test data generation.
"""

import contextlib
import logging
import random
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import transaction
from django.utils import timezone
from faker import Faker

from apps.billing.currency_models import FXRate
from apps.billing.invoice_models import InvoiceSequence
from apps.billing.models import Currency, Invoice, InvoiceLine, ProformaInvoice, ProformaLine, TaxRule
from apps.billing.payment_models import CreditLedger, Payment
from apps.billing.proforma_models import ProformaSequence
from apps.billing.refund_models import Refund
from apps.billing.subscription_models import Subscription, SubscriptionItem
from apps.customers.models import (
    Customer,
    CustomerAddress,
    CustomerBillingProfile,
    CustomerNote,
    CustomerPaymentMethod,
    CustomerTaxProfile,
)
from apps.domains.models import TLD, Domain, Registrar, TLDRegistrarAssignment
from apps.integrations.models import WebhookEvent
from apps.notifications.models import EmailPreference
from apps.orders.models import Order, OrderItem
from apps.products.models import Product, ProductPrice
from apps.provisioning.models import Server, Service, ServicePlan
from apps.tickets.models import SupportCategory, Ticket, TicketComment, TicketWorklog
from apps.users.models import CustomerMembership

if TYPE_CHECKING:
    from apps.users.models import User
else:
    User = get_user_model()


@dataclass
class SampleDataConfig:
    """Configuration parameters for sample data generation"""

    services_count: int
    orders_count: int
    invoices_count: int
    proformas_count: int
    tickets_count: int


_ROMANIAN_COUNTIES: list[str] = ["București", "Cluj", "Timiș", "Iași", "Constanța", "Brașov"]

_ROMANIAN_CITIES: list[tuple[str, str]] = [
    ("București", "București"),
    ("Cluj-Napoca", "Cluj"),
    ("Timișoara", "Timiș"),
    ("Iași", "Iași"),
    ("Constanța", "Constanța"),
    ("Brașov", "Brașov"),
    ("Sibiu", "Sibiu"),
    ("Oradea", "Bihor"),
]


def _cycle(items: list[Any], index: int) -> Any:
    """Round-robin select from a list by index. DRY helper for the ubiquitous items[i % len(items)] pattern."""
    if not items:
        raise ValueError("_cycle() requires a non-empty list")
    return items[index % len(items)]


class Command(BaseCommand):
    help = "Generate sample data for Romanian hosting provider"

    # NOTE: Django's objects.create() does NOT call full_clean() or clean().
    # All generated field values must manually satisfy model validators and DB constraints.

    def _get_admin_user(self) -> "User | None":
        """Cached admin user lookup — used by 6+ methods."""
        if not hasattr(self, "_admin_user"):
            self._admin_user = User.objects.filter(is_superuser=True).first()
        return self._admin_user

    def _get_ron_currency(self) -> Currency:
        """Cached RON currency lookup — used by 5+ methods."""
        if not hasattr(self, "_ron_currency"):
            self._ron_currency = Currency.objects.get(code="RON")
        return self._ron_currency

    def _get_ro_tax_rule(self) -> TaxRule:
        """Cached Romanian VAT tax rule — used by invoices, proformas, payments."""
        if not hasattr(self, "_ro_tax_rule"):
            self._ro_tax_rule, _ = TaxRule.objects.get_or_create(
                country_code="RO",
                tax_type="vat",
                valid_from=date(2025, 8, 1),
                defaults={
                    "rate": Decimal("0.21"),
                    "applies_to_b2b": True,
                    "applies_to_b2c": True,
                    "reverse_charge_eligible": True,
                    "is_eu_member": True,
                    "vies_required": True,
                },
            )
        return self._ro_tax_rule

    @staticmethod
    def _billing_address_snapshot(customer: Customer) -> dict[str, str]:
        """Build billing address JSON snapshot from customer — used by orders, invoices, proformas."""
        billing_addr = customer.addresses.filter(is_billing=True, is_current=True).first() or customer.addresses.first()
        if not billing_addr:
            return {}
        return {
            "address_line1": billing_addr.address_line1,
            "address_line2": billing_addr.address_line2,
            "city": billing_addr.city,
            "county": billing_addr.county,
            "postal_code": billing_addr.postal_code,
            "country": billing_addr.country,
        }

    @staticmethod
    def _customer_tax_id(customer: Customer) -> str:
        """Get customer CUI/VAT ID for billing documents — used by orders, invoices, proformas."""
        tax_profile = customer.get_tax_profile()
        return tax_profile.cui if tax_profile and tax_profile.cui else ""

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--customers", type=int, default=5, help="Number of customers to create")
        parser.add_argument("--users", type=int, default=10, help="Number of users to create")
        parser.add_argument("--services-per-customer", type=int, default=5, help="Number of services per customer")
        parser.add_argument("--orders-per-customer", type=int, default=3, help="Number of orders per customer")
        parser.add_argument("--invoices-per-customer", type=int, default=5, help="Number of invoices per customer")
        parser.add_argument("--proformas-per-customer", type=int, default=5, help="Number of proformas per customer")
        parser.add_argument("--tickets-per-customer", type=int, default=5, help="Number of tickets per customer")

    def handle(self, *args: Any, **options: Any) -> None:
        # Simple safety check - must be in DEBUG mode
        if not settings.DEBUG:
            raise CommandError(
                "🚫 Sample data generation only works in DEBUG mode. This prevents accidental production usage."
            )

        # Suppress noisy signal/audit/django-q INFO logging during fixture generation.
        # Errors and warnings still surface. The audit trail is stored in DB regardless.
        noisy_loggers = [logging.getLogger(name) for name in ("apps", "django-q")]
        prev_levels = [lgr.level for lgr in noisy_loggers]
        for lgr in noisy_loggers:
            lgr.setLevel(logging.WARNING)

        try:
            self._generate(options)
        finally:
            for lgr, level in zip(noisy_loggers, prev_levels, strict=True):
                lgr.setLevel(level)

    def _generate(self, options: dict[str, Any]) -> None:
        fake = Faker("ro_RO")  # Romanian locale
        Faker.seed(42)  # Consistent data

        self.stdout.write("�� Generating comprehensive test data for PragmaticHost...")

        # Create foundation data first
        self.create_admin_users(fake)
        self.create_service_plans()
        self.create_servers()
        self.create_support_categories()
        self.create_billing_foundation()
        self.create_domain_foundation()

        # Create customers and all their related data
        num_customers = options["customers"]
        num_users = options["users"]
        services_per_customer = options["services_per_customer"]
        orders_per_customer = options["orders_per_customer"]
        invoices_per_customer = options["invoices_per_customer"]
        proformas_per_customer = options["proformas_per_customer"]
        tickets_per_customer = options["tickets_per_customer"]

        # Create all users first
        self.stdout.write(f"Creating {num_users} users...")
        users = self.create_users(fake, num_users)

        # Create the guaranteed test company first (will always have ID #1)
        config = SampleDataConfig(
            services_count=services_per_customer,
            orders_count=orders_per_customer,
            invoices_count=invoices_per_customer,
            proformas_count=proformas_per_customer,
            tickets_count=tickets_per_customer,
        )
        test_customer = self.create_test_company_customer(fake, users, config)
        customers = [test_customer]
        self.stdout.write(f"  ✓ Created guaranteed test customer #1: {test_customer.get_display_name()}")
        self.ensure_e2e_users(test_customer)

        # Create deterministic permutation customers covering all choice combinations
        permutation_customers = self._create_customer_permutations(fake, users)
        customers.extend(permutation_customers)

        # Create remaining customers with comprehensive data
        remaining_customers = max(0, num_customers - 1)  # -1 because we already created the test customer
        if remaining_customers > 0:
            self.stdout.write(f"Creating {remaining_customers} additional customers with complete data...")
            for i in range(remaining_customers):
                customer = self.create_customer_with_data(
                    fake,
                    i + 1,
                    users,
                    config,  # i + 1 to continue numbering after test customer
                )
                customers.append(customer)
                self.stdout.write(f"  ✓ Complete customer {i + 2}/{num_customers}: {customer.get_display_name()}")
        else:
            self.stdout.write("Only creating the guaranteed test customer.")

        # Create webhook events (not tied to specific customers)
        self.create_webhook_events()

        total_customers = len(customers)
        self.stdout.write(
            self.style.SUCCESS(
                f"✅ Success! Generated: {total_customers} customers "
                f"(1 test + 8 permutation + {max(0, num_customers - 1)} random), "
                f"{num_users} users, "
                f"{Service.objects.count()} services, "
                f"{Order.objects.count()} orders, "
                f"{Invoice.objects.count() + ProformaInvoice.objects.count()} billing documents, "
                f"{Payment.objects.count()} payments, "
                f"{Subscription.objects.count()} subscriptions, "
                f"{Refund.objects.count()} refunds, "
                f"{Domain.objects.count()} domains, "
                f"{Ticket.objects.count()} tickets ({TicketComment.objects.count()} comments), "
                f"{WebhookEvent.objects.count()} webhook events"
            )
        )

        self._print_credentials()

    def _print_credentials(self) -> None:
        """Print available login credentials table."""
        self.stdout.write("")
        self.stdout.write("━" * 60)
        self.stdout.write(self.style.SUCCESS("  Available login credentials"))
        self.stdout.write("━" * 60)
        self.stdout.write(f"  {'Role':<16} {'Email':<38} {'Password'}")
        self.stdout.write(f"  {'─' * 16} {'─' * 38} {'─' * 12}")
        self.stdout.write(f"  {'Admin':<16} {'admin@pragmatichost.com':<38} admin123")
        self.stdout.write(f"  {'Support':<16} {'john@pragmatichost.com':<38} support123")
        self.stdout.write(f"  {'Support':<16} {'jane@pragmatichost.com':<38} support123")
        self.stdout.write(f"  {'Support':<16} {'mike@pragmatichost.com':<38} support123")
        self.stdout.write(f"  {'Manager':<16} {'manager@pragmatichost.com':<38} manager123")
        self.stdout.write(f"  {'Customer':<16} {'customer@pragmatichost.com':<38} testpass123")
        self.stdout.write(f"  {'Multi-company':<16} {'multi-company@example.com':<38} testpass123")
        self.stdout.write(f"  {'Suspended':<16} {'suspended@example.com':<38} testpass123")
        self.stdout.write(f"  {'E2E Admin':<16} {'e2e-admin@test.local':<38} test123")
        self.stdout.write(f"  {'E2E Customer':<16} {'e2e-customer@test.local':<38} test123")
        self.stdout.write("━" * 60)
        self.stdout.write("  Platform: http://localhost:8700")
        self.stdout.write("  Portal:   http://localhost:8701")
        self.stdout.write("━" * 60)

    def create_admin_users(self, fake: Faker) -> None:
        self.stdout.write("Creating admin users...")

        # Create superuser with consistent credentials for E2E testing
        # Note: These are development/test credentials only - DEBUG mode enforced above
        if not User.objects.filter(email="admin@pragmatichost.com").exists():
            admin_user = User.objects.create_superuser(
                first_name="Admin",
                last_name="PRAHO",
                email="admin@pragmatichost.com",
                password="admin123",  # Dev/test only - protected by DEBUG check
            )
            self.stdout.write(f"  ✓ Admin: {admin_user.email}")

        # Create support users
        support_users = [
            ("John", "Doe", "john@pragmatichost.com"),
            ("Jane", "Smith", "jane@pragmatichost.com"),
            ("Mike", "Johnson", "mike@pragmatichost.com"),
        ]

        for first, last, email in support_users:
            if not User.objects.filter(email=email).exists():
                user = User.objects.create_user(
                    first_name=first,
                    last_name=last,
                    email=email,
                    password="support123",  # Dev/test only
                    staff_role="support",
                    is_active=True,
                )
                self.stdout.write(f"  ✓ Support: {user.email}")

    def ensure_e2e_users(self, test_customer: Customer) -> None:
        """Ensure deterministic E2E users required by Playwright flows."""
        self.stdout.write("Ensuring deterministic E2E users...")

        # E2E admin for platform login helpers
        e2e_admin, _ = User.objects.get_or_create(
            email="e2e-admin@test.local",
            defaults={
                "first_name": "E2E",
                "last_name": "Admin",
                "is_staff": True,
                "is_superuser": True,
                "is_active": True,
                "staff_role": "admin",
            },
        )
        e2e_admin.is_active = True
        e2e_admin.is_staff = True
        e2e_admin.is_superuser = True
        e2e_admin.staff_role = "admin"
        e2e_admin.set_password("test123")  # nosemgrep: unvalidated-password — test fixture data, not user-facing
        e2e_admin.save()
        self.stdout.write("  ✓ E2E admin: e2e-admin@test.local")

        # Ensure E2E admin has a customer membership (required for portal login)
        CustomerMembership.objects.update_or_create(
            user=e2e_admin,
            customer=test_customer,
            defaults={
                "role": "owner",
                "is_primary": True,
                "is_active": True,
                "created_by": e2e_admin,
            },
        )
        self.stdout.write(f"  ✓ Linked E2E admin to: {test_customer.get_display_name()}")

        # E2E customer for portal login helpers
        e2e_customer, _ = User.objects.get_or_create(
            email="e2e-customer@test.local",
            defaults={
                "first_name": "E2E",
                "last_name": "Customer",
                "is_staff": False,
                "is_superuser": False,
                "is_active": True,
            },
        )
        e2e_customer.is_active = True
        e2e_customer.is_staff = False
        e2e_customer.is_superuser = False
        e2e_customer.set_password("test123")  # nosemgrep: unvalidated-password — test fixture data, not user-facing
        e2e_customer.save()
        self.stdout.write("  ✓ E2E customer: e2e-customer@test.local")

        CustomerMembership.objects.update_or_create(
            user=e2e_customer,
            customer=test_customer,
            defaults={
                "role": "owner",
                "is_primary": True,
                "is_active": True,
                "created_by": e2e_admin,
            },
        )
        self.stdout.write(f"  ✓ Linked E2E customer to: {test_customer.get_display_name()}")

    def create_service_plans(self) -> list[ServicePlan]:
        self.stdout.write("Creating service plans...")

        plans = [
            {
                "name": "Web Hosting Starter",
                "plan_type": "shared_hosting",
                "description": (
                    "Pachet ideal pentru site-uri personale și mici afaceri. "
                    "Include 5 GB spațiu SSD, 50 GB transfer lunar, 10 conturi email "
                    "și 2 baze de date MySQL. Găzduit pe servere optimizate LiteSpeed "
                    "cu certificat SSL gratuit și panou de control cPanel inclus."
                ),
                "price_monthly": Decimal("29.99"),
                "price_annual": Decimal("299.90"),
                "disk_space_gb": 5,
                "bandwidth_gb": 50,
                "email_accounts": 10,
                "databases": 2,
                "domains": 1,
            },
            {
                "name": "Web Hosting Professional",
                "plan_type": "shared_hosting",
                "description": (
                    "Soluție completă pentru site-uri de business și magazine online. "
                    "20 GB spațiu SSD NVMe, 200 GB transfer lunar, 50 conturi email, "
                    "10 baze de date MySQL și suport pentru 5 domenii. "
                    "Include backup zilnic automat, CDN gratuit și suport prioritar 24/7."
                ),
                "price_monthly": Decimal("59.99"),
                "price_annual": Decimal("599.90"),
                "disk_space_gb": 20,
                "bandwidth_gb": 200,
                "email_accounts": 50,
                "databases": 10,
                "domains": 5,
            },
            {
                "name": "VPS Basic",
                "plan_type": "vps",
                "description": (
                    "Server virtual privat entry-level pentru aplicații și site-uri cu trafic mediu. "
                    "2 vCPU, 4 GB RAM DDR4, 80 GB SSD NVMe. "
                    "Acces root complet, IP dedicat, snapshots automate și monitorizare inclusă. "
                    "Ideal pentru magazine online, aplicații Node.js/Python sau servere de email."
                ),
                "price_monthly": Decimal("99.99"),
                "price_annual": Decimal("999.90"),
                "cpu_cores": 2,
                "ram_gb": 4,
                "disk_space_gb": 80,
            },
            {
                "name": "VPS Advanced",
                "plan_type": "vps",
                "description": (
                    "Server virtual performant pentru aplicații intensive și trafic ridicat. "
                    "4 vCPU, 8 GB RAM DDR4, 160 GB SSD NVMe RAID-10. "
                    "Include IP dedicat, backup zilnic, protecție DDoS și SLA 99.9%. "
                    "Recomandat pentru platforme e-commerce, ERP sau aplicații SaaS."
                ),
                "price_monthly": Decimal("199.99"),
                "price_annual": Decimal("1999.90"),
                "cpu_cores": 4,
                "ram_gb": 8,
                "disk_space_gb": 160,
            },
        ]

        created_plans = []
        for plan_data in plans:
            plan, created = ServicePlan.objects.get_or_create(name=plan_data["name"], defaults=plan_data)
            created_plans.append(plan)
            if created:
                self.stdout.write(f"  ✓ Plan: {plan.name}")

        return created_plans

    def create_servers(self) -> list[Server]:
        self.stdout.write("Creating servers...")

        servers = [
            {
                "name": "WEB01",
                "hostname": "web01.pragmatichost.com",
                "server_type": "shared",
                "primary_ip": "185.123.45.67",
                "location": "București",
                "datacenter": "DataCenter București",
                "cpu_model": "Intel Xeon E5-2630v4",
                "cpu_cores": 20,
                "ram_gb": 64,
                "disk_type": "SSD",
                "disk_capacity_gb": 2000,
                "os_type": "CentOS 8",
                "control_panel": "cPanel",
            },
            {
                "name": "VPS01",
                "hostname": "vps01.pragmatichost.com",
                "server_type": "vps_host",
                "primary_ip": "185.123.45.68",
                "location": "București",
                "datacenter": "DataCenter București",
                "cpu_model": "Intel Xeon Gold 6248R",
                "cpu_cores": 48,
                "ram_gb": 256,
                "disk_type": "NVMe",
                "disk_capacity_gb": 4000,
                "os_type": "Ubuntu 22.04",
                "control_panel": "Virtualizor",
            },
        ]

        created_servers = []
        for server_data in servers:
            server, created = Server.objects.get_or_create(hostname=server_data["hostname"], defaults=server_data)
            created_servers.append(server)
            if created:
                self.stdout.write(f"  ✓ Server: {server.name}")

        return created_servers

    def create_support_categories(self) -> list[SupportCategory]:
        self.stdout.write("Creating support categories...")

        categories = [
            {
                "name": "Problemă tehnică",
                "name_en": "Technical Issue",
                "icon": "alert-circle",
                "color": "#EF4444",
                "description": "Issues with hosting services, servers, or technical problems",
            },
            {
                "name": "Întrebare facturare",
                "name_en": "Billing Question",
                "icon": "credit-card",
                "color": "#3B82F6",
                "description": "Questions about invoices, payments, or billing concerns",
            },
            {
                "name": "Cerere serviciu nou",
                "name_en": "New Service Request",
                "icon": "plus-circle",
                "color": "#10B981",
                "description": "Requests for new services or service upgrades",
            },
        ]

        created_categories = []
        for cat_data in categories:
            category, created = SupportCategory.objects.get_or_create(name=cat_data["name"], defaults=cat_data)
            created_categories.append(category)
            if created:
                self.stdout.write(f"  ✓ Categorie: {category.name}")

        return created_categories

    # ===============================================================================
    # COMPREHENSIVE DATA GENERATION METHODS
    # ===============================================================================

    def create_billing_foundation(self) -> None:
        """Create base billing data and clean existing sample data"""
        # Clean existing sample data in proper order to avoid FK constraints.
        # Use all_objects to include soft-deleted records.
        # Match "example." to catch both @example.com and subdomain.example.com emails
        example_filter = {"customer__primary_email__contains": "example."}

        # Delete in reverse dependency order — new models first
        CreditLedger.objects.filter(**example_filter).delete()
        Refund.objects.filter(**example_filter).delete()
        Payment.objects.filter(**example_filter).delete()
        SubscriptionItem.objects.filter(subscription__customer__primary_email__contains="example.").delete()
        Subscription.objects.filter(**example_filter).delete()
        Domain.objects.filter(**example_filter).delete()
        EmailPreference.objects.filter(**example_filter).delete()
        WebhookEvent.objects.filter(source__in=["stripe", "paypal", "virtualmin", "efactura"]).delete()

        # Original models
        Order.objects.filter(**example_filter).delete()
        Invoice.objects.filter(**example_filter).delete()
        ProformaInvoice.objects.filter(**example_filter).delete()
        Ticket.objects.filter(**example_filter).delete()
        Service.objects.filter(**example_filter).delete()
        CustomerMembership.objects.filter(**example_filter).delete()

        # Contact models use SoftDeleteManager — use all_objects to catch soft-deleted
        CustomerNote.all_objects.filter(**example_filter).delete()
        CustomerPaymentMethod.all_objects.filter(**example_filter).delete()
        CustomerAddress.all_objects.filter(**example_filter).delete()
        CustomerTaxProfile.all_objects.filter(**example_filter).delete()
        CustomerBillingProfile.all_objects.filter(**example_filter).delete()

        # Now delete customers (all_objects to include soft-deleted)
        Customer.all_objects.filter(primary_email__contains="example.").delete()

        # Delete users
        User.objects.filter(email__contains="@example.").delete()

        self.stdout.write("✓ Cleaned existing sample data")

        # Create essential billing components
        self.create_billing_essentials()

        # Create Products from ServicePlans if they don't exist
        self.create_products_from_service_plans()

    def create_billing_essentials(self) -> None:
        """Create essential billing components like currencies and tax rules"""
        # Create RON currency if it doesn't exist
        _, created = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "RON", "decimals": 2}
        )
        if created:
            self.stdout.write("✓ Created RON currency")

        # Create Romanian VAT tax rule
        _, created = TaxRule.objects.get_or_create(
            country_code="RO",
            tax_type="vat",
            valid_from=date(2025, 8, 1),
            defaults={
                "rate": Decimal("0.21"),  # 21% VAT for Romania (Aug 2025)
                "applies_to_b2b": True,
                "applies_to_b2c": True,
                "reverse_charge_eligible": True,
                "is_eu_member": True,
                "vies_required": True,
            },
        )
        if created:
            self.stdout.write("✓ Created Romanian VAT tax rule")

        # Create FX rates (EUR/RON, USD/RON, EUR/USD)
        self._create_fx_rates()
        self.stdout.write("✓ Created FX rates")

    def create_products_from_service_plans(self) -> None:
        """Create Product objects and ProductPrice objects based on existing ServicePlans with new pricing model"""
        service_plans = ServicePlan.objects.all()

        # Get RON currency (should exist from billing foundation)
        try:
            ron_currency = Currency.objects.get(code="RON")
        except Currency.DoesNotExist:
            # Create RON currency if it doesn't exist
            ron_currency = Currency.objects.create(code="RON", name="Romanian Leu", symbol="RON", is_active=True)
            self.stdout.write("✓ Created RON currency")

        # Map ServicePlan types to Product types
        type_mapping = {
            "shared_hosting": "shared_hosting",
            "vps": "vps",
            "dedicated": "dedicated",
            "cloud": "shared_hosting",  # Map to shared hosting
            "domain": "domain",
            "ssl": "ssl",
            "email": "email",
            "backup": "backup",
            "maintenance": "addon",  # Map to addon
        }

        products_created = 0
        prices_created = 0

        for plan in service_plans:
            # Check if Product already exists for this plan
            product, product_created = Product.objects.get_or_create(
                slug=f"product-{plan.id}",
                defaults={
                    "name": plan.name,
                    "description": plan.description,
                    "short_description": plan.description[:200] if plan.description else "",
                    "product_type": type_mapping.get(plan.plan_type, "shared_hosting"),
                    "is_active": plan.is_active,
                    "is_featured": False,
                    "requires_domain": plan.plan_type in ["shared_hosting", "vps", "dedicated"],
                    "includes_vat": plan.includes_vat,
                },
            )

            # Update description on existing products if plan now has one
            if not product_created and plan.description and not product.description:
                product.description = plan.description
                product.short_description = plan.description[:200]
                product.save(update_fields=["description", "short_description"])

            if product_created:
                products_created += 1

            # Create ProductPrice with new simplified pricing model
            # Convert monthly price to cents
            monthly_price_cents = int(plan.price_monthly * 100) if plan.price_monthly else 2999  # Default to 29.99 RON

            # Create/update ProductPrice for this product
            _, price_created = ProductPrice.objects.get_or_create(
                product=product,
                currency=ron_currency,
                defaults={
                    "monthly_price_cents": monthly_price_cents,
                    "setup_cents": 0,  # No setup fee by default
                    "semiannual_discount_percent": Decimal("5.00"),  # 5% discount for 6-month billing
                    "annual_discount_percent": Decimal("10.00"),  # 10% discount for 12-month billing
                    "minimum_quantity": 1,
                    "maximum_quantity": None,  # Unlimited
                    "is_active": True,
                },
            )

            if price_created:
                prices_created += 1

        self.stdout.write(f"✓ Created/verified {service_plans.count()} products from service plans")
        self.stdout.write(f"✓ Created {products_created} new products, {prices_created} new product prices")

    def create_users(self, fake: Faker, count: int) -> list[User]:
        """Create users that will be attached to customers"""
        users = []

        # Clear existing users first to avoid conflicts
        User.objects.filter(email__contains="@example.").delete()

        for i in range(count):
            # Some users are individuals, some are business contacts
            is_business = random.choice([True, False])

            user_data = {
                "first_name": fake.first_name(),
                "last_name": fake.last_name(),
                "email": f"user{i + 1}@example.com",  # Use unique predictable emails
                "is_active": True,
                "staff_role": "customer",
            }

            user = User.objects.create_user(password="testpass123", **user_data)
            users.append(user)

            if i % 2 == 0:
                self.stdout.write(f"  ✓ User {i + 1}/{count}: {user.email}")

        return users

    def create_test_company_customer(self, fake: Faker, users: list[User], config: SampleDataConfig) -> Customer:
        """Create the guaranteed test company customer that should always have ID #1"""

        # Check if test company already exists
        test_company_email = "contact@testcompany.com"
        customer = None
        try:
            customer = Customer.objects.get(primary_email=test_company_email)
            self.stdout.write(f"  ✓ Test company already exists: {customer.get_display_name()} (ID: {customer.id})")
        except Customer.DoesNotExist:
            customer = None

        # Create the specific test user first if it doesn't exist
        test_user_email = "customer@pragmatichost.com"
        test_user = None
        try:
            test_user = User.objects.get(email=test_user_email)
            self.stdout.write(f"  ✓ Test user already exists: {test_user_email}")
        except User.DoesNotExist:
            test_user = User.objects.create_user(
                first_name="Ion",
                last_name="Pop",
                email=test_user_email,
                password="testpass123",
                is_active=True,
                staff_role="customer",
            )
            users.append(test_user)
            self.stdout.write(f"  ✓ Created test user: {test_user_email}")

        # Create or update test company — always ensure full data
        if customer is None:
            customer = Customer.objects.create(
                customer_type="company",
                name="Test Company SRL",
                company_name="Test Company SRL",
                primary_email=test_company_email,
                primary_phone="+40722123456",
                status="active",
                data_processing_consent=True,
                marketing_consent=True,
            )
            self.stdout.write(f"  ✓ Created test company: {customer.get_display_name()} (ID: {customer.id})")
        else:
            # Update existing to ensure consent flags are set
            customer.data_processing_consent = True
            customer.marketing_consent = True
            customer.save(update_fields=["data_processing_consent", "marketing_consent"])

        # Clear ALL existing test data for idempotent re-runs
        self.stdout.write("  ✓ Clearing existing test data for Test Company...")
        CreditLedger.objects.filter(customer=customer).delete()
        Refund.objects.filter(customer=customer).delete()
        Payment.objects.filter(customer=customer).delete()
        SubscriptionItem.objects.filter(subscription__customer=customer).delete()
        Subscription.objects.filter(customer=customer).delete()
        Domain.objects.filter(customer=customer).delete()
        EmailPreference.objects.filter(customer=customer).delete()
        Service.objects.filter(customer=customer).delete()
        Order.objects.filter(customer=customer).delete()
        Invoice.objects.filter(customer=customer).delete()
        ProformaInvoice.objects.filter(customer=customer).delete()
        Ticket.objects.filter(customer=customer).delete()
        CustomerAddress.all_objects.filter(customer=customer).delete()
        CustomerPaymentMethod.all_objects.filter(customer=customer).delete()
        CustomerNote.all_objects.filter(customer=customer).delete()
        CustomerTaxProfile.all_objects.filter(customer=customer).delete()
        CustomerBillingProfile.all_objects.filter(customer=customer).delete()

        self._setup_test_company_profiles(customer, test_user)
        self._create_all_customer_data(
            fake,
            customer,
            0,
            services_count=7,
            orders_count=7,
            invoices_count=10,
            proformas_count=5,
            tickets_count=10,
            domains_count=5,
            subscriptions_count=7,
        )

        self.stdout.write(
            "  ✅ Created comprehensive test data: services, orders, invoices, payments, "
            "subscriptions, refunds, domains, tickets with comments/worklogs, email preferences"
        )

        return customer

    def _setup_test_company_profiles(self, customer: Customer, test_user: "User") -> None:
        """Create addresses, tax/billing profiles, payment methods, notes, and membership for test company."""
        # Primary address (also serves as billing for this customer)
        CustomerAddress.objects.create(
            customer=customer,
            is_primary=True,
            is_billing=False,
            address_line1="Str. Victoriei nr. 10",
            address_line2="Bl. A1, Sc. 2, Et. 3, Ap. 15",
            city="București",
            county="București",
            postal_code="010061",
            country="România",
            is_current=True,
            is_validated=True,
        )
        # Separate billing address
        CustomerAddress.objects.create(
            customer=customer,
            is_primary=False,
            is_billing=True,
            address_line1="Str. Revoluției nr. 1",
            address_line2="Corp B, Parter",
            city="București",
            county="București",
            postal_code="010000",
            country="România",
            is_current=True,
            is_validated=True,
        )
        # Extra address (no special role)
        CustomerAddress.objects.create(
            customer=customer,
            is_primary=False,
            is_billing=False,
            address_line1="Str. Depozitelor nr. 8",
            city="București",
            county="București",
            postal_code="040012",
            country="România",
            is_current=True,
        )

        # Tax profile — fully filled out
        CustomerTaxProfile.objects.create(
            customer=customer,
            cui="RO12345678",
            is_vat_payer=True,
            vat_number="RO12345678",
            registration_number="J40/1234/2020",
            reverse_charge_eligible=True,
        )

        # Billing profile
        CustomerBillingProfile.objects.create(
            customer=customer,
            payment_terms=30,
            preferred_currency="RON",
            auto_payment_enabled=True,
            credit_limit=Decimal("25000.00"),
        )

        # Payment methods — card (default) + bank transfer
        CustomerPaymentMethod.objects.create(
            customer=customer,
            method_type="stripe_card",
            display_name="Visa •••• 4242",
            last_four="4242",
            stripe_customer_id="cus_testcompany001",
            stripe_payment_method_id="pm_testcompany001",
            is_default=True,
            is_active=True,
        )
        CustomerPaymentMethod.objects.create(
            customer=customer,
            method_type="bank_transfer",
            display_name="Transfer BT - Cont principal",
            is_default=False,
            is_active=True,
            bank_details={
                "iban": "RO49BTRL0301202012345678",
                "bank_name": "Banca Transilvania",
                "swift_code": "BTRLRO22",
                "account_holder": "Test Company SRL",
            },
        )

        # Notes
        admin = self._get_admin_user()
        CustomerNote.objects.create(
            customer=customer,
            created_by=admin,
            note_type="general",
            title="Cont de test principal",
            content="Acesta este contul principal de test pentru dezvoltare și QA.",
            is_important=True,
        )
        CustomerNote.objects.create(
            customer=customer,
            created_by=admin,
            note_type="call",
            title="Apel onboarding",
            content="Client contactat pentru configurarea inițială a serviciilor de hosting.",
        )

        # Membership for the test user
        _, created = CustomerMembership.objects.get_or_create(
            customer=customer, user=test_user, defaults={"role": "owner", "is_primary": True}
        )
        if created:
            self.stdout.write(f"  ✓ Created customer membership for {test_user.email}")
        else:
            self.stdout.write(f"  ✓ Customer membership already exists for {test_user.email}")

    def _create_all_customer_data(  # noqa: PLR0913
        self,
        fake: Faker,
        customer: Customer,
        index: int,
        *,
        services_count: int,
        orders_count: int,
        invoices_count: int,
        proformas_count: int,
        tickets_count: int,
        domains_count: int = 3,
        subscriptions_count: int = 3,
    ) -> None:
        """Create all related data for a customer: services, orders, invoices, payments, etc."""
        with transaction.atomic():
            self.create_customer_services(fake, customer, services_count)
            orders = self.create_customer_orders(fake, customer, orders_count)
            invoices = self.create_customer_invoices(fake, customer, orders, invoices_count)
            self.create_customer_proformas(fake, customer, orders, proformas_count)
            tickets = self.create_customer_tickets(fake, customer, tickets_count)
            self.create_ticket_comments(fake, tickets)
            self.create_ticket_worklogs(fake, tickets)
            payments = self.create_customer_payments(fake, customer, invoices)
            self.create_customer_credit_entries(fake, customer, payments)
            self.create_customer_subscriptions(fake, customer, subscriptions_count)
            self.create_customer_refunds(fake, customer, orders, invoices, payments)
            self.create_customer_domains(fake, customer, domains_count)
            self.create_customer_email_preference(customer, index)

    def create_customer_with_data(
        self, fake: Faker, index: int, users: list[User], config: SampleDataConfig
    ) -> Customer:
        """Create a customer with all related data: profiles, services, orders, invoices, tickets"""

        # Round-robin over all 4 types and statuses so every variant appears
        customer_types = ["individual", "company", "pfa", "ngo"]
        statuses = ["active", "inactive", "suspended", "prospect"]
        customer_type = customer_types[index % len(customer_types)]
        status = statuses[index % len(statuses)]

        # Build customer data
        customer_data: dict[str, Any] = {
            "customer_type": customer_type,
            "name": f"{fake.first_name()} {fake.last_name()}",
            "primary_email": fake.unique.email(),
            "primary_phone": f"+40{fake.random_int(min=700000000, max=799999999)}",
            "status": status,
            "data_processing_consent": index % 3 != 0,  # ~67% have GDPR consent
            "marketing_consent": index % 2 == 0,  # 50% have marketing consent
        }

        if customer_type in ("company", "pfa", "ngo"):
            customer_data["company_name"] = fake.company()

        customer = Customer.objects.create(**customer_data)

        self._create_random_customer_addresses(fake, customer, customer_type, index)

        # --- Tax profile: every customer gets one ---
        if customer_type in ("company", "pfa"):
            tax_number = f"RO{fake.random_int(min=10000000, max=99999999)}"
            reg_prefix = "J40" if customer_type == "company" else "F40"
            CustomerTaxProfile.objects.create(
                customer=customer,
                cui=tax_number,
                is_vat_payer=customer_type == "company" or index % 2 == 0,
                vat_number=tax_number,
                registration_number=f"{reg_prefix}/{fake.random_int(min=100, max=9999)}/{fake.random_int(min=2015, max=2025)}",
                reverse_charge_eligible=index % 3 == 0,
            )
        elif customer_type == "ngo":
            # NGOs in Romania have CUI/CIF but are typically VAT-exempt
            tax_number = f"RO{fake.random_int(min=10000000, max=99999999)}"
            CustomerTaxProfile.objects.create(
                customer=customer,
                cui=tax_number,
                is_vat_payer=False,
                registration_number=f"AS/{fake.random_int(min=100, max=999)}/{fake.random_int(min=2015, max=2025)}",
                reverse_charge_eligible=False,
            )
        elif customer_type == "individual":
            # All individuals get a CNP for invoice/tax purposes
            # Romanian CNP: S(1) + YY(2) + MM(2) + DD(2) + CC(2) + NNN(3) + C(1) = 13 digits
            century = 1 if index % 2 == 0 else 2
            yy = fake.random_int(min=60, max=99)
            mm = fake.random_int(min=1, max=12)
            dd = fake.random_int(min=1, max=28)
            cc = fake.random_int(min=1, max=52)
            nnn = fake.random_int(min=1, max=999)
            check = index % 10
            CustomerTaxProfile.objects.create(
                customer=customer,
                cnp=f"{century}{yy:02d}{mm:02d}{dd:02d}{cc:02d}{nnn:03d}{check}",
                is_vat_payer=False,
            )

        # --- Billing profile with variety ---
        currencies = ["RON", "EUR"]
        payment_terms_options = [15, 30, 45, 60]
        CustomerBillingProfile.objects.create(
            customer=customer,
            payment_terms=payment_terms_options[index % len(payment_terms_options)],
            preferred_currency=currencies[index % len(currencies)],
            auto_payment_enabled=index % 4 == 0,
            credit_limit=Decimal("5000.00") if customer_type == "company" else Decimal("0.00"),
        )

        # --- Payment methods ---
        secondary_methods = ["bank_transfer", "cash", "other"]
        # Default: Stripe card
        CustomerPaymentMethod.objects.create(
            customer=customer,
            method_type="stripe_card",
            display_name=f"Visa •••• {fake.random_int(min=1000, max=9999)}",
            last_four=str(fake.random_int(min=1000, max=9999)),
            stripe_customer_id=f"cus_{fake.hexify(text='^^^^^^^^^^^^^^')}",
            stripe_payment_method_id=f"pm_{fake.hexify(text='^^^^^^^^^^^^^^')}",
            is_default=True,
            is_active=True,
        )
        # Secondary method (round-robin)
        sec_method = secondary_methods[index % len(secondary_methods)]
        sec_kwargs: dict[str, Any] = {
            "customer": customer,
            "method_type": sec_method,
            "display_name": {"bank_transfer": "Transfer BT", "cash": "Numerar", "other": "PayPal"}[sec_method],
            "is_default": False,
            "is_active": index % 3 != 0,  # Some inactive
        }
        if sec_method == "bank_transfer":
            sec_kwargs["bank_details"] = {
                "iban": f"RO49AAAA1B31{fake.random_int(min=10000000, max=99999999)}",
                "bank_name": random.choice(["Banca Transilvania", "BRD", "ING Bank", "BCR"]),
                "swift_code": random.choice(["BTRLRO22", "BRDEROBU", "INGBROBU", "RNCBROBU"]),
            }
        CustomerPaymentMethod.objects.create(**sec_kwargs)

        # --- Notes ---
        note_types = ["general", "call", "email", "meeting", "complaint", "compliment"]
        # 2 notes per customer, round-robin type
        for n in range(2):
            note_type = note_types[(index * 2 + n) % len(note_types)]
            CustomerNote.objects.create(
                customer=customer,
                created_by=self._get_admin_user(),
                note_type=note_type,
                title=f"{note_type.title()} note for {customer.get_display_name()}",
                content=fake.text(max_nb_chars=300),
                is_important=n == 0 and index % 2 == 0,
                is_private=n == 1 and index % 3 == 0,
            )

        # --- Memberships with full role coverage ---
        roles = ["owner", "billing", "tech", "viewer"]
        contact_methods = ["email", "phone", "both"]
        num_members = random.randint(1, min(3, len(users)))
        customer_users = random.sample(users, num_members)
        for u_idx, user in enumerate(customer_users):
            role = roles[(index + u_idx) % len(roles)]
            CustomerMembership.objects.create(
                user=user,
                customer=customer,
                role=role,
                is_primary=u_idx == 0,
                is_active=True,
                notification_language="en" if (index + u_idx) % 3 == 0 else "ro",
                preferred_contact_method=contact_methods[(index + u_idx) % len(contact_methods)],
                email_billing=role in ("owner", "billing"),
                email_technical=role in ("owner", "tech"),
                email_marketing=customer.marketing_consent and role == "owner",
            )

        # Create related data
        self._create_all_customer_data(
            fake,
            customer,
            index,
            services_count=config.services_count,
            orders_count=config.orders_count,
            invoices_count=config.invoices_count,
            proformas_count=config.proformas_count,
            tickets_count=config.tickets_count,
            domains_count=random.randint(2, 3),
            subscriptions_count=3,
        )

        return customer

    # ===============================================================================
    # DETERMINISTIC PERMUTATION CUSTOMERS
    # ===============================================================================

    def _create_customer_permutations(self, fake: Faker, users: list[User]) -> list[Customer]:
        """Create deterministic customers covering every choice/flag combination.

        Generates 8 customers that collectively exercise:
        - All 4 customer types (individual, company, pfa, ngo)
        - All 4 statuses (active, inactive, suspended, prospect)
        - All 4 address types with versioning
        - All 4 payment method types
        - All 6 note types
        - All 4 membership roles
        - Varied GDPR/marketing consent, billing profiles, notification prefs
        - Multi-company users, multi-user companies, suspended users
        """
        self.stdout.write("Creating deterministic permutation customers...")
        admin_user = User.objects.filter(is_superuser=True).first()
        customers: list[Customer] = []

        # ── Shared multi-company user: belongs to multiple customers ──
        multi_co_user, _ = User.objects.get_or_create(
            email="multi-company@example.com",
            defaults={
                "first_name": "Maria",
                "last_name": "Ionescu",
                "is_active": True,
                "staff_role": "customer",
            },
        )
        # Intentional: reset password on re-runs for idempotent fixture state
        multi_co_user.set_password("testpass123")  # nosemgrep: unvalidated-password
        multi_co_user.save()

        # ── Suspended user: exists but cannot log in ──
        suspended_user, _ = User.objects.get_or_create(
            email="suspended@example.com",
            defaults={
                "first_name": "Andrei",
                "last_name": "Popa",
                "is_active": False,
                "staff_role": "customer",
            },
        )
        suspended_user.is_active = False
        # Intentional: reset password on re-runs for idempotent fixture state
        suspended_user.set_password("testpass123")  # nosemgrep: unvalidated-password
        suspended_user.save()

        # ── Inactive staff user: staff_role but disabled ──
        inactive_staff, _ = User.objects.get_or_create(
            email="inactive-staff@pragmatichost.com",
            defaults={
                "first_name": "Elena",
                "last_name": "Vasile",
                "is_active": False,
                "is_staff": True,
                "staff_role": "support",
            },
        )
        inactive_staff.is_active = False
        # Intentional: reset password on re-runs for idempotent fixture state
        inactive_staff.set_password("support123")  # nosemgrep: unvalidated-password
        inactive_staff.save()

        # ── Manager user: assigned as account manager to some customers ──
        manager_user, _ = User.objects.get_or_create(
            email="manager@pragmatichost.com",
            defaults={
                "first_name": "Dragoș",
                "last_name": "Marin",
                "is_active": True,
                "is_staff": True,
                "staff_role": "manager",
            },
        )
        # Intentional: reset password on re-runs for idempotent fixture state
        manager_user.set_password("manager123")  # nosemgrep: unvalidated-password
        manager_user.save()

        # ── Permutation definitions ──
        #   type, status, consent_gdpr, consent_marketing, has_account_manager
        permutations: list[dict[str, Any]] = [
            # 1: Active individual, full consent, CNP, RON, email delivery
            {
                "customer_type": "individual",
                "name": "Alexandru Popescu",
                "primary_email": "alexandru.popescu@example.com",
                "primary_phone": "+40722100001",
                "status": "active",
                "data_processing_consent": True,
                "marketing_consent": True,
            },
            # 2: Inactive company, GDPR only, CUI+VAT, EUR, postal delivery
            {
                "customer_type": "company",
                "name": "Ion Marinescu",
                "company_name": "TechSoft Solutions SRL",
                "primary_email": "contact@techsoft-solutions.example.com",
                "primary_phone": "+40722100002",
                "status": "inactive",
                "data_processing_consent": True,
                "marketing_consent": False,
            },
            # 3: Suspended PFA, no consent, CUI, RON, both delivery
            {
                "customer_type": "pfa",
                "name": "Cristina Dumitrescu",
                "company_name": "Dumitrescu Cristina PFA",
                "primary_email": "cristina.pfa@example.com",
                "primary_phone": "+40722100003",
                "status": "suspended",
                "data_processing_consent": False,
                "marketing_consent": False,
            },
            # 4: Prospect NGO, both consents, no tax profile, email delivery
            {
                "customer_type": "ngo",
                "name": "Mihai Stancu",
                "company_name": "Asociația Digital România",
                "primary_email": "contact@digital-romania.example.com",
                "primary_phone": "+40722100004",
                "status": "prospect",
                "data_processing_consent": True,
                "marketing_consent": True,
            },
            # 5: Active company with account manager, full details, multi-user
            {
                "customer_type": "company",
                "name": "Adriana Radu",
                "company_name": "CloudHost Pro SRL",
                "primary_email": "contact@cloudhost-pro.example.com",
                "primary_phone": "+40722100005",
                "status": "active",
                "data_processing_consent": True,
                "marketing_consent": True,
                "assigned_account_manager": manager_user,
            },
            # 6: Active PFA, auto-payment, credit limit, EUR
            {
                "customer_type": "pfa",
                "name": "Bogdan Tănase",
                "company_name": "Tănase Bogdan PFA",
                "primary_email": "bogdan.tanase@example.com",
                "primary_phone": "+40722100006",
                "status": "active",
                "data_processing_consent": True,
                "marketing_consent": True,
            },
            # 7: Inactive individual, minimal data, GDPR only
            {
                "customer_type": "individual",
                "name": "Gabriela Stoica",
                "primary_email": "gabriela.stoica@example.com",
                "primary_phone": "+40722100007",
                "status": "inactive",
                "data_processing_consent": True,
                "marketing_consent": False,
            },
            # 8: Active NGO with suspended user membership
            {
                "customer_type": "ngo",
                "name": "Victor Moldovan",
                "company_name": "Fundația Open Source România",
                "primary_email": "contact@opensource-ro.example.com",
                "primary_phone": "+40722100008",
                "status": "active",
                "data_processing_consent": True,
                "marketing_consent": False,
            },
        ]

        payment_method_types = ["stripe_card", "bank_transfer", "cash", "other"]
        note_types = ["general", "call", "email", "meeting", "complaint", "compliment"]
        membership_roles = ["owner", "billing", "tech", "viewer"]
        currencies = ["RON", "EUR"]
        contact_methods = ["email", "phone", "both"]

        for idx, cust_data in enumerate(permutations):
            city, county = _ROMANIAN_CITIES[idx % len(_ROMANIAN_CITIES)]

            customer = Customer.objects.create(**cust_data)
            customers.append(customer)
            self.stdout.write(
                f"  ✓ Permutation {idx + 1}/8: {customer.get_display_name()} "
                f"[{customer.customer_type}/{customer.status}]"
            )

            self._perm_addresses(customer, idx, city, county)
            self._perm_tax_profile(customer, idx)
            self._perm_billing_profile(customer, idx, currencies)
            self._perm_payment_methods(customer, idx, payment_method_types)
            self._perm_notes(fake, customer, idx, admin_user, note_types)
            self._perm_memberships(
                customer,
                idx,
                users,
                multi_co_user,
                suspended_user,
                membership_roles,
                contact_methods,
            )

        # ── Soft-delete one customer to test SoftDeleteManager ──
        soft_del_customer = customers[6]  # Gabriela Stoica, inactive individual
        soft_del_customer.soft_delete()
        self.stdout.write(f"  ✓ Soft-deleted: {soft_del_customer.name} (tests SoftDeleteManager.with_deleted())")

        self.stdout.write(
            self.style.SUCCESS(
                f"  ✅ Created {len(customers)} permutation customers "
                f"(4 types x 4 statuses, all address/payment/note/role variants, "
                f"1 soft-deleted, 1 suspended user, 1 multi-company user)"
            )
        )

        return customers

    def _perm_addresses(self, customer: Customer, idx: int, city: str, county: str) -> None:
        """Create deterministic addresses for a permutation customer."""
        # Historical billing address (version 1, superseded)
        CustomerAddress.objects.create(
            customer=customer,
            is_billing=True,
            is_primary=False,
            address_line1=f"Str. Veche nr. {idx + 1}",
            city=city,
            county=county,
            postal_code=f"{100000 + idx * 1111}",
            country="România",
            is_current=False,
            is_validated=True,
            version=1,
        )
        # Current billing address (version 2)
        CustomerAddress.objects.create(
            customer=customer,
            is_billing=True,
            is_primary=False,
            address_line1=f"Bd. Unirii nr. {idx * 10 + 1}",
            city=city,
            county=county,
            postal_code=f"{100000 + idx * 1111}",
            country="România",
            is_current=True,
            is_validated=True,
            version=2,
        )
        # Primary address
        CustomerAddress.objects.create(
            customer=customer,
            is_primary=True,
            is_billing=False,
            address_line1=f"Str. Principală nr. {idx + 10}",
            city=city,
            county=county,
            postal_code=f"{200000 + idx * 1111}",
            country="România",
            is_current=True,
            is_validated=idx % 2 == 0,
        )
        # Extra address (not for minimal customer #7)
        if idx != 6:
            CustomerAddress.objects.create(
                customer=customer,
                is_primary=False,
                is_billing=False,
                address_line1=f"Str. Livrare nr. {idx + 20}",
                city=city,
                county=county,
                postal_code=f"{300000 + idx * 1111}",
                country="România",
                is_current=True,
            )

    def _perm_tax_profile(self, customer: Customer, idx: int) -> None:
        """Create deterministic tax profile for a permutation customer.

        Every customer type gets a tax profile — Romanian law requires CUI/CIF
        for companies, PFAs, and NGOs alike. Individuals get a CNP.
        """
        if customer.customer_type == "company":
            cui_num = f"RO{30000000 + idx * 1111111}"
            CustomerTaxProfile.objects.create(
                customer=customer,
                cui=cui_num,
                is_vat_payer=True,
                vat_number=cui_num,
                registration_number=f"J40/{1000 + idx}/{2020 + idx}",
                reverse_charge_eligible=idx % 2 == 0,
            )
        elif customer.customer_type == "pfa":
            cui_num = f"RO{40000000 + idx * 1111111}"
            CustomerTaxProfile.objects.create(
                customer=customer,
                cui=cui_num,
                is_vat_payer=idx % 2 == 0,
                vat_number=cui_num if idx % 2 == 0 else "",
                registration_number=f"F40/{500 + idx}/{2021 + idx}",
                reverse_charge_eligible=False,
            )
        elif customer.customer_type == "ngo":
            # NGOs in Romania have CUI/CIF but are typically VAT-exempt
            cui_num = f"RO{50000000 + idx * 1111111}"
            CustomerTaxProfile.objects.create(
                customer=customer,
                cui=cui_num,
                is_vat_payer=False,
                vat_number="",
                registration_number=f"AS/{100 + idx}/{2019 + idx}",
                reverse_charge_eligible=False,
            )
        elif customer.customer_type == "individual":
            # All individuals get a CNP for tax/invoice purposes
            # Vary century digit (1=male, 2=female) and birth year
            # Romanian CNP: S(1) + YY(2) + MM(2) + DD(2) + CC(2) + NNN(3) + C(1) = 13 digits
            century_digit = 1 if idx % 2 == 0 else 2
            birth_year = 85 + idx * 3
            CustomerTaxProfile.objects.create(
                customer=customer,
                cnp=f"{century_digit}{birth_year:02d}0101{40 + idx:02d}{idx:03d}1",
                is_vat_payer=False,
            )

    def _perm_billing_profile(self, customer: Customer, idx: int, currencies: list[str]) -> None:
        """Create deterministic billing profile for a permutation customer."""
        CustomerBillingProfile.objects.create(
            customer=customer,
            payment_terms=[15, 30, 45, 60][idx % 4],
            preferred_currency=currencies[idx % len(currencies)],
            auto_payment_enabled=idx in (5, 6),
            credit_limit=Decimal("10000.00") if customer.customer_type == "company" else Decimal("0.00"),
        )

    def _perm_payment_methods(self, customer: Customer, idx: int, payment_method_types: list[str]) -> None:
        """Create deterministic payment methods for a permutation customer."""
        pm_type_1 = payment_method_types[idx % len(payment_method_types)]
        pm_type_2 = payment_method_types[(idx + 1) % len(payment_method_types)]

        for pm_idx, pm_type in enumerate([pm_type_1, pm_type_2]):
            pm_kwargs: dict[str, Any] = {
                "customer": customer,
                "method_type": pm_type,
                "is_default": pm_idx == 0,
                "is_active": not (pm_idx == 1 and idx % 4 == 0),
            }
            if pm_type == "stripe_card":
                last4 = str(1000 + idx * 100 + pm_idx)
                pm_kwargs.update(
                    {
                        "display_name": f"Visa •••• {last4}",
                        "last_four": last4,
                        "stripe_customer_id": f"cus_perm{idx}{pm_idx}test",
                        "stripe_payment_method_id": f"pm_perm{idx}{pm_idx}test",
                    }
                )
            elif pm_type == "bank_transfer":
                pm_kwargs.update(
                    {
                        "display_name": "Transfer BT",
                        "bank_details": {
                            "iban": f"RO49BTRL{10000000 + idx * 1000000:08d}",
                            "bank_name": "Banca Transilvania",
                            "swift_code": "BTRLRO22",
                            "account_holder": customer.get_display_name(),
                        },
                    }
                )
            elif pm_type == "cash":
                pm_kwargs["display_name"] = "Numerar la sediu"
            else:
                pm_kwargs["display_name"] = "PayPal"
            CustomerPaymentMethod.objects.create(**pm_kwargs)

    def _perm_notes(
        self,
        fake: Faker,
        customer: Customer,
        idx: int,
        admin_user: User | None,
        note_types: list[str],
    ) -> None:
        """Create deterministic notes for a permutation customer."""
        note_titles = {
            "general": "Observație generală",
            "call": "Apel de follow-up",
            "email": "Corespondență email",
            "meeting": "Întâlnire client",
            "complaint": "Reclamație serviciu",
            "compliment": "Feedback pozitiv",
        }
        for n_idx in range(2):
            n_type = note_types[(idx * 2 + n_idx) % len(note_types)]
            CustomerNote.objects.create(
                customer=customer,
                created_by=admin_user,
                note_type=n_type,
                title=f"{note_titles[n_type]} — {customer.get_display_name()}",
                content=fake.text(max_nb_chars=400),
                is_important=n_idx == 0 and idx % 2 == 0,
                is_private=n_idx == 1 and idx % 3 == 0,
            )

    def _perm_memberships(  # noqa: PLR0913
        self,
        customer: Customer,
        idx: int,
        users: list[User],
        multi_co_user: User,
        suspended_user: User,
        membership_roles: list[str],
        contact_methods: list[str],
    ) -> None:
        """Create deterministic memberships for a permutation customer."""
        role = membership_roles[idx % len(membership_roles)]

        # Multi-company user gets membership on customers 0, 2, 4
        if idx % 2 == 0:
            CustomerMembership.objects.create(
                user=multi_co_user,
                customer=customer,
                role=role,
                is_primary=idx == 0,
                is_active=True,
                notification_language="ro",
                preferred_contact_method=contact_methods[idx % len(contact_methods)],
                email_billing=role in ("owner", "billing"),
                email_technical=role in ("owner", "tech"),
                email_marketing=customer.marketing_consent,
            )

        # Suspended user gets membership on customer #8 (tests inactive user + active membership)
        if idx == 7:
            CustomerMembership.objects.create(
                user=suspended_user,
                customer=customer,
                role="owner",
                is_primary=True,
                is_active=True,
                notification_language="ro",
            )

        # Regular user memberships — multi-user company on customer #5 (CloudHost Pro)
        if idx == 4:
            available_users = [u for u in users[:4] if u.email != multi_co_user.email]
            for u_idx, user in enumerate(available_users):
                u_role = membership_roles[u_idx % len(membership_roles)]
                CustomerMembership.objects.create(
                    user=user,
                    customer=customer,
                    role=u_role,
                    is_primary=u_idx == 0,
                    is_active=True,
                    notification_language="en" if u_idx % 3 == 0 else "ro",
                    preferred_contact_method=contact_methods[u_idx % len(contact_methods)],
                    email_billing=u_role in ("owner", "billing"),
                    email_technical=u_role in ("owner", "tech"),
                    email_marketing=u_role == "owner",
                )
        elif idx != 7 and idx % 2 != 0:
            if users:
                reg_user = users[idx % len(users)]
                CustomerMembership.objects.create(
                    user=reg_user,
                    customer=customer,
                    role=role,
                    is_primary=True,
                    is_active=True,
                    notification_language="en" if idx % 3 == 0 else "ro",
                    preferred_contact_method=contact_methods[idx % len(contact_methods)],
                )

    def _create_random_customer_addresses(
        self, fake: Faker, customer: Customer, customer_type: str, index: int
    ) -> None:
        """Create randomised addresses for a generated customer."""
        county = _ROMANIAN_COUNTIES[index % len(_ROMANIAN_COUNTIES)]

        # Historical billing address (version 1, non-current) — demonstrates versioning
        CustomerAddress.objects.create(
            customer=customer,
            is_billing=True,
            is_primary=False,
            address_line1=fake.street_address(),
            city=fake.city(),
            county=county,
            postal_code=fake.postcode(),
            country="România",
            is_current=False,
            version=1,
        )
        # Current billing address (version 2)
        CustomerAddress.objects.create(
            customer=customer,
            is_billing=True,
            is_primary=False,
            address_line1=fake.street_address(),
            city=fake.city(),
            county=county,
            postal_code=fake.postcode(),
            country="România",
            is_current=True,
            is_validated=True,
            version=2,
        )
        # Primary address (also used for registered office for business types)
        CustomerAddress.objects.create(
            customer=customer,
            is_primary=True,
            is_billing=False,
            label="Sediu social" if customer_type in ("company", "pfa") else "",
            address_line1=fake.street_address(),
            city=fake.city(),
            county=county,
            postal_code=fake.postcode(),
            country="România",
            is_current=True,
        )
        # Extra address for some customers
        if index % 3 == 0:
            CustomerAddress.objects.create(
                customer=customer,
                is_primary=False,
                is_billing=False,
                address_line1=fake.street_address(),
                city=fake.city(),
                county=county,
                postal_code=fake.postcode(),
                country="România",
                is_current=True,
            )

    def create_customer_services(self, fake: Faker, customer: Customer, count: int) -> list[Service]:
        """Create services for a customer with diverse statuses"""
        services = []
        plans = list(ServicePlan.objects.all())
        servers = list(Server.objects.all())

        # Service statuses: pending, provisioning, active, suspended, terminated, expired
        service_statuses = ["pending", "provisioning", "active", "suspended", "terminated", "expired", "active"]

        for i in range(count):
            plan = random.choice(plans)
            server = random.choice(servers) if servers else None

            # Use specific statuses for comprehensive testing (Test Company gets all statuses)
            status = service_statuses[i % len(service_statuses)]

            now = timezone.now()
            activated = now - timedelta(days=random.randint(30, 365)) if status in ("active", "suspended") else None
            suspended_at = now - timedelta(days=random.randint(1, 30)) if status == "suspended" else None

            service_data: dict[str, Any] = {
                "customer": customer,
                "service_plan": plan,
                "currency": self._get_ron_currency(),
                "server": server,
                "service_name": f"{plan.name} - {customer.get_display_name()} [{status.title()}]",
                "domain": fake.domain_name(),
                "username": f"user{customer.id:04d}{i:03d}{random.randint(100, 999)}",  # Unique username
                "billing_cycle": ["monthly", "quarterly", "semi_annual", "annual"][i % 4],
                "price": plan.price_monthly,
                "status": status,
                "auto_renew": status == "active",
                "activated_at": activated,
                "expires_at": activated + timedelta(days=365) if activated else None,
                "suspended_at": suspended_at,
                "suspension_reason": "Neplată factură restantă" if status == "suspended" else "",
            }
            # Active services get realistic usage data
            if status == "active":
                service_data.update(
                    {
                        "disk_usage_mb": random.randint(50, (plan.disk_space_gb or 5) * 800),
                        "bandwidth_usage_mb": random.randint(100, (plan.bandwidth_gb or 100) * 600),
                        "email_accounts_used": random.randint(0, plan.email_accounts or 5),
                        "databases_used": random.randint(0, plan.databases or 2),
                    }
                )

            service = Service.objects.create(**service_data)
            services.append(service)

        return services

    def create_customer_orders(self, fake: Faker, customer: Customer, count: int) -> list[Order]:
        """Create orders for a customer with diverse statuses and full billing data"""
        orders = []
        services = list(Service.objects.filter(customer=customer))
        currency = self._get_ron_currency()

        # Order statuses: draft, pending, confirmed, processing, completed, cancelled, failed
        order_statuses = ["draft", "pending", "confirmed", "processing", "completed", "cancelled", "failed"]
        payment_methods = ["card", "bank_transfer", "paypal", "manual"]
        now = timezone.now()

        billing_address_json = self._billing_address_snapshot(customer)
        customer_vat_id = self._customer_tax_id(customer)

        for i in range(count):
            # Generate amounts in cents for precision
            base_amount = Decimal(str(random.uniform(50.0, 500.0))).quantize(Decimal("0.01"))
            subtotal_cents = int(base_amount * 100)
            item_tax_cents = int(subtotal_cents * Decimal("0.21"))  # 21% VAT
            total_cents = subtotal_cents + item_tax_cents

            status = order_statuses[i % len(order_statuses)]
            created_at = fake.date_time_between(
                start_date="-1y", end_date="now", tzinfo=timezone.get_current_timezone()
            )

            order_data: dict[str, Any] = {
                "customer": customer,
                "order_number": f"ORD-{customer.id:04d}-{i + 1:03d}-{status.upper()}",
                "status": status,
                "currency": currency,
                "subtotal_cents": subtotal_cents,
                "tax_cents": item_tax_cents,
                "total_cents": total_cents,
                "customer_email": customer.primary_email,
                "customer_name": customer.name,
                "customer_company": customer.company_name or "",
                "customer_vat_id": customer_vat_id,
                "billing_address": billing_address_json,
                "payment_method": payment_methods[i % len(payment_methods)],
                "created_at": created_at,
            }
            # Completed orders get completion timestamp and notes
            if status == "completed":
                order_data["completed_at"] = created_at + timedelta(days=random.randint(1, 7))
                order_data["notes"] = "Comandă procesată și livrată cu succes."
            elif status == "cancelled":
                order_data["notes"] = "Anulată la cererea clientului."
            elif status == "draft":
                order_data["expires_at"] = now + timedelta(days=7)

            order = Order.objects.create(**order_data)

            # Add order items (link to services)
            if services:
                num_items = random.randint(1, min(3, len(services)))
                order_services = random.sample(services, num_items)

                for _item_idx, service in enumerate(order_services):
                    unit_price_cents = int(service.price * 100)
                    line_tax_cents = int(unit_price_cents * Decimal("0.21"))
                    line_total_cents = unit_price_cents + line_tax_cents

                    # Get the Product that corresponds to this service's plan
                    try:
                        product = Product.objects.get(slug=f"product-{service.service_plan.id}")
                    except Product.DoesNotExist:
                        product = Product.objects.create(
                            slug=f"product-{service.service_plan.id}",
                            name=service.service_plan.name,
                            description=service.service_plan.description,
                            product_type="shared_hosting",
                            is_active=True,
                        )

                    # Provisioning status matches order status
                    prov_status = {
                        "completed": "completed",
                        "processing": "in_progress",
                        "cancelled": "cancelled",
                        "failed": "failed",
                    }.get(status, "pending")

                    OrderItem.objects.create(
                        order=order,
                        product=product,
                        product_name=service.service_plan.name,
                        product_type=service.service_plan.plan_type,
                        quantity=1,
                        unit_price_cents=unit_price_cents,
                        tax_rate=Decimal("0.2100"),
                        tax_cents=line_tax_cents,
                        line_total_cents=line_total_cents,
                        service=service,
                        domain_name=service.domain,
                        provisioning_status=prov_status,
                        provisioned_at=now - timedelta(days=random.randint(1, 30))
                        if prov_status == "completed"
                        else None,
                    )

            orders.append(order)

        return orders

    def create_customer_invoices(
        self, fake: Faker, customer: Customer, orders: list[Order], count: int
    ) -> list[Invoice]:
        """Create invoices for a customer with logical dates, multiple line items, and status-aware fields"""
        invoices = []
        currency = self._get_ron_currency()
        tax_rule = self._get_ro_tax_rule()
        admin_user = self._get_admin_user()
        services = list(Service.objects.filter(customer=customer))

        # Invoice statuses — extra paid/issued for realism
        invoice_statuses = [
            "draft",
            "issued",
            "paid",
            "overdue",
            "void",
            "refunded",
            "paid",
            "issued",
            "paid",
            "overdue",
        ]

        # Billing address snapshot
        billing_snapshot = self._billing_address_snapshot(customer)
        bill_to_tax_id = self._customer_tax_id(customer)

        # Get payment terms for logical due_at calculation
        billing_profile = None
        with contextlib.suppress(ObjectDoesNotExist):
            billing_profile = customer.billing_profile
        payment_terms_days = billing_profile.payment_terms if billing_profile else 30

        for i in range(count):
            # Some invoices linked to orders, some standalone
            order = random.choice(orders) if orders and random.random() < 0.5 else None
            if order:
                base_amount = Decimal(order.subtotal_cents) / 100
                tax_amount = Decimal(order.tax_cents) / 100
                total_amount = Decimal(order.total_cents) / 100
            else:
                base_amount = Decimal(str(random.uniform(100.0, 1000.0))).quantize(Decimal("0.01"))
                tax_amount = base_amount * tax_rule.rate
                total_amount = base_amount + tax_amount

            base_amount_cents = int(base_amount * 100)
            tax_amount_cents = int(tax_amount * 100)
            total_amount_cents = int(total_amount * 100)

            status = invoice_statuses[i % len(invoice_statuses)]

            # Logical dates: due_at = issued_at + payment_terms
            # Use timezone-aware datetimes for DateTimeFields
            issued_date = fake.date_between(start_date="-1y", end_date="today")
            issued_at = timezone.make_aware(datetime.combine(issued_date, datetime.min.time()))
            due_at = issued_at + timedelta(days=payment_terms_days)

            invoice_data: dict[str, Any] = {
                "customer": customer,
                "status": status,
                "issued_at": issued_at,
                "due_at": due_at,
                "subtotal_cents": base_amount_cents,
                "tax_cents": tax_amount_cents,
                "total_cents": total_amount_cents,
                "currency": currency,
                "created_by": admin_user,
                "bill_to_name": customer.get_display_name(),
                "bill_to_email": customer.primary_email,
                "bill_to_address1": billing_snapshot.get("address_line1", ""),
                "bill_to_address2": billing_snapshot.get("address_line2", ""),
                "bill_to_city": billing_snapshot.get("city", ""),
                "bill_to_region": billing_snapshot.get("county", ""),
                "bill_to_country": "RO",
                "bill_to_postal": billing_snapshot.get("postal_code", ""),
                "bill_to_tax_id": bill_to_tax_id,
            }

            invoice = Invoice.objects.create(**invoice_data)

            # Generate proper invoice number using sequence
            sequence, _ = InvoiceSequence.objects.get_or_create(scope="default")
            invoice.number = sequence.get_next_number("INV")
            invoice.save()

            # Set locked_at/paid_at via update() to bypass clean() validation on locked invoices
            post_create_fields: dict[str, Any] = {}
            if status == "paid":
                post_create_fields["paid_at"] = issued_at + timedelta(days=random.randint(1, payment_terms_days))
                post_create_fields["locked_at"] = post_create_fields["paid_at"]
            elif status in ("issued", "overdue", "void"):
                post_create_fields["locked_at"] = issued_at
            if post_create_fields:
                Invoice.objects.filter(pk=invoice.pk).update(**post_create_fields)

            self._create_invoice_lines(fake, invoice, i, base_amount_cents, services)
            invoices.append(invoice)

        return invoices

    def _split_amount_across_lines(self, total_cents: int, num_lines: int, tax_rate: Decimal) -> list[tuple[int, int]]:
        """Split total_cents across num_lines, returning (line_amount_cents, line_total_cents) tuples."""
        base_amount = total_cents // num_lines
        remainder = total_cents - (base_amount * num_lines)
        result = []
        for i in range(num_lines):
            line_amount = base_amount + (1 if i < remainder else 0)
            line_total = line_amount + int(line_amount * tax_rate)
            result.append((line_amount, line_total))
        return result

    def _create_invoice_lines(
        self, fake: Faker, invoice: Invoice, index: int, base_amount_cents: int, services: list[Service]
    ) -> None:
        """Add 1-3 invoice lines with variety in kinds and descriptions."""
        line_kinds = ["service", "setup", "misc"]
        line_descriptions = [
            f"Găzduire web — {fake.month_name()} {fake.year()}",
            f"Taxă instalare server — {fake.month_name()} {fake.year()}",
            f"Consultanță tehnică — {fake.month_name()} {fake.year()}",
        ]
        num_lines = 1 if index % 3 == 0 else (2 if index % 3 == 1 else 3)
        tax_rate = Decimal("0.2100")
        line_splits = self._split_amount_across_lines(base_amount_cents, num_lines, tax_rate)

        for line_idx, (line_amount_cents, line_total_cents) in enumerate(line_splits):
            linked_service = services[line_idx % len(services)] if services and line_idx == 0 else None

            InvoiceLine.objects.create(
                invoice=invoice,
                kind=_cycle(line_kinds, line_idx),
                description=_cycle(line_descriptions, line_idx),
                quantity=Decimal("1.000"),
                unit_price_cents=line_amount_cents,
                tax_rate=tax_rate,
                line_total_cents=line_total_cents,
                service=linked_service,
            )

    def create_customer_proformas(
        self, fake: Faker, customer: Customer, orders: list[Order], count: int
    ) -> list[ProformaInvoice]:
        """Create proforma invoices with logical validity dates and multiple line items"""
        proformas = []
        currency = self._get_ron_currency()
        tax_rule = self._get_ro_tax_rule()
        services = list(Service.objects.filter(customer=customer))

        # Proforma statuses: draft, sent, accepted, expired
        proforma_statuses = ["draft", "sent", "accepted", "expired"]

        # Billing address snapshot
        billing_snapshot = self._billing_address_snapshot(customer)
        bill_to_tax_id = self._customer_tax_id(customer)

        proforma_notes = [
            "Ofertă valabilă conform termenilor comerciali agreați.",
            "Preț include suport tehnic 24/7 și backup zilnic.",
            f"Ofertă personalizată pentru {customer.get_display_name()}.",
            "",
        ]

        for i in range(count):
            order = random.choice(orders) if orders and random.random() < 0.5 else None
            if order:
                base_amount = Decimal(order.subtotal_cents) / 100
                tax_amount = Decimal(order.tax_cents) / 100
                total_amount = Decimal(order.total_cents) / 100
            else:
                base_amount = Decimal(str(random.uniform(100.0, 1000.0))).quantize(Decimal("0.01"))
                tax_amount = base_amount * tax_rule.rate
                total_amount = base_amount + tax_amount

            base_amount_cents = int(base_amount * 100)
            tax_amount_cents = int(tax_amount * 100)
            total_amount_cents = int(total_amount * 100)

            status = proforma_statuses[i % len(proforma_statuses)]

            # Logical valid_until: expired proformas must have past dates
            # Use timezone-aware datetimes for DateTimeFields
            if status == "expired":
                valid_date = fake.date_between(start_date="-60d", end_date="-1d")
            else:
                valid_date = fake.date_between(start_date="today", end_date="+30d")
            valid_until = timezone.make_aware(datetime.combine(valid_date, datetime.min.time()))

            proforma_data: dict[str, Any] = {
                "customer": customer,
                "status": status,
                "valid_until": valid_until,
                "subtotal_cents": base_amount_cents,
                "tax_cents": tax_amount_cents,
                "total_cents": total_amount_cents,
                "currency": currency,
                "notes": proforma_notes[i % len(proforma_notes)],
                "bill_to_name": customer.get_display_name(),
                "bill_to_email": customer.primary_email,
                "bill_to_address1": billing_snapshot.get("address_line1", ""),
                "bill_to_address2": billing_snapshot.get("address_line2", ""),
                "bill_to_city": billing_snapshot.get("city", ""),
                "bill_to_region": billing_snapshot.get("county", ""),
                "bill_to_country": "RO",
                "bill_to_postal": billing_snapshot.get("postal_code", ""),
                "bill_to_tax_id": bill_to_tax_id,
            }

            proforma = ProformaInvoice.objects.create(**proforma_data)

            # Generate proper proforma number using sequence
            sequence, _ = ProformaSequence.objects.get_or_create(scope="default")
            proforma.number = sequence.get_next_number("PRO")
            proforma.save()

            # Add proforma lines — 1-2 items
            num_lines = 1 if i % 2 == 0 else 2
            tax_rate = Decimal("0.2100")
            line_splits = self._split_amount_across_lines(base_amount_cents, num_lines, tax_rate)

            for line_idx, (line_amount_cents, line_total_cents) in enumerate(line_splits):
                linked_service = services[line_idx % len(services)] if services and line_idx == 0 else None
                line_kind = "service" if line_idx == 0 else "setup"
                line_desc = (
                    f"Găzduire web — {fake.month_name()} {fake.year()}"
                    if line_idx == 0
                    else f"Taxă configurare — {fake.month_name()} {fake.year()}"
                )

                ProformaLine.objects.create(
                    proforma=proforma,
                    kind=line_kind,
                    description=line_desc,
                    quantity=Decimal("1.000"),
                    unit_price_cents=line_amount_cents,
                    tax_rate=tax_rate,
                    line_total_cents=line_total_cents,
                    service=linked_service,
                )

            proformas.append(proforma)

        return proformas

    def create_customer_tickets(self, fake: Faker, customer: Customer, count: int) -> list[Ticket]:
        """Create support tickets with full contact info, resolution data, and time tracking"""
        tickets = []
        categories = list(SupportCategory.objects.all())
        support_users = list(User.objects.filter(staff_role="support"))
        admin_user = self._get_admin_user()
        services = list(Service.objects.filter(customer=customer))
        now = timezone.now()

        # Ticket statuses and priorities
        ticket_statuses = ["open", "in_progress", "waiting_on_customer", "closed"]
        ticket_priorities = ["low", "normal", "high", "urgent"]
        ticket_sources = ["web", "email", "phone", "chat", "api"]
        resolution_codes = ["fixed", "invalid", "duplicate", "by_design", "refunded", "other"]

        for i in range(count):
            category = random.choice(categories)
            status = ticket_statuses[i % len(ticket_statuses)]
            priority = ticket_priorities[i % len(ticket_priorities)]

            # Assign to support staff for in-progress/waiting statuses
            assigned_to = None
            assigned_at = None
            if status in ("in_progress", "waiting_on_customer", "closed") and support_users:
                assigned_to = support_users[i % len(support_users)]
                assigned_at = now - timedelta(days=random.randint(1, 30))

            ticket_data: dict[str, Any] = {
                "title": fake.sentence(nb_words=6),
                "description": f"Status: {status}, Priority: {priority}. {fake.text(max_nb_chars=400)}",
                "customer": customer,
                "contact_person": customer.name,
                "contact_email": customer.primary_email,
                "contact_phone": customer.primary_phone or "",
                "category": category,
                "priority": priority,
                "status": status,
                "source": ticket_sources[i % len(ticket_sources)],
                "assigned_to": assigned_to,
                "assigned_at": assigned_at,
                "created_by": admin_user,
                "related_service": services[i % len(services)] if services else None,
                "estimated_hours": Decimal(str(random.choice([0.5, 1.0, 2.0, 4.0, 8.0]))),
                "is_escalated": i % 5 == 0 and priority in ("high", "urgent"),
            }

            # Closed tickets get resolution data and satisfaction
            if status == "closed":
                ticket_data["resolution_code"] = resolution_codes[i % len(resolution_codes)]
                ticket_data["actual_hours"] = Decimal(str(random.choice([0.25, 0.5, 1.0, 2.0, 3.0])))
                ticket_data["satisfaction_rating"] = random.randint(1, 5)
                ticket_data["satisfaction_comment"] = random.choice(
                    [
                        "Rezolvare rapidă, mulțumesc!",
                        "Am așteptat prea mult.",
                        "Excelent suport tehnic.",
                        "",
                    ]
                )

            # Waiting tickets get customer reply tracking
            if status == "waiting_on_customer":
                ticket_data["customer_replied_at"] = now - timedelta(days=random.randint(0, 3))
                ticket_data["has_customer_replied"] = i % 2 == 0

            # In-progress tickets track time spent
            if status == "in_progress":
                ticket_data["actual_hours"] = Decimal(str(random.choice([0.25, 0.5, 1.0])))

            ticket = Ticket.objects.create(**ticket_data)
            tickets.append(ticket)

        return tickets

    # ===============================================================================
    # TICKET COMMENTS AND WORKLOGS
    # ===============================================================================

    def create_ticket_comments(self, fake: Faker, tickets: list[Ticket]) -> None:
        """Create realistic conversation threads per ticket status.

        Open: 1 customer comment. In-progress: 3 comments (customer→support→internal).
        Waiting: 2 comments (customer→reply_and_wait). Closed: 4 comments with solution.
        """
        support_users = list(User.objects.filter(staff_role="support"))
        comment_types = ["customer", "support", "internal", "system"]
        reply_actions = ["reply", "reply_and_wait", "internal_note", "close_with_resolution"]

        for idx, ticket in enumerate(tickets):
            support_user = _cycle(support_users, idx) if support_users else self._get_admin_user()
            customer_name = ticket.contact_person or ticket.customer.name
            customer_email = ticket.contact_email or ticket.customer.primary_email

            if ticket.status == "open":
                TicketComment.objects.create(
                    ticket=ticket,
                    content=f"Bună ziua, {fake.text(max_nb_chars=200)}",
                    comment_type="customer",
                    author_name=customer_name,
                    author_email=customer_email,
                    is_public=True,
                    reply_action="reply",
                )
            elif ticket.status == "in_progress":
                # Customer opens
                TicketComment.objects.create(
                    ticket=ticket,
                    content=f"Am o problemă cu serviciul: {fake.text(max_nb_chars=150)}",
                    comment_type="customer",
                    author_name=customer_name,
                    author_email=customer_email,
                    is_public=True,
                    reply_action="reply",
                )
                # Support replies
                TicketComment.objects.create(
                    ticket=ticket,
                    content=f"Bună ziua, investigăm problema. {fake.text(max_nb_chars=150)}",
                    comment_type="support",
                    author=support_user,
                    author_name=support_user.get_full_name(),
                    author_email=support_user.email,
                    is_public=True,
                    reply_action="reply",
                    time_spent=Decimal("0.25"),
                )
                # Internal note
                TicketComment.objects.create(
                    ticket=ticket,
                    content=f"Notă internă: {fake.text(max_nb_chars=100)}",
                    comment_type="internal",
                    author=support_user,
                    author_name=support_user.get_full_name(),
                    author_email=support_user.email,
                    is_public=False,
                    reply_action="internal_note",
                    time_spent=Decimal("0.50"),
                )
            elif ticket.status == "waiting_on_customer":
                TicketComment.objects.create(
                    ticket=ticket,
                    content=f"Cerere asistență: {fake.text(max_nb_chars=200)}",
                    comment_type="customer",
                    author_name=customer_name,
                    author_email=customer_email,
                    is_public=True,
                    reply_action="reply",
                )
                TicketComment.objects.create(
                    ticket=ticket,
                    content="Vă rugăm să ne furnizați informații suplimentare pentru a continua investigarea.",
                    comment_type="support",
                    author=support_user,
                    author_name=support_user.get_full_name(),
                    author_email=support_user.email,
                    is_public=True,
                    reply_action="reply_and_wait",
                    sets_waiting_on_customer=True,
                    time_spent=Decimal("0.25"),
                )
            elif ticket.status == "closed":
                # Full conversation: customer→support→customer→resolution
                TicketComment.objects.create(
                    ticket=ticket,
                    content=f"Problemă: {fake.text(max_nb_chars=150)}",
                    comment_type="customer",
                    author_name=customer_name,
                    author_email=customer_email,
                    is_public=True,
                    reply_action="reply",
                )
                TicketComment.objects.create(
                    ticket=ticket,
                    content=f"Am identificat cauza. {fake.text(max_nb_chars=100)}",
                    comment_type="support",
                    author=support_user,
                    author_name=support_user.get_full_name(),
                    author_email=support_user.email,
                    is_public=True,
                    reply_action="reply",
                    time_spent=Decimal("0.50"),
                )
                TicketComment.objects.create(
                    ticket=ticket,
                    content="Mulțumesc, funcționează acum.",
                    comment_type=_cycle(comment_types, idx),  # Round-robin variety
                    author_name=customer_name,
                    author_email=customer_email,
                    is_public=True,
                    reply_action=_cycle(reply_actions, idx),
                )
                TicketComment.objects.create(
                    ticket=ticket,
                    content="Problema a fost rezolvată. Închidem tichetul.",
                    comment_type="support",
                    author=support_user,
                    author_name=support_user.get_full_name(),
                    author_email=support_user.email,
                    is_public=True,
                    is_solution=True,
                    reply_action="close_with_resolution",
                    time_spent=Decimal("0.25"),
                )

    def create_ticket_worklogs(self, fake: Faker, tickets: list[Ticket]) -> None:
        """Create 1-3 worklogs for in_progress/closed tickets."""
        support_users = list(User.objects.filter(staff_role="support"))
        time_options = [Decimal("0.25"), Decimal("0.50"), Decimal("1.00"), Decimal("2.00"), Decimal("4.00")]
        descriptions_ro = [
            "Investigare problemă server",
            "Configurare DNS și nameservere",
            "Optimizare bază de date MySQL",
            "Restaurare backup și verificare integritate",
            "Actualizare certificat SSL",
            "Migrare cont hosting pe server nou",
            "Diagnosticare erori PHP și Apache",
        ]

        for idx, ticket in enumerate(tickets):
            if ticket.status not in ("in_progress", "closed"):
                continue

            support_user = _cycle(support_users, idx) if support_users else self._get_admin_user()
            num_worklogs = (idx % 3) + 1  # 1-3 worklogs

            for w_idx in range(num_worklogs):
                is_billable = (idx + w_idx) % 3 == 0
                TicketWorklog.objects.create(
                    ticket=ticket,
                    user=support_user,
                    description=_cycle(descriptions_ro, idx + w_idx),
                    time_spent=_cycle(time_options, idx + w_idx),
                    is_billable=is_billable,
                    hourly_rate=Decimal("150.00") if is_billable else None,
                    work_date=(timezone.now() - timedelta(days=random.randint(0, 14))).date(),
                )

    # ===============================================================================
    # DOMAIN FOUNDATION
    # ===============================================================================

    def create_domain_foundation(self) -> None:
        """Create TLDs, Registrars, and TLD-Registrar assignments."""
        self.stdout.write("Creating domain foundation...")

        tld_data = [
            {
                "extension": ".com",
                "description": "Commercial domain",
                "registration_price_cents": 4999,
                "renewal_price_cents": 5999,
                "transfer_price_cents": 4999,
                "registrar_cost_cents": 800,
                "grace_period_days": 45,
                "is_featured": True,
            },
            {
                "extension": ".ro",
                "description": "Romania country-code domain",
                "registration_price_cents": 2999,
                "renewal_price_cents": 2999,
                "transfer_price_cents": 2999,
                "registrar_cost_cents": 500,
                "grace_period_days": 30,
                "requires_local_presence": True,
                "is_featured": True,
            },
            {
                "extension": ".eu",
                "description": "European Union domain",
                "registration_price_cents": 3499,
                "renewal_price_cents": 3999,
                "transfer_price_cents": 3499,
                "registrar_cost_cents": 600,
                "grace_period_days": 40,
            },
            {
                "extension": ".net",
                "description": "Network infrastructure domain",
                "registration_price_cents": 5499,
                "renewal_price_cents": 5999,
                "transfer_price_cents": 5499,
                "registrar_cost_cents": 850,
                "grace_period_days": 45,
            },
            {
                "extension": ".org",
                "description": "Organization domain",
                "registration_price_cents": 4999,
                "renewal_price_cents": 5499,
                "transfer_price_cents": 4999,
                "registrar_cost_cents": 750,
                "grace_period_days": 45,
            },
            {
                "extension": ".tech",
                "description": "Technology domain",
                "registration_price_cents": 1999,
                "renewal_price_cents": 4999,
                "transfer_price_cents": 3999,
                "registrar_cost_cents": 400,
                "grace_period_days": 30,
            },
        ]

        tlds = {}
        for td in tld_data:
            tld, created = TLD.objects.get_or_create(extension=td["extension"], defaults=td)
            tlds[td["extension"]] = tld
            if created:
                self.stdout.write(f"  ✓ TLD: {tld.extension}")

        registrar_data = [
            {
                "name": "namecheap",
                "display_name": "Namecheap",
                "website_url": "https://www.namecheap.com",
                "api_endpoint": "https://api.namecheap.com/xml.response",
                "status": "active",
                "default_nameservers": ["ns1.pragmatichost.com", "ns2.pragmatichost.com"],
                "currency": "USD",
            },
            {
                "name": "rotld",
                "display_name": "ROTLD (.ro Registry)",
                "website_url": "https://www.rotld.ro",
                "api_endpoint": "https://rest.rotld.ro",
                "status": "active",
                "default_nameservers": ["ns1.pragmatichost.com", "ns2.pragmatichost.com"],
                "currency": "RON",
            },
            {
                "name": "godaddy",
                "display_name": "GoDaddy",
                "website_url": "https://www.godaddy.com",
                "api_endpoint": "https://api.godaddy.com/v1",
                "status": "suspended",
                "default_nameservers": ["ns1.pragmatichost.com", "ns2.pragmatichost.com"],
                "currency": "USD",
            },
        ]

        registrars = {}
        for rd in registrar_data:
            registrar, created = Registrar.objects.get_or_create(name=rd["name"], defaults=rd)
            registrars[rd["name"]] = registrar
            if created:
                self.stdout.write(f"  ✓ Registrar: {registrar.display_name}")

        # TLD → Registrar assignments
        assignments = [
            (".com", "namecheap", True, 1),
            (".com", "godaddy", False, 2),
            (".ro", "rotld", True, 1),
            (".eu", "namecheap", True, 1),
            (".net", "namecheap", True, 1),
            (".org", "namecheap", True, 1),
            (".tech", "namecheap", True, 1),
        ]

        for ext, reg_name, is_primary, priority in assignments:
            TLDRegistrarAssignment.objects.get_or_create(
                tld=tlds[ext],
                registrar=registrars[reg_name],
                defaults={"is_primary": is_primary, "priority": priority},
            )

        self.stdout.write(f"  ✓ Domain foundation: {len(tlds)} TLDs, {len(registrars)} registrars")

    # ===============================================================================
    # CUSTOMER DOMAINS
    # ===============================================================================

    def create_customer_domains(self, fake: Faker, customer: Customer, count: int) -> list[Domain]:
        """Create domains per customer, round-robin over all 7 statuses."""
        domains: list[Domain] = []
        tlds = list(TLD.objects.filter(is_active=True))
        registrars = list(Registrar.objects.filter(status="active"))
        if not tlds or not registrars:
            return domains

        domain_statuses = ["pending", "active", "expired", "suspended", "transfer_in", "transfer_out", "cancelled"]
        now = timezone.now()

        for i in range(count):
            tld = _cycle(tlds, i)
            registrar = _cycle(registrars, i)
            status = _cycle(domain_statuses, i)
            domain_name = f"{fake.domain_word()}-{customer.id}-{i}{tld.extension}"

            domain_kwargs: dict[str, Any] = {
                "name": domain_name,
                "tld": tld,
                "registrar": registrar,
                "customer": customer,
                "status": status,
            }

            if status == "active":
                registered = now - timedelta(days=random.randint(60, 365))
                domain_kwargs.update(
                    {
                        "registered_at": registered,
                        "expires_at": registered + timedelta(days=365),
                        "auto_renew": True,
                        "locked": True,
                        "nameservers": ["ns1.pragmatichost.com", "ns2.pragmatichost.com"],
                        "last_paid_amount_cents": tld.renewal_price_cents,
                    }
                )
            elif status == "expired":
                registered = now - timedelta(days=random.randint(400, 730))
                domain_kwargs.update(
                    {
                        "registered_at": registered,
                        "expires_at": registered + timedelta(days=365),
                        "auto_renew": False,
                        "locked": False,
                    }
                )
            elif status in ("transfer_in", "transfer_out"):
                domain_kwargs.update(
                    {
                        "registered_at": now - timedelta(days=random.randint(100, 300)),
                        "expires_at": now + timedelta(days=random.randint(30, 200)),
                        "locked": False,
                    }
                )
            elif status == "pending":
                domain_kwargs["nameservers"] = ["ns1.pragmatichost.com", "ns2.pragmatichost.com"]

            domain = Domain.objects.create(**domain_kwargs)
            domains.append(domain)

        return domains

    # ===============================================================================
    # FX RATES
    # ===============================================================================

    def _create_fx_rates(self) -> None:
        """Create FX rate entries for EUR→RON, USD→RON, EUR→USD (current + historical)."""
        ron = self._get_ron_currency()
        eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"name": "Euro", "symbol": "€", "decimals": 2})
        usd, _ = Currency.objects.get_or_create(
            code="USD", defaults={"name": "US Dollar", "symbol": "$", "decimals": 2}
        )

        today = timezone.now().date()
        historical = today - timedelta(days=30)

        rates = [
            (eur, ron, Decimal("4.97500000"), today),
            (usd, ron, Decimal("4.56000000"), today),
            (eur, usd, Decimal("1.09100000"), today),
            (eur, ron, Decimal("4.96800000"), historical),
            (usd, ron, Decimal("4.54200000"), historical),
        ]

        for base, quote, rate, as_of in rates:
            FXRate.objects.get_or_create(base_code=base, quote_code=quote, as_of=as_of, defaults={"rate": rate})

    # ===============================================================================
    # PAYMENTS AND CREDIT LEDGER
    # ===============================================================================

    def create_customer_payments(self, fake: Faker, customer: Customer, invoices: list[Invoice]) -> list[Payment]:
        """Create payments for paid invoices + 1 pending + 1 failed."""
        payments = []
        currency = self._get_ron_currency()
        admin_user = self._get_admin_user()
        payment_methods = ["stripe", "bank", "paypal", "cash", "other"]
        now = timezone.now()

        # Payments for paid invoices
        paid_invoices = [inv for inv in invoices if inv.status == "paid"]
        for idx, invoice in enumerate(paid_invoices):
            method = _cycle(payment_methods, idx)
            payment_kwargs: dict[str, Any] = {
                "customer": customer,
                "invoice": invoice,
                "status": "succeeded",
                "payment_method": method,
                "amount_cents": invoice.total_cents,
                "currency": currency,
                "received_at": now - timedelta(days=random.randint(1, 60)),
                "idempotency_key": Payment.generate_idempotency_key(),
                "created_by": admin_user,
            }
            if method == "stripe":
                payment_kwargs["gateway_txn_id"] = f"pi_{fake.hexify(text='^^^^^^^^^^^^^^^^^^^^^^^^')}"
            elif method == "bank":
                payment_kwargs["reference_number"] = f"BT-{fake.random_int(min=100000, max=999999)}"

            payment = Payment.objects.create(**payment_kwargs)
            payments.append(payment)

        # 1 pending payment
        pending_payment = Payment.objects.create(
            customer=customer,
            status="pending",
            payment_method="stripe",
            amount_cents=random.randint(5000, 50000),
            currency=currency,
            gateway_txn_id=f"pi_{fake.hexify(text='^^^^^^^^^^^^^^^^^^^^^^^^')}",
            idempotency_key=Payment.generate_idempotency_key(),
            received_at=now,
            created_by=admin_user,
        )
        payments.append(pending_payment)

        # 1 failed payment
        failed_payment = Payment.objects.create(
            customer=customer,
            status="failed",
            payment_method="stripe",
            amount_cents=random.randint(5000, 50000),
            currency=currency,
            gateway_txn_id=f"pi_{fake.hexify(text='^^^^^^^^^^^^^^^^^^^^^^^^')}",
            idempotency_key=Payment.generate_idempotency_key(),
            received_at=now - timedelta(days=2),
            notes="Card declined — insufficient funds",
            created_by=admin_user,
        )
        payments.append(failed_payment)

        return payments

    def create_customer_credit_entries(self, fake: Faker, customer: Customer, payments: list[Payment]) -> None:
        """Create 3-4 CreditLedger entries per customer (mix of credits and debits)."""
        admin_user = self._get_admin_user()
        succeeded_payments = [p for p in payments if p.status == "succeeded"]

        # Promotional credit
        CreditLedger.objects.create(
            customer=customer,
            delta_cents=5000,
            reason="Credit promoțional — bun venit",
            created_by=admin_user,
        )
        # Credit used on invoice
        first_invoice = Invoice.objects.filter(customer=customer, status="paid").first()
        CreditLedger.objects.create(
            customer=customer,
            invoice=first_invoice,
            delta_cents=-3000,
            reason="Credit aplicat pe factura",
            created_by=admin_user,
        )
        # Overpayment credit
        if succeeded_payments:
            CreditLedger.objects.create(
                customer=customer,
                payment=succeeded_payments[0],
                delta_cents=1200,
                reason="Suprapagină — diferență rambursată ca credit",
                created_by=admin_user,
            )
        # Refund credit
        CreditLedger.objects.create(
            customer=customer,
            delta_cents=8000,
            reason="Credit din rambursare serviciu anulat",
            created_by=admin_user,
        )

    # ===============================================================================
    # SUBSCRIPTIONS
    # ===============================================================================

    def create_customer_subscriptions(self, fake: Faker, customer: Customer, count: int) -> list[Subscription]:
        """Create subscriptions covering all 7 statuses and billing cycles."""
        subscriptions: list[Subscription] = []
        products = list(Product.objects.filter(is_active=True))
        currency = self._get_ron_currency()
        admin_user = self._get_admin_user()

        if not products:
            return subscriptions

        statuses = ["trialing", "active", "past_due", "paused", "cancelled", "expired", "pending"]
        billing_cycles = ["monthly", "quarterly", "semi_annual", "yearly"]
        cancel_reasons = [
            "customer_request",
            "non_payment",
            "fraud",
            "service_issue",
            "upgrade",
            "downgrade",
            "business_closed",
            "competitor",
            "other",
        ]
        now = timezone.now()

        for i in range(count):
            product = _cycle(products, i)
            status = _cycle(statuses, i)
            cycle = _cycle(billing_cycles, i)

            # Get product price for realistic pricing
            price = ProductPrice.objects.filter(product=product, currency=currency).first()
            unit_price_cents = price.monthly_price_cents if price else 2999

            # Period dates must satisfy clean(): period_end > period_start
            period_start = now - timedelta(days=15)
            period_end = now + timedelta(days=15)

            # Adjust for expired: both dates in the past, end > start
            if status == "expired":
                period_start = now - timedelta(days=60)
                period_end = now - timedelta(days=random.randint(1, 30))

            sub_kwargs: dict[str, Any] = {
                "customer": customer,
                "product": product,
                "status": status,
                "billing_cycle": cycle,
                "currency": currency,
                "unit_price_cents": unit_price_cents,
                "current_period_start": period_start,
                "current_period_end": period_end,
                "next_billing_date": period_end,
                "created_by": admin_user,
            }

            self._apply_subscription_status_fields(
                sub_kwargs, status, i, now, unit_price_cents, period_end, cancel_reasons
            )

            subscription = Subscription.objects.create(**sub_kwargs)
            self._create_subscription_items(subscription, status, i, products, currency)
            subscriptions.append(subscription)

        return subscriptions

    @staticmethod
    def _apply_subscription_status_fields(  # noqa: PLR0913
        sub_kwargs: dict[str, Any],
        status: str,
        index: int,
        now: Any,
        unit_price_cents: int,
        period_end: Any,
        cancel_reasons: list[str],
    ) -> None:
        """Apply status-specific fields to subscription kwargs."""
        if status == "active":
            sub_kwargs["started_at"] = now - timedelta(days=random.randint(30, 180))
            sub_kwargs["failed_payment_count"] = 0
            sub_kwargs["last_payment_date"] = now - timedelta(days=random.randint(1, 30))
            sub_kwargs["last_payment_amount_cents"] = unit_price_cents
            if index == 0:  # Grandfathered price on first active subscription
                sub_kwargs["locked_price_cents"] = int(unit_price_cents * 0.8)
                sub_kwargs["locked_price_reason"] = "Preț grandfathered — client fidel"
                sub_kwargs["locked_price_expires_at"] = now + timedelta(days=365)
        elif status == "trialing":
            sub_kwargs["trial_start"] = now - timedelta(days=3)
            sub_kwargs["trial_end"] = now + timedelta(days=11)
            sub_kwargs["trial_converted"] = False
        elif status == "past_due":
            sub_kwargs["started_at"] = now - timedelta(days=90)
            sub_kwargs["failed_payment_count"] = 2
            sub_kwargs["grace_period_ends_at"] = now + timedelta(days=3)
        elif status == "paused":
            sub_kwargs["started_at"] = now - timedelta(days=120)
            sub_kwargs["paused_at"] = now - timedelta(days=5)
            sub_kwargs["resume_at"] = now + timedelta(days=25)
        elif status == "cancelled":
            sub_kwargs["started_at"] = now - timedelta(days=200)
            sub_kwargs["cancelled_at"] = now - timedelta(days=random.randint(1, 10))
            sub_kwargs["cancellation_reason"] = _cycle(cancel_reasons, index)
            sub_kwargs["cancel_at_period_end"] = index % 2 == 0
        elif status == "expired":
            sub_kwargs["started_at"] = now - timedelta(days=400)
            sub_kwargs["ended_at"] = period_end

    @staticmethod
    def _create_subscription_items(
        subscription: Subscription,
        status: str,
        index: int,
        products: list[Product],
        currency: Currency,
    ) -> None:
        """Add 1-2 SubscriptionItems for active/trialing subscriptions."""
        if status not in ("active", "trialing"):
            return
        num_items = min(2, len(products))
        for si_idx in range(num_items):
            si_product = _cycle(products, index + si_idx + 1)
            si_price = ProductPrice.objects.filter(product=si_product, currency=currency).first()
            si_unit = si_price.monthly_price_cents if si_price else 1999
            SubscriptionItem.objects.get_or_create(
                subscription=subscription,
                product=si_product,
                defaults={"unit_price_cents": si_unit, "quantity": 1},
            )

    # ===============================================================================
    # REFUNDS
    # ===============================================================================

    def create_customer_refunds(
        self,
        fake: Faker,
        customer: Customer,
        orders: list[Order],
        invoices: list[Invoice],
        payments: list[Payment],
    ) -> list[Refund]:
        """Create 3-5 refunds per customer. XOR constraint: each gets EITHER order OR invoice."""
        refunds = []
        currency = self._get_ron_currency()
        admin_user = self._get_admin_user()

        refund_statuses = ["pending", "processing", "approved", "completed", "rejected", "failed", "cancelled"]
        refund_reasons = [
            "customer_request",
            "error_correction",
            "dispute",
            "service_failure",
            "duplicate_payment",
            "fraud",
            "cancellation",
            "downgrade",
            "administrative",
        ]

        count = min(5, max(3, len(orders) + len(invoices)))
        succeeded_payments = [p for p in payments if p.status == "succeeded"]

        for i in range(count):
            status = _cycle(refund_statuses, i)
            reason = _cycle(refund_reasons, i)

            # XOR constraint: odd index → order, even index → invoice
            order = None
            invoice = None
            if i % 2 == 1 and orders:
                order = _cycle(orders, i)
                original_cents = order.total_cents
            elif invoices:
                invoice = _cycle(invoices, i)
                original_cents = invoice.total_cents
            elif orders:
                order = _cycle(orders, i)
                original_cents = order.total_cents
            else:
                continue  # No orders or invoices to refund

            # Full or partial
            refund_type = "full" if i % 2 == 0 else "partial"
            amount_cents = original_cents if refund_type == "full" else max(1, original_cents // 2)

            refund_kwargs: dict[str, Any] = {
                "customer": customer,
                "order": order,
                "invoice": invoice,
                "payment": _cycle(succeeded_payments, i) if succeeded_payments else None,
                "status": status,
                "refund_type": refund_type,
                "reason": reason,
                "amount_cents": amount_cents,
                "original_amount_cents": original_cents,
                "currency": currency,
                "reason_description": f"Motiv rambursare: {reason.replace('_', ' ')}",
                "created_by": admin_user,
            }

            if status in ("approved", "completed"):
                refund_kwargs["approved_by"] = admin_user
            if status == "completed":
                refund_kwargs["processed_at"] = timezone.now() - timedelta(days=random.randint(1, 14))
                refund_kwargs["processed_by"] = admin_user

            refund = Refund.objects.create(**refund_kwargs)
            refunds.append(refund)

        return refunds

    # ===============================================================================
    # EMAIL PREFERENCES
    # ===============================================================================

    def create_customer_email_preference(self, customer: Customer, index: int) -> None:
        """Create EmailPreference for a customer with varied settings."""
        frequencies = ["immediate", "daily_digest", "weekly_digest"]
        is_global_unsub = index == 3  # One customer fully unsubscribed

        defaults: dict[str, Any] = {
            "notification_frequency": _cycle(frequencies, index),
            "marketing": customer.marketing_consent,
            "newsletter": index % 2 == 0,
            "product_updates": True,
            "global_unsubscribe": is_global_unsub,
        }

        if customer.marketing_consent:
            defaults["marketing_consent_date"] = timezone.now() - timedelta(days=random.randint(30, 365))
            defaults["marketing_consent_source"] = "registration_form"

        if is_global_unsub:
            defaults["unsubscribed_at"] = timezone.now() - timedelta(days=random.randint(1, 30))
            defaults["unsubscribe_reason"] = "Prea multe emailuri"

        EmailPreference.objects.get_or_create(customer=customer, defaults=defaults)

    # ===============================================================================
    # WEBHOOK EVENTS
    # ===============================================================================

    def create_webhook_events(self) -> None:
        """Create 8-10 webhook events covering all statuses and sources."""
        self.stdout.write("Creating webhook events...")

        events: list[dict[str, Any]] = [
            {
                "source": "stripe",
                "event_id": "evt_test_payment_succeeded_001",
                "event_type": "payment_intent.succeeded",
                "status": "processed",
                "payload": {
                    "type": "payment_intent.succeeded",
                    "data": {"object": {"id": "pi_test001", "amount": 29990}},
                },
            },
            {
                "source": "stripe",
                "event_id": "evt_test_subscription_created_001",
                "event_type": "customer.subscription.created",
                "status": "processed",
                "payload": {"type": "customer.subscription.created", "data": {"object": {"id": "sub_test001"}}},
            },
            {
                "source": "stripe",
                "event_id": "evt_test_payment_failed_001",
                "event_type": "payment_intent.payment_failed",
                "status": "failed",
                "payload": {"type": "payment_intent.payment_failed", "data": {"object": {"id": "pi_fail001"}}},
                "error_message": "Card declined: insufficient_funds",
                "retry_count": 2,
                "next_retry_at": timezone.now() + timedelta(hours=4),
            },
            {
                "source": "paypal",
                "event_id": "WH-test-paypal-001",
                "event_type": "PAYMENT.CAPTURE.COMPLETED",
                "status": "processed",
                "payload": {"event_type": "PAYMENT.CAPTURE.COMPLETED", "resource": {"id": "CAP-001"}},
            },
            {
                "source": "virtualmin",
                "event_id": "vm-hook-domain-created-001",
                "event_type": "domain.created",
                "status": "processed",
                "payload": {"action": "domain.created", "domain": "test.pragmatichost.com"},
            },
            {
                "source": "virtualmin",
                "event_id": "vm-hook-backup-completed-001",
                "event_type": "backup.completed",
                "status": "pending",
                "payload": {"action": "backup.completed", "domain": "test.pragmatichost.com", "size_mb": 250},
            },
            {
                "source": "efactura",
                "event_id": "efact-upload-001",
                "event_type": "invoice.uploaded",
                "status": "processed",
                "payload": {"index_incarcare": "12345", "stare": "ok"},
            },
            {
                "source": "efactura",
                "event_id": "efact-download-001",
                "event_type": "invoice.response_received",
                "status": "skipped",
                "payload": {"index_incarcare": "12345", "stare": "duplicat"},
                "error_message": "Duplicate event — already processed",
            },
            {
                "source": "stripe",
                "event_id": "evt_test_invoice_paid_001",
                "event_type": "invoice.paid",
                "status": "processed",
                "payload": {"type": "invoice.paid", "data": {"object": {"id": "in_test001", "amount_paid": 59990}}},
            },
            {
                "source": "paypal",
                "event_id": "WH-test-paypal-refund-001",
                "event_type": "PAYMENT.CAPTURE.REFUNDED",
                "status": "pending",
                "payload": {"event_type": "PAYMENT.CAPTURE.REFUNDED", "resource": {"id": "REF-001"}},
            },
        ]

        for evt in events:
            evt_copy: dict[str, Any] = {**evt}
            source = evt_copy.pop("source")
            event_id = evt_copy.pop("event_id")
            WebhookEvent.objects.get_or_create(source=source, event_id=event_id, defaults=evt_copy)

        self.stdout.write(f"  ✓ Webhook events: {WebhookEvent.objects.count()}")
