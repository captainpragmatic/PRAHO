"""
Django management command to generate sample data for PRAHO Platform
Romanian hosting provider test data generation.
"""

import random
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.utils import timezone
from faker import Faker

from apps.billing.invoice_models import InvoiceSequence
from apps.billing.models import Currency, Invoice, InvoiceLine, ProformaInvoice, ProformaLine, TaxRule
from apps.billing.proforma_models import ProformaSequence
from apps.customers.models import (
    Customer,
    CustomerAddress,
    CustomerBillingProfile,
    CustomerNote,
    CustomerPaymentMethod,
    CustomerTaxProfile,
)
from apps.orders.models import Order, OrderItem
from apps.products.models import Product, ProductPrice
from apps.provisioning.models import Server, Service, ServicePlan
from apps.tickets.models import SupportCategory, Ticket
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


class Command(BaseCommand):
    help = "Generate sample data for Romanian hosting provider"

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

        fake = Faker("ro_RO")  # Romanian locale
        Faker.seed(42)  # Consistent data

        self.stdout.write("�� Generating comprehensive test data for PragmaticHost...")

        # Create foundation data first
        self.create_admin_users(fake)
        self.create_service_plans()
        self.create_servers()
        self.create_support_categories()
        self.create_billing_foundation()

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

        total_customers = len(customers)
        self.stdout.write(
            self.style.SUCCESS(
                f"✅ Success! Generated: {total_customers} customers "
                f"(1 test + 8 permutation + {max(0, num_customers - 1)} random), "
                f"{num_users} users, "
                f"{total_customers * services_per_customer} services, "
                f"{total_customers * orders_per_customer} orders, "
                f"{total_customers * (invoices_per_customer + proformas_per_customer)} billing documents, "
                f"{total_customers * tickets_per_customer} tickets"
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

    def create_customers(self, fake: Faker, count: int) -> list[Customer]:
        self.stdout.write(f"Creez {count} clienți...")
        customers = []

        # Romanian counties
        counties = [
            "București",
            "Cluj",
            "Timiș",
            "Iași",
            "Constanța",
            "Brașov",
            "Galați",
            "Craiova",
            "Ploiești",
            "Oradea",
        ]

        for i in range(count):
            customer_type = random.choice(["individual", "company", "pfa"])

            customer_data = {
                "customer_type": customer_type,
                "status": random.choice(["active", "prospect"]),
                "name": fake.name(),
                "email": fake.email(),
                "phone": f"+40.7{random.randint(10, 99)}.{random.randint(100, 999)}.{random.randint(100, 999)}",
                "address_line1": fake.street_address(),
                "city": fake.city(),
                "county": random.choice(counties),
                "postal_code": f"{random.randint(100000, 999999)}",
                "country": "România",
                "payment_terms": random.choice([15, 30, 45]),
                "data_processing_consent": True,
                "marketing_consent": random.choice([True, False]),
            }

            if customer_type in ["company", "pfa"]:
                customer_data.update(
                    {
                        "company_name": fake.company(),
                        "cui": f"RO{random.randint(1000000, 99999999)}",
                        "is_vat_payer": True,
                        "industry": random.choice(
                            ["IT & Software", "E-commerce", "Servicii", "Producție", "Consultanță", "Media"]
                        ),
                    }
                )

            customer = Customer.objects.create(**customer_data)
            customers.append(customer)

            if i % 10 == 0:
                self.stdout.write(f"  ✓ Creat {i + 1}/{count} clienți")

        return customers

    def create_services(self, fake: Faker, customers: list[Customer], count: int) -> None:
        self.stdout.write(f"Creez {count} servicii...")

        plans = list(ServicePlan.objects.all())
        servers = list(Server.objects.all())

        for i in range(count):
            customer = random.choice(customers)
            plan = random.choice(plans)
            server = random.choice(servers) if servers else None

            status = random.choice(["active", "pending", "suspended"])
            activated = timezone.now() - timedelta(days=random.randint(30, 365)) if status == "active" else None
            service_data = {
                "customer": customer,
                "service_plan": plan,
                "server": server,
                "service_name": f"{plan.name} - {customer.name}",
                "domain": f"{fake.domain_name()}",
                "username": f"user{random.randint(1000, 9999)}",
                "billing_cycle": random.choice(["monthly", "annual"]),
                "price": plan.price_monthly,
                "status": status,
                "auto_renew": random.choice([True, False]),
                "activated_at": activated,
                "expires_at": timezone.now() + timedelta(days=random.randint(30, 365)) if activated else None,
            }

            service = Service.objects.create(**service_data)

            if i % 20 == 0:
                self.stdout.write(f"  ✓ Creat {i + 1}/{count} servicii")

    def create_tickets(self, fake: Faker, customers: list[Customer], count: int) -> None:
        self.stdout.write(f"Creez {count} tickete...")

        categories = list(SupportCategory.objects.all())
        support_users = list(User.objects.filter(role="support"))

        for i in range(count):
            customer = random.choice(customers)
            category = random.choice(categories)
            assigned_to = random.choice(support_users) if random.choice([True, False]) else None

            ticket_data = {
                "title": fake.sentence(nb_words=6),
                "description": fake.text(max_nb_chars=500),
                "customer": customer,
                "contact_email": customer.primary_email,
                "category": category,
                "priority": random.choice(["low", "normal", "high"]),
                "status": random.choice(["open", "in_progress", "waiting_on_customer", "closed"]),
                "source": random.choice(["web", "email", "phone"]),
                "assigned_to": assigned_to,
            }

            ticket = Ticket.objects.create(**ticket_data)

            if i % 50 == 0:
                self.stdout.write(f"  ✓ Creat {i + 1}/{count} tickete")

    # ===============================================================================
    # COMPREHENSIVE DATA GENERATION METHODS
    # ===============================================================================

    def create_billing_foundation(self) -> None:
        """Create base billing data and clean existing sample data"""
        # Clean existing sample data in proper order to avoid FK constraints
        # Delete orders first (and their items via CASCADE)

        # Delete in reverse dependency order
        Order.objects.filter(customer__primary_email__contains="@example.").delete()
        Invoice.objects.filter(customer__primary_email__contains="@example.").delete()
        ProformaInvoice.objects.filter(customer__primary_email__contains="@example.").delete()
        Ticket.objects.filter(customer__primary_email__contains="@example.").delete()

        # Delete services (which may be referenced by orders)
        Service.objects.filter(customer__primary_email__contains="@example.").delete()

        # Delete customer memberships
        CustomerMembership.objects.filter(customer__primary_email__contains="@example.").delete()

        # Now delete customers and their profiles
        Customer.objects.filter(primary_email__contains="@example.").delete()

        # Delete users
        User.objects.filter(email__contains="@example.").delete()

        print("✓ Cleaned existing sample data")

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
            print("✓ Created RON currency")

        # Create Romanian VAT tax rule
        _, created = TaxRule.objects.get_or_create(
            country_code="RO",
            tax_type="vat",
            valid_from=timezone.now().date(),
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
            print("✓ Created Romanian VAT tax rule")

    def create_products_from_service_plans(self) -> None:
        """Create Product objects and ProductPrice objects based on existing ServicePlans with new pricing model"""
        service_plans = ServicePlan.objects.all()

        # Get RON currency (should exist from billing foundation)
        try:
            ron_currency = Currency.objects.get(code="RON")
        except Currency.DoesNotExist:
            # Create RON currency if it doesn't exist
            ron_currency = Currency.objects.create(code="RON", name="Romanian Leu", symbol="RON", is_active=True)
            print("✓ Created RON currency")

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

        print(f"✓ Created/verified {service_plans.count()} products from service plans")
        print(f"✓ Created {products_created} new products, {prices_created} new product prices")

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

        # Create test company if it doesn't exist
        if customer is None:
            customer_data = {
                "customer_type": "company",
                "name": "Test Company SRL",
                "company_name": "Test Company SRL",
                "primary_email": test_company_email,
                "primary_phone": "+40722123456",
                "status": "active",
            }

            customer = Customer.objects.create(**customer_data)
            self.stdout.write(f"  ✓ Created test company: {customer.get_display_name()} (ID: {customer.id})")

            # Create customer address with specific data
            address = CustomerAddress.objects.create(
                customer=customer,
                address_type="billing",
                address_line1="Str. Revolutiei nr. 1",
                city="Bucharest",
                county="Bucharest",
                postal_code="010000",
                country="România",
            )

            # Create tax profile with specific CUI
            tax_profile = CustomerTaxProfile.objects.create(
                customer=customer,
                cui="RO12345678",
                is_vat_payer=True,
                vat_number="RO12345678",
                reverse_charge_eligible=True,
            )

            # Create billing profile
            billing_profile = CustomerBillingProfile.objects.create(
                customer=customer, payment_terms=30, preferred_currency="RON", invoice_delivery_method="email"
            )

        # Create customer membership for the test user (if it doesn't exist)
        _, created = CustomerMembership.objects.get_or_create(
            customer=customer, user=test_user, defaults={"role": "owner", "is_primary": True}
        )

        if created:
            self.stdout.write(f"  ✓ Created customer membership for {test_user.email}")
        else:
            self.stdout.write(f"  ✓ Customer membership already exists for {test_user.email}")

        # Clear existing test data for Test Company to ensure fresh comprehensive test data
        self.stdout.write("  ✓ Clearing existing test data for Test Company...")
        Service.objects.filter(customer=customer).delete()
        Order.objects.filter(customer=customer).delete()

        Invoice.objects.filter(customer=customer).delete()
        ProformaInvoice.objects.filter(customer=customer).delete()
        Ticket.objects.filter(customer=customer).delete()

        # Create services, orders, invoices, proformas, and tickets with comprehensive test data
        services = self.create_customer_services(fake, customer, 7)  # 7 services with different statuses
        orders = self.create_customer_orders(fake, customer, 7)  # 7 orders with different statuses
        self.create_customer_invoices(fake, customer, orders, 10)  # 10 invoices with different statuses
        self.create_customer_proformas(fake, customer, orders, 5)  # 5 proformas with different statuses
        self.create_customer_tickets(fake, customer, 10)  # 10 tickets with different statuses

        self.stdout.write(
            "  ✅ Created comprehensive test data: 7 services, 7 orders, 10 invoices, 5 proformas, 10 tickets"
        )

        return customer

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

        # --- Tax profile ---
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
        elif customer_type == "individual":
            # Some individuals have a CNP for tax purposes
            if index % 2 == 0:
                CustomerTaxProfile.objects.create(
                    customer=customer,
                    cnp=f"1{fake.random_int(min=800101, max=990101)}{fake.random_int(min=10, max=52)}{fake.random_int(min=100, max=999)}",
                    is_vat_payer=False,
                )

        # --- Billing profile with variety ---
        currencies = ["RON", "EUR"]
        delivery_methods = ["email", "postal", "both"]
        payment_terms_options = [15, 30, 45, 60]
        CustomerBillingProfile.objects.create(
            customer=customer,
            payment_terms=payment_terms_options[index % len(payment_terms_options)],
            preferred_currency=currencies[index % len(currencies)],
            invoice_delivery_method=delivery_methods[index % len(delivery_methods)],
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
                "swift": random.choice(["BTRLRO22", "BRDEROBU", "INGBROBU", "RNCBROBU"]),
            }
        CustomerPaymentMethod.objects.create(**sec_kwargs)

        # --- Notes ---
        admin_user = User.objects.filter(is_superuser=True).first()
        note_types = ["general", "call", "email", "meeting", "complaint", "compliment"]
        # 2 notes per customer, round-robin type
        for n in range(2):
            note_type = note_types[(index * 2 + n) % len(note_types)]
            CustomerNote.objects.create(
                customer=customer,
                created_by=admin_user,
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
        self.create_customer_services(fake, customer, config.services_count)
        orders = self.create_customer_orders(fake, customer, config.orders_count)
        self.create_customer_invoices(fake, customer, orders, config.invoices_count)
        self.create_customer_proformas(fake, customer, orders, config.proformas_count)
        self.create_customer_tickets(fake, customer, config.tickets_count)

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

        # Cities and counties for address variety
        romanian_cities = [
            ("București", "București"),
            ("Cluj-Napoca", "Cluj"),
            ("Timișoara", "Timiș"),
            ("Iași", "Iași"),
            ("Constanța", "Constanța"),
            ("Brașov", "Brașov"),
            ("Sibiu", "Sibiu"),
            ("Oradea", "Bihor"),
        ]

        address_types = ["primary", "billing", "delivery", "legal"]
        payment_method_types = ["stripe_card", "bank_transfer", "cash", "other"]
        note_types = ["general", "call", "email", "meeting", "complaint", "compliment"]
        membership_roles = ["owner", "billing", "tech", "viewer"]
        currencies = ["RON", "EUR"]
        delivery_methods = ["email", "postal", "both"]
        contact_methods = ["email", "phone", "both"]

        for idx, cust_data in enumerate(permutations):
            city, county = romanian_cities[idx % len(romanian_cities)]

            customer = Customer.objects.create(**cust_data)
            customers.append(customer)
            self.stdout.write(
                f"  ✓ Permutation {idx + 1}/8: {customer.get_display_name()} "
                f"[{customer.customer_type}/{customer.status}]"
            )

            self._perm_addresses(customer, idx, city, county)
            self._perm_tax_profile(customer, idx)
            self._perm_billing_profile(customer, idx, currencies, delivery_methods)
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
            address_type="billing",
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
            address_type="billing",
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
            address_type="primary",
            address_line1=f"Str. Principală nr. {idx + 10}",
            city=city,
            county=county,
            postal_code=f"{200000 + idx * 1111}",
            country="România",
            is_current=True,
            is_validated=idx % 2 == 0,
        )
        # Delivery address (not for minimal customer #7)
        if idx != 6:
            CustomerAddress.objects.create(
                customer=customer,
                address_type="delivery",
                address_line1=f"Str. Livrare nr. {idx + 20}",
                city=city,
                county=county,
                postal_code=f"{300000 + idx * 1111}",
                country="România",
                is_current=True,
            )
        # Legal address for business types
        if customer.customer_type in ("company", "pfa", "ngo"):
            CustomerAddress.objects.create(
                customer=customer,
                address_type="legal",
                address_line1=f"Str. Sediu Social nr. {idx + 30}",
                address_line2=f"Et. {idx + 1}, Ap. {idx * 3 + 1}",
                city=city,
                county=county,
                postal_code=f"{400000 + idx * 1111}",
                country="România",
                is_current=True,
                is_validated=True,
            )

    def _perm_tax_profile(self, customer: Customer, idx: int) -> None:
        """Create deterministic tax profile for a permutation customer."""
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
        elif customer.customer_type == "individual" and idx == 0:
            CustomerTaxProfile.objects.create(
                customer=customer,
                cnp="1850101400001",
                is_vat_payer=False,
            )

    def _perm_billing_profile(
        self, customer: Customer, idx: int, currencies: list[str], delivery_methods: list[str]
    ) -> None:
        """Create deterministic billing profile for a permutation customer."""
        CustomerBillingProfile.objects.create(
            customer=customer,
            payment_terms=[15, 30, 45, 60][idx % 4],
            preferred_currency=currencies[idx % len(currencies)],
            invoice_delivery_method=delivery_methods[idx % len(delivery_methods)],
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
                            "swift": "BTRLRO22",
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
        romanian_counties = ["București", "Cluj", "Timiș", "Iași", "Constanța", "Brașov"]
        county = romanian_counties[index % len(romanian_counties)]

        # Historical billing address (version 1, non-current) — demonstrates versioning
        CustomerAddress.objects.create(
            customer=customer,
            address_type="billing",
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
            address_type="billing",
            address_line1=fake.street_address(),
            city=fake.city(),
            county=county,
            postal_code=fake.postcode(),
            country="România",
            is_current=True,
            is_validated=True,
            version=2,
        )
        # Primary address
        CustomerAddress.objects.create(
            customer=customer,
            address_type="primary",
            address_line1=fake.street_address(),
            city=fake.city(),
            county=county,
            postal_code=fake.postcode(),
            country="România",
            is_current=True,
        )
        # Legal address for business types
        if customer_type in ("company", "pfa"):
            CustomerAddress.objects.create(
                customer=customer,
                address_type="legal",
                address_line1=f"Str. {fake.last_name()} nr. {fake.random_int(min=1, max=200)}",
                city=fake.city(),
                county=county,
                postal_code=fake.postcode(),
                country="România",
                is_current=True,
            )
        # Delivery address for some
        if index % 3 == 0:
            CustomerAddress.objects.create(
                customer=customer,
                address_type="delivery",
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

            activated = timezone.now() - timedelta(days=random.randint(30, 365)) if status == "active" else None
            service_data = {
                "customer": customer,
                "service_plan": plan,
                "server": server,
                "service_name": f"{plan.name} - {customer.get_display_name()} [{status.title()}]",
                "domain": fake.domain_name(),
                "username": f"user{customer.id:04d}{i:03d}{random.randint(100, 999)}",  # Unique username
                "billing_cycle": random.choice(["monthly", "quarterly", "annual"]),
                "price": plan.price_monthly,
                "status": status,
                "auto_renew": status == "active",  # Only active services auto-renew
                "activated_at": activated,
                "expires_at": timezone.now() + timedelta(days=random.randint(30, 365)) if activated else None,
            }

            service = Service.objects.create(**service_data)
            services.append(service)

        return services

    def create_customer_orders(self, fake: Faker, customer: Customer, count: int) -> list[Order]:
        """Create orders for a customer with diverse statuses"""
        orders = []
        services = list(Service.objects.filter(customer=customer))
        currency = Currency.objects.get(code="RON")

        # Order statuses: draft, pending, confirmed, processing, completed, cancelled, failed, refunded, partially_refunded
        order_statuses = ["draft", "pending", "confirmed", "processing", "completed", "cancelled", "failed"]

        for i in range(count):
            # Generate amounts in cents for precision
            base_amount = Decimal(str(random.uniform(50.0, 500.0))).quantize(Decimal("0.01"))
            subtotal_cents = int(base_amount * 100)  # Convert to cents
            tax_cents = int(subtotal_cents * Decimal("0.21"))  # 21% VAT
            total_cents = subtotal_cents + tax_cents

            # Use specific statuses for comprehensive testing
            status = order_statuses[i % len(order_statuses)]

            order_data = {
                "customer": customer,
                "order_number": f"ORD-{customer.id:04d}-{i + 1:03d}-{status.upper()}",
                "status": status,
                "currency": currency,
                "subtotal_cents": subtotal_cents,
                "tax_cents": tax_cents,
                "total_cents": total_cents,
                "customer_email": customer.primary_email,
                "customer_name": customer.name,
                "customer_company": customer.company_name or "",
                "created_at": fake.date_time_between(
                    start_date="-1y", end_date="now", tzinfo=timezone.get_current_timezone()
                ),
            }

            order = Order.objects.create(**order_data)

            # Add order items (link to services)
            if services:
                num_items = random.randint(1, min(3, len(services)))
                order_services = random.sample(services, num_items)

                for service in order_services:
                    unit_price_cents = int(service.price * 100)
                    tax_cents = int(unit_price_cents * Decimal("0.21"))  # 21% VAT
                    line_total_cents = unit_price_cents + tax_cents

                    # Get the Product that corresponds to this service's plan
                    try:
                        product = Product.objects.get(slug=f"product-{service.service_plan.id}")
                    except Product.DoesNotExist:
                        # Fallback: create a basic product
                        product = Product.objects.create(
                            slug=f"product-{service.service_plan.id}",
                            name=service.service_plan.name,
                            description=service.service_plan.description,
                            product_type="shared_hosting",
                            is_active=True,
                        )

                    OrderItem.objects.create(
                        order=order,
                        product=product,
                        product_name=service.service_plan.name,
                        product_type=service.service_plan.plan_type,
                        quantity=1,
                        unit_price_cents=unit_price_cents,
                        tax_rate=Decimal("0.2100"),
                        tax_cents=tax_cents,
                        line_total_cents=line_total_cents,
                        service=service,  # Link to provisioned service
                    )

            orders.append(order)

        return orders

    def create_customer_invoices(
        self, fake: Faker, customer: Customer, orders: list[Order], count: int
    ) -> list[Invoice]:
        """Create invoices for a customer linked to orders"""
        invoices = []
        currency = Currency.objects.get(code="RON")
        tax_rule, _ = TaxRule.objects.get_or_create(
            country_code="RO",
            tax_type="vat",
            valid_from=timezone.now().date(),
            defaults={
                "rate": Decimal("0.21"),  # 21% VAT for Romania (Aug 2025)
                "applies_to_b2b": True,
                "applies_to_b2c": True,
                "reverse_charge_eligible": True,
                "is_eu_member": True,
                "vies_required": True,
            },
        )

        # Invoice statuses: draft, issued, paid, overdue, void, refunded
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

        for i in range(count):
            # Some invoices are linked to orders, some are standalone
            order = random.choice(orders) if orders and random.random() < 0.5 else None
            if order:
                base_amount = Decimal(order.subtotal_cents) / 100  # Convert cents to decimal
                tax_amount = Decimal(order.tax_cents) / 100
                total_amount = Decimal(order.total_cents) / 100
            else:
                base_amount = Decimal(str(random.uniform(100.0, 1000.0))).quantize(Decimal("0.01"))
                tax_amount = base_amount * tax_rule.rate
                total_amount = base_amount + tax_amount
            # Generate amounts in cents for precision
            base_amount_cents = int(base_amount * 100)
            tax_amount_cents = int(tax_amount * 100)
            total_amount_cents = int(total_amount * 100)

            # Use specific statuses for comprehensive testing (includes extra paid/issued for realism)
            status = invoice_statuses[i % len(invoice_statuses)]

            invoice_data = {
                "customer": customer,
                "status": status,
                "issued_at": fake.date_between(start_date="-1y", end_date="today"),
                "due_at": fake.date_between(start_date="today", end_date="+30d"),
                "subtotal_cents": base_amount_cents,
                "tax_cents": tax_amount_cents,
                "total_cents": total_amount_cents,
                "currency": currency,
                "bill_to_name": customer.get_display_name(),
                "bill_to_email": customer.primary_email,
                # Add billing address from customer profiles
                "bill_to_address1": customer.addresses.first().address_line1 if customer.addresses.exists() else "",
                "bill_to_address2": customer.addresses.first().address_line2 if customer.addresses.exists() else "",
                "bill_to_city": customer.addresses.first().city if customer.addresses.exists() else "",
                "bill_to_region": customer.addresses.first().county if customer.addresses.exists() else "",
                "bill_to_country": "RO",
                "bill_to_postal": customer.addresses.first().postal_code if customer.addresses.exists() else "",
                "bill_to_tax_id": customer.get_tax_profile().cui if customer.get_tax_profile() else "",
            }

            invoice = Invoice.objects.create(**invoice_data)

            # Generate proper invoice number using sequence
            sequence, _ = InvoiceSequence.objects.get_or_create(scope="default")
            invoice.number = sequence.get_next_number("INV")
            invoice.save()

            # Add invoice items
            InvoiceLine.objects.create(
                invoice=invoice,
                kind="service",
                description=f"Hosting services - {fake.month_name()} {fake.year()}",
                quantity=Decimal("1.000"),
                unit_price_cents=base_amount_cents,
                tax_rate=Decimal("0.2100"),
                line_total_cents=base_amount_cents,
            )

            invoices.append(invoice)

        return invoices

    def create_customer_proformas(
        self, fake: Faker, customer: Customer, orders: list[Order], count: int
    ) -> list[ProformaInvoice]:
        """Create proforma invoices for a customer"""
        proformas = []
        currency = Currency.objects.get(code="RON")
        tax_rule, _ = TaxRule.objects.get_or_create(
            country_code="RO",
            tax_type="vat",
            valid_from=timezone.now().date(),
            defaults={
                "rate": Decimal("0.21"),  # 21% VAT for Romania (Aug 2025)
                "applies_to_b2b": True,
                "applies_to_b2c": True,
                "reverse_charge_eligible": True,
                "is_eu_member": True,
                "vies_required": True,
            },
        )

        # Proforma statuses: draft, sent, accepted, expired
        proforma_statuses = ["draft", "sent", "accepted", "expired"]

        for i in range(count):
            # Some proformas are linked to orders
            order = random.choice(orders) if orders and random.random() < 0.5 else None
            if order:
                base_amount = Decimal(order.subtotal_cents) / 100  # Convert cents to decimal
                tax_amount = Decimal(order.tax_cents) / 100
                total_amount = Decimal(order.total_cents) / 100
            else:
                base_amount = Decimal(str(random.uniform(100.0, 1000.0))).quantize(Decimal("0.01"))
                tax_amount = base_amount * tax_rule.rate
                total_amount = base_amount + tax_amount

            # Generate amounts in cents for precision
            base_amount_cents = int(base_amount * 100)
            tax_amount_cents = int(tax_amount * 100)
            total_amount_cents = int(total_amount * 100)

            # Use specific statuses for comprehensive testing
            status = proforma_statuses[i % len(proforma_statuses)]

            proforma_data = {
                "customer": customer,
                "status": status,
                "valid_until": fake.date_between(start_date="today", end_date="+30d"),
                "subtotal_cents": base_amount_cents,
                "tax_cents": tax_amount_cents,
                "total_cents": total_amount_cents,
                "currency": currency,
                "notes": fake.text(max_nb_chars=200) if random.choice([True, False]) else "",
                "bill_to_name": customer.get_display_name(),
                "bill_to_email": customer.primary_email,
                "bill_to_address1": customer.addresses.first().address_line1 if customer.addresses.exists() else "",
                "bill_to_address2": customer.addresses.first().address_line2 if customer.addresses.exists() else "",
                "bill_to_city": customer.addresses.first().city if customer.addresses.exists() else "",
                "bill_to_region": customer.addresses.first().county if customer.addresses.exists() else "",
                "bill_to_country": "RO",
                "bill_to_postal": customer.addresses.first().postal_code if customer.addresses.exists() else "",
                "bill_to_tax_id": customer.get_tax_profile().cui if customer.get_tax_profile() else "",
            }

            proforma = ProformaInvoice.objects.create(**proforma_data)

            # Generate proper proforma number using sequence
            sequence, _ = ProformaSequence.objects.get_or_create(scope="default")
            proforma.number = sequence.get_next_number("PRO")
            proforma.save()

            # Add proforma items
            ProformaLine.objects.create(
                proforma=proforma,
                kind="service",
                description=f"Hosting services - {fake.month_name()} {fake.year()}",
                quantity=Decimal("1.000"),
                unit_price_cents=base_amount_cents,
                tax_rate=Decimal("0.2100"),
                line_total_cents=base_amount_cents,
            )

            proformas.append(proforma)

        return proformas

    def create_customer_tickets(self, fake: Faker, customer: Customer, count: int) -> list[Ticket]:
        """Create support tickets for a customer with diverse statuses"""
        tickets = []
        categories = list(SupportCategory.objects.all())
        support_users = list(User.objects.filter(staff_role="support"))

        # Ticket statuses: open, in_progress, waiting_on_customer, closed
        ticket_statuses = ["open", "in_progress", "waiting_on_customer", "closed"]
        ticket_priorities = ["low", "normal", "high", "urgent"]

        for i in range(count):
            category = random.choice(categories)
            assigned_to = random.choice(support_users) if random.choice([True, False]) and support_users else None

            # Use specific statuses and priorities for comprehensive testing
            status = ticket_statuses[i % len(ticket_statuses)]
            priority = ticket_priorities[i % len(ticket_priorities)]

            ticket_data = {
                "title": f"{fake.sentence(nb_words=6)}",
                "description": f"Status: {status}, Priority: {priority}. {fake.text(max_nb_chars=400)}",
                "customer": customer,
                "contact_email": customer.primary_email,
                "category": category,
                "priority": priority,
                "status": status,
                "source": random.choice(["web", "email", "phone"]),
                "assigned_to": assigned_to if status in ["in_progress", "waiting_on_customer"] else None,
            }

            ticket = Ticket.objects.create(**ticket_data)
            tickets.append(ticket)

        return tickets
