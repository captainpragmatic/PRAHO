"""
Django management command to generate sample data for PRAHO Platform
Romanian hosting provider test data generation.
"""

import random
from dataclasses import dataclass
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
from apps.customers.models import Customer, CustomerAddress, CustomerBillingProfile, CustomerTaxProfile
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
                self.stdout.write(f"  ✓ Complete customer {i+2}/{num_customers}: {customer.get_display_name()}")
        else:
            self.stdout.write("Only creating the guaranteed test customer.")

        self.stdout.write(
            self.style.SUCCESS(
                f"✅ Success! Generated: {num_customers} customers, {num_users} users, "
                f"{num_customers * services_per_customer} services, "
                f"{num_customers * orders_per_customer} orders, "
                f"{num_customers * (invoices_per_customer + proformas_per_customer)} billing documents, "
                f"{num_customers * tickets_per_customer} tickets"
            )
        )

        # Print available login credentials
        self.stdout.write("")
        self.stdout.write("━" * 60)
        self.stdout.write(self.style.SUCCESS("  Available login credentials"))
        self.stdout.write("━" * 60)
        self.stdout.write(f"  {'Role':<12} {'Email':<32} {'Password'}")
        self.stdout.write(f"  {'─' * 12} {'─' * 32} {'─' * 12}")
        self.stdout.write(f"  {'Admin':<12} {'admin@pragmatichost.com':<32} admin123")
        self.stdout.write(f"  {'Support':<12} {'john@pragmatichost.com':<32} support123")
        self.stdout.write(f"  {'Support':<12} {'jane@pragmatichost.com':<32} support123")
        self.stdout.write(f"  {'Support':<12} {'mike@pragmatichost.com':<32} support123")
        self.stdout.write(f"  {'Customer':<12} {'customer@pragmatichost.com':<32} testpass123")
        self.stdout.write(f"  {'E2E Admin':<12} {'e2e-admin@test.local':<32} test123")
        self.stdout.write(f"  {'E2E Customer':<12} {'e2e-customer@test.local':<32} test123")
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
                "price_monthly": Decimal("99.99"),
                "price_annual": Decimal("999.90"),
                "cpu_cores": 2,
                "ram_gb": 4,
                "disk_space_gb": 80,
            },
            {
                "name": "VPS Advanced",
                "plan_type": "vps",
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

            service_data = {
                "customer": customer,
                "service_plan": plan,
                "server": server,
                "service_name": f"{plan.name} - {customer.name}",
                "domain": f"{fake.domain_name()}",
                "username": f"user{random.randint(1000, 9999)}",
                "billing_cycle": random.choice(["monthly", "annual"]),
                "price": plan.price_monthly,
                "status": random.choice(["active", "pending", "suspended"]),
                "auto_renew": random.choice([True, False]),
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
                    "short_description": plan.description[:500] if plan.description else "",
                    "product_type": type_mapping.get(plan.plan_type, "shared_hosting"),
                    "is_active": plan.is_active,
                    "is_featured": False,
                    "requires_domain": plan.plan_type in ["shared_hosting", "vps", "dedicated"],
                    "includes_vat": plan.includes_vat,
                },
            )

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
                "email": f"user{i+1}@example.com",  # Use unique predictable emails
                "is_active": True,
                "staff_role": "customer",
            }

            user = User.objects.create_user(password="testpass123", **user_data)
            users.append(user)

            if i % 2 == 0:
                self.stdout.write(f"  ✓ User {i+1}/{count}: {user.email}")

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

        # Decide if this is a company or individual
        is_company = random.choice([True, False, True])  # 2/3 chance of company

        if is_company:
            customer_data = {
                "customer_type": "company",
                "name": f"{fake.first_name()} {fake.last_name()}",
                "company_name": fake.company(),
                "primary_email": fake.unique.email(),
                "primary_phone": f"+40{fake.random_int(min=700000000, max=799999999)}",
                "status": "active",
            }
        else:
            customer_data = {
                "customer_type": "individual",
                "name": f"{fake.first_name()} {fake.last_name()}",
                "primary_email": fake.unique.email(),
                "primary_phone": f"+40{fake.random_int(min=700000000, max=799999999)}",
                "status": "active",
            }

        customer = Customer.objects.create(**customer_data)

        # Create customer address
        address = CustomerAddress.objects.create(
            customer=customer,
            address_type="billing",
            address_line1=fake.street_address(),
            city=fake.city(),
            county=fake.city(),  # Use city as county
            postal_code=fake.postcode(),
            country="România",
        )

        # Create tax profile for companies
        if is_company:
            tax_number = f"RO{fake.random_int(min=10000000, max=99999999)}"
            tax_profile = CustomerTaxProfile.objects.create(
                customer=customer,
                cui=tax_number,
                is_vat_payer=True,
                vat_number=tax_number,
                reverse_charge_eligible=True,
            )

        # Create billing profile
        billing_profile = CustomerBillingProfile.objects.create(
            customer=customer, payment_terms=30, preferred_currency="RON", invoice_delivery_method="email"
        )

        # Attach 1-3 users to this customer
        customer_users = random.sample(users, random.randint(1, min(3, len(users))))
        for user in customer_users:
            CustomerMembership.objects.create(
                user=user,
                customer=customer,
                role=random.choice(["owner", "billing", "tech"]),
                is_primary=random.choice([True, False]),
            )

        # Create related data
        self.create_customer_services(fake, customer, config.services_count)
        orders = self.create_customer_orders(fake, customer, config.orders_count)
        self.create_customer_invoices(fake, customer, orders, config.invoices_count)
        self.create_customer_proformas(fake, customer, orders, config.proformas_count)
        self.create_customer_tickets(fake, customer, config.tickets_count)

        return customer

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
                "order_number": f"ORD-{customer.id:04d}-{i+1:03d}-{status.upper()}",
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
                "title": f"[{status.upper()}] {fake.sentence(nb_words=4)} - {priority.title()} Priority",
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
