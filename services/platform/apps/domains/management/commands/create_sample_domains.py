# ===============================================================================
# CREATE SAMPLE DOMAINS COMMAND - PRAHO DEVELOPMENT DATA
# ===============================================================================
# NOTE: Uses random module for sample data generation (non-cryptographic purposes)

import random
from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, DomainOrderItem, Registrar, TLDRegistrarAssignment
from apps.orders.models import Order


class Command(BaseCommand):
    """🌍 Create sample domains with full functionality for testing"""

    help = "Create 5 random domains with TLDs, registrars, and full data"

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--count", type=int, default=5, help="Number of domains to create (default: 5)")

    def handle(self, *args: Any, **options: Any) -> None:
        count = options["count"]

        self.stdout.write("🚀 Creating sample domains with full functionality...")

        # Create TLDs
        tlds_created = self.create_sample_tlds()
        self.stdout.write(f"✅ Created {tlds_created} TLDs")

        # Create registrars
        registrars_created = self.create_sample_registrars()
        self.stdout.write(f"✅ Created {registrars_created} registrars")

        # Create TLD-Registrar assignments
        assignments_created = self.create_tld_registrar_assignments()
        self.stdout.write(f"✅ Created {assignments_created} TLD-registrar assignments")

        # Get or create customers
        customers = self.ensure_sample_customers()
        self.stdout.write(f"✅ Ensured {len(customers)} customers exist")

        # Create domains
        domains_created = self.create_sample_domains(count, customers)
        self.stdout.write(f"✅ Created {domains_created} domains")

        self.stdout.write(
            self.style.SUCCESS(
                f"\n🎉 Successfully created complete domain infrastructure!\n"
                f"   • {tlds_created} TLDs\n"
                f"   • {registrars_created} registrars\n"
                f"   • {assignments_created} TLD assignments\n"
                f"   • {domains_created} domains\n"
            )
        )

    def create_sample_tlds(self) -> int:
        """🌐 Create sample TLD configurations"""
        tlds_data = [
            {
                "extension": "com",
                "description": "Commercial domains",
                "registration_price_cents": 4500,  # 45 RON
                "renewal_price_cents": 4500,
                "transfer_price_cents": 4500,
                "registrar_cost_cents": 3000,  # 30 RON cost
                "is_featured": True,
                "whois_privacy_available": True,
            },
            {
                "extension": "ro",
                "description": "Romanian domains",
                "registration_price_cents": 6000,  # 60 RON
                "renewal_price_cents": 6000,
                "transfer_price_cents": 6000,
                "registrar_cost_cents": 4500,  # 45 RON cost
                "is_featured": True,
                "requires_local_presence": True,
                "whois_privacy_available": False,
            },
            {
                "extension": "net",
                "description": "Network domains",
                "registration_price_cents": 4800,  # 48 RON
                "renewal_price_cents": 4800,
                "transfer_price_cents": 4800,
                "registrar_cost_cents": 3200,  # 32 RON cost
                "is_featured": True,
                "whois_privacy_available": True,
            },
            {
                "extension": "org",
                "description": "Organization domains",
                "registration_price_cents": 4800,  # 48 RON
                "renewal_price_cents": 4800,
                "transfer_price_cents": 4800,
                "registrar_cost_cents": 3200,  # 32 RON cost
                "is_featured": True,
                "whois_privacy_available": True,
            },
            {
                "extension": "tech",
                "description": "Technology domains",
                "registration_price_cents": 12000,  # 120 RON
                "renewal_price_cents": 12000,
                "transfer_price_cents": 12000,
                "registrar_cost_cents": 8000,  # 80 RON cost
                "is_featured": False,
                "whois_privacy_available": True,
            },
        ]

        created_count = 0
        for tld_data in tlds_data:
            tld, created = TLD.objects.get_or_create(extension=tld_data["extension"], defaults=tld_data)
            if created:
                created_count += 1
                self.stdout.write(f"   📄 Created TLD: .{tld.extension}")

        return created_count

    def create_sample_registrars(self) -> int:
        """🏢 Create sample registrar configurations"""
        registrars_data = [
            {
                "name": "namecheap",
                "display_name": "Namecheap",
                "website_url": "https://www.namecheap.com/",
                "api_endpoint": "https://api.namecheap.com/xml.response",
                "api_username": "test_user",
                "api_key": "test_key_123",
                "status": "active",
                "currency": "USD",
                "default_nameservers": ["ns1.example.com", "ns2.example.com"],
                "total_domains": 0,
            },
            {
                "name": "rotld",
                "display_name": "ROTLD (Romanian Registry)",
                "website_url": "https://www.rotld.ro/",
                "api_endpoint": "https://api.rotld.ro/",
                "api_username": "praho_test",
                "api_key": "rotld_key_456",
                "status": "active",
                "currency": "RON",
                "default_nameservers": ["ns1.rotld.ro", "ns2.rotld.ro"],
                "total_domains": 0,
            },
            {
                "name": "godaddy",
                "display_name": "GoDaddy",
                "website_url": "https://www.godaddy.com/",
                "api_endpoint": "https://api.godaddy.com/v1/",
                "api_username": "godaddy_user",
                "api_key": "godaddy_secret_789",
                "status": "active",
                "currency": "USD",
                "default_nameservers": ["ns01.domaincontrol.com", "ns02.domaincontrol.com"],
                "total_domains": 0,
            },
        ]

        created_count = 0
        for registrar_data in registrars_data:
            registrar, created = Registrar.objects.get_or_create(name=registrar_data["name"], defaults=registrar_data)
            if created:
                created_count += 1
                self.stdout.write(f"   🏢 Created registrar: {registrar.display_name}")

        return created_count

    def create_tld_registrar_assignments(self) -> int:
        """🔗 Create TLD-Registrar assignments"""
        assignments = [
            # .com domains - Namecheap primary, GoDaddy backup
            {"tld": "com", "registrar": "namecheap", "is_primary": True, "priority": 1},
            {"tld": "com", "registrar": "godaddy", "is_primary": False, "priority": 2},
            # .ro domains - ROTLD only
            {"tld": "ro", "registrar": "rotld", "is_primary": True, "priority": 1},
            # .net domains - Namecheap primary, GoDaddy backup
            {"tld": "net", "registrar": "namecheap", "is_primary": True, "priority": 1},
            {"tld": "net", "registrar": "godaddy", "is_primary": False, "priority": 2},
            # .org domains - Namecheap primary
            {"tld": "org", "registrar": "namecheap", "is_primary": True, "priority": 1},
            # .tech domains - GoDaddy primary
            {"tld": "tech", "registrar": "godaddy", "is_primary": True, "priority": 1},
        ]

        created_count = 0
        for assignment_data in assignments:
            try:
                tld = TLD.objects.get(extension=assignment_data["tld"])
                registrar = Registrar.objects.get(name=assignment_data["registrar"])

                _assignment, created = TLDRegistrarAssignment.objects.get_or_create(
                    tld=tld,
                    registrar=registrar,
                    defaults={
                        "is_primary": assignment_data["is_primary"],
                        "priority": assignment_data["priority"],
                        "is_active": True,
                    },
                )
                if created:
                    created_count += 1
                    self.stdout.write(f"   🔗 Assigned .{tld.extension} to {registrar.display_name}")
            except (TLD.DoesNotExist, Registrar.DoesNotExist):
                self.stdout.write(f"   ⚠️  Skipped assignment: {assignment_data}")

        return created_count

    def ensure_sample_customers(self) -> list[Customer]:
        """👥 Ensure sample customers exist"""
        if Customer.objects.exists():
            return list(Customer.objects.all()[:5])

        # If no customers exist, create some basic ones
        customers_data = [
            {
                "first_name": "Ion",
                "last_name": "Popescu",
                "company_name": "Tech Solutions SRL",
                "primary_email": "ion.popescu@techsolutions.ro",
                "phone": "+40721123456",
                "cui": "RO12345678",
                "address": "Str. Republicii nr. 1",
                "city": "Bucharest",
                "county": "Bucharest",
                "postal_code": "010001",
                "country": "RO",
            },
            {
                "first_name": "Maria",
                "last_name": "Ionescu",
                "company_name": "Creative Design Studio",
                "primary_email": "maria@creative-design.ro",
                "phone": "+40722234567",
                "cui": "RO23456789",
                "address": "Bd. Unirii nr. 15",
                "city": "Cluj-Napoca",
                "county": "Cluj",
                "postal_code": "400001",
                "country": "RO",
            },
            {
                "first_name": "Alexandru",
                "last_name": "Radu",
                "company_name": "WebDev Pro SRL",
                "primary_email": "alex@webdevpro.ro",
                "phone": "+40723345678",
                "cui": "RO34567890",
                "address": "Str. Mircea cel Batran nr. 8",
                "city": "Timisoara",
                "county": "Timis",
                "postal_code": "300001",
                "country": "RO",
            },
        ]

        customers = []
        for customer_data in customers_data:
            customer, created = Customer.objects.get_or_create(
                primary_email=customer_data["primary_email"], defaults=customer_data
            )
            customers.append(customer)
            if created:
                self.stdout.write(f"   👤 Created customer: {customer.get_display_name()}")

        return customers

    def create_sample_domains(self, count: int, customers: list[Customer]) -> int:
        """🌍 Create sample domains with realistic data"""
        domain_names = [
            "tech-solutions.com",
            "creative-design.ro",
            "webdev-pro.net",
            "digital-marketing.org",
            "startup-hub.tech",
            "romanian-business.ro",
            "web-agency.com",
            "it-consulting.net",
            "design-studio.org",
            "online-shop.ro",
        ]

        created_count = 0
        available_tlds = list(TLD.objects.all())

        for i in range(count):
            if i < len(domain_names):
                domain_name = domain_names[i]
                # Extract TLD from domain name
                tld_extension = domain_name.split(".")[-1]
                try:
                    tld = TLD.objects.get(extension=tld_extension)
                except TLD.DoesNotExist:
                    # Fallback to random TLD
                    tld = random.choice(available_tlds)  # Sample data generation  # noqa: S311
                    domain_name = f"{domain_name.split('.')[0]}.{tld.extension}"
            else:
                # Generate random domain
                tld = random.choice(available_tlds)  # Sample data generation  # noqa: S311
                domain_name = f"sample-domain-{i + 1}.{tld.extension}"

            # Get primary registrar for this TLD
            try:
                assignment = TLDRegistrarAssignment.objects.get(tld=tld, is_primary=True)
                registrar = assignment.registrar
            except TLDRegistrarAssignment.DoesNotExist:
                # Fallback to any active registrar
                registrar_candidate = Registrar.objects.filter(status="active").first()
                if not registrar_candidate:
                    self.stdout.write("   ❌ No active registrar found")
                    continue
                registrar = registrar_candidate

            # Random customer
            customer = random.choice(customers)  # Sample data generation  # noqa: S311

            # Random dates
            registered_at = timezone.now() - timedelta(
                days=random.randint(30, 365)  # noqa: S311 - Sample data generation
            )
            expires_at = registered_at + timedelta(
                days=365 * random.randint(1, 3)  # noqa: S311 - Sample data generation
            )

            # Create domain
            domain, created = Domain.objects.get_or_create(
                name=domain_name,
                defaults={
                    "tld": tld,
                    "registrar": registrar,
                    "customer": customer,
                    "status": random.choice(  # noqa: S311 - Sample data generation
                        ["active", "active", "active", "pending"]
                    ),
                    "registered_at": registered_at,
                    "expires_at": expires_at,
                    "registrar_domain_id": f"DOM_{random.randint(100000, 999999)}",  # Sample data generation  # noqa: S311
                    "epp_code": f"EPP{random.randint(100000, 999999)}",  # Sample data generation  # noqa: S311
                    "auto_renew": random.choice([True, True, False]),  # Sample data generation  # noqa: S311
                    "whois_privacy": random.choice([True, False])  # noqa: S311 - Sample data generation
                    if tld.whois_privacy_available
                    else False,
                    "locked": True,
                    "nameservers": registrar.default_nameservers or [],
                    "last_paid_amount_cents": tld.registration_price_cents,
                    "notes": f"Sample domain created for testing - Customer: {customer.get_display_name()}",
                },
            )

            if created:
                created_count += 1
                # Update registrar domain count
                registrar.total_domains += 1
                registrar.save(update_fields=["total_domains"])

                self.stdout.write(f"   🌍 Created domain: {domain.name} ({customer.get_display_name()})")

                # Create sample order history for active domains
                if domain.status == "active":
                    self.create_domain_order_history(domain)

        return created_count

    def create_domain_order_history(self, domain: Domain) -> None:
        """📦 Create sample order history for a domain"""
        # Note: This assumes an Order model exists.
        # If not available, skip order creation to avoid errors.
        try:
            # Get RON currency or create it
            currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian Leu", "symbol": "RON"})

            # Generate order number
            date_str = (
                domain.registered_at.strftime("%Y%m%d") if domain.registered_at else timezone.now().strftime("%Y%m%d")
            )
            order_number = f"DOM-{date_str}-{domain.id.hex[:8].upper()}"

            # Create a sample order for the domain registration
            order = Order.objects.create(
                order_number=order_number,
                customer=domain.customer,
                currency=currency,
                subtotal_cents=domain.last_paid_amount_cents,
                tax_cents=int(domain.last_paid_amount_cents * 0.21),  # 21% VAT
                total_cents=int(domain.last_paid_amount_cents * 1.21),
                status="completed",
                created_at=domain.registered_at or timezone.now(),
                notes=f"Domain registration: {domain.name}",
            )

            # Create domain order item
            DomainOrderItem.objects.create(
                order=order,
                domain_name=domain.name,
                tld=domain.tld,
                action="register",
                years=1,
                unit_price_cents=domain.tld.registration_price_cents,
                total_price_cents=domain.tld.registration_price_cents,
                whois_privacy=domain.whois_privacy,
                auto_renew=domain.auto_renew,
                domain=domain,
            )

            self.stdout.write(f"     📦 Created order history for {domain.name}")

        except ImportError:
            # Orders app not available, skip order creation
            self.stdout.write("     ⚠️  Orders app not available, skipped order history")
