"""
Django management command to generate sample data for PRAHO Platform
Romanian hosting provider test data generation.
"""

import random
from decimal import Decimal

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from faker import Faker

from apps.customers.models import Customer
from apps.provisioning.models import Server, Service, ServicePlan
from apps.tickets.models import SupportCategory, Ticket

User = get_user_model()

class Command(BaseCommand):
    help = 'Generate sample data for Romanian hosting provider'

    def add_arguments(self, parser):
        parser.add_argument(
            '--customers',
            type=int,
            default=50,
            help='Number of customers to create'
        )
        parser.add_argument(
            '--services',
            type=int,
            default=100,
            help='Number of services to create'
        )
        parser.add_argument(
            '--tickets',
            type=int,
            default=200,
            help='Number of tickets to create'
        )

    def handle(self, *args, **options):
        # Simple safety check - must be in DEBUG mode
        if not settings.DEBUG:
            raise CommandError(
                "🚫 Sample data generation only works in DEBUG mode. "
                "This prevents accidental production usage."
            )
        
        fake = Faker('ro_RO')  # Romanian locale
        Faker.seed(42)  # Consistent data
        
        self.stdout.write('🇷🇴 Generez date de test pentru PragmaticHost...')
        
        # Create admin users
        self.create_admin_users(fake)
        
        # Create service plans
        self.create_service_plans()
        
        # Create servers
        self.create_servers()
        
        # Create support categories
        self.create_support_categories()
        
        # Create customers
        customers = self.create_customers(fake, options['customers'])
        
        # Create services
        self.create_services(fake, customers, options['services'])
        
        # Create tickets
        self.create_tickets(fake, customers, options['tickets'])
        
        self.stdout.write(
            self.style.SUCCESS('✅ Date generate cu succes!')
        )

    def create_admin_users(self, fake):
        self.stdout.write('Creez utilizatori admin...')
        
        # Create superuser with consistent credentials for E2E testing
        # Note: These are development/test credentials only - DEBUG mode enforced above
        if not User.objects.filter(email='admin@pragmatichost.com').exists():
            admin_user = User.objects.create_superuser(
                first_name='Admin',
                last_name='PRAHO',
                email='admin@pragmatichost.com',
                password='admin123'  # Dev/test only - protected by DEBUG check
            )
            self.stdout.write(f'  ✓ Admin: {admin_user.email}')
        
        # Create support users
        support_users = [
            ('Ionuț', 'Popescu', 'ionut@pragmatichost.com'),
            ('Maria', 'Gheorghe', 'maria@pragmatichost.com'),
            ('Andrei', 'Stancu', 'andrei@pragmatichost.com'),
        ]
        
        for first, last, email in support_users:
            if not User.objects.filter(email=email).exists():
                user = User.objects.create_user(
                    username=email.split('@')[0],
                    email=email,
                    password='support123',  # Dev/test only - protected by DEBUG check
                    first_name=first,
                    last_name=last,
                    role='support',
                    is_customer=False
                )
                self.stdout.write(f'  ✓ Suport: {user.email}')

    def create_service_plans(self):
        self.stdout.write('Creez planuri de servicii...')
        
        plans = [
            {
                'name': 'Web Hosting Starter',
                'plan_type': 'shared_hosting',
                'price_monthly': Decimal('29.99'),
                'price_annual': Decimal('299.90'),
                'disk_space_gb': 5,
                'bandwidth_gb': 50,
                'email_accounts': 10,
                'databases': 2,
                'domains': 1,
            },
            {
                'name': 'Web Hosting Professional',
                'plan_type': 'shared_hosting',
                'price_monthly': Decimal('59.99'),
                'price_annual': Decimal('599.90'),
                'disk_space_gb': 20,
                'bandwidth_gb': 200,
                'email_accounts': 50,
                'databases': 10,
                'domains': 5,
            },
            {
                'name': 'VPS Basic',
                'plan_type': 'vps',
                'price_monthly': Decimal('99.99'),
                'price_annual': Decimal('999.90'),
                'cpu_cores': 2,
                'ram_gb': 4,
                'disk_space_gb': 80,
            },
            {
                'name': 'VPS Advanced',
                'plan_type': 'vps',
                'price_monthly': Decimal('199.99'),
                'price_annual': Decimal('1999.90'),
                'cpu_cores': 4,
                'ram_gb': 8,
                'disk_space_gb': 160,
            },
        ]
        
        for plan_data in plans:
            plan, created = ServicePlan.objects.get_or_create(
                name=plan_data['name'],
                defaults=plan_data
            )
            if created:
                self.stdout.write(f'  ✓ Plan: {plan.name}')

    def create_servers(self):
        self.stdout.write('Creez servere...')
        
        servers = [
            {
                'name': 'WEB01',
                'hostname': 'web01.pragmatichost.com',
                'server_type': 'shared',
                'primary_ip': '185.123.45.67',
                'location': 'București',
                'datacenter': 'DataCenter București',
                'cpu_model': 'Intel Xeon E5-2630v4',
                'cpu_cores': 20,
                'ram_gb': 64,
                'disk_type': 'SSD',
                'disk_capacity_gb': 2000,
                'os_type': 'CentOS 8',
                'control_panel': 'cPanel',
            },
            {
                'name': 'VPS01',
                'hostname': 'vps01.pragmatichost.com',
                'server_type': 'vps_host',
                'primary_ip': '185.123.45.68',
                'location': 'București',
                'datacenter': 'DataCenter București',
                'cpu_model': 'Intel Xeon Gold 6248R',
                'cpu_cores': 48,
                'ram_gb': 256,
                'disk_type': 'NVMe',
                'disk_capacity_gb': 4000,
                'os_type': 'Ubuntu 22.04',
                'control_panel': 'Virtualizor',
            },
        ]
        
        for server_data in servers:
            server, created = Server.objects.get_or_create(
                hostname=server_data['hostname'],
                defaults=server_data
            )
            if created:
                self.stdout.write(f'  ✓ Server: {server.name}')

    def create_support_categories(self):
        self.stdout.write('Creez categorii de suport...')
        
        categories = [
            {
                'name': 'Problemă tehnică',
                'name_en': 'Technical Issue',
                'sla_response_hours': 2,
                'sla_resolution_hours': 24,
                'icon': 'alert-circle',
                'color': '#EF4444',
            },
            {
                'name': 'Întrebare facturare',
                'name_en': 'Billing Question',
                'sla_response_hours': 4,
                'sla_resolution_hours': 24,
                'icon': 'credit-card',
                'color': '#3B82F6',
            },
            {
                'name': 'Cerere serviciu nou',
                'name_en': 'New Service Request',
                'sla_response_hours': 8,
                'sla_resolution_hours': 48,
                'icon': 'plus-circle',
                'color': '#10B981',
            },
        ]
        
        for cat_data in categories:
            category, created = SupportCategory.objects.get_or_create(
                name=cat_data['name'],
                defaults=cat_data
            )
            if created:
                self.stdout.write(f'  ✓ Categorie: {category.name}')

    def create_customers(self, fake, count):
        self.stdout.write(f'Creez {count} clienți...')
        customers = []
        
        # Romanian counties
        counties = [
            'București', 'Cluj', 'Timiș', 'Iași', 'Constanța',
            'Brașov', 'Galați', 'Craiova', 'Ploiești', 'Oradea'
        ]
        
        for i in range(count):
            customer_type = random.choice(['individual', 'company', 'pfa'])
            
            customer_data = {
                'customer_type': customer_type,
                'status': random.choice(['active', 'prospect']),
                'name': fake.name(),
                'email': fake.email(),
                'phone': f'+40.7{random.randint(10,99)}.{random.randint(100,999)}.{random.randint(100,999)}',
                'address_line1': fake.street_address(),
                'city': fake.city(),
                'county': random.choice(counties),
                'postal_code': f'{random.randint(100000,999999)}',
                'country': 'România',
                'payment_terms': random.choice([15, 30, 45]),
                'data_processing_consent': True,
                'marketing_consent': random.choice([True, False]),
            }
            
            if customer_type in ['company', 'pfa']:
                customer_data.update({
                    'company_name': fake.company(),
                    'cui': f'RO{random.randint(1000000,99999999)}',
                    'is_vat_payer': True,
                    'industry': random.choice([
                        'IT & Software', 'E-commerce', 'Servicii',
                        'Producție', 'Consultanță', 'Media'
                    ]),
                })
            
            customer = Customer.objects.create(**customer_data)
            customers.append(customer)
            
            if i % 10 == 0:
                self.stdout.write(f'  ✓ Creat {i+1}/{count} clienți')
        
        return customers

    def create_services(self, fake, customers, count):
        self.stdout.write(f'Creez {count} servicii...')
        
        plans = list(ServicePlan.objects.all())
        servers = list(Server.objects.all())
        
        for i in range(count):
            customer = random.choice(customers)
            plan = random.choice(plans)
            server = random.choice(servers) if servers else None
            
            service_data = {
                'customer': customer,
                'service_plan': plan,
                'server': server,
                'service_name': f'{plan.name} - {customer.name}',
                'domain': f'{fake.domain_name()}',
                'username': f'user{random.randint(1000,9999)}',
                'billing_cycle': random.choice(['monthly', 'annual']),
                'price': plan.price_monthly,
                'status': random.choice(['active', 'pending', 'suspended']),
                'auto_renew': random.choice([True, False]),
            }
            
            service = Service.objects.create(**service_data)
            
            if i % 20 == 0:
                self.stdout.write(f'  ✓ Creat {i+1}/{count} servicii')

    def create_tickets(self, fake, customers, count):
        self.stdout.write(f'Creez {count} tickete...')
        
        categories = list(SupportCategory.objects.all())
        support_users = list(User.objects.filter(role='support'))
        
        for i in range(count):
            customer = random.choice(customers)
            category = random.choice(categories)
            assigned_to = random.choice(support_users) if random.choice([True, False]) else None
            
            ticket_data = {
                'title': fake.sentence(nb_words=6),
                'description': fake.text(max_nb_chars=500),
                'customer': customer,
                'contact_email': customer.email,
                'category': category,
                'priority': random.choice(['low', 'normal', 'high']),
                'status': random.choice(['new', 'open', 'pending', 'resolved']),
                'source': random.choice(['web', 'email', 'phone']),
                'assigned_to': assigned_to,
            }
            
            ticket = Ticket.objects.create(**ticket_data)
            
            if i % 50 == 0:
                self.stdout.write(f'  ✓ Creat {i+1}/{count} tickete')
