#!/usr/bin/env python3
"""
PRAHO Platform Test Data Setup Script
Creates comprehensive test data for development environment.
"""

import os
import sys
import django
from decimal import Decimal
from datetime import date, timedelta

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.dev')
django.setup()

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from apps.customers.models import Customer, CustomerTaxProfile, CustomerBillingProfile, CustomerAddress
from apps.users.models import CustomerMembership
from apps.billing.models import ProformaInvoice, Invoice, Currency
from apps.provisioning.models import Service, ServicePlan
from apps.tickets.models import Ticket, TicketComment, SupportCategory

User = get_user_model()

def check_existing_data():
    """Check if we already have test data."""
    users_count = User.objects.count()
    customers_count = Customer.objects.count()
    memberships_count = CustomerMembership.objects.count()
    
    if users_count > 0 or customers_count > 0 or memberships_count > 0:
        print(f"ℹ️  Found existing data: {users_count} users, {customers_count} customers, {memberships_count} memberships")
        return True
    return False

def create_test_data():
    """Create comprehensive test data for all models."""
    print("🚀 Creating comprehensive test data...")
    
    with transaction.atomic():
        # 1. Create superuser
        superuser, created = User.objects.get_or_create(
            email='admin@pragmatichost.com',
            defaults={
                'first_name': 'Super',
                'last_name': 'Admin',
                'is_staff': True,
                'is_superuser': True,
                'is_active': True,
            }
        )
        if created:
            superuser.set_password('admin123')
            superuser.save()
            print("✅ Created superuser")
        else:
            print("ℹ️  Superuser already exists")

        # 2. Create test customer
        customer, created = Customer.objects.get_or_create(
            name='Test Company SRL',
            defaults={
                'customer_type': 'company',
                'status': 'active',
                'company_name': 'Test Company SRL',
                'primary_email': 'contact@testcompany.com',
                'primary_phone': '+40722123456',
                'industry': 'Web Hosting',
                'data_processing_consent': True,
            }
        )
        if created:
            print("✅ Created test customer")
        else:
            print("ℹ️  Test customer already exists")

        # 3. Create tax profile for customer
        tax_profile, created = CustomerTaxProfile.objects.get_or_create(
            customer=customer,
            defaults={
                'cui': 'RO12345678',
                'vat_number': 'RO12345678',
                'is_vat_payer': True,
                'registration_number': 'J40/1234/2023',
            }
        )
        if created:
            print("✅ Created tax profile")

        # 4. Create billing profile for customer
        billing_profile, created = CustomerBillingProfile.objects.get_or_create(
            customer=customer,
            defaults={
                'payment_terms': 30,
                'credit_limit': Decimal('1000.00'),
                'auto_payment_enabled': False,
                'preferred_currency': 'RON',
                'invoice_delivery_method': 'email',
            }
        )
        if created:
            print("✅ Created billing profile")

        # 5. Create primary address for customer
        primary_address, created = CustomerAddress.objects.get_or_create(
            customer=customer,
            address_type='primary',
            defaults={
                'address_line1': 'Str. Revolutiei nr. 1',
                'city': 'Bucharest',
                'county': 'Bucharest',
                'country': 'România',
                'postal_code': '010000',
                'is_current': True,
            }
        )
        if created:
            print("✅ Created primary address")

        # 6. Create customer user
        customer_user, created = User.objects.get_or_create(
            email='customer@pragmatichost.com',
            defaults={
                'first_name': 'Ion',
                'last_name': 'Popescu',
                'is_staff': False,
                'is_superuser': False,
                'is_active': True,
            }
        )
        if created:
            customer_user.set_password('admin123')
            customer_user.save()
            print("✅ Created customer user")
        else:
            print("ℹ️  Customer user already exists")

        # 7. Create membership relationship
        membership, created = CustomerMembership.objects.get_or_create(
            user=customer_user,
            customer=customer,
            defaults={
                'role': 'owner',
                'is_primary': True,
            }
        )
        if created:
            print("✅ Created customer membership")

        # 8. Create test service plan and service
        try:
            # First create a service plan (required dependency)
            service_plan, plan_created = ServicePlan.objects.get_or_create(
                name='Starter Web Hosting',
                defaults={
                    'plan_type': 'shared_hosting',
                    'description': 'Basic shared hosting plan for small websites',
                    'price_monthly': Decimal('29.99'),
                    'price_annual': Decimal('299.90'),
                    'disk_space_gb': 5,
                    'bandwidth_gb': 100,
                    'email_accounts': 10,
                    'databases': 5,
                    'is_active': True,
                }
            )
            if plan_created:
                print("✅ Created service plan")
            
            # Now create the service
            service, created = Service.objects.get_or_create(
                customer=customer,
                service_name='testcompany.com Hosting',
                defaults={
                    'service_plan': service_plan,
                    'domain': 'testcompany.com',
                    'username': 'testcompany',
                    'billing_cycle': 'monthly',
                    'price': service_plan.price_monthly,
                    'status': 'active',
                }
            )
            if created:
                print("✅ Created test service")
        except Exception as e:
            print(f"⚠️  Service creation skipped: {e}")

        # 7. Create billing data (invoices and proformas)
        create_billing_data_if_missing(customer)

        # 8. Create tickets with replies
        create_tickets_if_missing(customer, customer_user, superuser)

        # Note: All test data created successfully
        print("✅ Test data setup complete")

    return superuser, customer_user, customer

def create_service_if_missing(customer):
    """Create service plan and service if they don't exist."""
    try:
        # First create a service plan (required dependency)
        service_plan, plan_created = ServicePlan.objects.get_or_create(
            name='Starter Web Hosting',
            defaults={
                'plan_type': 'shared_hosting',
                'description': 'Basic shared hosting plan for small websites',
                'price_monthly': Decimal('29.99'),
                'price_annual': Decimal('299.90'),
                'disk_space_gb': 5,
                'bandwidth_gb': 100,
                'email_accounts': 10,
                'databases': 5,
                'is_active': True,
            }
        )
        if plan_created:
            print("✅ Created service plan")
        
        # Now create the service for this customer
        service, created = Service.objects.get_or_create(
            customer=customer,
            service_name=f'{customer.name} Hosting',
            defaults={
                'service_plan': service_plan,
                'domain': f'{customer.name.lower().replace(" ", "")}.com',
                'username': f'test_{customer.name.lower().replace(" ", "")}',
                'billing_cycle': 'monthly',
                'price': service_plan.price_monthly,
                'status': 'active',
            }
        )
        if created:
            print(f"✅ Created test service for {customer.name}")
        
        # Create invoices and proformas
        create_billing_data_if_missing(customer)
    except Exception as e:
        print(f"⚠️  Service creation failed: {e}")

def create_billing_data_if_missing(customer):
    """Create sample invoices and proformas with different currencies and VAT."""
    try:
        # Ensure currencies exist
        ron_currency, _ = Currency.objects.get_or_create(
            code='RON', 
            defaults={'symbol': 'LEI', 'decimals': 2}
        )
        eur_currency, _ = Currency.objects.get_or_create(
            code='EUR', 
            defaults={'symbol': '€', 'decimals': 2}
        )
        
        # Create 4 invoices
        invoices_data = [
            {
                'number': 'INV-2025-001',
                'currency': ron_currency,
                'subtotal_cents': 10000,  # 100.00 RON
                'tax_cents': 1900,        # 19.00 RON VAT
                'total_cents': 11900,     # 119.00 RON
                'description': 'RON Invoice with VAT'
            },
            {
                'number': 'INV-2025-002', 
                'currency': ron_currency,
                'subtotal_cents': 5000,   # 50.00 RON
                'tax_cents': 0,           # No VAT
                'total_cents': 5000,      # 50.00 RON
                'description': 'RON Invoice without VAT'
            },
            {
                'number': 'INV-2025-003',
                'currency': eur_currency,
                'subtotal_cents': 2000,   # 20.00 EUR
                'tax_cents': 380,         # 3.80 EUR VAT
                'total_cents': 2380,      # 23.80 EUR
                'description': 'EUR Invoice with VAT'
            },
            {
                'number': 'INV-2025-004',
                'currency': eur_currency,
                'subtotal_cents': 1500,   # 15.00 EUR
                'tax_cents': 0,           # No VAT
                'total_cents': 1500,      # 15.00 EUR
                'description': 'EUR Invoice without VAT'
            }
        ]
        
        invoice_count = 0
        for invoice_data in invoices_data:
            invoice, created = Invoice.objects.get_or_create(
                customer=customer,
                number=invoice_data['number'],
                defaults={
                    'status': 'issued',
                    'currency': invoice_data['currency'],
                    'issued_at': timezone.now() - timedelta(days=10),
                    'due_at': timezone.now() + timedelta(days=20),
                    'subtotal_cents': invoice_data['subtotal_cents'],
                    'tax_cents': invoice_data['tax_cents'],
                    'total_cents': invoice_data['total_cents'],
                    'bill_to_name': customer.name,
                    'bill_to_email': customer.primary_email,
                }
            )
            if created:
                invoice_count += 1
        
        if invoice_count > 0:
            print(f"✅ Created {invoice_count} test invoices")
        
        # Create 4 proformas
        proformas_data = [
            {
                'number': 'PRO-2025-001',
                'currency': ron_currency,
                'subtotal_cents': 12000,  # 120.00 RON
                'tax_cents': 2280,        # 22.80 RON VAT
                'total_cents': 14280,     # 142.80 RON
                'description': 'RON Proforma with VAT'
            },
            {
                'number': 'PRO-2025-002',
                'currency': ron_currency,
                'subtotal_cents': 8000,   # 80.00 RON
                'tax_cents': 0,           # No VAT
                'total_cents': 8000,      # 80.00 RON
                'description': 'RON Proforma without VAT'
            },
            {
                'number': 'PRO-2025-003',
                'currency': eur_currency,
                'subtotal_cents': 2500,   # 25.00 EUR
                'tax_cents': 475,         # 4.75 EUR VAT
                'total_cents': 2975,      # 29.75 EUR
                'description': 'EUR Proforma with VAT'
            },
            {
                'number': 'PRO-2025-004',
                'currency': eur_currency,
                'subtotal_cents': 1800,   # 18.00 EUR
                'tax_cents': 0,           # No VAT
                'total_cents': 1800,      # 18.00 EUR
                'description': 'EUR Proforma without VAT'
            }
        ]
        
        proforma_count = 0
        for proforma_data in proformas_data:
            proforma, created = ProformaInvoice.objects.get_or_create(
                customer=customer,
                number=proforma_data['number'],
                defaults={
                    'currency': proforma_data['currency'],
                    'valid_until': timezone.now() + timedelta(days=30),
                    'subtotal_cents': proforma_data['subtotal_cents'],
                    'tax_cents': proforma_data['tax_cents'],
                    'total_cents': proforma_data['total_cents'],
                    'bill_to_name': customer.name,
                    'bill_to_email': customer.primary_email,
                }
            )
            if created:
                proforma_count += 1
        
        if proforma_count > 0:
            print(f"✅ Created {proforma_count} test proformas")
            
    except Exception as e:
        print(f"⚠️  Billing data creation failed: {e}")

def create_tickets_if_missing(customer, customer_user, superuser):
    """Create sample tickets with different statuses and replies."""
    try:
        # First create a support category
        support_category, _ = SupportCategory.objects.get_or_create(
            name='Technical Support',
            defaults={
                'name_en': 'Technical Support',
                'description': 'General technical support issues',
                'icon': 'settings',
                'color': '#3B82F6',
                'sla_response_hours': 4,
                'sla_resolution_hours': 24,
                'is_active': True,
            }
        )

        # Create 3 tickets with different scenarios
        tickets_data = [
            {
                'title': 'Website loading slowly',
                'description': 'My website has been loading very slowly for the past few days. Can you please check what might be causing this issue?',
                'status': 'open',
                'priority': 'normal',
                'contact_email': customer_user.email,
                'contact_person': f'{customer_user.first_name} {customer_user.last_name}',
                'replies': 0,  # No replies
            },
            {
                'title': 'Email not receiving messages',
                'description': 'I am not receiving emails to my main contact address. The last email I received was 3 days ago.',
                'status': 'closed',
                'priority': 'high',
                'contact_email': customer_user.email,
                'contact_person': f'{customer_user.first_name} {customer_user.last_name}',
                'replies': 1,  # 1 reply (solution)
            },
            {
                'title': 'Need help with SSL certificate installation',
                'description': 'I purchased an SSL certificate and need assistance with the installation process. Can someone guide me through the steps?',
                'status': 'open',
                'priority': 'normal',
                'contact_email': customer_user.email,
                'contact_person': f'{customer_user.first_name} {customer_user.last_name}',
                'replies': 5,  # 5 replies conversation
            },
        ]

        tickets_created = 0
        for i, ticket_data in enumerate(tickets_data, 1):
            # Generate unique ticket number
            ticket_number = f'TKT-2025-{i:03d}'
            
            ticket, created = Ticket.objects.get_or_create(
                ticket_number=ticket_number,
                defaults={
                    'title': ticket_data['title'],
                    'description': ticket_data['description'],
                    'customer': customer,
                    'category': support_category,
                    'status': ticket_data['status'],
                    'priority': ticket_data['priority'],
                    'contact_email': ticket_data['contact_email'],
                    'contact_person': ticket_data['contact_person'],
                    'source': 'web',
                    'created_by': customer_user,
                    'assigned_to': superuser,
                }
            )
            
            if created:
                tickets_created += 1
                
                # Create replies based on the ticket scenario
                if ticket_data['replies'] == 1:
                    # Single solution reply for the closed ticket
                    TicketComment.objects.create(
                        ticket=ticket,
                        content='I checked your email configuration and found the issue. The MX records were misconfigured. I have corrected them and your email should be working normally now. Please test and let me know if you need any further assistance.',
                        comment_type='support',
                        author=superuser,
                        is_public=True,
                        is_solution=True,
                        time_spent=0.5,
                    )
                    
                elif ticket_data['replies'] == 5:
                    # 5-reply conversation between customer and support
                    comments_data = [
                        {
                            'content': 'Thank you for contacting us. I can definitely help you with SSL certificate installation. Could you please provide me with the certificate files you received?',
                            'author': superuser,
                            'comment_type': 'support',
                            'time_spent': 0.25,
                        },
                        {
                            'content': 'I have the certificate files but I\'m not sure how to upload them to the control panel. Could you provide step-by-step instructions?',
                            'author': customer_user,
                            'comment_type': 'customer',
                            'time_spent': 0,
                        },
                        {
                            'content': 'Of course! Please log into your control panel and navigate to SSL/TLS section. Then click on "Install SSL Certificate" and upload your .crt and .key files. Here\'s a detailed guide: [link to guide]',
                            'author': superuser,
                            'comment_type': 'support',
                            'time_spent': 0.5,
                        },
                        {
                            'content': 'I uploaded the files but I\'m getting an error message saying "Certificate and private key do not match". What should I do?',
                            'author': customer_user,
                            'comment_type': 'customer',
                            'time_spent': 0,
                        },
                        {
                            'content': 'This error usually means the certificate and private key files don\'t belong together. Could you please double-check you\'re using the correct pair of files? If you\'re still having issues, I can install it for you if you provide the files via secure upload.',
                            'author': superuser,
                            'comment_type': 'support',
                            'time_spent': 0.33,
                        },
                    ]
                    
                    # Create comments with time delays
                    base_time = timezone.now() - timedelta(days=2)
                    for j, comment_data in enumerate(comments_data):
                        comment = TicketComment.objects.create(
                            ticket=ticket,
                            content=comment_data['content'],
                            comment_type=comment_data['comment_type'],
                            author=comment_data['author'],
                            is_public=True,
                            time_spent=comment_data['time_spent'],
                        )
                        # Manually set creation time to simulate conversation over time
                        comment.created_at = base_time + timedelta(hours=j * 4)
                        comment.save(update_fields=['created_at'])

        if tickets_created > 0:
            print(f"✅ Created {tickets_created} test tickets with replies")
            
    except Exception as e:
        print(f"⚠️  Ticket creation failed: {e}")

def print_credentials(superuser, customer_user, customer):
    """Print login credentials and test data info."""
    print("\n" + "="*60)
    print("🎉 PRAHO Platform Test Data Ready!")
    print("="*60)
    print("\n📋 Login credentials:")
    print(f"   🔐 Superuser: {superuser.email} / admin123")
    print(f"   👤 Customer user: {customer_user.email} / admin123")
    print(f"   🏢 Customer: {customer.name}")
    
    try:
        tax = customer.tax_profile
        print(f"   💼 Tax info: CUI {tax.cui}")
    except:
        print("   💼 Tax info: Not configured")
    
    print(f"\n🌐 Access URLs:")
    print(f"   📊 Dashboard: http://localhost:8001/app/")
    print(f"   🔐 Admin: http://localhost:8001/admin/")
    print(f"   🎯 Login: http://localhost:8001/auth/login/")
    
    print(f"\n📊 Database stats:")
    print(f"   👥 Users: {User.objects.count()}")
    customers_count = Customer.objects.count()
    print(f"   🏢 Customers: {customers_count}")
    memberships_count = CustomerMembership.objects.count()
    print(f"   🔗 Memberships: {memberships_count}")
    
    if customers_count > 1:
        print(f"   ℹ️  Multiple customers found (multi-tenant setup from sample data)")
    
    # Check optional models
    try:
        from apps.provisioning.models import Service
        services_count = Service.objects.count()
        print(f"   🚀 Services: {services_count}")
        if services_count == 0:
            print(f"   ➡️  Create services via Admin: http://localhost:8001/admin/provisioning/service/")
    except:
        pass
    
    try:
        from apps.billing.models import Invoice, ProformaInvoice
        invoices_count = Invoice.objects.count()
        proformas_count = ProformaInvoice.objects.count()
        print(f"   🧾 Invoices: {invoices_count}")
        print(f"   📄 Proformas: {proformas_count}")
        if invoices_count == 0:
            print(f"   ➡️  Create invoices via Admin: http://localhost:8001/admin/billing/invoice/")
    except:
        pass
    
    try:
        from apps.tickets.models import Ticket
        tickets_count = Ticket.objects.count()
        print(f"   🎫 Tickets: {tickets_count}")
        if tickets_count == 0:
            print(f"   ➡️  Create tickets via Dashboard: http://localhost:8001/app/tickets/create/")
    except:
        pass
    
    print("\n🚀 Ready to develop!")
    print("="*60)

def main():
    """Main function."""
    if check_existing_data():
        print("ℹ️  Test data already exists. Retrieving existing data...")
        
        try:
            # Get existing test accounts - try both possible emails
            superuser = None
            for email in ['admin@pragmatichost.com', 'admin@example.com']:
                try:
                    superuser = User.objects.get(email=email)
                    break
                except User.DoesNotExist:
                    continue
            
            if not superuser:
                superuser = User.objects.filter(is_staff=True, is_superuser=True).first()
            
            # Try to find customer user (could be different email)
            customer_user = None
            for email in ['customer@pragmatichost.com', 'user@testcompany.com', 'customer@test.com']:
                try:
                    customer_user = User.objects.get(email=email)
                    break
                except User.DoesNotExist:
                    continue
            
            if not customer_user:
                customer_user = User.objects.filter(is_staff=False).first()
            
            # Try to find customer
            customer = None
            for name in ['Test Company SRL', 'Test Customer']:
                try:
                    customer = Customer.objects.get(name=name)
                    break
                except Customer.DoesNotExist:
                    continue
            
            if not customer:
                customer = Customer.objects.first()
            
            # Always try to create missing service data
            if customer:
                try:
                    create_service_if_missing(customer)
                    create_billing_data_if_missing(customer)
                    create_tickets_if_missing(customer, customer_user, superuser)
                except Exception as e:
                    print(f"⚠️  Data creation failed: {e}")
            
            if customer_user and customer:
                print_credentials(superuser, customer_user, customer)
            else:
                print("⚠️  Could not find complete test data setup")
                print("   Run 'python manage.py flush' and restart to create proper test data.")
        except User.DoesNotExist as e:
            print(f"⚠️  Could not find expected test data: {e}")
            print("   Use 'python manage.py flush' to reset database and recreate test data.")
        return
    
    try:
        superuser, customer_user, customer = create_test_data()
        print_credentials(superuser, customer_user, customer)
    except Exception as e:
        print(f"❌ Error creating test data: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()