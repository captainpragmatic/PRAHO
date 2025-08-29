#!/usr/bin/env python3
"""
PRAHO Platform Test Data Setup Script
Creates comprehensive test data for development environment.
"""

import os
import sys
from datetime import timedelta
from decimal import Decimal

import django

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.dev')
django.setup()

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from apps.billing.models import Currency, Invoice, ProformaInvoice
from apps.customers.models import (
    Customer,
    CustomerAddress,
    CustomerBillingProfile,
    CustomerTaxProfile,
)
from apps.orders.models import Order, OrderItem
from apps.products.models import (
    Product,
    ProductBundle,
    ProductBundleItem,
    ProductPrice,
    ProductRelationship,
)
from apps.provisioning.models import Service, ServicePlan
from apps.tickets.models import SupportCategory, Ticket, TicketComment
from apps.users.models import CustomerMembership

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

        # 7.1 Create dedicated E2E users used by Playwright tests
        # Admin test user (superuser)
        e2e_admin, _ = User.objects.get_or_create(
            email='e2e-admin@test.local',
            defaults={
                'first_name': 'E2E',
                'last_name': 'Admin',
                'is_staff': True,
                'is_superuser': True,
                'is_active': True,
            }
        )
        # Ensure known password for repeatable E2E runs
        e2e_admin.set_password('test123')
        e2e_admin.save()
        print("✅ Ensured E2E admin user (e2e-admin@test.local)")

        # Customer test user
        e2e_customer, _ = User.objects.get_or_create(
            email='e2e-customer@test.local',
            defaults={
                'first_name': 'E2E',
                'last_name': 'Customer',
                'is_staff': False,
                'is_superuser': False,
                'is_active': True,
            }
        )
        # Ensure known password for repeatable E2E runs
        e2e_customer.set_password('test123')
        e2e_customer.save()
        print("✅ Ensured E2E customer user (e2e-customer@test.local)")

        # Ensure the E2E customer is linked to the test customer organization
        cm_defaults = {
            'role': 'owner',
            'is_primary': True,
        }
        cm, cm_created = CustomerMembership.objects.get_or_create(
            user=e2e_customer,
            customer=customer,
            defaults=cm_defaults,
        )
        if cm_created:
            print("✅ Linked E2E customer to test customer organization")
        else:
            # Keep membership consistent with expected defaults
            updated = False
            for k, v in cm_defaults.items():
                if getattr(cm, k) != v:
                    setattr(cm, k, v)
                    updated = True
            if updated:
                cm.save()
                print("🔧 Updated E2E customer membership settings")

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

        # 8. Create products
        create_products_if_missing()

        # 9. Create orders  
        create_orders_if_missing(customer, customer_user)

        # 10. Create tickets with replies
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

def create_products_if_missing():
    """Create comprehensive product catalog with all related models."""
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

        # ===============================================================================
        # 1. CREATE CORE PRODUCTS
        # ===============================================================================
        
        products_data = [
            {
                'slug': 'web-hosting-basic',
                'name': 'Web Hosting Basic',
                'description': 'Perfect starter plan for small websites and blogs. Includes all essential features with cPanel control panel.',
                'short_description': 'Basic shared hosting plan with 5GB storage and 10 email accounts.',
                'product_type': 'shared_hosting',
                'module': 'cpanel',
                'module_config': {
                    'disk_quota': 5000,  # MB
                    'bandwidth_quota': 100000,  # MB
                    'email_accounts': 10,
                    'databases': 5,
                    'subdomains': 'unlimited',
                    'ftp_accounts': 5,
                    'ssl_included': True
                },
                'is_featured': False,
                'sort_order': 1
            },
            {
                'slug': 'web-hosting-premium',
                'name': 'Web Hosting Premium',
                'description': 'Professional hosting solution for growing businesses. Enhanced performance and features with priority support.',
                'short_description': 'Premium shared hosting with 25GB storage, unlimited email accounts and priority support.',
                'product_type': 'shared_hosting',
                'module': 'cpanel',
                'module_config': {
                    'disk_quota': 25000,  # MB
                    'bandwidth_quota': 500000,  # MB
                    'email_accounts': 'unlimited',
                    'databases': 25,
                    'subdomains': 'unlimited',
                    'ftp_accounts': 25,
                    'ssl_included': True,
                    'priority_support': True,
                    'daily_backups': True
                },
                'is_featured': True,
                'sort_order': 2
            },
            {
                'slug': 'domain-registration',
                'name': 'Domain Registration',
                'description': 'Register your perfect domain name with various TLD options. Includes DNS management and privacy protection.',
                'short_description': 'Domain registration with DNS management and privacy protection.',
                'product_type': 'domain',
                'module': 'domain_manager',
                'module_config': {
                    'supported_tlds': ['.com', '.ro', '.eu', '.org', '.net'],
                    'dns_management': True,
                    'privacy_protection': True,
                    'auto_renewal': True
                },
                'is_featured': False,
                'sort_order': 3
            },
            {
                'slug': 'ssl-certificate',
                'name': 'SSL Certificate',
                'description': 'Secure your website with SSL encryption. Includes installation and automatic renewal.',
                'short_description': 'SSL certificate with installation and automatic renewal.',
                'product_type': 'ssl',
                'module': 'ssl_manager',
                'module_config': {
                    'certificate_type': 'domain_validated',
                    'encryption_strength': '256-bit',
                    'warranty': 10000,  # USD
                    'auto_install': True,
                    'auto_renewal': True
                },
                'is_featured': False,
                'sort_order': 4
            },
            {
                'slug': 'email-hosting',
                'name': 'Professional Email Hosting',
                'description': 'Professional email hosting with your domain. Includes webmail, IMAP/POP3, and spam protection.',
                'short_description': 'Professional email hosting with webmail and spam protection.',
                'product_type': 'email',
                'module': 'email_manager',
                'module_config': {
                    'mailbox_size': 10000,  # MB per mailbox
                    'max_mailboxes': 50,
                    'webmail_included': True,
                    'spam_protection': True,
                    'virus_protection': True,
                    'mobile_sync': True
                },
                'is_featured': False,
                'sort_order': 5
            }
        ]

        products_created = 0
        created_products = {}
        
        for product_data in products_data:
            product, created = Product.objects.get_or_create(
                slug=product_data['slug'],
                defaults={
                    'name': product_data['name'],
                    'description': product_data['description'],
                    'short_description': product_data['short_description'],
                    'product_type': product_data['product_type'],
                    'module': product_data['module'],
                    'module_config': product_data['module_config'],
                    'is_active': True,
                    'is_featured': product_data['is_featured'],
                    'sort_order': product_data['sort_order'],
                }
            )
            if created:
                products_created += 1
            created_products[product_data['slug']] = product

        if products_created > 0:
            print(f"✅ Created {products_created} hosting products")

        # ===============================================================================
        # 2. CREATE PRODUCT PRICES
        # ===============================================================================
        
        prices_data = [
            # Web Hosting Basic
            {'product': 'web-hosting-basic', 'currency': ron_currency, 'period': 'monthly', 'amount_cents': 2999, 'setup_cents': 0},
            {'product': 'web-hosting-basic', 'currency': ron_currency, 'period': 'annual', 'amount_cents': 29990, 'setup_cents': 0},
            {'product': 'web-hosting-basic', 'currency': eur_currency, 'period': 'monthly', 'amount_cents': 699, 'setup_cents': 0},
            {'product': 'web-hosting-basic', 'currency': eur_currency, 'period': 'annual', 'amount_cents': 6990, 'setup_cents': 0},
            
            # Web Hosting Premium
            {'product': 'web-hosting-premium', 'currency': ron_currency, 'period': 'monthly', 'amount_cents': 4999, 'setup_cents': 0},
            {'product': 'web-hosting-premium', 'currency': ron_currency, 'period': 'annual', 'amount_cents': 49990, 'setup_cents': 0},
            {'product': 'web-hosting-premium', 'currency': eur_currency, 'period': 'monthly', 'amount_cents': 1199, 'setup_cents': 0},
            {'product': 'web-hosting-premium', 'currency': eur_currency, 'period': 'annual', 'amount_cents': 11990, 'setup_cents': 0},
            
            # Domain Registration
            {'product': 'domain-registration', 'currency': ron_currency, 'period': 'annual', 'amount_cents': 4900, 'setup_cents': 0},
            {'product': 'domain-registration', 'currency': eur_currency, 'period': 'annual', 'amount_cents': 1200, 'setup_cents': 0},
            
            # SSL Certificate
            {'product': 'ssl-certificate', 'currency': ron_currency, 'period': 'annual', 'amount_cents': 9900, 'setup_cents': 2000},
            {'product': 'ssl-certificate', 'currency': eur_currency, 'period': 'annual', 'amount_cents': 2400, 'setup_cents': 500},
            
            # Email Hosting
            {'product': 'email-hosting', 'currency': ron_currency, 'period': 'monthly', 'amount_cents': 1999, 'setup_cents': 0},
            {'product': 'email-hosting', 'currency': ron_currency, 'period': 'annual', 'amount_cents': 19990, 'setup_cents': 0},
            {'product': 'email-hosting', 'currency': eur_currency, 'period': 'monthly', 'amount_cents': 499, 'setup_cents': 0},
            {'product': 'email-hosting', 'currency': eur_currency, 'period': 'annual', 'amount_cents': 4990, 'setup_cents': 0},
        ]

        prices_created = 0
        for price_data in prices_data:
            product = created_products[price_data['product']]
            price, created = ProductPrice.objects.get_or_create(
                product=product,
                currency=price_data['currency'],
                billing_period=price_data['period'],
                defaults={
                    'amount_cents': price_data['amount_cents'],
                    'setup_cents': price_data['setup_cents'],
                }
            )
            if created:
                prices_created += 1

        if prices_created > 0:
            print(f"✅ Created {prices_created} product prices")

        # ===============================================================================
        # 3. CREATE PRODUCT RELATIONSHIPS
        # ===============================================================================
        
        relationships_data = [
            # Basic hosting requires domain
            {'source': 'web-hosting-basic', 'target': 'domain-registration', 'type': 'requires'},
            # Premium hosting requires domain
            {'source': 'web-hosting-premium', 'target': 'domain-registration', 'type': 'requires'},
            # Basic can upgrade to Premium
            {'source': 'web-hosting-basic', 'target': 'web-hosting-premium', 'type': 'upgrades_to'},
            # SSL cross-sell with hosting
            {'source': 'web-hosting-basic', 'target': 'ssl-certificate', 'type': 'cross_sell'},
            {'source': 'web-hosting-premium', 'target': 'ssl-certificate', 'type': 'cross_sell'},
            # Email hosting cross-sell
            {'source': 'web-hosting-basic', 'target': 'email-hosting', 'type': 'cross_sell'},
            {'source': 'web-hosting-premium', 'target': 'email-hosting', 'type': 'cross_sell'},
        ]

        relationships_created = 0
        for rel_data in relationships_data:
            source_product = created_products[rel_data['source']]
            target_product = created_products[rel_data['target']]
            
            relationship, created = ProductRelationship.objects.get_or_create(
                source_product=source_product,
                target_product=target_product,
                relationship_type=rel_data['type'],
                defaults={
                    'is_active': True,
                    'sort_order': 0,
                }
            )
            if created:
                relationships_created += 1

        if relationships_created > 0:
            print(f"✅ Created {relationships_created} product relationships")

        # ===============================================================================
        # 4. CREATE PRODUCT BUNDLES
        # ===============================================================================
        
        bundles_data = [
            {
                'name': 'Complete Web Hosting Package',
                'description': 'Everything you need to get your website online: hosting, domain, SSL certificate, and professional email.',
                'discount_type': 'percent',
                'discount_value': Decimal('15.00'),  # 15% off
                'items': [
                    {'product': 'web-hosting-premium', 'quantity': 1},
                    {'product': 'domain-registration', 'quantity': 1},
                    {'product': 'ssl-certificate', 'quantity': 1},
                    {'product': 'email-hosting', 'quantity': 1},
                ]
            },
            {
                'name': 'Starter Website Bundle',
                'description': 'Basic package for small websites: hosting and domain registration.',
                'discount_type': 'percent',
                'discount_value': Decimal('10.00'),  # 10% off
                'items': [
                    {'product': 'web-hosting-basic', 'quantity': 1},
                    {'product': 'domain-registration', 'quantity': 1},
                ]
            }
        ]

        bundles_created = 0
        for bundle_data in bundles_data:
            bundle, created = ProductBundle.objects.get_or_create(
                name=bundle_data['name'],
                defaults={
                    'description': bundle_data['description'],
                    'discount_type': bundle_data['discount_type'],
                    'discount_value': bundle_data['discount_value'],
                    'is_active': True,
                }
            )
            
            if created:
                bundles_created += 1
                
                # Create bundle items
                for item_data in bundle_data['items']:
                    product = created_products[item_data['product']]
                    ProductBundleItem.objects.create(
                        bundle=bundle,
                        product=product,
                        quantity=item_data['quantity'],
                        is_required=True,
                    )

        if bundles_created > 0:
            print(f"✅ Created {bundles_created} product bundles with items")

        print("✅ Complete product catalog created with all relationships")

    except Exception as e:
        print(f"⚠️  Products creation failed: {e}")
        import traceback
        traceback.print_exc()

def create_orders_if_missing(customer, customer_user):
    """Create sample orders with various statuses."""
    try:
        # Get currencies
        ron_currency = Currency.objects.get(code='RON')
        eur_currency = Currency.objects.get(code='EUR')
        
        # Get products
        basic_product = Product.objects.get(slug='web-hosting-basic')
        premium_product = Product.objects.get(slug='web-hosting-premium')

        orders_data = [
            {
                'order_number': 'ORD-2025-001',
                'status': 'draft',
                'currency': ron_currency,
                'subtotal_cents': 2999,  # 29.99 RON
                'tax_cents': 570,        # 5.70 RON (19% VAT)
                'total_cents': 3569,     # 35.69 RON
                'product': basic_product,
                'quantity': 1,
                'billing_period': 'monthly',
                'notes': 'Draft order for basic hosting'
            },
            {
                'order_number': 'ORD-2025-002',
                'status': 'pending',
                'currency': ron_currency,
                'subtotal_cents': 4999,  # 49.99 RON
                'tax_cents': 950,        # 9.50 RON (19% VAT)
                'total_cents': 5949,     # 59.49 RON
                'product': premium_product,
                'quantity': 1,
                'billing_period': 'monthly',
                'notes': 'Pending payment for premium hosting'
            },
            {
                'order_number': 'ORD-2025-003',
                'status': 'processing',
                'currency': eur_currency,
                'subtotal_cents': 799,   # 7.99 EUR
                'tax_cents': 152,        # 1.52 EUR (19% VAT)
                'total_cents': 951,      # 9.51 EUR
                'product': basic_product,
                'quantity': 1,
                'billing_period': 'monthly',
                'notes': 'Payment received, setting up hosting account'
            },
            {
                'order_number': 'ORD-2025-004',
                'status': 'completed',
                'currency': eur_currency,
                'subtotal_cents': 1299,  # 12.99 EUR
                'tax_cents': 247,        # 2.47 EUR (19% VAT)
                'total_cents': 1546,     # 15.46 EUR
                'product': premium_product,
                'quantity': 1,
                'billing_period': 'monthly',
                'notes': 'Successfully provisioned premium hosting'
            },
            {
                'order_number': 'ORD-2025-005',
                'status': 'cancelled',
                'currency': ron_currency,
                'subtotal_cents': 2999,  # 29.99 RON
                'tax_cents': 570,        # 5.70 RON (19% VAT) 
                'total_cents': 3569,     # 35.69 RON
                'product': basic_product,
                'quantity': 1,
                'billing_period': 'monthly',
                'notes': 'Cancelled by customer before payment'
            }
        ]

        orders_created = 0
        for order_data in orders_data:
            order, created = Order.objects.get_or_create(
                order_number=order_data['order_number'],
                defaults={
                    'customer': customer,
                    'status': order_data['status'],
                    'currency': order_data['currency'],
                    'subtotal_cents': order_data['subtotal_cents'],
                    'tax_cents': order_data['tax_cents'],
                    'total_cents': order_data['total_cents'],
                    'customer_email': customer_user.email,
                    'notes': order_data['notes'],
                    'created_by': customer_user,
                }
            )

            if created:
                orders_created += 1
                
                # Create order item
                OrderItem.objects.create(
                    order=order,
                    product=order_data['product'],
                    product_name=order_data['product'].name,
                    product_type=order_data['product'].product_type,
                    billing_period=order_data['billing_period'],
                    quantity=order_data['quantity'],
                    unit_price_cents=order_data['subtotal_cents'],
                    tax_rate=Decimal('0.1900'),  # 19% VAT
                    tax_cents=order_data['tax_cents'],
                )

        if orders_created > 0:
            print(f"✅ Created {orders_created} test orders with various statuses")

    except Exception as e:
        print(f"⚠️  Orders creation failed: {e}")

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

    print("\n🌐 Access URLs:")
    print("   📊 Dashboard: http://localhost:8001/app/")
    print("   🔐 Admin: http://localhost:8001/admin/")
    print("   🎯 Login: http://localhost:8001/auth/login/")

    print("\n📊 Database stats:")
    print(f"   👥 Users: {User.objects.count()}")
    customers_count = Customer.objects.count()
    print(f"   🏢 Customers: {customers_count}")
    memberships_count = CustomerMembership.objects.count()
    print(f"   🔗 Memberships: {memberships_count}")

    if customers_count > 1:
        print("   ℹ️  Multiple customers found (multi-tenant setup from sample data)")

    # Check optional models
    try:
        from apps.products.models import Product
        products_count = Product.objects.count()
        print(f"   📦 Products: {products_count}")
        if products_count == 0:
            print("   ➡️  Create products via Admin: http://localhost:8001/admin/products/product/")
    except:
        pass

    try:
        from apps.orders.models import Order
        orders_count = Order.objects.count()
        print(f"   🛒 Orders: {orders_count}")
        if orders_count == 0:
            print("   ➡️  Create orders via Dashboard: http://localhost:8001/app/orders/create/")
    except:
        pass

    try:
        from apps.provisioning.models import Service
        services_count = Service.objects.count()
        print(f"   🚀 Services: {services_count}")
        if services_count == 0:
            print("   ➡️  Create services via Admin: http://localhost:8001/admin/provisioning/service/")
    except:
        pass

    try:
        from apps.billing.models import Invoice, ProformaInvoice
        invoices_count = Invoice.objects.count()
        proformas_count = ProformaInvoice.objects.count()
        print(f"   🧾 Invoices: {invoices_count}")
        print(f"   📄 Proformas: {proformas_count}")
        if invoices_count == 0:
            print("   ➡️  Create invoices via Admin: http://localhost:8001/admin/billing/invoice/")
    except:
        pass

    try:
        from apps.tickets.models import Ticket
        tickets_count = Ticket.objects.count()
        print(f"   🎫 Tickets: {tickets_count}")
        if tickets_count == 0:
            print("   ➡️  Create tickets via Dashboard: http://localhost:8001/app/tickets/create/")
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
                    create_products_if_missing()
                    create_orders_if_missing(customer, customer_user)
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
