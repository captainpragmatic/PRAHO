# ===============================================================================
# CORE TEST FACTORIES FOR PRAHO PLATFORM
# ===============================================================================
"""
Comprehensive test factories for all major models in the PRAHO Platform.

These factories use factory_boy for consistent, maintainable test data generation
with proper relationships and realistic Romanian business data.
"""

from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal
from typing import Any

from django.contrib.auth import get_user_model
from django.utils import timezone

from apps.billing.models import Currency, Invoice, InvoiceLine, Payment, Proforma
from apps.customers.models import (
    Customer,
    CustomerAddress,
    CustomerBillingProfile,
    CustomerTaxProfile,
)
from apps.orders.models import Order, OrderItem
from apps.products.models import Product, ProductCategory

User = get_user_model()


# ===============================================================================
# USER FACTORIES
# ===============================================================================

@dataclass
class UserCreationRequest:
    """Parameter object for user creation"""
    username: str = 'testuser'
    email: str = 'test@pragmatichost.com'
    password: str = 'SecureTestPass123!'
    first_name: str = 'Test'
    last_name: str = 'User'
    is_staff: bool = False
    is_superuser: bool = False
    staff_role: str = ''


def create_user(request: UserCreationRequest | None = None) -> User:
    """Create a user with sensible defaults."""
    if request is None:
        request = UserCreationRequest()

    # Generate unique username if already exists
    username = request.username
    counter = 1
    while User.objects.filter(username=username).exists():
        username = f"{request.username}_{counter}"
        counter += 1

    return User.objects.create_user(
        username=username,
        email=request.email,
        password=request.password,
        first_name=request.first_name,
        last_name=request.last_name,
        is_staff=request.is_staff,
        is_superuser=request.is_superuser,
        staff_role=request.staff_role,
    )


def create_staff_user(
    username: str = 'staffuser',
    staff_role: str = 'support'
) -> User:
    """Create a staff user with specific role."""
    return create_user(UserCreationRequest(
        username=username,
        email=f'{username}@pragmatichost.com',
        is_staff=True,
        staff_role=staff_role,
    ))


def create_admin_user(username: str = 'adminuser') -> User:
    """Create an admin user with full permissions."""
    return create_user(UserCreationRequest(
        username=username,
        email=f'{username}@pragmatichost.com',
        is_staff=True,
        is_superuser=True,
        staff_role='admin',
    ))


# ===============================================================================
# CUSTOMER FACTORIES
# ===============================================================================

@dataclass
class CustomerCreationRequest:
    """Parameter object for customer creation"""
    name: str = 'SC Test SRL'
    customer_type: str = 'company'
    company_name: str = 'SC Test SRL'
    primary_email: str = 'contact@test.ro'
    primary_phone: str = '+40721234567'
    data_processing_consent: bool = True
    status: str = 'active'
    created_by: User | None = None
    with_tax_profile: bool = True
    with_billing_profile: bool = True
    with_address: bool = True
    cui: str = 'RO12345678'
    vat_number: str = 'RO12345678'
    is_vat_payer: bool = True


def create_full_customer(request: CustomerCreationRequest | None = None) -> Customer:
    """Create a complete customer with all profiles and address."""
    if request is None:
        request = CustomerCreationRequest()

    # Create admin user if not provided
    if request.created_by is None:
        request.created_by = create_admin_user(username=f'admin_{timezone.now().timestamp()}')

    # Generate unique email if already exists
    email = request.primary_email
    counter = 1
    while Customer.objects.filter(primary_email=email).exists():
        email = f"contact_{counter}@test.ro"
        counter += 1

    customer = Customer.objects.create(
        name=request.name,
        customer_type=request.customer_type,
        company_name=request.company_name,
        primary_email=email,
        primary_phone=request.primary_phone,
        data_processing_consent=request.data_processing_consent,
        status=request.status,
        created_by=request.created_by,
    )

    if request.with_tax_profile:
        CustomerTaxProfile.objects.create(
            customer=customer,
            cui=request.cui,
            vat_number=request.vat_number,
            registration_number='J40/1234/2023',
            is_vat_payer=request.is_vat_payer,
            vat_rate=Decimal('19.00'),
        )

    if request.with_billing_profile:
        CustomerBillingProfile.objects.create(
            customer=customer,
            payment_terms=30,
            credit_limit=Decimal('5000.00'),
            preferred_currency='RON',
        )

    if request.with_address:
        CustomerAddress.objects.create(
            customer=customer,
            address_type='legal',
            address_line1='Str. Test Nr. 1',
            city='București',
            county='Sector 1',
            postal_code='010101',
            country='România',
            is_current=True,
        )

    return customer


def create_individual_customer(
    first_name: str = 'Ion',
    last_name: str = 'Popescu',
    email: str = 'ion.popescu@example.ro'
) -> Customer:
    """Create an individual (non-company) customer."""
    admin = create_admin_user(username=f'admin_{timezone.now().timestamp()}')

    customer = Customer.objects.create(
        name=f'{first_name} {last_name}',
        customer_type='individual',
        first_name=first_name,
        last_name=last_name,
        primary_email=email,
        primary_phone='+40722123456',
        data_processing_consent=True,
        status='active',
        created_by=admin,
    )

    CustomerBillingProfile.objects.create(
        customer=customer,
        payment_terms=14,
        preferred_currency='RON',
    )

    CustomerAddress.objects.create(
        customer=customer,
        address_type='billing',
        address_line1='Bd. Unirii Nr. 10, Ap. 5',
        city='București',
        county='Sector 3',
        postal_code='030167',
        country='România',
        is_current=True,
    )

    return customer


# ===============================================================================
# PRODUCT FACTORIES
# ===============================================================================

@dataclass
class ProductCreationRequest:
    """Parameter object for product creation"""
    name: str = 'Web Hosting Standard'
    sku: str = 'WH-STD-001'
    description: str = 'Standard web hosting package'
    price_cents: int = 9900  # 99.00 RON
    currency_code: str = 'RON'
    billing_cycle: str = 'monthly'
    is_active: bool = True
    category_name: str = 'Web Hosting'


def create_product_category(name: str = 'Web Hosting') -> ProductCategory:
    """Create a product category."""
    category, _ = ProductCategory.objects.get_or_create(
        name=name,
        defaults={
            'slug': name.lower().replace(' ', '-'),
            'description': f'{name} products',
            'is_active': True,
        }
    )
    return category


def create_product(request: ProductCreationRequest | None = None) -> Product:
    """Create a product with sensible defaults."""
    if request is None:
        request = ProductCreationRequest()

    category = create_product_category(request.category_name)

    # Generate unique SKU if already exists
    sku = request.sku
    counter = 1
    while Product.objects.filter(sku=sku).exists():
        sku = f"{request.sku}-{counter}"
        counter += 1

    return Product.objects.create(
        name=request.name,
        sku=sku,
        description=request.description,
        price_cents=request.price_cents,
        currency_code=request.currency_code,
        billing_cycle=request.billing_cycle,
        is_active=request.is_active,
        category=category,
    )


def create_hosting_products() -> list[Product]:
    """Create a set of common hosting products."""
    products = []

    product_configs = [
        ('Web Hosting Basic', 'WH-BASIC', 4900, 'Basic web hosting - 5GB storage'),
        ('Web Hosting Standard', 'WH-STD', 9900, 'Standard web hosting - 20GB storage'),
        ('Web Hosting Premium', 'WH-PREM', 19900, 'Premium web hosting - 50GB storage'),
        ('VPS Basic', 'VPS-BASIC', 29900, 'Basic VPS - 2 vCPU, 4GB RAM'),
        ('VPS Standard', 'VPS-STD', 59900, 'Standard VPS - 4 vCPU, 8GB RAM'),
        ('Domain Registration .ro', 'DOM-RO', 4500, '.ro domain registration - 1 year'),
        ('SSL Certificate', 'SSL-STD', 9900, 'Standard SSL certificate - 1 year'),
    ]

    for name, sku, price, desc in product_configs:
        products.append(create_product(ProductCreationRequest(
            name=name,
            sku=sku,
            price_cents=price,
            description=desc,
        )))

    return products


# ===============================================================================
# ORDER FACTORIES
# ===============================================================================

@dataclass
class OrderCreationRequest:
    """Parameter object for order creation"""
    customer: Customer | None = None
    status: str = 'draft'
    currency_code: str = 'RON'
    created_by: User | None = None
    items: list[tuple[Product, int]] = field(default_factory=list)  # (product, quantity) pairs


def create_order(request: OrderCreationRequest | None = None) -> Order:
    """Create an order with optional items."""
    if request is None:
        request = OrderCreationRequest()

    if request.customer is None:
        request.customer = create_full_customer()

    if request.created_by is None:
        request.created_by = create_admin_user(username=f'admin_order_{timezone.now().timestamp()}')

    order = Order.objects.create(
        customer=request.customer,
        status=request.status,
        currency_code=request.currency_code,
        created_by=request.created_by,
    )

    for product, quantity in request.items:
        OrderItem.objects.create(
            order=order,
            product=product,
            product_name=product.name,
            product_sku=product.sku,
            quantity=quantity,
            unit_price_cents=product.price_cents,
            total_cents=product.price_cents * quantity,
        )

    return order


def create_order_with_items(
    customer: Customer | None = None,
    num_items: int = 2
) -> Order:
    """Create an order with random items."""
    products = create_hosting_products()[:num_items]

    if customer is None:
        customer = create_full_customer()

    items = [(product, 1) for product in products]

    return create_order(OrderCreationRequest(
        customer=customer,
        status='pending',
        items=items,
    ))


# ===============================================================================
# INVOICE FACTORIES
# ===============================================================================

@dataclass
class InvoiceCreationRequest:
    """Parameter object for invoice creation"""
    customer: Customer | None = None
    currency: Currency | None = None
    number: str = ''
    status: str = 'issued'
    total_cents: int = 10000
    subtotal_cents: int = 8403  # Before 19% VAT
    vat_cents: int = 1597  # 19% VAT
    due_days: int = 30
    order: Order | None = None


def create_ron_currency() -> Currency:
    """Create Romanian Lei currency."""
    currency, _ = Currency.objects.get_or_create(
        code='RON',
        defaults={
            'name': 'Romanian Leu',
            'symbol': 'L',
            'decimals': 2,
            'is_active': True,
        }
    )
    return currency


def create_eur_currency() -> Currency:
    """Create Euro currency."""
    currency, _ = Currency.objects.get_or_create(
        code='EUR',
        defaults={
            'name': 'Euro',
            'symbol': '€',
            'decimals': 2,
            'is_active': True,
        }
    )
    return currency


def create_full_invoice(request: InvoiceCreationRequest | None = None) -> Invoice:
    """Create an invoice with all required fields."""
    if request is None:
        request = InvoiceCreationRequest()

    if request.customer is None:
        request.customer = create_full_customer()

    if request.currency is None:
        request.currency = create_ron_currency()

    if not request.number:
        request.number = f'INV-{timezone.now().year}-{Invoice.objects.count() + 1:05d}'

    invoice = Invoice.objects.create(
        customer=request.customer,
        currency=request.currency,
        number=request.number,
        status=request.status,
        total_cents=request.total_cents,
        subtotal_cents=request.subtotal_cents,
        vat_cents=request.vat_cents,
        due_at=timezone.now() + timedelta(days=request.due_days),
        order=request.order,
    )

    # Add a line item
    InvoiceLine.objects.create(
        invoice=invoice,
        description='Web Hosting Standard - 1 month',
        quantity=1,
        unit_price_cents=request.subtotal_cents,
        total_cents=request.subtotal_cents,
    )

    return invoice


# ===============================================================================
# PAYMENT FACTORIES
# ===============================================================================

@dataclass
class FullPaymentCreationRequest:
    """Parameter object for payment creation with invoice"""
    invoice: Invoice | None = None
    payment_method: str = 'stripe'
    status: str = 'succeeded'
    amount_cents: int | None = None  # Defaults to invoice total


def create_full_payment(request: FullPaymentCreationRequest | None = None) -> Payment:
    """Create a payment linked to an invoice."""
    if request is None:
        request = FullPaymentCreationRequest()

    if request.invoice is None:
        request.invoice = create_full_invoice()

    amount = request.amount_cents or request.invoice.total_cents

    return Payment.objects.create(
        customer=request.invoice.customer,
        invoice=request.invoice,
        currency=request.invoice.currency,
        amount_cents=amount,
        payment_method=request.payment_method,
        status=request.status,
    )


# ===============================================================================
# PROFORMA FACTORIES
# ===============================================================================

def create_proforma(
    customer: Customer | None = None,
    currency: Currency | None = None,
    total_cents: int = 10000
) -> Proforma:
    """Create a proforma invoice."""
    if customer is None:
        customer = create_full_customer()

    if currency is None:
        currency = create_ron_currency()

    return Proforma.objects.create(
        customer=customer,
        currency=currency,
        number=f'PRO-{timezone.now().year}-{Proforma.objects.count() + 1:05d}',
        status='draft',
        total_cents=total_cents,
        subtotal_cents=int(total_cents / 1.19),
        valid_until=timezone.now() + timedelta(days=30),
    )


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================

def create_complete_order_to_invoice_flow(
    customer: Customer | None = None
) -> dict[str, Any]:
    """Create a complete flow from order to paid invoice."""
    if customer is None:
        customer = create_full_customer()

    # Create order
    order = create_order_with_items(customer=customer, num_items=2)

    # Calculate totals
    subtotal = sum(item.total_cents for item in order.items.all())
    vat = int(subtotal * Decimal('0.19'))
    total = subtotal + vat

    # Create invoice from order
    invoice = create_full_invoice(InvoiceCreationRequest(
        customer=customer,
        order=order,
        subtotal_cents=subtotal,
        vat_cents=vat,
        total_cents=total,
    ))

    # Create payment
    payment = create_full_payment(FullPaymentCreationRequest(
        invoice=invoice,
    ))

    return {
        'customer': customer,
        'order': order,
        'invoice': invoice,
        'payment': payment,
    }
