"""Deterministic local browser prerequisites, separate from pytest's ORM database.

Only the guarded management commands call this module. Scenario rows are owned by
their key; tests receive exact identifiers instead of borrowing the first live row.
"""

# ruff: noqa: S105, S106 -- public credentials for the guarded, dedicated E2E database

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from io import StringIO
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection, transaction
from django.utils import timezone

from apps.common.management.commands.generate_sample_data import Command as DemoCommand
from apps.orders.services import BillingAddressData, OrderCreateData, OrderService, StatusChangeData

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.users.models import User

OWNER = "praho-e2e-v1"
PASSWORD = "test123"
CLOSED_TICKET_SEQUENCE = 2
CUSTOMER_EMAILS = ("e2e-customer@test.local", "customer2@pragmatichost.com")


def require_e2e_database() -> None:
    """Never seed a development, production, or pytest database by accident."""
    expected = getattr(settings, "E2E_DATABASE_PATH", None)
    if (
        not getattr(settings, "E2E_FIXTURES_ENABLED", False)
        or not settings.DEBUG
        or not expected
        or str(connection.settings_dict["NAME"]) != str(expected)
    ):
        raise CommandError("E2E fixtures require config.settings.e2e and its dedicated live database.")


def _user(email: str, *, staff: bool = False, password: str = PASSWORD) -> User:
    from apps.users.models import User  # noqa: PLC0415 -- cross-domain fixture orchestration

    user, _ = User.objects.update_or_create(
        email=email,
        defaults={
            "first_name": "E2E",
            "last_name": "Admin" if staff else "Customer",
            "is_active": True,
            "is_staff": staff,
            "is_superuser": staff,
            "staff_role": "admin" if staff else "",
        },
    )
    user.set_password(password)
    user.save(update_fields=["password"])
    return user


def _customer(key: str, *, name: str) -> Customer:
    from apps.customers.models import (  # noqa: PLC0415 -- cross-domain fixture orchestration
        Customer,
        CustomerAddress,
        CustomerBillingProfile,
        CustomerTaxProfile,
    )

    customer, created = Customer.objects.get_or_create(
        primary_email=f"{key}@e2e.test",
        defaults={
            "name": name,
            "company_name": name,
            "customer_type": "company",
            "status": "active",
            "primary_phone": "+40722123456",
            "data_processing_consent": True,
            "meta": {"fixture_owner": OWNER, "fixture_name": key},
        },
    )
    if customer.meta.get("fixture_owner") != OWNER:
        raise CommandError(f"Refusing to adopt unowned customer {key}")
    if created:
        CustomerTaxProfile.objects.create(
            customer=customer,
            cui="RO14399847",
            vat_number="RO14399847",
            is_vat_payer=True,
            registration_number="J40/1234/2020",
        )
        CustomerBillingProfile.objects.create(customer=customer, preferred_currency="RON", payment_terms=30)
        CustomerAddress.objects.create(
            customer=customer,
            is_primary=True,
            is_billing=True,
            address_line1="Str. Victoriei nr. 10",
            city="București",
            county="București",
            postal_code="010061",
            country="România",
            is_current=True,
        )
    return customer


def _document(customer: Customer, key: str, *, proforma: bool = False, paid: bool = False) -> Any:
    from apps.billing.models import (  # noqa: PLC0415 -- cross-domain fixture orchestration
        Invoice,
        InvoiceLine,
        ProformaInvoice,
        ProformaLine,
    )
    from apps.billing.payment_models import Payment  # noqa: PLC0415 -- cross-domain fixture orchestration

    model = ProformaInvoice if proforma else Invoice
    number = f"E2E-{'PRO' if proforma else 'INV'}-{key}"
    document = model.objects.filter(number=number).first()
    if document:
        return document
    fields: dict[str, Any] = {
        "customer": customer,
        "currency_id": "RON",
        "number": number,
        "bill_to_name": customer.get_billing_name(),
        "bill_to_email": customer.primary_email,
        "bill_to_address1": "Str. Victoriei nr. 10",
        "bill_to_city": "București",
        "bill_to_region": "București",
        "bill_to_postal": "010061",
        "bill_to_country": "RO",
        "bill_to_tax_id": "RO14399847",
        "meta": {"fixture_owner": OWNER, "fixture_name": key},
    }
    if proforma:
        fields["valid_until"] = timezone.now() + timedelta(days=30)
    else:
        fields["due_at"] = timezone.now() + timedelta(days=30)
    document = model.objects.create(**fields)
    line = ProformaLine(proforma=document) if isinstance(document, ProformaInvoice) else InvoiceLine(invoice=document)
    line.description = f"E2E hosting {key}"
    line.kind = "service"
    line.quantity = Decimal("1.000")
    line.unit_price_cents = 10000
    line.tax_rate = Decimal("0.21")
    line.calculate_totals()
    line.save()
    document.recalculate_totals()
    if isinstance(document, ProformaInvoice):
        document.send_proforma()
    else:
        document.issue()
    document.save()
    if paid:
        assert isinstance(document, Invoice), "Only fiscal invoices can be seeded as paid"
        payment = Payment.objects.create(
            customer=customer,
            invoice=document,
            currency_id="RON",
            amount_cents=document.total_cents,
            payment_method="bank",
        )
        payment.succeed()
        payment.save()
        # The payment signal settles the invoice; do not apply the FSM twice.
        document.refresh_from_db()
        if document.status != "paid":
            raise CommandError(f"Seed payment did not settle {document.number}")
    return document


@transaction.atomic
def seed_baseline() -> dict[str, Any]:
    """Read-only page prerequisites. Mutating workflows use their own scenarios."""
    from apps.products.models import Product, ProductPrice  # noqa: PLC0415 -- cross-domain fixture orchestration
    from apps.provisioning.models import Service, ServicePlan  # noqa: PLC0415 -- cross-domain fixture orchestration
    from apps.settings.models import SystemSetting  # noqa: PLC0415 -- cross-domain fixture orchestration
    from apps.tickets.models import (  # noqa: PLC0415 -- cross-domain fixture orchestration
        SupportCategory,
        Ticket,
        TicketComment,
    )
    from apps.users.models import CustomerMembership  # noqa: PLC0415 -- cross-domain fixture orchestration

    for command in ("setup_default_settings", "setup_tax_rules", "setup_email_templates"):
        call_command(command, stdout=StringIO())
    SystemSetting.objects.filter(key="node_deployment.dns_default_zone").update(value="nodes.e2e.example")
    demo = DemoCommand(stdout=StringIO())
    demo.create_service_plans()
    demo.create_support_categories()
    demo.create_billing_essentials()
    demo.create_products_from_service_plans()
    demo.create_servers()
    demo.create_domain_foundation()
    plan, _ = ServicePlan.objects.get_or_create(
        name="E2E Hosting",
        defaults={
            "plan_type": "shared_hosting",
            "price_monthly": Decimal("100.00"),
            "is_active": True,
            "is_public": True,
            "auto_provision": False,
        },
    )
    ServicePlan.objects.filter(pk=plan.pk).update(disk_space_gb=10, bandwidth_gb=100)
    product, _ = Product.objects.get_or_create(
        slug="e2e-hosting",
        defaults={
            "name": "E2E Hosting",
            "short_description": "Hosting for browser workflow verification.",
            "product_type": "shared_hosting",
            "is_active": True,
            "requires_domain": False,
            "default_service_plan": plan,
        },
    )
    ProductPrice.objects.update_or_create(
        product=product,
        currency_id="RON",
        defaults={"monthly_price_cents": 10000, "annual_discount_percent": Decimal("20.00")},
    )
    admin = _user("e2e-admin@test.local", staff=True)
    _user("admin@pragmatichost.com", staff=True, password="admin123")
    category = (
        SupportCategory.objects.get(name="Suport Tehnic")
        if SupportCategory.objects.filter(name="Suport Tehnic").exists()
        else SupportCategory.objects.order_by("pk").first()
    )
    for index, email in enumerate(CUSTOMER_EMAILS, start=1):
        customer = _customer(f"customer-{index}", name="Test Company SRL" if index == 1 else "E2E Second Company SRL")
        user = _user(email, password=PASSWORD if index == 1 else "admin123")
        members = [user, admin] if index == 1 else [user]
        if index == 1:
            members.append(_user("customer@pragmatichost.com", password="admin123"))
        for member in members:
            CustomerMembership.objects.update_or_create(
                user=member, customer=customer, defaults={"role": "owner", "is_primary": True, "is_active": True}
            )
        # Enough records to exercise pagination, with explicit stable identity.
        for sequence in range(1, 26 if index == 1 else 3):
            key = f"{index}-{sequence:02}"
            _document(customer, key, paid=sequence % 2 == 0)
            _document(customer, key, proforma=True)
            service, _ = Service.objects.get_or_create(
                username=f"e2e-{key}",
                defaults={
                    "customer": customer,
                    "service_plan": plan,
                    "currency_id": "RON",
                    "service_name": f"E2E Hosting {key}",
                    "domain": f"hosting-{key}.example",
                    "price": Decimal("100.00"),
                    "status": "active",
                    "activated_at": timezone.now() - timedelta(days=30),
                    "expires_at": timezone.now() + timedelta(days=335),
                    "disk_usage_mb": 120,
                },
            )
            ticket, created = Ticket.objects.get_or_create(
                ticket_number=f"E2E-{key}",
                defaults={
                    "customer": customer,
                    "title": f"E2E hosting help {key}",
                    "description": "Please check the hosting configuration.",
                    "category": category,
                    "contact_email": email,
                    "related_service": service,
                },
            )
            if created:
                TicketComment.objects.create(ticket=ticket, author=admin, content="We are checking your configuration.")
            if sequence == CLOSED_TICKET_SEQUENCE and ticket.status != "closed":
                ticket.close()
                ticket.save()
    return validate_baseline()


def validate_baseline() -> dict[str, Any]:
    """Read-only validation; a failed setup cannot turn into smaller passing tests."""
    from apps.billing.models import Invoice, ProformaInvoice  # noqa: PLC0415 -- cross-domain fixture orchestration
    from apps.customers.models import Customer  # noqa: PLC0415 -- cross-domain fixture orchestration
    from apps.products.models import Product  # noqa: PLC0415 -- cross-domain fixture orchestration
    from apps.provisioning.models import Service  # noqa: PLC0415 -- cross-domain fixture orchestration
    from apps.tickets.models import Ticket  # noqa: PLC0415 -- cross-domain fixture orchestration
    from apps.users.models import CustomerMembership, User  # noqa: PLC0415 -- cross-domain fixture orchestration

    result: dict[str, Any] = {"version": OWNER, "customers": []}
    for index, email in enumerate(CUSTOMER_EMAILS, start=1):
        customer = Customer.objects.get(primary_email=f"customer-{index}@e2e.test", meta__fixture_owner=OWNER)
        user = User.objects.get(email=email, is_active=True)
        if not user.check_password(PASSWORD if index == 1 else "admin123"):
            raise CommandError(f"E2E password does not match for {email}")
        memberships = CustomerMembership.objects.filter(user=user, is_active=True)
        if set(memberships.values_list("customer_id", flat=True)) != {customer.pk}:
            raise CommandError(f"E2E customer {email} must have exactly its own membership")
        invoice = Invoice.objects.get(number=f"E2E-INV-{index}-01", customer=customer)
        paid_invoice = Invoice.objects.get(number=f"E2E-INV-{index}-02", customer=customer, status="paid")
        proforma = ProformaInvoice.objects.get(number=f"E2E-PRO-{index}-01", customer=customer)
        service = Service.objects.get(username=f"e2e-{index}-01", customer=customer)
        if invoice.status != "issued" or service.status != "active":
            raise CommandError("Read-only E2E invoice/service prerequisites were mutated")
        ticket = Ticket.objects.get(ticket_number=f"E2E-{index}-01", customer=customer)
        renewal_date = service.get_next_billing_date()
        if renewal_date is None:
            raise CommandError("E2E service must have a scheduled renewal")
        result["customers"].append(
            {
                "id": customer.pk,
                "name": customer.name,
                "email": email,
                "user_id": user.pk,
                "invoice_number": invoice.number,
                "paid_invoice_number": paid_invoice.number,
                "proforma_number": proforma.number,
                "invoice_id": invoice.pk,
                "proforma_id": proforma.pk,
                "service_id": str(service.pk),
                "service_renewal_date": renewal_date.strftime("%d.%m.%Y"),
                "ticket_id": ticket.pk,
                "closed_ticket_id": Ticket.objects.get(ticket_number=f"E2E-{index}-02").pk,
            }
        )
    admin = User.objects.get(email="e2e-admin@test.local", is_active=True, is_staff=True, is_superuser=True)
    if not admin.check_password(PASSWORD):
        raise CommandError("E2E admin password does not match")
    result["product_id"] = str(Product.objects.get(slug="e2e-hosting", is_active=True).pk)
    return result


@transaction.atomic
def seed_scenario(scenario: str, key: str) -> dict[str, Any]:
    from apps.customers.models import CustomerAddress  # noqa: PLC0415 -- cross-domain fixture orchestration
    from apps.products.models import Product  # noqa: PLC0415 -- cross-domain fixture orchestration
    from apps.users.models import CustomerMembership  # noqa: PLC0415 -- cross-domain fixture orchestration

    if scenario == "pricing":
        product = Product.objects.create(
            name=f"E2E pricing {key}",
            slug=f"e2e-pricing-{key}",
            product_type="shared_hosting",
            requires_domain=False,
            is_active=True,
            meta={"fixture_owner": OWNER, "fixture_name": key},
        )
        return {"product_id": str(product.pk), "product_slug": product.slug, "name": product.name}
    customer = _customer(f"scenario-{key}", name=f"E2E billing {key}")
    if scenario == "account":
        user = _user(f"account-{key}@e2e.test")
        CustomerMembership.objects.create(user=user, customer=customer, role="owner", is_primary=True)
        other_address = CustomerAddress.objects.create(
            customer=customer,
            label=f"E2E secondary {key}",
            address_line1="Str. Noua 20",
            city="Cluj-Napoca",
            county="Cluj",
            postal_code="400001",
            country="România",
            is_current=True,
        )
        return {
            "customer_id": customer.pk,
            "user_id": user.pk,
            "email": user.email,
            "password": PASSWORD,
            "name": customer.name,
            "address_id": other_address.pk,
        }
    product = Product.objects.get(slug="e2e-hosting")
    address: BillingAddressData = {
        "company_name": customer.company_name,
        "contact_name": "E2E Customer",
        "email": customer.primary_email,
        "phone": customer.primary_phone,
        "address_line1": "Str. Victoriei nr. 10",
        "address_line2": "",
        "city": "București",
        "county": "București",
        "postal_code": "010061",
        "country": "RO",
        "fiscal_code": "RO14399847",
        "registration_number": "J40/1234/2020",
        "vat_number": "RO14399847",
    }
    result = OrderService.create_order(
        OrderCreateData(
            customer=customer,
            billing_address=address,
            items=[
                {
                    "product_id": product.pk,
                    "quantity": 1,
                    "unit_price_cents": 10000,
                    "setup_cents": 2500,
                    "billing_period": "monthly",
                    "description": product.name,
                }
            ],
            meta={"fixture_owner": OWNER, "fixture_name": key},
        )
    )
    if result.is_err():
        raise CommandError(result.unwrap_err())
    order = result.unwrap()
    submitted = OrderService.update_order_status(order, StatusChangeData(new_status="awaiting_payment"))
    if submitted.is_err():
        raise CommandError(submitted.unwrap_err())
    order.refresh_from_db()
    return {
        "customer_id": customer.pk,
        "order_id": str(order.pk),
        "order_number": order.order_number,
        "proforma_id": order.proforma_id,
        "total_cents": order.total_cents,
    }
