"""Shared inputs for real workflows in pytest's isolated ORM database."""

from decimal import Decimal
from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from apps.billing.models import Currency
from apps.billing.proforma_service import ProformaPaymentService
from apps.customers.models import Customer, CustomerBillingProfile, CustomerTaxProfile
from apps.orders.services import OrderCreateData, OrderService, StatusChangeData
from apps.products.models import Product, ProductPrice
from apps.provisioning.models import ServicePlan
from apps.users.models import User


class WorkflowCase(TestCase):
    def setUp(self):
        call_command("setup_email_templates", stdout=StringIO())
        self.admin = User.objects.create_user(
            email="workflow@e2e.test", password="test123", is_staff=True, is_superuser=True, staff_role="admin"
        )
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            name="E2E Workflow SRL",
            company_name="E2E Workflow SRL",
            primary_email="workflow-customer@e2e.test",
            customer_type="company",
            status="active",
            data_processing_consent=True,
        )
        CustomerTaxProfile.objects.create(
            customer=self.customer, cui="RO14399847", vat_number="RO14399847", is_vat_payer=True, vat_rate=Decimal("21")
        )
        CustomerBillingProfile.objects.create(customer=self.customer, preferred_currency="RON")
        self.plan = ServicePlan.objects.create(
            name="Workflow Hosting", plan_type="shared_hosting", price_monthly=Decimal("100.00"), auto_provision=False
        )
        self.product = Product.objects.create(
            name="Workflow Hosting",
            slug="workflow-hosting",
            requires_domain=False,
            product_type="shared_hosting",
            default_service_plan=self.plan,
        )
        ProductPrice.objects.create(product=self.product, currency=self.currency, monthly_price_cents=10000)
        self.address = {
            "company_name": self.customer.company_name,
            "contact_name": "Test Owner",
            "email": self.customer.primary_email,
            "phone": "+40722123456",
            "address_line1": "Str. Victoriei 10",
            "address_line2": "",
            "city": "București",
            "county": "București",
            "postal_code": "010061",
            "country": "RO",
            "fiscal_code": "RO14399847",
            "registration_number": "J40/1234/2020",
            "vat_number": "RO14399847",
        }

    def create_order(self, *, items=None, submit=True):
        with self.captureOnCommitCallbacks(execute=True):
            result = OrderService.create_order(
                OrderCreateData(
                    customer=self.customer,
                    billing_address=self.address,
                    items=items
                    or [
                        {
                            "product_id": self.product.pk,
                            "quantity": 1,
                            "unit_price_cents": 10000,
                            "setup_cents": 2500,
                            "billing_period": "monthly",
                            "description": self.product.name,
                        }
                    ],
                ),
                created_by=self.admin,
            )
            self.assertTrue(result.is_ok(), str(result))
            order = result.unwrap()
            if submit:
                submitted = OrderService.update_order_status(
                    order, StatusChangeData(new_status="awaiting_payment", changed_by=self.admin)
                )
                self.assertTrue(submitted.is_ok(), str(submitted))
        order.refresh_from_db()
        return order

    def pay(self, order):
        with self.captureOnCommitCallbacks(execute=True):
            result = ProformaPaymentService.record_payment_and_convert(
                str(order.proforma_id), order.total_cents, "bank_transfer", "E2E-BANK-REFERENCE", self.admin
            )
            self.assertTrue(result.is_ok(), str(result))
        order.refresh_from_db()
        invoice = result.unwrap()
        invoice.refresh_from_db()
        return invoice
