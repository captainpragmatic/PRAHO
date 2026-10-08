"""Shared service-domain fixtures for API and cross-service tests."""

from decimal import Decimal
from typing import ClassVar

from django.test import TestCase, override_settings

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, Registrar
from apps.provisioning.relationship_models import ServiceDomain
from apps.provisioning.service_models import Service, ServicePlan
from apps.users.models import CustomerMembership, User

from .hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    PORTAL_HMAC_MODE="legacy",
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    LANGUAGE_CODE="en",
)
class ServiceDomainsFixture(HMACTestMixin, TestCase):
    customer: ClassVar[Customer]
    user: ClassVar[User]
    service: ClassVar[Service]
    other_service: ClassVar[Service]
    primary: ClassVar[ServiceDomain]
    subdomain: ClassVar[ServiceDomain]

    @classmethod
    def setUpTestData(cls) -> None:
        currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2}
        )
        cls.customer = Customer.objects.create(
            name="Domains customer", primary_email="domains@example.com", status="active"
        )
        other = Customer.objects.create(
            name="Other customer", primary_email="other-domains@example.com", status="active"
        )
        cls.user = User.objects.create_user(email="domain-owner@example.com")
        CustomerMembership.objects.create(user=cls.user, customer=cls.customer, role="owner", is_active=True)
        plan = ServicePlan.objects.create(
            name="Domains hosting", plan_type="shared_hosting", price_monthly=Decimal("10.00")
        )
        cls.service = Service.objects.create(
            customer=cls.customer,
            service_plan=plan,
            currency=currency,
            service_name="Own hosting",
            username="domains-own",
            price=Decimal("10.00"),
            status="active",
        )
        cls.other_service = Service.objects.create(
            customer=other,
            service_plan=plan,
            currency=currency,
            service_name="Other hosting",
            username="domains-other",
            price=Decimal("10.00"),
            status="active",
        )
        tld = TLD.objects.create(
            extension="com",
            description="Commercial",
            registration_price_cents=1000,
            renewal_price_cents=1000,
            transfer_price_cents=1000,
        )
        registrar = Registrar.objects.create(
            name="domains-test",
            display_name="Test registrar",
            website_url="https://registrar.example.com",
            api_endpoint="https://registrar.example.com/api/",
        )
        domain = Domain.objects.create(
            name="wp8-example.com", customer=cls.customer, tld=tld, registrar=registrar, status="active"
        )
        cls.primary = ServiceDomain.objects.create(service=cls.service, domain=domain, ssl_enabled=True)
        cls.subdomain = ServiceDomain.objects.create(
            service=cls.service, domain=domain, domain_type="subdomain", subdomain="blog", is_active=False
        )
        foreign_domain = Domain.objects.create(
            name="wp8-private.com", customer=other, tld=tld, registrar=registrar, status="active"
        )
        ServiceDomain.objects.create(service=cls.other_service, domain=foreign_domain)

    def _body(self) -> dict[str, object]:
        return {"customer_id": self.customer.pk, "user_id": self.user.pk}
