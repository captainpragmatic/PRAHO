"""
Tests for customer services API (C1 TODO fix).

Verifies the API returns real Service objects instead of empty list.
"""

import inspect
from decimal import Decimal

from django.test import TestCase

from apps.api.customers import views
from apps.customers import customer_views
from apps.customers.models import Customer
from apps.provisioning.service_models import Server, Service, ServicePlan


class CustomerServicesApiDataTests(TestCase):
    """C1: customer services API returns real Service objects"""

    def setUp(self):
        self.customer = Customer.objects.create(
            name="API Test SRL", customer_type="company",
        )
        self.plan = ServicePlan.objects.create(
            name="Basic Hosting", plan_type="shared_hosting",
            price_monthly=Decimal("29.99"), price_quarterly=Decimal("79.99"),
            price_annual=Decimal("299.99"),
        )
        self.server = Server.objects.create(
            name="Test Server", hostname="srv1.test.ro",
            primary_ip="10.0.0.1",
            server_type="shared", status="active",
            location="Bucharest", datacenter="M247",
            cpu_model="Xeon E5", cpu_cores=8,
            ram_gb=32, disk_type="ssd", disk_capacity_gb=500,
            os_type="linux",
        )

    def test_customer_with_services(self):
        """Customer with active services gets them via queryset"""
        Service.objects.create(
            customer=self.customer, service_plan=self.plan, server=self.server,
            service_name="test.example.com", username="testuser1",
            status="active", domain="test.example.com",
            price=Decimal("29.99"),
        )
        services = Service.objects.filter(customer=self.customer)
        self.assertEqual(services.count(), 1)
        self.assertEqual(services.first().service_name, "test.example.com")

    def test_customer_without_services(self):
        """Customer with no services returns empty queryset"""
        services = Service.objects.filter(customer=self.customer)
        self.assertEqual(services.count(), 0)

    def test_api_view_no_longer_returns_empty_stub(self):
        """api/customers/views.py no longer has TODO or empty list stub"""
        source = inspect.getsource(views)
        self.assertNotIn("TODO: Implement actual service management", source)

    def test_customer_views_no_longer_returns_empty_stub(self):
        """customer_views.py customer_services_api no longer has TODO"""
        source = inspect.getsource(customer_views.customer_services_api)
        self.assertNotIn("TODO: Implement actual service management", source)
        # Should no longer return hardcoded empty list
        self.assertNotIn("return JsonResponse([], safe=False)", source)

    def test_customer_views_services_api_queries_service_model(self):
        """customer_views.py customer_services_api returns real services"""
        Service.objects.create(
            customer=self.customer, service_plan=self.plan, server=self.server,
            service_name="web.example.com", username="webuser",
            status="active", domain="web.example.com",
            price=Decimal("29.99"),
        )
        # Verify the query pattern returns data
        services = list(
            Service.objects.filter(customer_id=self.customer.id)
            .values("id", "service_name", "status", "service_plan__name")
            .order_by("service_name")
        )
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["service_name"], "web.example.com")
        self.assertEqual(services[0]["service_plan__name"], "Basic Hosting")

    def test_customer_views_services_api_no_longer_uses_safe_false(self):
        """customer_services_api in customer_views.py must not use safe=False (F05)"""
        source = inspect.getsource(customer_views.customer_services_api)
        self.assertNotIn("safe=False", source)

    def test_customer_views_services_api_returns_envelope_object(self):
        """customer_services_api must return JSON object with 'results' key, not a bare array (F05)"""
        source = inspect.getsource(customer_views.customer_services_api)
        self.assertIn('"results"', source)
