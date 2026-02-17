# =====================================
# 🧪 CROSS-APP INTEGRATION TESTS
# ===============================================================================
"""
Comprehensive tests for Cross-App Integration Points.

Tests the integration between:
- Billing → Provisioning (payment triggers)
- Domains → Provisioning (domain sync)
- Provisioning → Audit (compliance logging)
- Customers → Provisioning (membership linking)

🚨 Coverage Target: ≥90% for cross-app integration logic
📊 Query Budget: Tests include performance and database interaction validation
🔒 Security: Tests audit logging and GDPR compliance
"""

import unittest
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.customers.models import Customer
from apps.billing.models import Invoice, Payment, Currency
from apps.billing.signals import _trigger_virtualmin_provisioning_on_payment
from apps.common.types import Ok
from apps.domains.models import Domain, TLD, Registrar
from apps.domains.signals import sync_domain_to_virtualmin
from apps.orders.models import Order, OrderItem
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_signals import (
    audit_virtualmin_account_changes,
    audit_virtualmin_account_deletion,
    audit_virtualmin_provisioning_jobs,
    log_virtualmin_security_event,
    notify_provisioning_completion,
)
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer, VirtualminProvisioningJob
from apps.users.models import User, CustomerMembership


class BillingProvisioningIntegrationTest(TestCase):
    """Test billing → provisioning integration (payment triggers)"""

    def setUp(self):
        """Set up test data"""
        # Create customer
        self.customer = Customer.objects.create(
            company_name="Test Customer Ltd",
            fiscal_code="RO12345678",
            customer_type="company"
        )

        # Create user and membership
        self.user = User.objects.create_user(
            email="test@example.com",
            password="testpass123"
        )

        self.membership = CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role="owner",
            is_primary=True
        )

        # Create currency
        self.currency = Currency.objects.create(
            code="RON",
            name="Romanian Leu",
            symbol="RON"
        )

        # Create product
        from apps.products.models import Product
        self.product = Product.objects.create(
            slug="shared-hosting",
            name="Shared Hosting",
            product_type="shared_hosting"
        )

        # Create service plan
        self.service_plan = ServicePlan.objects.create(
            name="Shared Hosting Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99"),
            setup_fee=Decimal("0.00")
        )

        # Create service
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name="Test Hosting",
            domain="example.com",
            username="testuser",
            price=Decimal("29.99"),
            status="active"
        )

        # Create order
        self.order = Order.objects.create(
            customer=self.customer,
            total_cents=2999,  # €29.99 in cents
            currency=self.currency,
            status="completed"
        )

        # Create order item
        self.order_item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            service=self.service,
            quantity=1,
            unit_price_cents=2999,  # €29.99 in cents
        )

        # Create invoice
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            number="INV-001",
            total_cents=2999,  # 29.99 RON in cents
            currency=self.currency,
            status="issued"
        )

        # Link order to invoice
        self.order.invoice = self.invoice
        self.order.save()

    # TODO: Consider adding integration tests for Django-Q2 task processing

    def test_service_requires_hosting_account_detection(self):
        """Test Service.requires_hosting_account() method"""
        # Test hosting service
        self.assertTrue(self.service.requires_hosting_account())

        # Test non-hosting service
        self.service_plan.plan_type = "domain_registration"
        self.service_plan.save()
        self.assertFalse(self.service.requires_hosting_account())

        # Test service without domain
        self.service_plan.plan_type = "shared_hosting"
        self.service_plan.save()
        self.service.domain = ""
        self.service.save()
        self.assertFalse(self.service.requires_hosting_account())

        # Test inactive service
        self.service.domain = "example.com"
        self.service.status = "terminated"
        self.service.save()
        self.assertFalse(self.service.requires_hosting_account())

    def test_service_get_primary_domain(self):
        """Test Service.get_primary_domain() method"""
        # Test service with domain
        self.assertEqual(self.service.get_primary_domain(), "example.com")

        # Test service without domain
        self.service.domain = ""
        self.service.save()
        self.assertIsNone(self.service.get_primary_domain())

    def test_service_get_customer_membership(self):
        """Test Service.get_customer_membership() method"""
        # Test getting primary membership
        membership = self.service.get_customer_membership()
        self.assertEqual(membership, self.membership)
        self.assertTrue(membership.is_primary)


class DomainsProvisioningIntegrationTest(TestCase):
    """Test domains → provisioning integration (domain sync)"""

    def setUp(self):
        """Set up test data"""
        # Create customer
        self.customer = Customer.objects.create(
            company_name="Test Customer Ltd",
            fiscal_code="RO12345678",
            customer_type="company"
        )

        # Create TLD and registrar
        self.tld = TLD.objects.create(
            extension="com",
            description="Commercial domains",
            registration_price_cents=1500,  # 15.00 RON in cents
            renewal_price_cents=1500,       # 15.00 RON in cents
            transfer_price_cents=1500,      # 15.00 RON in cents
            is_active=True
        )

        self.registrar = Registrar.objects.create(
            name="Test Registrar",
            display_name="Test Registrar",
            website_url="https://registrar.com",
            api_endpoint="https://api.registrar.com",
            status="active"
        )

        # Create domain
        self.domain = Domain.objects.create(
            name="example.com",
            customer=self.customer,
            tld=self.tld,
            registrar=self.registrar,
            status="active",
            expires_at=timezone.now() + timezone.timedelta(days=365)
        )

        # Create service plan and service
        self.service_plan = ServicePlan.objects.create(
            name="Shared Hosting Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99")
        )

        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name="Test Hosting",
            domain="example.com",
            username="testuser",
            price=Decimal("29.99"),
            status="active"
        )

        # Create Virtualmin server and account
        self.server = VirtualminServer.objects.create(
            hostname="vm1.example.com",
            capacity=1000,
            status="healthy"
        )

        self.virtualmin_account = VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="active"
        )

        # Create ServiceDomain relationship so domain sync can find the service
        from apps.provisioning.relationship_models import ServiceDomain
        ServiceDomain.objects.create(
            service=self.service,
            domain=self.domain,
            domain_type="primary"
        )

    @patch('apps.provisioning.virtualmin_service.VirtualminProvisioningService.suspend_account')
    def test_domain_status_change_suspends_virtualmin_account(self, mock_suspend):
        """Test that domain status change suspends Virtualmin account"""
        mock_suspend.return_value = Ok(True)

        # Change domain status to inactive
        self.domain.status = "suspended"
        self.domain.save()

        # Trigger domain sync
        sync_domain_to_virtualmin(self.domain)

        # Verify suspension was called
        mock_suspend.assert_called_once_with(
            self.virtualmin_account,
            reason="Domain status changed to suspended"
        )

    @patch('apps.provisioning.virtualmin_service.VirtualminProvisioningService.unsuspend_account')
    def test_domain_reactivation_unsuspends_virtualmin_account(self, mock_unsuspend):
        """Test that domain reactivation unsuspends Virtualmin account"""
        mock_unsuspend.return_value = Ok(True)

        # Set account as suspended
        self.virtualmin_account.status = "suspended"
        self.virtualmin_account.save()

        # Change domain status to active
        self.domain.status = "active"
        self.domain.save()

        # Trigger domain sync
        sync_domain_to_virtualmin(self.domain)

        # Verify unsuspension was called
        mock_unsuspend.assert_called_once_with(self.virtualmin_account)

    def test_domain_sync_handles_missing_virtualmin_account(self):
        """Test that domain sync handles missing Virtualmin account gracefully"""
        # Delete the Virtualmin account
        self.virtualmin_account.delete()

        # Should not raise exception
        sync_domain_to_virtualmin(self.domain)

    def test_domain_sync_skips_non_hosting_domains(self):
        """Test that domain sync skips domains without hosting services"""
        # Delete the hosting service
        self.service.delete()

        # Should handle gracefully (no hosting services found)
        sync_domain_to_virtualmin(self.domain)


class ProvisioningAuditIntegrationTest(TestCase):
    """Test provisioning → audit integration (compliance logging)"""

    def setUp(self):
        """Set up test data"""
        # Create customer
        self.customer = Customer.objects.create(
            company_name="Test Customer Ltd",
            fiscal_code="RO12345678",
            customer_type="company"
        )

        # Create service
        self.service_plan = ServicePlan.objects.create(
            name="Test Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99")
        )

        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name="Test Hosting",
            domain="example.com",
            username="testuser",
            price=Decimal("29.99")
        )

        # Create Virtualmin server
        self.server = VirtualminServer.objects.create(
            hostname="vm1.example.com",
            capacity=1000,
            status="healthy"
        )

    @override_settings(DISABLE_AUDIT_SIGNALS=False)
    @patch('apps.audit.services.AuditService.log_event')
    def test_virtualmin_account_creation_audit(self, mock_audit):
        """Test that Virtualmin account creation is audited"""
        # Create Virtualmin account
        account = VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="provisioning"
        )

        # Verify audit logging was called
        mock_audit.assert_called_once()
        call_args = mock_audit.call_args[0][0]  # Get AuditEventData
        context_args = mock_audit.call_args[1]['context']  # Get AuditContext
        self.assertEqual(call_args.event_type, "virtualmin_account_created")
        self.assertEqual(call_args.new_values["domain"], "example.com")
        self.assertTrue(context_args.metadata["compliance_event"])
        self.assertTrue(context_args.metadata["provisioning_action"])

    @override_settings(DISABLE_AUDIT_SIGNALS=False)
    @patch('apps.audit.services.AuditService.log_event')
    def test_virtualmin_account_status_change_audit(self, mock_audit):
        """Test that Virtualmin account status changes are audited"""
        # Create account
        account = VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="provisioning"
        )

        # Clear mock calls from creation
        mock_audit.reset_mock()

        # Change status
        account.status = "active"
        account.save(update_fields=["status"])

        # Verify audit logging was called for status change
        mock_audit.assert_called_once()
        call_args = mock_audit.call_args[0][0]  # Get AuditEventData
        context_args = mock_audit.call_args[1]['context']  # Get AuditContext
        self.assertEqual(call_args.event_type, "virtualmin_account_status_changed")
        self.assertEqual(call_args.new_values["status"], "active")
        self.assertTrue(context_args.metadata["status_change"])

    @override_settings(DISABLE_AUDIT_SIGNALS=False)
    @patch('apps.audit.services.AuditService.log_event')
    def test_virtualmin_account_deletion_audit(self, mock_audit):
        """Test that Virtualmin account deletion is audited"""
        # Create account
        account = VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="active"
        )

        # Clear mock calls from creation
        mock_audit.reset_mock()

        # Delete account
        account.delete()

        # Verify audit logging was called for deletion
        mock_audit.assert_called_once()
        call_args = mock_audit.call_args[0][0]  # Get AuditEventData
        context_args = mock_audit.call_args[1]['context']  # Get AuditContext
        self.assertEqual(call_args.event_type, "virtualmin_account_deleted")
        self.assertEqual(call_args.old_values["domain"], "example.com")
        self.assertTrue(context_args.metadata["account_termination"])
        self.assertTrue(context_args.metadata["requires_gdpr_logging"])

    @override_settings(DISABLE_AUDIT_SIGNALS=True)
    @patch('apps.audit.services.AuditService.log_event')
    def test_audit_signals_can_be_disabled(self, mock_audit):
        """Test that audit signals can be disabled for testing"""
        # Create account with audit signals disabled
        VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="provisioning"
        )

        # Verify no audit logging occurred
        mock_audit.assert_not_called()

    @override_settings(DISABLE_AUDIT_SIGNALS=False)
    @patch('apps.audit.services.AuditService.log_event')
    def test_virtualmin_provisioning_job_audit(self, mock_audit):
        """Test that provisioning job lifecycle is audited"""
        # Create account
        account = VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="provisioning"
        )

        # Clear mock calls from account creation
        mock_audit.reset_mock()

        # Create provisioning job
        job = VirtualminProvisioningJob.objects.create(
            operation="create_domain",
            server=self.server,
            account=account,
            correlation_id="test-123",
            status="pending"
        )

        # Verify audit logging was called for job creation
        mock_audit.assert_called_once()
        call_args = mock_audit.call_args[0][0]  # Get AuditEventData
        context_args = mock_audit.call_args[1]['context']  # Get AuditContext
        self.assertEqual(call_args.event_type, "virtualmin_provisioning_job_created")
        self.assertEqual(call_args.new_values["operation"], "create_domain")
        self.assertTrue(context_args.metadata["provisioning_job"])


    @patch('apps.audit.services.AuditService.log_event')
    def test_provisioning_completion_notification(self, mock_audit):
        """Test provisioning completion notification helper"""
        # Create account
        account = VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="active"
        )

        # Clear mock calls from creation
        mock_audit.reset_mock()

        # Notify completion
        notify_provisioning_completion(
            account,
            success=True,
            details={"server": "vm1.example.com"}
        )

        # Verify audit logging was called
        mock_audit.assert_called_once()
        call_args = mock_audit.call_args[0][0]  # Get AuditEventData
        context_args = mock_audit.call_args[1]['context']  # Get AuditContext
        self.assertEqual(call_args.event_type, "virtualmin_provisioning_completed")
        self.assertTrue(call_args.new_values["success"])
        self.assertTrue(context_args.metadata["provisioning_completion"])


class CustomerProvisioningIntegrationTest(TestCase):
    """Test customers → provisioning integration (membership linking)"""

    def setUp(self):
        """Set up test data"""
        # Create customer
        self.customer = Customer.objects.create(
            company_name="Test Customer Ltd",
            fiscal_code="RO12345678",
            customer_type="company"
        )

        # Create user and membership
        self.user = User.objects.create_user(
            email="test@example.com",
            password="testpass123"
        )

        self.membership = CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role="owner",
            is_primary=True
        )

        # Create service
        self.service_plan = ServicePlan.objects.create(
            name="Test Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99")
        )

        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name="Test Hosting",
            domain="example.com",
            username="testuser",
            price=Decimal("29.99")
        )

        # Create Virtualmin server
        self.server = VirtualminServer.objects.create(
            hostname="vm1.example.com",
            capacity=1000,
            status="healthy"
        )

    def test_virtualmin_account_customer_membership_link(self):
        """Test linking Virtualmin account to customer membership"""
        # Create Virtualmin account with customer membership link
        account = VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            customer_membership=self.membership,
            status="active"
        )

        # Verify the link
        self.assertEqual(account.customer_membership, self.membership)
        self.assertEqual(self.membership.virtualmin_accounts.first(), account)

    def test_virtualmin_account_without_customer_membership(self):
        """Test Virtualmin account creation without customer membership (backwards compatibility)"""
        # Create account without membership link
        account = VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="active"
        )

        # Should work fine (nullable field)
        self.assertIsNone(account.customer_membership)

    def test_customer_membership_can_access_virtualmin_accounts(self):
        """Test that customer membership can access related Virtualmin accounts"""
        # Create Virtualmin account linked to membership
        account = VirtualminAccount.objects.create(
            domain="example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            customer_membership=self.membership,
            status="active"
        )

        # Verify reverse relationship
        accounts = self.membership.virtualmin_accounts.all()
        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts.first(), account)


class CrossAppIntegrationPerformanceTest(TestCase):
    """Test performance aspects of cross-app integration"""

    def setUp(self):
        """Set up test data for performance testing"""
        # Create customer
        self.customer = Customer.objects.create(
            company_name="Test Customer Ltd",
            fiscal_code="RO12345678",
            customer_type="company"
        )

        # Create currency
        self.currency = Currency.objects.create(
            code="RON",
            name="Romanian Leu",
            symbol="RON"
        )

    # TODO: Consider adding query efficiency tests for Django-Q2 task processing
    def _removed_test_payment_provisioning_trigger_query_efficiency(self, mock_provision_task):
        """Test that payment-triggered provisioning is query-efficient"""
        # Create product for order items
        from apps.products.models import Product
        product = Product.objects.create(
            slug="hosting-service",
            name="Hosting Service",
            product_type="shared_hosting"
        )

        # Create multiple services and orders
        services = []
        for i in range(5):
            service_plan = ServicePlan.objects.create(
                name=f"Plan {i}",
                plan_type="shared_hosting",
                price_monthly=Decimal("29.99")
            )

            service = Service.objects.create(
                customer=self.customer,
                service_plan=service_plan,
                service_name=f"Service {i}",
                domain=f"example{i}.com",
                username=f"user{i}",
                price=Decimal("29.99"),
                status="active"
            )
            services.append(service)

        # Create invoice
        invoice = Invoice.objects.create(
            customer=self.customer,
            number="INV-001",
            total_cents=14995,  # 149.95 RON for 5 services
            currency=self.currency,
            status="issued"
        )

        # Create order and items
        order = Order.objects.create(
            customer=self.customer,
            invoice=invoice,
            total_cents=14995,  # €149.95 in cents
            currency=self.currency,
            status="completed"
        )

        for service in services:
            OrderItem.objects.create(
                order=order,
                product=product,
                service=service,
                quantity=1,
                unit_price_cents=2999,  # €29.99 in cents
            )

        # Test query efficiency using assertNumQueries
        with self.assertNumQueries(4):  # Should be efficient regardless of number of services
            _trigger_virtualmin_provisioning_on_payment(invoice)

        # Verify all services were queued for provisioning
        self.assertEqual(mock_provision_task.call_count, 5)

    def test_domain_sync_query_efficiency(self):
        """Test that domain sync is query-efficient"""
        # Create domain and services
        tld = TLD.objects.create(
            extension="com",
            registration_price_cents=1500,  # €15.00 in cents
            renewal_price_cents=1500,  # €15.00 in cents
            transfer_price_cents=1500,  # €15.00 in cents
            is_active=True
        )

        registrar = Registrar.objects.create(
            name="Test Registrar",
            display_name="Test Registrar",
            website_url="https://registrar.com",
            api_endpoint="https://api.registrar.com",
            status="active"
        )

        domain = Domain.objects.create(
            name="example.com",
            customer=self.customer,
            tld=tld,
            registrar=registrar,
            status="active",
            expires_at=timezone.now() + timezone.timedelta(days=365)
        )

        # Create hosting service and service plan for the domain
        from apps.provisioning.models import ServicePlan, Service
        from apps.provisioning.relationship_models import ServiceDomain

        service_plan = ServicePlan.objects.create(
            name="Test Hosting Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99")
        )

        service = Service.objects.create(
            customer=self.customer,
            service_plan=service_plan,
            service_name="Test Service",
            domain="example.com",
            username="testuser",
            price=Decimal("29.99"),
            status="active"
        )

        # Link domain to service
        ServiceDomain.objects.create(
            service=service,
            domain=domain,
            domain_type="primary"
        )

        # Test query efficiency
        with self.assertNumQueries(2):  # Should be efficient
            sync_domain_to_virtualmin(domain)
