# =====================================
# 🧪 IDEMPOTENCY AND ROLLBACK TESTS
# ===============================================================================
"""
Comprehensive tests for Virtualmin provisioning idempotency and rollback mechanisms.

🚨 Coverage Target: ≥90% for idempotency and rollback logic
📊 These tests verify:
   - Idempotency: Operations can be safely retried
   - Rollback: Failed provisioning attempts are cleaned up
"""

from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.types import Err, Ok
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.security_utils import IdempotencyManager
from apps.provisioning.virtualmin_models import (
    VirtualminAccount,
    VirtualminProvisioningJob,
    VirtualminServer,
)
from apps.provisioning.virtualmin_service import (
    VirtualminProvisioningService,
)
from tests.mocks.virtualmin_mock import MockVirtualminGateway


class IdempotencyManagerTest(TestCase):
    """Test IdempotencyManager functionality"""

    def test_generate_key_consistent(self):
        """Test that generate_key produces consistent keys"""
        key1 = IdempotencyManager.generate_key(
            "service-123", "suspend_account", {"domain": "test.com"}
        )
        key2 = IdempotencyManager.generate_key(
            "service-123", "suspend_account", {"domain": "test.com"}
        )
        self.assertEqual(key1, key2)

    def test_generate_key_different_params(self):
        """Test that different params produce different keys"""
        key1 = IdempotencyManager.generate_key(
            "service-123", "suspend_account", {"domain": "test1.com"}
        )
        key2 = IdempotencyManager.generate_key(
            "service-123", "suspend_account", {"domain": "test2.com"}
        )
        self.assertNotEqual(key1, key2)

    @patch('apps.provisioning.security_utils.cache')
    def test_check_and_set_new_operation(self, mock_cache):
        """Test check_and_set for new operation"""
        mock_cache.get.return_value = None
        mock_cache.add.return_value = True

        is_new, existing = IdempotencyManager.check_and_set("test-key", {"status": "pending"})

        self.assertTrue(is_new)
        self.assertIsNone(existing)
        mock_cache.add.assert_called_once()

    @patch('apps.provisioning.security_utils.cache')
    def test_check_and_set_existing_operation(self, mock_cache):
        """Test check_and_set for existing operation"""
        mock_cache.get.return_value = {"success": True}

        is_new, existing = IdempotencyManager.check_and_set("test-key")

        self.assertFalse(is_new)
        self.assertEqual(existing, {"success": True})

    @patch('apps.provisioning.security_utils.cache')
    def test_complete_operation(self, mock_cache):
        """Test marking operation as complete"""
        IdempotencyManager.complete("test-key", {"success": True})
        mock_cache.set.assert_called_once()

    @patch('apps.provisioning.security_utils.cache')
    def test_clear_operation(self, mock_cache):
        """Test clearing idempotency key"""
        IdempotencyManager.clear("test-key")
        mock_cache.delete.assert_called_once_with("test-key")


class VirtualminProvisioningJobRollbackTest(TestCase):
    """Test VirtualminProvisioningJob rollback tracking"""

    def setUp(self):
        """Set up test data"""
        self.server = VirtualminServer.objects.create(
            name="test-server",
            hostname="test.example.com",
            api_username="test_api_user",
            max_domains=1000,
            current_domains=100
        )
        self.server.set_api_password("test_password")
        self.server.save()

    def test_mark_failed_without_rollback(self):
        """Test mark_failed without rollback tracking"""
        job = VirtualminProvisioningJob.objects.create(
            operation="suspend_domain",
            server=self.server,
            correlation_id="test-123",
        )
        job.mark_started()
        job.mark_failed("Test error")

        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        self.assertEqual(job.status_message, "Test error")
        self.assertFalse(job.rollback_executed)
        self.assertEqual(job.rollback_status, "")
        self.assertEqual(job.rollback_details, {})

    def test_mark_failed_with_successful_rollback(self):
        """Test mark_failed with successful rollback"""
        job = VirtualminProvisioningJob.objects.create(
            operation="suspend_domain",
            server=self.server,
            correlation_id="test-124",
        )
        job.mark_started()

        rollback_details = {
            "operations": [
                {"operation": "enable-domain", "status": "success"}
            ],
            "total_operations": 1,
            "successful_operations": 1,
            "failed_operations": 0,
        }

        job.mark_failed(
            "DB update failed",
            rollback_executed=True,
            rollback_status="success",
            rollback_details=rollback_details,
        )

        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        self.assertTrue(job.rollback_executed)
        self.assertEqual(job.rollback_status, "success")
        self.assertEqual(job.rollback_details["successful_operations"], 1)

    def test_mark_failed_with_partial_rollback(self):
        """Test mark_failed with partial rollback"""
        job = VirtualminProvisioningJob.objects.create(
            operation="create_domain",
            server=self.server,
            correlation_id="test-125",
        )
        job.mark_started()

        rollback_details = {
            "operations": [
                {"operation": "delete-domain", "status": "success"},
                {"operation": "revert_server_stats", "status": "failed"},
            ],
            "total_operations": 2,
            "successful_operations": 1,
            "failed_operations": 1,
        }

        job.mark_failed(
            "Provisioning failed",
            rollback_executed=True,
            rollback_status="partial",
            rollback_details=rollback_details,
        )

        job.refresh_from_db()
        self.assertEqual(job.rollback_status, "partial")
        self.assertEqual(job.rollback_details["failed_operations"], 1)

    def test_schedule_retry_clears_rollback(self):
        """Test that schedule_retry clears rollback status"""
        job = VirtualminProvisioningJob.objects.create(
            operation="suspend_domain",
            server=self.server,
            correlation_id="test-126",
            max_retries=3,
        )
        job.mark_started()
        job.mark_failed(
            "Error",
            rollback_executed=True,
            rollback_status="success",
            rollback_details={"test": "data"},
        )

        job.schedule_retry()

        job.refresh_from_db()
        self.assertEqual(job.status, "pending")
        self.assertFalse(job.rollback_executed)
        self.assertEqual(job.rollback_status, "")
        self.assertEqual(job.rollback_details, {})


class SuspendAccountIdempotencyTest(TestCase):
    """Test suspend_account idempotency"""

    def setUp(self):
        """Set up test data"""
        self.customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            customer_type="individual"
        )

        self.service_plan = ServicePlan.objects.create(
            name="Test Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("10.00"),
            setup_fee=Decimal("0.00")
        )

        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name="Test Service",
            username="test_user",
            price=Decimal("10.00"),
            status="active"
        )

        self.server = VirtualminServer.objects.create(
            name="test-server",
            hostname="test.example.com",
            api_username="test_api_user",
            max_domains=1000,
            current_domains=100
        )
        self.server.set_api_password("test_password")
        self.server.save()

        self.account = VirtualminAccount.objects.create(
            domain="test.example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="active",
        )
        self.account.set_password("test_password")
        self.account.save()

    def test_suspend_already_suspended_idempotent(self):
        """Test that suspending already suspended account is idempotent"""
        self.account.status = "suspended"
        self.account.save()

        service = VirtualminProvisioningService(self.server)
        result = service.suspend_account(self.account, "Test reason")

        self.assertTrue(result.is_ok())
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")

    @patch('apps.provisioning.virtualmin_service.VirtualminGateway')
    @patch('apps.provisioning.security_utils.cache')
    def test_suspend_in_progress_blocked(self, mock_cache, mock_gateway_class):
        """Test that concurrent suspend is blocked"""
        # Simulate operation already in progress
        mock_cache.get.return_value = "in_progress"

        service = VirtualminProvisioningService(self.server)
        result = service.suspend_account(self.account, "Test reason")

        self.assertTrue(result.is_err())
        self.assertIn("already in progress", result.unwrap_err())


class UnsuspendAccountIdempotencyTest(TestCase):
    """Test unsuspend_account idempotency"""

    def setUp(self):
        """Set up test data"""
        self.customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            customer_type="individual"
        )

        self.service_plan = ServicePlan.objects.create(
            name="Test Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("10.00"),
            setup_fee=Decimal("0.00")
        )

        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name="Test Service",
            username="test_user",
            price=Decimal("10.00"),
            status="active"
        )

        self.server = VirtualminServer.objects.create(
            name="test-server",
            hostname="test.example.com",
            api_username="test_api_user",
            max_domains=1000,
            current_domains=100
        )
        self.server.set_api_password("test_password")
        self.server.save()

        self.account = VirtualminAccount.objects.create(
            domain="test.example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="suspended",
        )
        self.account.set_password("test_password")
        self.account.save()

    def test_unsuspend_already_active_idempotent(self):
        """Test that unsuspending already active account is idempotent"""
        self.account.status = "active"
        self.account.save()

        service = VirtualminProvisioningService(self.server)
        result = service.unsuspend_account(self.account)

        self.assertTrue(result.is_ok())
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "active")


class DeleteAccountIdempotencyTest(TestCase):
    """Test delete_account idempotency"""

    def setUp(self):
        """Set up test data"""
        self.customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            customer_type="individual"
        )

        self.service_plan = ServicePlan.objects.create(
            name="Test Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("10.00"),
            setup_fee=Decimal("0.00")
        )

        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name="Test Service",
            username="test_user",
            price=Decimal("10.00"),
            status="active"
        )

        self.server = VirtualminServer.objects.create(
            name="test-server",
            hostname="test.example.com",
            api_username="test_api_user",
            max_domains=1000,
            current_domains=100
        )
        self.server.set_api_password("test_password")
        self.server.save()

        self.account = VirtualminAccount.objects.create(
            domain="test.example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="error",
            protected_from_deletion=False,
        )
        self.account.set_password("test_password")
        self.account.save()

    def test_delete_already_terminated_idempotent(self):
        """Test that deleting already terminated account is idempotent"""
        self.account.status = "terminated"
        self.account.save()

        service = VirtualminProvisioningService(self.server)
        result = service.delete_account(self.account)

        self.assertTrue(result.is_ok())
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "terminated")

    def test_delete_protected_account_blocked(self):
        """Test that deleting protected account is blocked"""
        self.account.protected_from_deletion = True
        self.account.save()

        service = VirtualminProvisioningService(self.server)
        result = service.delete_account(self.account)

        self.assertTrue(result.is_err())
        self.assertIn("protected from deletion", result.unwrap_err())

    def test_delete_active_account_blocked(self):
        """Test that deleting active account is blocked"""
        self.account.status = "active"
        self.account.protected_from_deletion = False
        self.account.save()

        service = VirtualminProvisioningService(self.server)
        result = service.delete_account(self.account)

        self.assertTrue(result.is_err())
        self.assertIn("must be terminated or in error state", result.unwrap_err())


class RollbackMechanismTest(TestCase):
    """Test rollback mechanisms using MockVirtualminGateway for realistic API simulation."""

    def setUp(self):
        """Set up test data"""
        self.customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            customer_type="individual"
        )

        self.service_plan = ServicePlan.objects.create(
            name="Test Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("10.00"),
            setup_fee=Decimal("0.00")
        )

        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name="Test Service",
            username="test_user",
            price=Decimal("10.00"),
            status="active"
        )

        self.server = VirtualminServer.objects.create(
            name="test-server",
            hostname="test.example.com",
            api_username="test_api_user",
            max_domains=1000,
            current_domains=100
        )
        self.server.set_api_password("test_password")
        self.server.save()

        self.account = VirtualminAccount.objects.create(
            domain="test.example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testuser",
            status="active",
        )
        self.account.set_password("test_password")
        self.account.save()

    @patch('apps.provisioning.virtualmin_service.VirtualminGateway')
    def test_execute_rollback_success(self, mock_gateway_class):
        """Test successful rollback execution using MockVirtualminGateway"""
        mock_gw = MockVirtualminGateway()
        # Seed the domain so delete-domain succeeds
        mock_gw.seed_domain("test.example.com")
        mock_gateway_class.return_value = mock_gw

        service = VirtualminProvisioningService(self.server)
        gateway = service._get_gateway()

        rollback_operations = [
            {
                "operation": "delete-domain",
                "params": {"domain": "test.example.com"},
                "description": "Delete test domain",
            }
        ]

        rollback_status, rollback_details = service._execute_rollback(
            rollback_operations, gateway, self.account
        )

        self.assertEqual(rollback_status, "success")
        self.assertEqual(rollback_details["successful_operations"], 1)
        self.assertEqual(rollback_details["failed_operations"], 0)

        # Verify domain was actually removed from mock state
        self.assertIsNone(mock_gw.get_domain_state("test.example.com"))
        # Verify call was logged
        self.assertEqual(len(mock_gw.get_calls("delete-domain")), 1)

    @patch('apps.provisioning.virtualmin_service.VirtualminGateway')
    def test_execute_rollback_partial(self, mock_gateway_class):
        """Test partial rollback: first op succeeds (domain exists), second fails (domain missing)"""
        mock_gw = MockVirtualminGateway()
        # Seed only the first domain
        mock_gw.seed_domain("test.example.com")
        # Do NOT seed test2.example.com so enable-domain returns not-found error
        mock_gateway_class.return_value = mock_gw

        service = VirtualminProvisioningService(self.server)
        gateway = service._get_gateway()

        rollback_operations = [
            {
                "operation": "delete-domain",
                "params": {"domain": "test.example.com"},
                "description": "Delete test domain",
            },
            {
                "operation": "enable-domain",
                "params": {"domain": "test2.example.com"},
                "description": "Re-enable test domain 2",
            },
        ]

        rollback_status, rollback_details = service._execute_rollback(
            rollback_operations, gateway, self.account
        )

        self.assertEqual(rollback_status, "partial")
        self.assertEqual(rollback_details["successful_operations"], 1)
        self.assertEqual(rollback_details["failed_operations"], 1)

    @patch('apps.provisioning.virtualmin_service.VirtualminGateway')
    def test_execute_rollback_handles_exceptions(self, mock_gateway_class):
        """Test rollback continues after operation exceptions using fail_operations"""
        mock_gw = MockVirtualminGateway(
            fail_operations={"delete-domain": "Connection error"}
        )
        mock_gateway_class.return_value = mock_gw

        service = VirtualminProvisioningService(self.server)
        gateway = service._get_gateway()

        rollback_operations = [
            {
                "operation": "delete-domain",
                "params": {"domain": "test.example.com"},
                "description": "Delete test domain",
            }
        ]

        rollback_status, rollback_details = service._execute_rollback(
            rollback_operations, gateway, self.account
        )

        # Should still complete (failed), not raise exception
        self.assertEqual(rollback_status, "failed")
        self.assertEqual(rollback_details["failed_operations"], 1)
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "error")
