"""
Tests for Virtualmin integration models.
"""

from decimal import Decimal
from django.test import TestCase

from apps.customers.models import Customer
from apps.provisioning.models import (
    Service,
    ServicePlan,
    VirtualminServer,
)


class VirtualminServerModelTest(TestCase):
    """Test VirtualminServer model functionality"""

    def test_server_creation(self):
        """Test basic VirtualminServer creation"""
        server = VirtualminServer.objects.create(
            name="test-server",
            hostname="test.example.com",
            api_username="test_api_user"
        )
        
        self.assertEqual(server.name, "test-server")
        self.assertEqual(server.hostname, "test.example.com")
        self.assertEqual(server.api_username, "test_api_user")

    def test_server_string_representation(self):
        """Test server string representation"""
        server = VirtualminServer(
            name="test-server",
            hostname="test.example.com",
            api_username="test_api_user"
        )
        expected = "test-server (test.example.com)"
        self.assertEqual(str(server), expected)