"""PostgreSQL statement failures must not abort membership creation."""

from unittest.mock import patch

from django.db import connection, transaction
from django.test import TransactionTestCase, override_settings

from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User
from tests.helpers.task_queue import quiet_task_queue


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class MembershipSignalPostgresIsolationTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("statement-aborts-transaction behavior requires PostgreSQL")
        quiet_task_queue(self)
        self.user = User.objects.create_user(email="postgres-isolation@example.com", password="test")
        self.customer = Customer.objects.create(name="Isolation", primary_email="postgres-customer@example.com")
        self.failed_sql = False

    def fail_sql(self, *args: object, **kwargs: object) -> None:
        self.failed_sql = True
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 / 0")

    def test_membership_commits_after_audit_statement_error(self) -> None:
        with patch("apps.audit.signals.AuditService.log_event", side_effect=self.fail_sql), transaction.atomic():
            membership = CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner")
        self.assertTrue(self.failed_sql)
        self.assertTrue(CustomerMembership.objects.filter(pk=membership.pk).exists())
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            self.assertEqual(cursor.fetchone(), (1,))
