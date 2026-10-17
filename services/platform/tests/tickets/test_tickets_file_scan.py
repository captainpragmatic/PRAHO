"""
Tests for ticket file security scanner integration (T1 TODO fix).

Verifies TicketAttachmentSecurityScanner is wired before attachment save.
"""

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from apps.customers.models import Customer
from apps.tickets.models import Ticket, TicketAttachment
from apps.tickets.security import TicketAttachmentSecurityScanner
from apps.users.models import CustomerMembership, User


class TicketAttachmentSecurityScannerTests(TestCase):
    """T1: TicketAttachmentSecurityScanner wired at attachment save point"""

    def test_scanner_class_importable(self):
        """TicketAttachmentSecurityScanner is importable from tickets.security"""
        scanner = TicketAttachmentSecurityScanner()
        self.assertTrue(hasattr(scanner, "scan_uploaded_file"))

    def test_safe_text_file_passes(self):
        """Normal text file passes security scan"""
        scanner = TicketAttachmentSecurityScanner()
        uploaded = SimpleUploadedFile("notes.txt", b"Hello world", content_type="text/plain")
        is_safe, _msg = scanner.scan_uploaded_file(uploaded)
        self.assertTrue(is_safe)

    def test_path_traversal_filename_rejected(self):
        """A traversal in the original filename is refused for being a traversal, as the API passes it"""
        scanner = TicketAttachmentSecurityScanner()
        uploaded = SimpleUploadedFile("passwd.txt", b"root:x:0:0", content_type="text/plain")
        is_safe, msg = scanner.scan_uploaded_file(uploaded, original_filename="../../../etc/passwd.txt")
        self.assertFalse(is_safe)
        self.assertEqual(msg, "Invalid filename")

    def test_the_staff_reply_runs_the_scanner(self):
        """A staff reply with a disguised file stores no attachment"""
        customer = Customer.objects.create(
            name="Scan Customer", customer_type="business", status="active", primary_email="scan@example.test"
        )
        user = User.objects.create_user(email="scan@example.test", password="testpass123")
        CustomerMembership.objects.create(user=user, customer=customer, role="admin")
        ticket = Ticket.objects.create(customer=customer, title="Scan", description="Scan", created_by=user)
        self.client.login(email="scan@example.test", password="testpass123")
        disguised = SimpleUploadedFile("report.pdf", b"\x89PNG\r\n\x1a\n" + bytes(64), content_type="application/pdf")

        self.client.post(reverse("tickets:reply", args=[ticket.pk]), {"reply": "See file", "attachments": disguised})

        self.assertFalse(TicketAttachment.objects.filter(ticket=ticket).exists())
