"""
Tests for ticket file security scanner integration (T1 TODO fix).

Verifies TicketAttachmentSecurityScanner is wired before attachment save.
"""

import inspect

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from apps.tickets import views
from apps.tickets.security import TicketAttachmentSecurityScanner


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
        """File with path traversal in name is rejected"""
        scanner = TicketAttachmentSecurityScanner()
        uploaded = SimpleUploadedFile("../../../etc/passwd", b"root:x:0:0", content_type="text/plain")
        is_safe, _msg = scanner.scan_uploaded_file(uploaded)
        self.assertFalse(is_safe)

    def test_scanner_referenced_in_views(self):
        """tickets/views.py imports and uses the scanner"""
        source = inspect.getsource(views)
        self.assertIn("TicketAttachmentSecurityScanner", source)
        self.assertIn("scan_uploaded_file", source)
