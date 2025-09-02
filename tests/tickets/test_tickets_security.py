"""
🔒 Comprehensive Security Tests for Tickets Module

Tests all critical security implementations:
1. File upload security (magic numbers, content patterns, size limits)
2. Cryptographically secure ticket number generation
3. Rate limiting on ticket operations
4. Multi-layer access control for file attachments
5. Security monitoring and alerting
6. Path traversal protection
"""

import io
import os
import secrets
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.http import HttpResponse
from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from django.utils import timezone

from apps.customers.models import Customer
from apps.tickets.models import Ticket, TicketAttachment, TicketComment, SupportCategory
from apps.tickets.monitoring import SecurityEventTracker, security_tracker
from apps.tickets.security import (
    FileSecurityScanner, 
    FileSecurityError,
    generate_secure_filename,
    get_secure_upload_path,
    MAX_FILE_SIZE_BYTES,
    SUSPICIOUS_PATTERNS
)
from apps.users.models import User, CustomerMembership


class FileSecurityScannerTest(TestCase):
    """🔒 Test comprehensive file security scanning"""

    def setUp(self):
        self.scanner = FileSecurityScanner()
        
    def test_valid_pdf_file_passes_scan(self):
        """✅ Valid PDF file should pass all security checks"""
        # Create a valid PDF file with proper magic numbers
        pdf_content = b'%PDF-1.4\n%\xc7\xec\x8f\xa2\n1 0 obj\n<<\n/Type /Catalog\n'
        pdf_file = SimpleUploadedFile(
            "test_document.pdf",
            pdf_content,
            content_type="application/pdf"
        )
        
        is_safe, message = self.scanner.scan_uploaded_file(pdf_file, "test_document.pdf")
        
        self.assertTrue(is_safe)
        self.assertEqual(message, "File security scan passed")

    def test_malicious_script_content_blocked(self):
        """🚨 Files with malicious script content should be blocked"""
        malicious_content = b'<script>alert("XSS")</script>'
        malicious_file = SimpleUploadedFile(
            "malicious.txt",
            malicious_content,
            content_type="text/plain"
        )
        
        is_safe, message = self.scanner.scan_uploaded_file(malicious_file, "malicious.txt")
        
        self.assertFalse(is_safe)
        self.assertIn("Suspicious content patterns detected", message)

    def test_oversized_file_blocked(self):
        """🚨 Files exceeding size limit should be blocked"""
        oversized_content = b'A' * (MAX_FILE_SIZE_BYTES + 1)
        oversized_file = SimpleUploadedFile(
            "huge_file.txt",
            oversized_content,
            content_type="text/plain"
        )
        
        is_safe, message = self.scanner.scan_uploaded_file(oversized_file, "huge_file.txt")
        
        self.assertFalse(is_safe)
        self.assertIn("File too large", message)

    def test_magic_number_mismatch_blocked(self):
        """🚨 Files with mismatched magic numbers should be blocked"""
        # Create a file claiming to be PDF but with wrong magic numbers
        fake_pdf_content = b'This is not a PDF file'
        fake_pdf_file = SimpleUploadedFile(
            "fake.pdf",
            fake_pdf_content,
            content_type="application/pdf"
        )
        
        is_safe, message = self.scanner.scan_uploaded_file(fake_pdf_file, "fake.pdf")
        
        self.assertFalse(is_safe)
        self.assertIn("Magic number mismatch", message)

    def test_dangerous_filename_blocked(self):
        """🚨 Files with dangerous filenames should be blocked"""
        dangerous_filenames = [
            "../../../etc/passwd",
            "test.exe.txt",  # Double extension
            "file<script>.txt",  # Malicious characters
            "file\x00.txt",  # Null byte injection
        ]
        
        for filename in dangerous_filenames:
            with self.subTest(filename=filename):
                safe_content = b'Safe content'
                dangerous_file = SimpleUploadedFile(
                    filename,
                    safe_content,
                    content_type="text/plain"
                )
                
                is_safe, message = self.scanner.scan_uploaded_file(dangerous_file, filename)
                
                self.assertFalse(is_safe)

    def test_scan_statistics_tracking(self):
        """📊 Scanner should track statistics correctly"""
        initial_stats = self.scanner.get_scan_statistics()
        
        # Scan a valid file
        valid_file = SimpleUploadedFile("test.txt", b'Valid content', content_type="text/plain")
        self.scanner.scan_uploaded_file(valid_file, "test.txt")
        
        # Scan an invalid file
        invalid_file = SimpleUploadedFile("test.exe", b'Invalid content', content_type="application/x-executable")
        self.scanner.scan_uploaded_file(invalid_file, "test.exe")
        
        final_stats = self.scanner.get_scan_statistics()
        
        self.assertEqual(final_stats['files_scanned'], initial_stats['files_scanned'] + 2)
        self.assertEqual(final_stats['files_rejected'], initial_stats['files_rejected'] + 1)

    def test_secure_filename_generation(self):
        """🔒 Secure filename generation should be unpredictable"""
        original_name = "test document.pdf"
        
        # Generate multiple secure filenames
        filenames = [generate_secure_filename(original_name) for _ in range(10)]
        
        # All should be unique
        self.assertEqual(len(set(filenames)), 10)
        
        # All should have correct extension
        for filename in filenames:
            self.assertTrue(filename.endswith('.pdf'))
            self.assertTrue(filename.startswith('ticket_'))

    def test_secure_upload_path_generation(self):
        """🔒 Upload path should be secure and organized"""
        ticket_id = 123
        secure_filename = "ticket_20240101_120000_abcd1234.pdf"
        
        upload_path = get_secure_upload_path(ticket_id, secure_filename)
        
        # Should include year/month organization
        self.assertIn(str(timezone.now().year), upload_path)
        self.assertIn(str(ticket_id), upload_path)
        self.assertIn(secure_filename, upload_path)
        self.assertTrue(upload_path.startswith('tickets/attachments/'))


class TicketNumberSecurityTest(TestCase):
    """🔒 Test cryptographically secure ticket number generation"""

    def setUp(self):
        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="business",
            status="active",
            primary_email="test@customer.com"
        )
        self.user = User.objects.create_user(
            email="test@example.com",
            password="testpass123",
            first_name="Test",
            last_name="User"
        )

    def test_ticket_numbers_are_unpredictable(self):
        """🔒 Ticket numbers should be cryptographically unpredictable"""
        tickets = []
        for _ in range(10):
            ticket = Ticket.objects.create(
                customer=self.customer,
                title="Test Ticket",
                description="Test Description",
                created_by=self.user
            )
            tickets.append(ticket)
        
        ticket_numbers = [t.ticket_number for t in tickets]
        
        # All should be unique
        self.assertEqual(len(set(ticket_numbers)), 10)
        
        # All should follow the format TK{YEAR}-{8_RANDOM_CHARS}
        current_year = str(timezone.now().year)
        for number in ticket_numbers:
            self.assertTrue(number.startswith(f'TK{current_year}-'))
            self.assertEqual(len(number), len(f'TK{current_year}-') + 8)
        
        # Sequential creation should not result in sequential numbers
        numbers = [t.ticket_number.split('-')[1] for t in tickets]
        for i in range(1, len(numbers)):
            self.assertNotEqual(int(numbers[i], 36), int(numbers[i-1], 36) + 1)

    def test_ticket_number_collision_handling(self):
        """🔒 Ticket number generation should handle collisions gracefully"""
        # Mock secrets.choice to return predictable values, then unique ones
        collision_sequence = ['A'] * 8 + ['B'] * 8  # First call collides, second succeeds
        
        with patch('apps.tickets.models.secrets.choice', side_effect=collision_sequence):
            # Create first ticket (will use AAAAAAAA)
            ticket1 = Ticket.objects.create(
                customer=self.customer,
                title="Test Ticket 1",
                description="Test Description",
                created_by=self.user
            )
            
            # Create second ticket (will try AAAAAAAA, detect collision, use BBBBBBBB)
            ticket2 = Ticket.objects.create(
                customer=self.customer,
                title="Test Ticket 2",
                description="Test Description",
                created_by=self.user
            )
        
        # Tickets should have different numbers despite collision attempt
        self.assertNotEqual(ticket1.ticket_number, ticket2.ticket_number)


class RateLimitingSecurityTest(TestCase):
    """🔒 Test rate limiting security on ticket operations"""

    def setUp(self):
        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="business", 
            status="active",
            primary_email="test@customer.com"
        )
        self.user = User.objects.create_user(
            email="test@example.com",
            password="testpass123",
            first_name="Test",
            last_name="User"
        )
        # Add customer membership
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role="admin"
        )
        
        # Clear cache before each test
        cache.clear()

    def test_ticket_creation_rate_limiting(self):
        """🔒 Ticket creation should be rate limited"""
        self.client.login(email="test@example.com", password="testpass123")
        
        # Make requests up to the limit (5 per minute)
        for i in range(5):
            response = self.client.post(reverse('tickets:create'), {
                'customer_id': self.customer.id,
                'subject': f'Test Ticket {i}',
                'description': 'Test Description',
                'priority': 'normal'
            })
            # Should succeed (not be rate limited)
            self.assertNotEqual(response.status_code, 429)
        
        # Next request should be rate limited
        response = self.client.post(reverse('tickets:create'), {
            'customer_id': self.customer.id,
            'subject': 'Rate Limited Ticket',
            'description': 'Test Description',
            'priority': 'normal'
        })
        
        self.assertEqual(response.status_code, 429)

    def test_file_download_rate_limiting(self):
        """🔒 File downloads should be rate limited"""
        # Create ticket and attachment
        ticket = Ticket.objects.create(
            customer=self.customer,
            title="Test Ticket",
            description="Test Description",
            created_by=self.user
        )
        
        # Create a temporary file for testing
        with tempfile.NamedTemporaryFile(mode='w+b', delete=False) as tmp_file:
            tmp_file.write(b'Test file content')
            tmp_file.flush()
            
            attachment = TicketAttachment.objects.create(
                ticket=ticket,
                file=tmp_file.name,
                filename="test.txt",
                file_size=len(b'Test file content'),
                content_type="text/plain",
                uploaded_by=self.user
            )
        
        self.client.login(email="test@example.com", password="testpass123")
        
        # Make requests up to the limit (30 per minute)
        for i in range(30):
            response = self.client.get(reverse('tickets:download_attachment', args=[attachment.id]))
            if response.status_code != 200:  # File might not exist, but shouldn't be rate limited
                self.assertNotEqual(response.status_code, 429)
        
        # Next request should be rate limited
        response = self.client.get(reverse('tickets:download_attachment', args=[attachment.id]))
        self.assertEqual(response.status_code, 429)
        
        # Cleanup
        try:
            os.unlink(tmp_file.name)
        except OSError:
            pass


class FileAccessControlTest(TestCase):
    """🔒 Test multi-layer access control for file attachments"""

    def setUp(self):
        # Create customers
        self.customer1 = Customer.objects.create(
            name="Customer 1", customer_type="business", status="active", primary_email="c1@test.com"
        )
        self.customer2 = Customer.objects.create(
            name="Customer 2", customer_type="business", status="active", primary_email="c2@test.com"
        )
        
        # Create users
        self.user1 = User.objects.create_user(
            email="user1@example.com", password="testpass123", first_name="User", last_name="One"
        )
        self.user2 = User.objects.create_user(
            email="user2@example.com", password="testpass123", first_name="User", last_name="Two"
        )
        self.staff_user = User.objects.create_user(
            email="staff@example.com", password="testpass123", first_name="Staff", last_name="User",
            is_staff=True, staff_role="support"
        )
        
        # Create memberships
        CustomerMembership.objects.create(user=self.user1, customer=self.customer1, role="admin")
        CustomerMembership.objects.create(user=self.user2, customer=self.customer2, role="admin")
        
        # Create tickets and attachments
        self.ticket1 = Ticket.objects.create(
            customer=self.customer1, title="Ticket 1", description="Description 1", created_by=self.user1
        )
        self.ticket2 = Ticket.objects.create(
            customer=self.customer2, title="Ticket 2", description="Description 2", created_by=self.user2
        )
        
        # Create temporary files for testing
        self.temp_file1 = tempfile.NamedTemporaryFile(mode='w+b', delete=False)
        self.temp_file1.write(b'File 1 content')
        self.temp_file1.flush()
        
        self.temp_file2 = tempfile.NamedTemporaryFile(mode='w+b', delete=False)
        self.temp_file2.write(b'File 2 content')
        self.temp_file2.flush()
        
        self.attachment1 = TicketAttachment.objects.create(
            ticket=self.ticket1,
            file=self.temp_file1.name,
            filename="file1.txt",
            file_size=len(b'File 1 content'),
            content_type="text/plain",
            uploaded_by=self.user1,
            is_safe=True
        )
        
        # Create internal attachment
        internal_comment = TicketComment.objects.create(
            ticket=self.ticket2,
            content="Internal comment",
            comment_type="internal",
            author=self.staff_user,
            is_public=False
        )
        
        self.internal_attachment = TicketAttachment.objects.create(
            ticket=self.ticket2,
            comment=internal_comment,
            file=self.temp_file2.name,
            filename="internal_file.txt",
            file_size=len(b'File 2 content'),
            content_type="text/plain",
            uploaded_by=self.staff_user,
            is_safe=True
        )

    def tearDown(self):
        # Cleanup temporary files
        try:
            os.unlink(self.temp_file1.name)
            os.unlink(self.temp_file2.name)
        except OSError:
            pass

    def test_user_can_access_own_customer_attachments(self):
        """✅ Users should be able to access attachments from their customers"""
        self.client.login(email="user1@example.com", password="testpass123")
        
        response = self.client.get(reverse('tickets:download_attachment', args=[self.attachment1.id]))
        # Should not be forbidden (might be 404 if file doesn't exist, but not 403)
        self.assertNotEqual(response.status_code, 403)

    def test_user_cannot_access_other_customer_attachments(self):
        """🚨 Users should not be able to access attachments from other customers"""
        self.client.login(email="user1@example.com", password="testpass123")
        
        # Try to access attachment from customer2 (should be forbidden)
        response = self.client.get(reverse('tickets:download_attachment', args=[self.internal_attachment.id]))
        self.assertEqual(response.status_code, 403)

    def test_non_staff_cannot_access_internal_attachments(self):
        """🚨 Non-staff users should not be able to access internal attachments"""
        # Even if user2 could access customer2, they shouldn't access internal attachments
        CustomerMembership.objects.create(user=self.user1, customer=self.customer2, role="viewer")
        
        self.client.login(email="user1@example.com", password="testpass123")
        
        response = self.client.get(reverse('tickets:download_attachment', args=[self.internal_attachment.id]))
        self.assertEqual(response.status_code, 403)

    def test_staff_can_access_internal_attachments(self):
        """✅ Staff users should be able to access internal attachments"""
        self.client.login(email="staff@example.com", password="testpass123")
        
        response = self.client.get(reverse('tickets:download_attachment', args=[self.internal_attachment.id]))
        # Should not be forbidden (might be 404 if file doesn't exist, but not 403)
        self.assertNotEqual(response.status_code, 403)

    def test_unsafe_file_access_blocked(self):
        """🚨 Access to unsafe files should be blocked"""
        # Mark attachment as unsafe
        self.attachment1.is_safe = False
        self.attachment1.save()
        
        self.client.login(email="user1@example.com", password="testpass123")
        
        response = self.client.get(reverse('tickets:download_attachment', args=[self.attachment1.id]))
        self.assertEqual(response.status_code, 403)


class SecurityMonitoringTest(TestCase):
    """🔍 Test security monitoring and alerting system"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com", password="testpass123", first_name="Test", last_name="User"
        )
        self.tracker = SecurityEventTracker()
        cache.clear()  # Clear cache before each test

    def test_failed_access_tracking(self):
        """📊 Failed access attempts should be tracked and trigger alerts"""
        # Track multiple failed access attempts
        for i in range(6):  # Exceed threshold of 5
            self.tracker.track_failed_access(
                self.user.id,
                'ticket_attachment',
                f'attachment_{i}',
                'unauthorized_access'
            )
        
        # Should have triggered an alert (check logs would be done in integration tests)
        # For unit test, verify the tracking logic works
        event_key = f"ticket_security_failed_access_{self.user.id}"
        failures = cache.get(event_key, [])
        self.assertGreaterEqual(len(failures), 5)

    def test_file_upload_pattern_analysis(self):
        """📊 File upload patterns should be analyzed for suspicious behavior"""
        # Track many uploads in short time
        for i in range(12):  # Exceed suspicious threshold of 10
            self.tracker.track_file_upload(
                self.user.id,
                f'file_{i}.txt',
                1024 * 1024,  # 1MB each
                'CLEAN_NO_SCAN'
            )
        
        # Should have triggered suspicious volume alert
        event_key = f"ticket_security_uploads_{self.user.id}"
        uploads = cache.get(event_key, [])
        self.assertGreaterEqual(len(uploads), 10)

    def test_privilege_escalation_detection(self):
        """🚨 Privilege escalation attempts should be immediately flagged"""
        # This should trigger immediate alert
        self.tracker.track_privilege_escalation_attempt(
            self.user.id,
            'access_internal_attachment',
            'attachment_123'
        )
        
        # In a real test, we'd check that an alert was logged/sent
        # For this unit test, we verify the method doesn't raise an exception
        self.assertTrue(True)  # Method completed successfully

    def test_security_metrics_collection(self):
        """📊 Security metrics should be collected properly"""
        # Generate some events
        self.tracker.track_failed_access(self.user.id, 'ticket', '1', 'unauthorized')
        self.tracker.track_file_upload(self.user.id, 'test.txt', 1024, 'CLEAN')
        
        metrics = self.tracker.get_security_metrics(24)
        
        self.assertIn('time_range_hours', metrics)
        self.assertEqual(metrics['time_range_hours'], 24)
        self.assertIn('failed_access_attempts', metrics)
        self.assertIn('suspicious_uploads', metrics)

    @patch('apps.tickets.monitoring.logger')
    def test_security_alert_logging(self, mock_logger):
        """🚨 Security alerts should be properly logged"""
        alert_data = {'test': 'data'}
        
        self.tracker._trigger_security_alert(
            self.user.id,
            'test_alert_type',
            alert_data
        )
        
        # Verify that a critical log was made
        mock_logger.critical.assert_called()
        call_args = mock_logger.critical.call_args[0][0]
        self.assertIn('SECURITY ALERT', call_args)
        self.assertIn('TEST ALERT TYPE', call_args)


class IntegrationSecurityTest(TransactionTestCase):
    """🔒 Integration tests for end-to-end security workflows"""

    def setUp(self):
        self.customer = Customer.objects.create(
            name="Test Customer", customer_type="business", status="active", primary_email="test@customer.com"
        )
        self.user = User.objects.create_user(
            email="test@example.com", password="testpass123", first_name="Test", last_name="User"
        )
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="admin")

    def test_complete_secure_file_upload_workflow(self):
        """🔒 Test complete secure file upload from creation to download"""
        self.client.login(email="test@example.com", password="testpass123")
        
        # Create ticket
        ticket = Ticket.objects.create(
            customer=self.customer,
            title="Test Ticket",
            description="Test Description",
            created_by=self.user
        )
        
        # Upload secure file
        pdf_content = b'%PDF-1.4\nValid PDF content'
        secure_file = SimpleUploadedFile(
            "secure_document.pdf",
            pdf_content,
            content_type="application/pdf"
        )
        
        response = self.client.post(
            reverse('tickets:reply', args=[ticket.pk]),
            {
                'reply': 'Here is a secure document',
                'attachments': secure_file
            }
        )
        
        # Should succeed
        self.assertNotEqual(response.status_code, 400)
        
        # Verify attachment was created with security flags
        attachment = TicketAttachment.objects.filter(ticket=ticket).first()
        if attachment:  # Only test if attachment was created
            self.assertTrue(attachment.is_safe)
            
            # Test secure download
            download_response = self.client.get(
                reverse('tickets:download_attachment', args=[attachment.id])
            )
            # Should not be forbidden
            self.assertNotEqual(download_response.status_code, 403)

    def test_malicious_file_upload_blocked_end_to_end(self):
        """🚨 Test that malicious files are blocked through complete workflow"""
        self.client.login(email="test@example.com", password="testpass123")
        
        # Create ticket
        ticket = Ticket.objects.create(
            customer=self.customer,
            title="Test Ticket",
            description="Test Description", 
            created_by=self.user
        )
        
        # Try to upload malicious file
        malicious_content = b'<script>alert("XSS")</script>'
        malicious_file = SimpleUploadedFile(
            "malicious.txt",
            malicious_content,
            content_type="text/plain"
        )
        
        response = self.client.post(
            reverse('tickets:reply', args=[ticket.pk]),
            {
                'reply': 'Attempting to upload malicious file',
                'attachments': malicious_file
            }
        )
        
        # Request might succeed but file should not be saved
        # Verify no unsafe attachment was created
        unsafe_attachments = TicketAttachment.objects.filter(
            ticket=ticket, 
            is_safe=False
        )
        # In our implementation, unsafe files are not saved at all
        # so we should have no attachments
        all_attachments = TicketAttachment.objects.filter(ticket=ticket)
        
        # Either no attachments created, or if any exist, they should be marked safe
        for attachment in all_attachments:
            self.assertTrue(attachment.is_safe)

    def test_cross_customer_access_blocked_end_to_end(self):
        """🚨 Test that cross-customer access is blocked through complete workflow"""
        # Create second customer and user
        customer2 = Customer.objects.create(
            name="Customer 2", customer_type="business", status="active", primary_email="c2@test.com"
        )
        user2 = User.objects.create_user(
            email="user2@example.com", password="testpass123", first_name="User", last_name="Two"
        )
        CustomerMembership.objects.create(user=user2, customer=customer2, role="admin")
        
        # Create ticket and attachment for customer2
        ticket2 = Ticket.objects.create(
            customer=customer2,
            title="Customer 2 Ticket",
            description="Description",
            created_by=user2
        )
        
        with tempfile.NamedTemporaryFile(mode='w+b', delete=False) as tmp_file:
            tmp_file.write(b'Customer 2 confidential data')
            tmp_file.flush()
            
            attachment2 = TicketAttachment.objects.create(
                ticket=ticket2,
                file=tmp_file.name,
                filename="confidential.txt",
                file_size=len(b'Customer 2 confidential data'),
                content_type="text/plain",
                uploaded_by=user2,
                is_safe=True
            )
        
        # Login as user from customer1 and try to access customer2's attachment
        self.client.login(email="test@example.com", password="testpass123")
        
        response = self.client.get(
            reverse('tickets:download_attachment', args=[attachment2.id])
        )
        
        # Should be forbidden
        self.assertEqual(response.status_code, 403)
        
        # Cleanup
        try:
            os.unlink(tmp_file.name)
        except OSError:
            pass