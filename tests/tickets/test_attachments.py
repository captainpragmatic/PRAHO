"""
Test ticket attachment functionality
"""

import os
import tempfile
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from django.conf import settings

from apps.customers.models import Customer, CustomerTaxProfile
from apps.users.models import CustomerMembership
from apps.tickets.models import Ticket, SupportCategory, TicketComment, TicketAttachment

User = get_user_model()


class TicketAttachmentTest(TestCase):
    """Test ticket attachment functionality"""

    def setUp(self):
        """Set up test data"""
        # Create test user
        self.user = User.objects.create_user(
            email='testuser@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        # Create test customer
        self.customer = Customer.objects.create(
            name='Test Company SRL',
            company_name='Test Company SRL',
            customer_type='company',
            status='active',
            primary_email='test@example.com',
            primary_phone='+40712345678'
        )
        
        # Create customer tax profile
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            vat_number='RO12345678',
            registration_number='12345678'
        )
        
        # Create customer membership
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='owner',
            is_primary=True
        )
        
        # Create support category
        self.category = SupportCategory.objects.create(
            name='Technical Support',
            name_en='Technical Support',
            sla_response_hours=24,
            sla_resolution_hours=72
        )
        
        # Create test ticket
        self.ticket = Ticket.objects.create(
            title='Test Ticket',
            description='Test description',
            customer=self.customer,
            contact_email='test@example.com',
            category=self.category,
            priority='normal',
            created_by=self.user
        )
        
        self.client = Client()
        self.client.login(email='testuser@example.com', password='testpass123')

    def test_file_upload_with_reply(self):
        """Test uploading file with ticket reply"""
        # Create test file
        test_content = b'This is a test file content'
        test_file = SimpleUploadedFile(
            'test_document.txt',
            test_content,
            content_type='text/plain'
        )
        
        # Submit reply with attachment
        response = self.client.post(
            reverse('tickets:reply', kwargs={'pk': self.ticket.pk}),
            {
                'reply': 'This is a test reply with attachment',
                'attachments': test_file
            }
        )
        
        # Should redirect or return success
        self.assertIn(response.status_code, [200, 302])
        
        # Check comment was created
        comment = TicketComment.objects.filter(ticket=self.ticket).first()
        self.assertIsNotNone(comment)
        self.assertEqual(comment.content, 'This is a test reply with attachment')
        
        # Check attachment was created
        attachment = TicketAttachment.objects.filter(comment=comment).first()
        self.assertIsNotNone(attachment)
        self.assertEqual(attachment.filename, 'test_document.txt')
        self.assertEqual(attachment.content_type, 'text/plain')
        self.assertEqual(attachment.file_size, len(test_content))

    def test_file_size_limit(self):
        """Test file size limit enforcement"""
        # Create file larger than 10MB
        large_content = b'x' * (11 * 1024 * 1024)  # 11MB
        large_file = SimpleUploadedFile(
            'large_file.txt',
            large_content,
            content_type='text/plain'
        )
        
        response = self.client.post(
            reverse('tickets:reply', kwargs={'pk': self.ticket.pk}),
            {
                'reply': 'Test reply with large file',
                'attachments': large_file
            }
        )
        
        # Should still create comment but not attachment
        comment = TicketComment.objects.filter(ticket=self.ticket).first()
        self.assertIsNotNone(comment)
        
        # Should not create attachment
        attachment_count = TicketAttachment.objects.filter(comment=comment).count()
        self.assertEqual(attachment_count, 0)

    def test_invalid_file_type(self):
        """Test invalid file type rejection"""
        # Create executable file
        exe_content = b'MZ\x90\x00'  # PE header
        exe_file = SimpleUploadedFile(
            'malicious.exe',
            exe_content,
            content_type='application/x-executable'
        )
        
        response = self.client.post(
            reverse('tickets:reply', kwargs={'pk': self.ticket.pk}),
            {
                'reply': 'Test reply with exe file',
                'attachments': exe_file
            }
        )
        
        # Should create comment but not attachment
        comment = TicketComment.objects.filter(ticket=self.ticket).first()
        self.assertIsNotNone(comment)
        
        # Should not create attachment
        attachment_count = TicketAttachment.objects.filter(comment=comment).count()
        self.assertEqual(attachment_count, 0)

    def test_attachment_download_security(self):
        """Test attachment download security"""
        # Create test attachment
        test_content = b'Private file content'
        test_file = SimpleUploadedFile(
            'private.txt',
            test_content,
            content_type='text/plain'
        )
        
        # Create comment and attachment
        comment = TicketComment.objects.create(
            ticket=self.ticket,
            content='Test comment',
            author=self.user
        )
        
        attachment = TicketAttachment.objects.create(
            ticket=self.ticket,
            comment=comment,
            file=test_file,
            filename='private.txt',
            file_size=len(test_content),
            content_type='text/plain',
            uploaded_by=self.user
        )
        
        # Test authorized download
        response = self.client.get(
            reverse('tickets:download_attachment', kwargs={'attachment_id': attachment.id})
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')
        
        # Test unauthorized access (different user)
        unauthorized_user = User.objects.create_user(
            email='unauthorized@example.com',
            password='testpass123',
            first_name='Unauthorized',
            last_name='User'
        )
        
        unauthorized_client = Client()
        unauthorized_client.login(email='unauthorized@example.com', password='testpass123')
        
        response = unauthorized_client.get(
            reverse('tickets:download_attachment', kwargs={'attachment_id': attachment.id})
        )
        self.assertEqual(response.status_code, 403)  # Permission denied

    def tearDown(self):
        """Clean up test files"""
        # Clean up any uploaded files
        for attachment in TicketAttachment.objects.all():
            if attachment.file and os.path.exists(attachment.file.path):
                os.remove(attachment.file.path)