"""
🔒 Model Security Integration Tests for Notifications App
Tests security features integrated into Django models.
"""

from unittest.mock import patch
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model

from apps.notifications.models import EmailTemplate, EmailLog, EmailCampaign

User = get_user_model()


class EmailTemplateSecurityTests(TestCase):
    """🔒 Tests for EmailTemplate model security"""
    
    def test_template_validation_on_clean(self):
        """🔒 Test that EmailTemplate validates content on clean()"""
        template = EmailTemplate(
            key="test.dangerous",
            locale="en", 
            subject="Test Subject",
            body_html="{% debug %}{{ dangerous_content }}",
            body_text="Safe text",
            category="system"
        )
        
        with self.assertRaises(ValidationError):
            template.clean()
    
    def test_template_json_field_validation(self):
        """🔒 Test that EmailTemplate validates JSON fields"""
        template = EmailTemplate(
            key="test.json",
            locale="en",
            subject="Test Subject", 
            body_html="<p>Safe content</p>",
            body_text="Safe content",
            category="system",
            variables={"data": "x" * 15000}  # Too large
        )
        
        with self.assertRaises(ValidationError):
            template.clean()
    
    def test_template_safe_content_passes(self):
        """✅ Test that safe template content passes validation"""
        template = EmailTemplate(
            key="test.safe",
            locale="en",
            subject="Safe Subject",
            body_html="<p>Hello {{ customer_name }}!</p>", 
            body_text="Hello {{ customer_name }}!",
            category="system",
            variables={"customer_name": "Customer name variable"}
        )
        
        try:
            template.clean()  # Should not raise ValidationError
        except ValidationError as e:
            self.fail(f"Safe template failed validation: {e}")
    
    def test_template_get_sanitized_content(self):
        """🔒 Test that template content sanitization works"""
        template = EmailTemplate(
            key="test.sanitize",
            locale="en",
            subject="Test Subject",
            body_html="<p>Hello <script>alert('xss')</script>{{ name }}!</p>",
            body_text="Hello {{ name }}!",
            category="system"
        )
        
        safe_html, safe_text = template.get_sanitized_content()
        
        # Should strip dangerous HTML tags
        self.assertNotIn("<script>", safe_html)
        self.assertIn("Hello", safe_html)
        self.assertIn("{{ name }}", safe_html)


class EmailLogSecurityTests(TestCase):
    """🔒 Tests for EmailLog model security"""
    
    @patch('apps.notifications.models.ENCRYPTION_AVAILABLE', True)
    @patch('apps.notifications.models.settings_encryption')
    def test_email_content_encryption_on_save(self, mock_encryption):
        """🔒 Test that EmailLog encrypts content on save"""
        mock_encryption.is_encrypted.return_value = False
        mock_encryption.encrypt_value.return_value = "enc:v1:encrypted"
        
        email_log = EmailLog(
            to_addr="test@example.com",
            subject="Test Email",
            body_html="<p>Sensitive content</p>",
            body_text="Sensitive content",
            template_key="test.template",
            status="sent"
        )
        
        email_log.save()
        
        # Should have called encryption
        mock_encryption.encrypt_value.assert_called()
    
    def test_email_validation_on_clean(self):
        """🔒 Test that EmailLog validates fields on clean()"""
        # Test subject header injection
        email_log = EmailLog(
            to_addr="test@example.com",
            subject="Subject\nBcc: evil@test.com",
            body_html="<p>Content</p>",
            template_key="test.template",
            status="sent"
        )
        
        with self.assertRaises(ValidationError):
            email_log.clean()
    
    def test_email_json_field_validation(self):
        """🔒 Test that EmailLog validates JSON fields"""
        email_log = EmailLog(
            to_addr="test@example.com", 
            subject="Test Subject",
            template_key="test.template",
            status="sent",
            meta={"data": "x" * 15000}  # Too large
        )
        
        with self.assertRaises(ValidationError):
            email_log.clean()
    
    @patch('apps.notifications.models.ENCRYPTION_AVAILABLE', True)
    @patch('apps.notifications.models.settings_encryption')  
    def test_safe_content_preview(self, mock_encryption):
        """🔒 Test that content preview is safe and limited"""
        mock_encryption.decrypt_if_needed.return_value = "Very long email content " * 100
        
        email_log = EmailLog(
            to_addr="test@example.com",
            subject="Test Email",
            body_text="enc:v1:encrypted",
            template_key="test.template",
            status="sent"
        )
        
        preview = email_log.get_safe_content_preview()
        
        # Should be limited in length
        self.assertLessEqual(len(preview), 103)  # 100 chars + "..."
        self.assertIn("...", preview)


class EmailCampaignSecurityTests(TestCase):
    """🔒 Tests for EmailCampaign model security"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            email="admin@test.com",
            password="testpass123",
            is_staff=True
        )
        
        self.template = EmailTemplate.objects.create(
            key="test.template",
            locale="en",
            subject="Test Template",
            body_html="<p>Test content</p>",
            body_text="Test content",
            category="marketing"
        )
    
    def test_campaign_json_field_validation(self):
        """🔒 Test that EmailCampaign validates JSON fields"""
        campaign = EmailCampaign(
            name="Test Campaign",
            template=self.template,
            audience="custom_filter",
            audience_filter={"data": "x" * 15000},  # Too large
            created_by=self.user
        )
        
        with self.assertRaises(ValidationError):
            campaign.clean()
    
    def test_campaign_name_length_validation(self):
        """🔒 Test that campaign name length is validated"""
        campaign = EmailCampaign(
            name="x" * 201,  # Too long
            template=self.template,
            audience="all_customers",
            created_by=self.user
        )
        
        with self.assertRaises(ValidationError):
            campaign.clean()
    
    @patch('apps.notifications.models.logger')
    def test_gdpr_compliance_warning(self, mock_logger):
        """🔒 Test that GDPR non-compliance triggers warning"""
        campaign = EmailCampaign(
            name="Marketing Campaign",
            template=self.template,
            audience="all_customers", 
            is_transactional=False,  # Marketing campaign
            requires_consent=False,  # No consent required - should warn
            created_by=self.user
        )
        
        campaign.clean()
        
        # Should log GDPR warning
        mock_logger.warning.assert_called()
        call_args = str(mock_logger.warning.call_args)
        self.assertIn("GDPR", call_args)
    
    def test_safe_campaign_passes_validation(self):
        """✅ Test that safe campaign passes validation"""
        campaign = EmailCampaign(
            name="Safe Marketing Campaign",
            template=self.template,
            audience="active_customers",
            audience_filter={"status": "active", "consent": True},
            is_transactional=False,
            requires_consent=True,  # GDPR compliant
            created_by=self.user
        )
        
        try:
            campaign.clean()  # Should not raise ValidationError
        except ValidationError as e:
            self.fail(f"Safe campaign failed validation: {e}")


class SecurityLoggingIntegrationTests(TestCase):
    """🔒 Tests for security logging in model operations"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            email="admin@test.com",
            password="testpass123",
            is_staff=True
        )
    
    @patch('apps.notifications.models.logger')
    def test_template_modification_logging(self, mock_logger):
        """🔒 Test that template modifications are logged"""
        template = EmailTemplate(
            key="test.logging",
            locale="en",
            subject="Test Subject",
            body_html="<p>Modified content</p>",
            body_text="Modified content", 
            category="system"
        )
        
        template.clean()
        
        # Should log template modification
        mock_logger.info.assert_called()
        call_args = str(mock_logger.info.call_args)
        self.assertIn("Template modified", call_args)
    
    @patch('apps.notifications.models.logger')
    def test_email_sending_logging(self, mock_logger):
        """🔒 Test that email sending is logged"""
        email_log = EmailLog(
            to_addr="test@example.com",
            subject="Test Email",
            body_text="Test content",
            template_key="test.template", 
            status="sent"  # This should trigger logging
        )
        
        email_log.clean()
        
        # Should log email sending with masked email
        mock_logger.info.assert_called()
        call_args = str(mock_logger.info.call_args)
        self.assertIn("Email sent", call_args)
        self.assertIn("tes***", call_args)  # Email should be masked