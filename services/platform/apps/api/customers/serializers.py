# ===============================================================================
# CUSTOMER API SERIALIZERS 📊
# ===============================================================================

import logging
import re

from django.contrib.auth import get_user_model
from django.db import transaction
from rest_framework import serializers

from apps.common.types import Err, Ok
from apps.customers.models import Customer
from apps.users.services import SecureUserRegistrationService

User = get_user_model()

# Romanian validation constants
MIN_VAT_DIGITS = 6  # Minimum number of digits in Romanian VAT number

logger = logging.getLogger(__name__)


class CustomerSearchSerializer(serializers.ModelSerializer):
    """
    Serializer for customer search API results.
    Used in dropdowns and autocomplete fields.
    """
    
    text = serializers.CharField(source='get_display_name', read_only=True)
    
    class Meta:
        model = Customer
        fields = ['id', 'text', 'primary_email']
        read_only_fields = ['id', 'text', 'primary_email']


class CustomerServiceSerializer(serializers.Serializer):
    """
    Serializer for customer services API.
    Placeholder for future service management.
    """
    
    id = serializers.IntegerField()
    name = serializers.CharField()
    status = serializers.CharField()
    
    # This is a placeholder - will be replaced with actual service models


# ===============================================================================
# CUSTOMER REGISTRATION SERIALIZERS 🔐
# ===============================================================================

class UserRegistrationDataSerializer(serializers.Serializer):
    """
    Serializer for user data in customer registration.
    """
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=30)
    last_name = serializers.CharField(max_length=30)
    phone = serializers.CharField(max_length=20, required=False, allow_blank=True)
    password = serializers.CharField(min_length=12, write_only=True)
    
    def validate_email(self, value):
        """Ensure email is not already taken"""
        if User.objects.filter(email=value.lower()).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value.lower()
    
    def validate_phone(self, value):
        """Validate Romanian phone format"""
        if value:
            if not re.match(r"^(\+40[\s\.]?[0-9][\s\.0-9]{8,11}[0-9]|0[0-9]{9})$", value):
                raise serializers.ValidationError("Invalid Romanian phone number format.")
        return value


class CustomerRegistrationDataSerializer(serializers.Serializer):
    """
    Serializer for customer data in registration.
    """
    customer_type = serializers.ChoiceField(
        choices=[('individual', 'Individual'), ('company', 'Company'), ('pfa', 'PFA'), ('ngo', 'NGO')],
        default='company'
    )
    company_name = serializers.CharField(max_length=255)
    vat_number = serializers.CharField(max_length=20, required=False, allow_blank=True)
    address_line1 = serializers.CharField(max_length=200)
    city = serializers.CharField(max_length=100)
    county = serializers.CharField(max_length=100, required=False, allow_blank=True)
    postal_code = serializers.CharField(max_length=10)
    data_processing_consent = serializers.BooleanField()
    marketing_consent = serializers.BooleanField(default=False)
    
    def validate_company_name(self, value):
        """Ensure company name is unique"""
        if Customer.objects.filter(company_name__iexact=value.strip()).exists():
            raise serializers.ValidationError("A company with this name already exists.")
        return value.strip()
    
    def validate_vat_number(self, value):
        """Validate Romanian VAT number format"""
        if value:
            value = value.strip().upper()
            if not value.startswith('RO'):
                if value.isdigit() and len(value) >= MIN_VAT_DIGITS:
                    value = f'RO{value}'
                else:
                    raise serializers.ValidationError("VAT number must start with RO followed by digits.")
            else:
                vat_digits = value[2:]
                if not vat_digits.isdigit() or len(vat_digits) < MIN_VAT_DIGITS:
                    raise serializers.ValidationError("VAT number must start with RO followed by digits.")
        return value
    
    def validate_data_processing_consent(self, value):
        """GDPR consent is required"""
        if not value:
            raise serializers.ValidationError("Data processing consent is required.")
        return value


class CustomerRegistrationSerializer(serializers.Serializer):
    """
    Main serializer for customer registration requests.
    Handles both user and customer data creation.
    """
    user_data = UserRegistrationDataSerializer()
    customer_data = CustomerRegistrationDataSerializer()
    
    def create(self, validated_data):
        """
        Create new customer owner using secure registration service.
        """
        user_data = validated_data['user_data']
        customer_data = validated_data['customer_data']
        
        # Get request context for IP tracking
        request = self.context.get('request')
        request_ip = None
        user_agent = None
        
        if request:
            request_ip = request.META.get('REMOTE_ADDR')
            user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        try:
            with transaction.atomic():
                # Use secure registration service
                result = SecureUserRegistrationService.register_new_customer_owner(
                    user_data=user_data,
                    customer_data=customer_data,
                    request_ip=request_ip,
                    user_agent=user_agent
                )
                
                if isinstance(result, Ok):
                    user, customer = result.value
                    logger.info(f"✅ [API Registration] Created user {user.email} and customer {customer.company_name}")
                    return {
                        'user': {
                            'id': user.id,
                            'email': user.email,
                            'first_name': user.first_name,
                            'last_name': user.last_name,
                        },
                        'customer': {
                            'id': customer.id,
                            'company_name': customer.company_name,
                            'customer_type': customer.customer_type,
                        }
                    }
                else:
                    # Result is Err, extract error message
                    error_msg = result.value if isinstance(result, Err) else "Registration failed"
                    logger.error(f"🔥 [API Registration] Service error: {error_msg}")
                    raise serializers.ValidationError({"non_field_errors": [error_msg]})
                    
        except Exception as e:
            logger.error(f"🔥 [API Registration] Unexpected error: {e}")
            raise serializers.ValidationError({"non_field_errors": ["Registration service temporarily unavailable"]})


# ===============================================================================
# CUSTOMER DETAIL SERIALIZERS 🏢
# ===============================================================================

class CustomerTaxProfileSerializer(serializers.Serializer):
    """
    Serializer for customer tax profile data (safe fields only).
    """
    vat_number = serializers.CharField(max_length=20, allow_blank=True)
    cui = serializers.CharField(max_length=20, allow_blank=True)
    is_vat_payer = serializers.BooleanField()


class CustomerBillingProfileSerializer(serializers.Serializer):
    """
    Serializer for customer billing profile data (safe fields only).
    Excludes sensitive banking details and credit limits.
    """
    payment_terms = serializers.CharField(max_length=50, allow_blank=True)
    preferred_currency = serializers.CharField(max_length=3, default='RON')
    invoice_delivery_method = serializers.CharField(max_length=20, default='email')
    auto_payment_enabled = serializers.BooleanField(default=False)


class CustomerDetailSerializer(serializers.ModelSerializer):
    """
    Serializer for customer detail API response with nested profiles.
    Returns safe customer data with optional expansions via 'include' parameter.
    """
    display_name = serializers.CharField(source='get_display_name', read_only=True)
    tax_profile = CustomerTaxProfileSerializer(read_only=True)
    billing_profile = CustomerBillingProfileSerializer(read_only=True)
    
    class Meta:
        model = Customer
        fields = [
            'id', 'display_name', 'customer_type', 'status', 'created_at', 'updated_at',
            'name', 'company_name', 'primary_email', 'primary_phone', 'website', 'industry',
            'tax_profile', 'billing_profile'
        ]
        read_only_fields = fields


# ===============================================================================
# CUSTOMER PROFILE SERIALIZERS 👤
# ===============================================================================

class CustomerProfileSerializer(serializers.Serializer):
    """
    Serializer for customer profile data.
    """
    # User fields
    first_name = serializers.CharField(max_length=30)
    last_name = serializers.CharField(max_length=30)
    phone = serializers.CharField(max_length=20, required=False, allow_blank=True)
    
    # Profile preferences
    preferred_language = serializers.ChoiceField(
        choices=[('ro', 'Română'), ('en', 'English')],
        default='ro'
    )
    timezone = serializers.ChoiceField(
        choices=[('Europe/Bucharest', 'Europe/Bucharest'), ('UTC', 'UTC')],
        default='Europe/Bucharest'
    )
    
    # Notification preferences
    email_notifications = serializers.BooleanField(default=True)
    sms_notifications = serializers.BooleanField(default=False)
    marketing_emails = serializers.BooleanField(default=False)
    
    def validate_phone(self, value):
        """Validate Romanian phone format"""
        if value:
            if not re.match(r"^(\+40[\s\.]?[0-9][\s\.0-9]{8,11}[0-9]|0[0-9]{9})$", value):
                raise serializers.ValidationError("Invalid Romanian phone number format.")
        return value
    
    def update(self, instance, validated_data):
        """
        Update user profile data.
        """
        # Update user fields
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.phone = validated_data.get('phone', instance.phone)
        instance.save()
        
        # Update or create user profile
        profile, created = instance.profile.get_or_create(
            defaults={
                'preferred_language': validated_data.get('preferred_language', 'ro'),
                'timezone': validated_data.get('timezone', 'Europe/Bucharest'),
                'email_notifications': validated_data.get('email_notifications', True),
                'sms_notifications': validated_data.get('sms_notifications', False),
                'marketing_emails': validated_data.get('marketing_emails', False),
            }
        )
        
        if not created:
            # Update existing profile
            profile.preferred_language = validated_data.get('preferred_language', profile.preferred_language)
            profile.timezone = validated_data.get('timezone', profile.timezone)
            profile.email_notifications = validated_data.get('email_notifications', profile.email_notifications)
            profile.sms_notifications = validated_data.get('sms_notifications', profile.sms_notifications)
            profile.marketing_emails = validated_data.get('marketing_emails', profile.marketing_emails)
            profile.save()
        
        return instance
    
    def to_representation(self, instance):
        """
        Convert user and profile data to API response format.
        """
        try:
            profile = instance.profile
        except:
            # Create default profile if missing
            profile = instance.profile.create(
                preferred_language='ro',
                timezone='Europe/Bucharest',
                email_notifications=True,
                sms_notifications=False,
                marketing_emails=False,
            )
        
        return {
            'first_name': instance.first_name,
            'last_name': instance.last_name,
            'phone': instance.phone,
            'preferred_language': profile.preferred_language,
            'timezone': profile.timezone,
            'email_notifications': profile.email_notifications,
            'sms_notifications': profile.sms_notifications,
            'marketing_emails': profile.marketing_emails,
        }
