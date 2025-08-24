# ===============================================================================
# USER REGISTRATION SERVICES - PROPER CUSTOMER ONBOARDING
# ===============================================================================

from typing import Dict, Any, Tuple, Optional, TYPE_CHECKING, List
from django.db import transaction
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import make_password, check_password
from django.core.cache import cache
from django.utils import timezone
import logging
import string
import random
import pyotp
import qrcode
import io
import base64

from apps.common.types import Result, Ok, Err
from apps.customers.models import Customer, CustomerTaxProfile, CustomerBillingProfile, CustomerAddress
from .models import CustomerMembership

if TYPE_CHECKING:
    from .models import User
else:
    User = get_user_model()

logger = logging.getLogger(__name__)


class UserRegistrationService:
    """
    🚀 Proper user registration with customer onboarding
    Ensures every user belongs to a customer organization
    """
    
    CUSTOMER_TYPES = [
        ('individual', _('Individual Person')),
        ('srl', _('SRL - Limited Liability Company')),  
        ('pfa', _('PFA - Authorized Physical Person')),
        ('sa', _('SA - Joint Stock Company')),
        ('ngo', _('NGO - Non-Governmental Organization')),
        ('other', _('Other Organization Type')),
    ]
    
    @classmethod
    @transaction.atomic
    def register_new_customer_owner(
        cls, 
        user_data: Dict[str, Any], 
        customer_data: Dict[str, Any]
    ) -> Result[Tuple[User, Customer], str]:
        """
        🏢 Register new user as owner of NEW customer organization
        This is the primary registration flow for new businesses
        """
        
        try:
            # Step 1: Check for existing company conflicts
            existing_check = cls._check_existing_customer(customer_data)
            if existing_check.is_err():
                # existing_check is now narrowed to Err[str] type
                return Err(existing_check.error)
            
            # Step 2: Create the user account (email is username)
            user = User.objects.create_user(
                username=user_data['email'],  # Django requirement
                email=user_data['email'],
                first_name=user_data['first_name'],
                last_name=user_data['last_name'],
                phone=user_data.get('phone', ''),
                accepts_marketing=user_data.get('accepts_marketing', False),
                gdpr_consent_date=user_data.get('gdpr_consent_date'),
            )
            
            # Step 3: Create customer organization with proper structure
            customer = Customer.objects.create(
                company_name=customer_data['company_name'],
                customer_type=customer_data['customer_type'],
                status='active',
                created_by=user
            )
            
            # Step 4: Create tax profile if needed
            vat_number = customer_data.get('vat_number', '').strip()
            registration_number = customer_data.get('registration_number', '').strip()
            
            if vat_number or registration_number:
                CustomerTaxProfile.objects.create(
                    customer=customer,
                    vat_number=vat_number or '',
                    registration_number=registration_number or '',
                    is_vat_payer=bool(vat_number),
                )
            
            # Step 5: Create billing profile (basic settings)
            CustomerBillingProfile.objects.create(
                customer=customer,
                payment_terms=30,  # Default 30 days
                preferred_currency='RON',
                invoice_delivery_method='email',
            )
            
            # Step 6: Create billing address
            CustomerAddress.objects.create(
                customer=customer,
                address_type='billing',
                address_line1=customer_data.get('billing_address', ''),
                city=customer_data.get('billing_city', ''),
                postal_code=customer_data.get('billing_postal_code', ''),
                county='',  # Could be enhanced to detect from city
                country='România',
                is_current=True,
            )
            
            # Step 7: Associate user as OWNER of the customer
            CustomerMembership.objects.create(
                user=user,
                customer=customer,
                role='owner',
                is_primary=True,
            )
            
            return Ok((user, customer))
            
        except Exception as e:
            return Err(f"Registration failed: {str(e)}")
    
    @classmethod
    def request_join_existing_customer(
        cls,
        user_data: Dict[str, Any],
        company_identifier: str,
        identification_type: str  # 'name', 'vat_number', 'registration_number'
    ) -> Result[Dict[str, Any], str]:
        """
        📧 Create user and request to join existing customer
        Puts user in pending state and notifies existing owners
        """
        
        try:
            # Step 1: Find existing customer
            existing_customer = cls._find_customer_by_identifier(
                company_identifier, 
                identification_type
            )
            
            if not existing_customer:
                return Err(_("No customer found with provided company information"))
            
            # Step 2: Create user in pending state
            user = User.objects.create_user(
                username=user_data['email'],  # Django requirement
                email=user_data['email'],
                first_name=user_data['first_name'],
                last_name=user_data['last_name'],
                phone=user_data.get('phone', ''),
                accepts_marketing=user_data.get('accepts_marketing', False),
                gdpr_consent_date=user_data.get('gdpr_consent_date'),
                is_active=False,  # 🚨 Pending approval
            )
            
            # Step 3: Create pending membership request
            membership = CustomerMembership.objects.create(
                user=user,
                customer=existing_customer,
                role='viewer',  # Default role, can be changed by owner
                is_primary=False,
            )
            
            # Step 4: Notify existing owners
            cls._notify_owners_of_join_request(existing_customer, user)
            
            return Ok({
                'user': user,
                'customer': existing_customer,
                'membership': membership,
                'status': 'pending_approval'
            })
            
        except Exception as e:
            return Err(f"Join request failed: {str(e)}")


class CustomerUserService:
    """
    🔗 Service for managing customer-user relationships
    Handles user creation, linking, and welcome emails with proper i18n
    """
    
    @classmethod
    @transaction.atomic
    def create_user_for_customer(
        cls, 
        customer, 
        first_name: str = "", 
        last_name: str = "", 
        send_welcome: bool = True,
        created_by=None
    ) -> Result[Tuple[User, bool], str]:
        """
        Create a user account for a customer
        Returns: (user, email_sent)
        """
        try:
            # Check if user already exists
            if User.objects.filter(email=customer.primary_email).exists():
                return Err(_("User with email {email} already exists").format(email=customer.primary_email))
            
            # Extract names if not provided
            if not first_name and not last_name and customer.name:
                name_parts = customer.name.split()
                first_name = name_parts[0] if name_parts else ''
                last_name = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''
            
            # Create user (no username field in this project)
            user = User.objects.create_user(
                email=customer.primary_email,
                first_name=first_name,
                last_name=last_name,
                phone=customer.primary_phone or '',
                is_active=True,
                created_by=created_by
            )
            user.set_unusable_password()
            user.save()
            
            # Create membership
            from .models import CustomerMembership
            CustomerMembership.objects.create(
                user=user,
                customer=customer,
                role='owner',
                is_primary=True,
                created_by=created_by
            )
            
            # Send welcome email
            email_sent = False
            if send_welcome:
                email_sent = cls._send_welcome_email(user, customer)
            
            logger.info(f"✅ [CustomerUser] Created user {user.email} for customer {customer.name}")
            return Ok((user, email_sent))
            
        except Exception as e:
            logger.error(f"🔥 [CustomerUser] Failed to create user: {str(e)}")
            return Err(_("Failed to create user: {error}").format(error=str(e)))
    
    @classmethod
    def link_existing_user(
        cls, 
        user: User, 
        customer, 
        role: str = 'owner',
        is_primary: bool = False,
        created_by=None
    ) -> Result[Any, str]:
        """Link an existing user to a customer"""
        try:
            from .models import CustomerMembership
            
            # Check if membership already exists
            existing = CustomerMembership.objects.filter(user=user, customer=customer).first()
            if existing:
                return Err(_("User {email} is already linked to customer {customer}").format(
                    email=user.email, 
                    customer=customer.name
                ))
            
            # Create membership
            membership = CustomerMembership.objects.create(
                user=user,
                customer=customer,
                role=role,
                is_primary=is_primary,
                created_by=created_by
            )
            
            logger.info(f"✅ [CustomerUser] Linked user {user.email} to customer {customer.name} as {role}")
            return Ok(membership)
            
        except Exception as e:
            logger.error(f"🔥 [CustomerUser] Failed to link user: {str(e)}")
            return Err(_("Failed to link user: {error}").format(error=str(e)))
    
    @classmethod
    def _send_welcome_email(cls, user: User, customer) -> bool:
        """Send welcome email with password reset link"""
        try:
            from django.contrib.auth.tokens import default_token_generator
            from django.utils.encoding import force_bytes
            from django.utils.http import urlsafe_base64_encode
            from django.template.loader import render_to_string
            from django.core.mail import send_mail
            from django.conf import settings
            
            # Generate password reset token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            # Prepare email context
            context = {
                'user': user,
                'customer': customer,
                'domain': settings.DOMAIN_NAME if hasattr(settings, 'DOMAIN_NAME') else 'localhost:8000',
                'uid': uid,
                'token': token,
                'protocol': 'https' if hasattr(settings, 'USE_HTTPS') and settings.USE_HTTPS else 'http',
            }
            
            # Render email templates
            subject = _('Welcome to PRAHO - Account Created for {customer_name}').format(customer_name=customer.name)
            text_message = render_to_string('customers/emails/welcome_email.txt', context)
            html_message = render_to_string('customers/emails/welcome_email.html', context)
            
            # Send email
            send_mail(
                subject=subject,
                message=text_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False
            )
            
            logger.info(f"📧 [CustomerUser] Welcome email sent to {user.email}")
            return True
            
        except Exception as e:
            logger.error(f"📧 [CustomerUser] Failed to send welcome email: {str(e)}")
            return False
    
    @classmethod 
    def invite_user_to_customer(
        cls,
        inviter,
        invitee_email: str,
        customer,
        role: str = 'viewer'
    ) -> Result[CustomerMembership, str]:
        """
        📤 Existing customer owner invites new user
        Creates user account and membership in pending state
        """
        
        # Check permissions
        if not inviter.can_access_customer(customer):
            return Err(_("You don't have permission to invite users to this organization"))
        
        owner_membership = CustomerMembership.objects.filter(
            user=inviter, 
            customer=customer, 
            role='owner'
        ).first()
        
        if not owner_membership:
            return Err(_("Only organization owners can invite new users"))
        
        try:
            # Check if user already exists
            existing_user = User.objects.filter(email=invitee_email).first()
            
            if existing_user:
                # Check if already member
                existing_membership = CustomerMembership.objects.filter(
                    user=existing_user,
                    customer=customer
                ).first()
                
                if existing_membership:
                    return Err(_("User is already a member of this organization"))
                
                # Add to existing user
                membership = CustomerMembership.objects.create(
                    user=existing_user,
                    customer=customer,
                    role=role,
                    is_primary=False,
                )
            else:
                # Create new user account (inactive until they accept)
                user = User.objects.create_user(
                    username=invitee_email,  # Django requirement
                    email=invitee_email,
                    is_active=False,  # Will be activated when they accept invite
                )
                
                membership = CustomerMembership.objects.create(
                    user=user,
                    customer=customer,
                    role=role,
                    is_primary=False,
                )
            
            # Send invitation email
            cls._send_invitation_email(membership, inviter)
            
            return Ok(membership)
            
        except Exception as e:
            return Err(f"Invitation failed: {str(e)}")
    
    # ===============================================================================
    # HELPER METHODS
    # ===============================================================================
    
    @classmethod
    def _check_existing_customer(cls, customer_data: Dict[str, Any]) -> Result[None, str]:
        """Check if customer organization already exists"""
        
        company_name = customer_data.get('company_name', '').strip()
        vat_number = customer_data.get('vat_number', '').strip()
        registration_number = customer_data.get('registration_number', '').strip()
        
        # Check by company name (fuzzy match)
        if Customer.objects.filter(company_name__iexact=company_name).exists():
            return Err(_("A company with this name already exists"))
        
        # Check by VAT number
        if vat_number and CustomerTaxProfile.objects.filter(vat_number=vat_number).exists():
            return Err(_("A company with this VAT number already exists"))
        
        # Check by registration number  
        if registration_number and CustomerTaxProfile.objects.filter(registration_number=registration_number).exists():
            return Err(_("A company with this registration number already exists"))
        
        return Ok(None)
    
    @classmethod
    def _find_customer_by_identifier(
        cls, 
        identifier: str, 
        identification_type: str
    ) -> Optional[Customer]:
        """Find existing customer by various identifiers"""
        
        if identification_type == 'name':
            return Customer.objects.filter(company_name__iexact=identifier).first()
        elif identification_type == 'vat_number':
            tax_profile = CustomerTaxProfile.objects.filter(vat_number=identifier).first()
            return tax_profile.customer if tax_profile else None
        elif identification_type == 'registration_number':
            tax_profile = CustomerTaxProfile.objects.filter(registration_number=identifier).first()
            return tax_profile.customer if tax_profile else None
        
        return None
    
    @classmethod
    def _notify_owners_of_join_request(cls, customer, requesting_user):
        """Notify existing owners of join request"""
        
        owners = User.objects.filter(
            customer_memberships__customer=customer,
            customer_memberships__role='owner',
        )
        
        for owner in owners:
            send_mail(
                subject=f'[PragmaticHost] New join request for {customer.company_name}',
                message=f'''
Hello {owner.get_full_name()},

{requesting_user.get_full_name()} ({requesting_user.email}) has requested to join your organization "{customer.company_name}".

Please review this request in your PragmaticHost dashboard.

Best regards,
PragmaticHost Team
                ''',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[owner.email],
                fail_silently=False,
            )
    
    @classmethod
    def _send_invitation_email(cls, membership, inviter):
        """Send invitation email to user"""
        
        user = membership.user
        customer = membership.customer
        
        send_mail(
            subject=f'[PragmaticHost] Invitation to join {customer.company_name}',
            message=f'''
Hello,

{inviter.get_full_name()} has invited you to join "{customer.company_name}" on PragmaticHost.

Click here to accept the invitation: [Accept Invitation Link]

Best regards,
PragmaticHost Team
            ''',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
