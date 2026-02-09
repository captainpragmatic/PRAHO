"""
Order Input Validators for PRAHO Portal
Comprehensive validation for order inputs with Romanian compliance.
"""

import logging
import re
from typing import Any

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

logger = logging.getLogger(__name__)


class OrderInputValidator:
    """Centralized validation for order inputs with security focus"""
    
    # Romanian hosting provider specific configurations
    ALLOWED_BILLING_PERIODS = {
        'monthly', 'quarterly', 'semiannual', 'annual', 'biennial', 'triennial'
    }
    
    # Domain validation with international support
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    # Configuration whitelists by product type
    ALLOWED_CONFIG_KEYS = {
        'shared_hosting': {
            'php_version', 'control_panel', 'ssl_type', 'backup_frequency',
            'server_location', 'email_accounts'
        },
        'vps': {
            'os_type', 'server_location', 'control_panel', 'cpu_cores',
            'ram_gb', 'storage_gb', 'backup_frequency'
        },
        'dedicated': {
            'os_type', 'server_location', 'raid_config', 'cpu_model',
            'ram_gb', 'storage_type', 'network_speed'
        },
        'domain': {
            'privacy_protection', 'auto_renew', 'transfer_lock'
        },
        'ssl': {
            'validation_type', 'wildcard', 'extended_validation'
        }
    }

    @staticmethod
    def validate_quantity(quantity: Any) -> int:
        """Validate and normalize quantity with Romanian error messages"""
        try:
            qty = int(quantity)
            if qty < 1:
                raise ValidationError(_("Cantitatea trebuie să fie cel puțin 1"))
            if qty > 50:
                raise ValidationError(_("Cantitatea nu poate depăși 50"))
            return qty
        except (ValueError, TypeError):
            raise ValidationError(_("Cantitate nevalidă"))
    
    @staticmethod
    def validate_billing_period(period: str) -> str:
        """Validate billing period against allowed values"""
        if not period or period not in OrderInputValidator.ALLOWED_BILLING_PERIODS:
            raise ValidationError(_("Perioada de facturare nevalidă"))
        return period
    
    @staticmethod
    def validate_domain_name(domain: str) -> str:
        """Validate domain name format with security checks"""
        if not domain:
            return ''
        
        # Sanitize input
        domain = domain.lower().strip()
        
        # Security check: prevent injection attempts
        if any(char in domain for char in ['<', '>', '"', "'", '&', ';']):
            raise ValidationError(_("Nume de domeniu conține caractere nevalide"))
        
        # Length validation
        if len(domain) > 253:
            raise ValidationError(_("Nume de domeniu prea lung"))
        
        # Format validation
        if not OrderInputValidator.DOMAIN_PATTERN.match(domain):
            raise ValidationError(_("Format nume de domeniu nevalid"))
            
        return domain
    
    @staticmethod
    def validate_product_slug(slug: str) -> str:
        """Validate product slug format for URL safety"""
        if not slug:
            raise ValidationError(_("Identificator produs lipsă"))
        
        # Allow only alphanumeric, hyphens, and underscores
        if not re.match(r'^[a-zA-Z0-9\-_]+$', slug):
            raise ValidationError(_("Identificator produs nevalid"))
        
        if len(slug) > 100:
            raise ValidationError(_("Identificator produs prea lung"))
            
        return slug.lower()
    
    @staticmethod
    def validate_config(config: dict[str, Any], product_type: str) -> dict[str, Any]:
        """Validate product configuration based on type with security filtering"""
        if not config:
            return {}
        
        # Get allowed keys for this product type
        allowed_keys = OrderInputValidator.ALLOWED_CONFIG_KEYS.get(product_type, set())
        
        # Filter config to only allowed keys
        validated_config = {}
        for key, value in config.items():
            if key in allowed_keys:
                # Additional validation for specific config types
                if key.endswith('_version') and isinstance(value, str):
                    # Validate version strings (PHP, MySQL, etc.)
                    if not re.match(r'^[a-zA-Z0-9\.\-_]+$', value):
                        continue  # Skip invalid versions
                elif key.endswith('_gb') and isinstance(value, int | str):
                    # Validate numeric values for GB configs
                    try:
                        numeric_value = int(value)
                        if 1 <= numeric_value <= 1000:  # Reasonable limits
                            value = numeric_value
                        else:
                            continue  # Skip invalid values
                    except (ValueError, TypeError):
                        continue
                elif isinstance(value, str):
                    # General string validation - prevent injection
                    if len(value) > 100 or any(char in value for char in ['<', '>', '"', "'"]):
                        continue  # Skip potentially dangerous values
                
                validated_config[key] = value
        
        logger.info(f"🔒 [Orders] Config validated for {product_type}: {len(validated_config)} valid keys")
        return validated_config
    
    @staticmethod
    def validate_notes(notes: str) -> str:
        """Validate customer notes with length and content limits"""
        if not notes:
            return ''
        
        # Trim whitespace and limit length
        notes = notes.strip()
        if len(notes) > 500:
            raise ValidationError(_("Notele nu pot depăși 500 de caractere"))
        
        # Basic security check - prevent script injection
        if any(pattern in notes.lower() for pattern in ['<script', 'javascript:', 'alert(', 'eval(']):
            raise ValidationError(_("Notele conțin conținut nevalid"))
        
        return notes
