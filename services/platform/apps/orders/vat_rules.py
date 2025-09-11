"""
Order-Specific VAT Rules for PRAHO Platform
Comprehensive EU VAT compliance for Romanian hosting provider.
🔒 Security: Server-computed VAT only with full audit logging.
"""

import logging
from dataclasses import dataclass
from decimal import Decimal
from typing import Dict, List, Optional, Tuple
from enum import Enum

from django.utils import timezone
from apps.audit.services import AuditService

logger = logging.getLogger(__name__)


class VATScenario(Enum):
    """VAT calculation scenarios for audit logging"""
    ROMANIA_B2C = "romania_b2c"           # Romanian consumer
    ROMANIA_B2B = "romania_b2b"           # Romanian business
    EU_B2C = "eu_b2c"                     # EU consumer
    EU_B2B_REVERSE_CHARGE = "eu_b2b_reverse"  # EU business (reverse charge)
    NON_EU_ZERO_VAT = "non_eu_zero"       # Non-EU customer
    

@dataclass
class VATCalculationResult:
    """Result of VAT calculation with audit trail"""
    scenario: VATScenario
    vat_rate: Decimal
    subtotal_cents: int
    vat_cents: int
    total_cents: int
    country_code: str
    is_business: bool
    vat_number: Optional[str]
    reasoning: str
    audit_data: Dict


class OrderVATCalculator:
    """
    🔒 Server-authoritative VAT calculator for orders
    Implements Romanian hosting provider VAT rules with EU compliance.
    """
    
    # VAT rates by country (as of 2024)
    VAT_RATES = {
        'RO': Decimal('21.0'),    # Romania - home country (updated)
        'AT': Decimal('20.0'),    # Austria
        'BE': Decimal('21.0'),    # Belgium
        'BG': Decimal('20.0'),    # Bulgaria
        'CY': Decimal('19.0'),    # Cyprus
        'CZ': Decimal('21.0'),    # Czech Republic
        'DE': Decimal('19.0'),    # Germany
        'DK': Decimal('25.0'),    # Denmark
        'EE': Decimal('20.0'),    # Estonia
        'ES': Decimal('21.0'),    # Spain
        'FI': Decimal('24.0'),    # Finland
        'FR': Decimal('20.0'),    # France
        'GR': Decimal('24.0'),    # Greece
        'HR': Decimal('25.0'),    # Croatia
        'HU': Decimal('27.0'),    # Hungary
        'IE': Decimal('23.0'),    # Ireland
        'IT': Decimal('22.0'),    # Italy
        'LT': Decimal('21.0'),    # Lithuania
        'LU': Decimal('17.0'),    # Luxembourg
        'LV': Decimal('21.0'),    # Latvia
        'MT': Decimal('18.0'),    # Malta
        'NL': Decimal('21.0'),    # Netherlands
        'PL': Decimal('23.0'),    # Poland
        'PT': Decimal('23.0'),    # Portugal
        'SE': Decimal('25.0'),    # Sweden
        'SI': Decimal('22.0'),    # Slovenia
        'SK': Decimal('20.0'),    # Slovakia
    }
    
    # EU member states
    EU_COUNTRIES = set(VAT_RATES.keys())
    
    @classmethod
    def calculate_vat(
        cls,
        subtotal_cents: int,
        customer_country: str,
        is_business: bool = False,
        vat_number: Optional[str] = None,
        customer_id: Optional[str] = None,
        order_id: Optional[str] = None
    ) -> VATCalculationResult:
        """
        🔒 Calculate VAT for order with full compliance and audit logging.
        
        Args:
            subtotal_cents: Order subtotal in cents
            customer_country: ISO 2-letter country code
            is_business: Whether customer is a business
            vat_number: Customer's VAT number (if business)
            customer_id: For audit logging
            order_id: For audit logging
            
        Returns:
            VATCalculationResult with full audit trail
        """
        
        country_code = customer_country.upper()
        
        # Determine VAT scenario
        scenario, vat_rate = cls._determine_vat_scenario(
            country_code, is_business, vat_number
        )
        
        # Calculate VAT amounts
        if vat_rate == Decimal('0.0'):
            vat_cents = 0
        else:
            # VAT = subtotal * (vat_rate / 100)
            vat_amount = Decimal(subtotal_cents) * (vat_rate / Decimal('100'))
            vat_cents = int(vat_amount.quantize(Decimal('1')))  # Round to nearest cent
        
        total_cents = subtotal_cents + vat_cents
        
        # Generate reasoning for audit
        reasoning = cls._generate_vat_reasoning(scenario, country_code, is_business, vat_number)
        
        # Create audit data
        audit_data = {
            'scenario': scenario.value,
            'country_code': country_code,
            'is_business': is_business,
            'vat_number': vat_number,
            'vat_rate_percent': str(vat_rate),
            'subtotal_cents': subtotal_cents,
            'vat_cents': vat_cents,
            'total_cents': total_cents,
            'customer_id': customer_id,
            'order_id': order_id,
            'calculated_at': timezone.now().isoformat(),
            'reasoning': reasoning
        }
        
        result = VATCalculationResult(
            scenario=scenario,
            vat_rate=vat_rate,
            subtotal_cents=subtotal_cents,
            vat_cents=vat_cents,
            total_cents=total_cents,
            country_code=country_code,
            is_business=is_business,
            vat_number=vat_number,
            reasoning=reasoning,
            audit_data=audit_data
        )
        
        # 🔒 SECURITY: Log VAT calculation for audit compliance
        cls._audit_vat_calculation(result)
        
        return result
    
    @classmethod
    def _determine_vat_scenario(
        cls,
        country_code: str,
        is_business: bool,
        vat_number: Optional[str]
    ) -> Tuple[VATScenario, Decimal]:
        """Determine VAT scenario and rate"""
        
        # Romania (home country) - always apply Romanian VAT
        if country_code == 'RO':
            vat_rate = cls.VAT_RATES['RO']
            if is_business:
                return VATScenario.ROMANIA_B2B, vat_rate
            else:
                return VATScenario.ROMANIA_B2C, vat_rate
        
        # EU member states
        elif country_code in cls.EU_COUNTRIES:
            if is_business and vat_number:
                # B2B EU: Reverse charge (0% VAT, customer pays in their country)
                return VATScenario.EU_B2B_REVERSE_CHARGE, Decimal('0.0')
            else:
                # B2C EU: Apply customer country VAT rate
                vat_rate = cls.VAT_RATES.get(country_code, Decimal('20.0'))  # Default 20%
                return VATScenario.EU_B2C, vat_rate
        
        # Non-EU countries
        else:
            # Non-EU: 0% VAT (export)
            return VATScenario.NON_EU_ZERO_VAT, Decimal('0.0')
    
    @classmethod
    def _generate_vat_reasoning(
        cls,
        scenario: VATScenario,
        country_code: str,
        is_business: bool,
        vat_number: Optional[str]
    ) -> str:
        """Generate human-readable reasoning for VAT calculation"""
        
        if scenario == VATScenario.ROMANIA_B2C:
            return f"Romanian consumer - apply Romanian VAT {cls.VAT_RATES['RO']}%"
        
        elif scenario == VATScenario.ROMANIA_B2B:
            return f"Romanian business - apply Romanian VAT {cls.VAT_RATES['RO']}%"
        
        elif scenario == VATScenario.EU_B2C:
            vat_rate = cls.VAT_RATES.get(country_code, Decimal('20.0'))
            return f"EU consumer ({country_code}) - apply destination country VAT {vat_rate}%"
        
        elif scenario == VATScenario.EU_B2B_REVERSE_CHARGE:
            return f"EU business ({country_code}) with VAT number {vat_number} - reverse charge 0%"
        
        elif scenario == VATScenario.NON_EU_ZERO_VAT:
            return f"Non-EU country ({country_code}) - export, 0% VAT"
        
        else:
            return "Unknown VAT scenario"
    
    @classmethod
    def _audit_vat_calculation(cls, result: VATCalculationResult) -> None:
        """🔒 Log VAT calculation for compliance audit"""
        
        try:
            AuditService.log_event(
                event_type='order_vat_calculation',
                object_type='order',
                object_id=result.audit_data.get('order_id'),
                user_id=None,  # System calculation
                customer_id=result.audit_data.get('customer_id'),
                data=result.audit_data,
                description=f"VAT calculated: {result.scenario.value} - {result.reasoning}"
            )
            
            logger.info(
                f"💰 [VAT] {result.scenario.value}: "
                f"{result.subtotal_cents}¢ + {result.vat_cents}¢ VAT = {result.total_cents}¢ "
                f"({result.country_code}, business={result.is_business})"
            )
            
        except Exception as e:
            # Don't fail order on audit logging error, but log it
            logger.error(f"🔥 [VAT] Audit logging failed: {e}")
    
    @classmethod
    def validate_vat_number(cls, vat_number: str, country_code: str) -> bool:
        """
        Basic VAT number format validation.
        Note: For production, integrate with EU VIES system for real validation.
        """
        if not vat_number:
            return False
        
        # Remove spaces and convert to uppercase
        vat_clean = vat_number.replace(' ', '').upper()
        
        # Basic format checks by country
        vat_patterns = {
            'RO': r'^RO\d{2,10}$',           # Romania: RO + 2-10 digits
            'DE': r'^DE\d{9}$',              # Germany: DE + 9 digits  
            'FR': r'^FR[A-Z0-9]{2}\d{9}$',   # France: FR + 2 chars + 9 digits
            'GB': r'^GB\d{9}(\d{3})?$',      # UK: GB + 9 or 12 digits
            'IT': r'^IT\d{11}$',             # Italy: IT + 11 digits
            # Add more as needed
        }
        
        pattern = vat_patterns.get(country_code)
        if pattern:
            import re
            return bool(re.match(pattern, vat_clean))
        
        # For countries without specific patterns, basic length check
        return len(vat_clean) >= 4 and len(vat_clean) <= 15
    
    @classmethod
    def get_vat_rates_for_country(cls, country_code: str) -> Dict[str, any]:
        """Get VAT information for a specific country"""
        
        country_code = country_code.upper()
        
        return {
            'country_code': country_code,
            'is_eu': country_code in cls.EU_COUNTRIES,
            'vat_rate': cls.VAT_RATES.get(country_code, Decimal('0.0')),
            'requires_vat_number_for_reverse_charge': country_code in cls.EU_COUNTRIES and country_code != 'RO'
        }
