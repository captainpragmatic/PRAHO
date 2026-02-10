"""
Order-Specific VAT Rules for PRAHO Platform
Comprehensive EU VAT compliance for Romanian hosting provider.
🔒 Security: Server-computed VAT only with full audit logging.
"""

import logging
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal
from enum import Enum
from typing import TypedDict

from django.utils import timezone

from apps.common.validators import log_security_event

logger = logging.getLogger(__name__)


class VATScenario(Enum):
    """VAT calculation scenarios for audit logging"""
    ROMANIA_B2C = "romania_b2c"           # Romanian consumer
    ROMANIA_B2B = "romania_b2b"           # Romanian business
    EU_B2C = "eu_b2c"                     # EU consumer
    EU_B2B_REVERSE_CHARGE = "eu_b2b_reverse"  # EU business (reverse charge)
    NON_EU_ZERO_VAT = "non_eu_zero"       # Non-EU customer


class CustomerVATInfo(TypedDict, total=False):
    """Customer VAT information for calculation"""
    country: str
    is_business: bool
    vat_number: str | None
    customer_id: str | None
    order_id: str | None


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
    vat_number: str | None
    reasoning: str
    audit_data: dict


class OrderVATCalculator:
    """
    🔒 Server-authoritative VAT calculator for orders
    Implements Romanian hosting provider VAT rules with EU compliance.
    """
    
    # IMPORTANT: VAT rates are now managed centrally via TaxService
    # This provides a single source of truth for all tax calculations

    @classmethod
    def _get_vat_rate(cls, country_code: str) -> Decimal:
        """Get VAT rate from centralized TaxService."""
        from apps.common.tax_service import TaxService
        return TaxService.get_vat_rate(country_code, as_decimal=False)

    @classmethod
    def _get_eu_countries(cls) -> set[str]:
        """Get EU countries from centralized TaxService."""
        from apps.common.tax_service import TaxService
        return TaxService.get_eu_countries()
    
    @classmethod
    def calculate_vat(
        cls,
        subtotal_cents: int,
        customer_info: CustomerVATInfo
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
        # Extract customer information
        country_code = customer_info['country'].upper()
        is_business = customer_info.get('is_business', False)
        vat_number = customer_info.get('vat_number')
        customer_id = customer_info.get('customer_id')
        order_id = customer_info.get('order_id')

        # Determine VAT scenario
        scenario, vat_rate = cls._determine_vat_scenario(
            country_code, is_business, vat_number
        )
        
        # Calculate VAT amounts
        if vat_rate == Decimal('0.0'):
            vat_cents = 0
        else:
            # Calculate VAT: subtotal * (vat_rate / 100)
            vat_amount = Decimal(subtotal_cents) * (vat_rate / Decimal('100'))
            # Use banker's rounding (round half to even) for financial consistency
            vat_cents = int(vat_amount.quantize(Decimal('1'), rounding=ROUND_HALF_EVEN))
        
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
        vat_number: str | None
    ) -> tuple[VATScenario, Decimal]:
        """
        Determine VAT scenario and rate - CONSERVATIVE APPROACH
        Default to Romanian VAT when uncertain for compliance
        """

        # Normalize and validate country code
        country_code = country_code.upper().strip() if country_code else 'RO'

        # Romania (home country) - always apply Romanian VAT
        if country_code == 'RO' or country_code in ['ROMANIA', 'ROMÂNIA']:
            vat_rate = cls._get_vat_rate('RO')
            if is_business:
                return VATScenario.ROMANIA_B2B, vat_rate
            else:
                return VATScenario.ROMANIA_B2C, vat_rate

        # EU member states with valid codes
        elif country_code in cls._get_eu_countries():
            if is_business and vat_number:
                # B2B EU: Reverse charge (0% VAT, customer pays in their country)
                return VATScenario.EU_B2B_REVERSE_CHARGE, Decimal('0.0')
            else:
                # B2C EU: Apply customer country VAT rate
                vat_rate = cls._get_vat_rate(country_code)
                return VATScenario.EU_B2C, vat_rate

        # Unknown/Invalid country codes - DEFAULT TO ROMANIAN VAT for compliance
        elif not country_code or len(country_code) != 2:
            # Apply Romanian VAT when country is unclear
            vat_rate = cls._get_vat_rate('RO')
            return VATScenario.ROMANIA_B2C, vat_rate  # Treat as consumer for safety

        # Non-EU countries with valid codes
        else:
            # Non-EU: 0% VAT (export) - only for clearly identified non-EU countries
            return VATScenario.NON_EU_ZERO_VAT, Decimal('0.0')
    
    @classmethod
    def _generate_vat_reasoning(
        cls,
        scenario: VATScenario,
        country_code: str,
        is_business: bool,
        vat_number: str | None
    ) -> str:
        """Generate human-readable reasoning for VAT calculation"""
        
        if scenario == VATScenario.ROMANIA_B2C:
            if country_code in ['RO', 'ROMANIA', 'ROMÂNIA']:
                return f"Romanian consumer - apply Romanian VAT {cls._get_vat_rate('RO')}%"
            else:
                return f"Unknown/Invalid country ({country_code}) - default to Romanian VAT {cls._get_vat_rate('RO')}% for compliance"

        elif scenario == VATScenario.ROMANIA_B2B:
            return f"Romanian business - apply Romanian VAT {cls._get_vat_rate('RO')}%"

        elif scenario == VATScenario.EU_B2C:
            vat_rate = cls._get_vat_rate(country_code)
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
            log_security_event(
                event_type="order_vat_calculation",
                details={
                    "scenario": result.scenario.value,
                    "reasoning": result.reasoning,
                    **result.audit_data,
                },
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
    def get_vat_rates_for_country(cls, country_code: str) -> dict[str, any]:
        """Get VAT information for a specific country"""
        
        country_code = country_code.upper()
        
        return {
            'country_code': country_code,
            'is_eu': country_code in cls._get_eu_countries(),
            'vat_rate': cls._get_vat_rate(country_code),
            'requires_vat_number_for_reverse_charge': country_code in cls._get_eu_countries() and country_code != 'RO'
        }
