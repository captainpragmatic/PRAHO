"""
Management command to set up Romanian and EU tax rules.
Populates the TaxRule model with current VAT rates for Romanian hosting business.
"""

from datetime import date
from decimal import Decimal
from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.billing.models import TaxRule


class Command(BaseCommand):
    help = 'Set up Romanian and EU VAT tax rules for hosting business'

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force recreation of existing tax rules',
        )

    def _get_romanian_tax_rules_data(self, today: date) -> list[dict[str, Any]]:
        """Get Romanian VAT rules configuration."""
        return [
            {
                'country_code': 'RO',
                'tax_type': 'vat',
                'rate': Decimal('0.19'),  # 19% standard VAT
                'valid_from': today,
                'applies_to_b2b': True,
                'applies_to_b2c': True,
                'reverse_charge_eligible': True,
                'is_eu_member': True,
                'vies_required': True,
                'meta': {
                    'description': 'Romanian standard VAT rate',
                    'legal_reference': 'Romanian Tax Code Art. 140',
                    'notes': 'Standard rate for hosting services'
                }
            }
        ]

    def _get_eu_tax_rules_data(self) -> list[dict[str, Any]]:
        """Get EU countries VAT rates."""
        return [
            # Germany
            {'country_code': 'DE', 'rate': Decimal('0.19'), 'reduced_rate': Decimal('0.07')},
            # France
            {'country_code': 'FR', 'rate': Decimal('0.20'), 'reduced_rate': Decimal('0.055')},
            # Italy
            {'country_code': 'IT', 'rate': Decimal('0.22'), 'reduced_rate': Decimal('0.04')},
            # Spain
            {'country_code': 'ES', 'rate': Decimal('0.21'), 'reduced_rate': Decimal('0.04')},
            # Netherlands
            {'country_code': 'NL', 'rate': Decimal('0.21'), 'reduced_rate': Decimal('0.09')},
            # Poland
            {'country_code': 'PL', 'rate': Decimal('0.23'), 'reduced_rate': Decimal('0.05')},
            # Czech Republic
            {'country_code': 'CZ', 'rate': Decimal('0.21'), 'reduced_rate': Decimal('0.10')},
            # Hungary
            {'country_code': 'HU', 'rate': Decimal('0.27'), 'reduced_rate': Decimal('0.05')},
            # Bulgaria
            {'country_code': 'BG', 'rate': Decimal('0.20'), 'reduced_rate': Decimal('0.09')},
        ]

    def _process_tax_rule(self, rule_data: dict[str, Any], force: bool) -> tuple[int, int]:
        """Process a single tax rule. Returns (created_count, updated_count)."""
        existing = TaxRule.objects.filter(
            country_code=rule_data['country_code'],
            tax_type=rule_data['tax_type'],
            valid_from=rule_data['valid_from']
        ).first()

        if existing and not force:
            self.stdout.write(f"  ⏭️  Skipping existing: {existing}")
            return 0, 0

        if existing and force:
            # Update existing
            for key, value in rule_data.items():
                setattr(existing, key, value)
            existing.save()
            self.stdout.write(f"  ✅ Updated: {existing}")
            return 0, 1
        else:
            # Create new
            rule = TaxRule.objects.create(**rule_data)
            self.stdout.write(f"  ✅ Created: {rule}")
            return 1, 0

    def _create_romanian_rules(self, today: date, force: bool) -> tuple[int, int]:
        """Create Romanian tax rules."""
        created_count = 0
        updated_count = 0
        
        romanian_rules = self._get_romanian_tax_rules_data(today)
        for rule_data in romanian_rules:
            created, updated = self._process_tax_rule(rule_data, force)
            created_count += created
            updated_count += updated
            
        return created_count, updated_count

    def _create_eu_rules(self, today: date, force: bool) -> tuple[int, int]:
        """Create EU countries tax rules."""
        created_count = 0
        updated_count = 0
        
        eu_vat_rules = self._get_eu_tax_rules_data()
        for eu_rule in eu_vat_rules:
            rule_data = {
                'country_code': eu_rule['country_code'],
                'tax_type': 'vat',
                'rate': eu_rule['rate'],
                'reduced_rate': eu_rule.get('reduced_rate'),
                'valid_from': today,
                'applies_to_b2b': True,
                'applies_to_b2c': True,
                'reverse_charge_eligible': True,
                'is_eu_member': True,
                'vies_required': True,
                'meta': {
                    'description': f'{eu_rule["country_code"]} standard VAT rate',
                    'notes': 'EU member state VAT for cross-border transactions'
                }
            }
            
            created, updated = self._process_tax_rule(rule_data, force)
            created_count += created
            updated_count += updated
            
        return created_count, updated_count

    def _create_non_eu_rules(self, today: date, force: bool) -> tuple[int, int]:
        """Create non-EU countries tax rules."""
        created_count = 0
        updated_count = 0
        
        non_eu_countries = ['US', 'GB', 'CH', 'NO', 'CA', 'AU']
        for country_code in non_eu_countries:
            rule_data = {
                'country_code': country_code,
                'tax_type': 'vat',
                'rate': Decimal('0.00'),  # No VAT
                'valid_from': today,
                'applies_to_b2b': False,
                'applies_to_b2c': False,
                'reverse_charge_eligible': False,
                'is_eu_member': False,
                'vies_required': False,
                'meta': {
                    'description': f'{country_code} - Non-EU, no VAT',
                    'notes': 'Non-EU country, VAT not applicable for Romanian provider'
                }
            }
            
            created, updated = self._process_tax_rule(rule_data, force)
            created_count += created
            updated_count += updated
            
        return created_count, updated_count

    def _print_summary(self, created_count: int, updated_count: int) -> None:
        """Print setup summary and verification info."""
        self.stdout.write("\n" + "="*60)
        self.stdout.write("📊 Tax Rules Setup Complete!")
        self.stdout.write(f"   ✅ Created: {created_count} new rules")
        if updated_count > 0:
            self.stdout.write(f"   🔄 Updated: {updated_count} existing rules")
        self.stdout.write(f"   📍 Total active rules: {TaxRule.objects.count()}")

        # Show Romanian rules for verification
        self.stdout.write("\n🇷🇴 Romanian VAT Rules:")
        romanian_rules = TaxRule.objects.filter(country_code='RO')
        for rule in romanian_rules:
            rate_display = f"{rule.rate * 100:.0f}%"
            self.stdout.write(f"   • {rule.tax_type.upper()} {rate_display} - {rule.meta.get('description', 'N/A')}")

        self.stdout.write("\n🔍 Quick test:")
        test_rate = TaxRule.get_active_rate('RO', 'vat')
        self.stdout.write(f"   Current Romanian VAT rate: {test_rate * 100:.0f}%")

        self.stdout.write("\n💡 Next steps:")
        self.stdout.write("   1. Set up payment retry policies: python manage.py setup_dunning_policies")
        self.stdout.write("   2. Configure VAT validation in settings")
        self.stdout.write("   3. Test VAT calculation in orders/invoices")

    def handle(self, *args: Any, **options: Any) -> None:
        """Set up tax rules for Romanian hosting provider"""
        force = options.get('force', False)
        today = timezone.now().date()
        
        self.stdout.write("🏛️  Setting up Romanian and EU VAT tax rules...")

        # Create all tax rules
        total_created = 0
        total_updated = 0
        
        created, updated = self._create_romanian_rules(today, force)
        total_created += created
        total_updated += updated
        
        created, updated = self._create_eu_rules(today, force)
        total_created += created
        total_updated += updated
        
        created, updated = self._create_non_eu_rules(today, force)
        total_created += created
        total_updated += updated

        self._print_summary(total_created, total_updated)
