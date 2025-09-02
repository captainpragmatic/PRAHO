"""
Management command for credential rotation and monitoring.

Implements the rotation workflow from virtualmin_review.md:
- Automatic monthly rotation
- Manual on-demand rotation  
- Rotation failure handling
- Monitoring and alerting

Usage:
    python manage.py rotate_credentials
    python manage.py rotate_credentials --service virtualmin
    python manage.py rotate_credentials --identifier server.example.com
    python manage.py rotate_credentials --test-only
"""

from argparse import ArgumentParser
from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import models
from django.utils import timezone

from apps.common.credential_vault import CredentialVault, EncryptedCredential, get_credential_vault

# Expiry urgency constants
CRITICAL_EXPIRY_DAYS = 3  # <= 3 days for critical urgency
WARNING_EXPIRY_DAYS = 7   # <= 7 days for warning urgency


class Command(BaseCommand):
    """Rotate credentials and monitor rotation health."""
    
    help = 'Rotate credentials and monitor rotation health'

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            '--service',
            type=str,
            help='Rotate credentials for specific service type'
        )
        
        parser.add_argument(
            '--identifier',
            type=str,
            help='Rotate credential for specific identifier'
        )
        
        parser.add_argument(
            '--test-only',
            action='store_true',
            help='Test rotation without actually changing credentials'
        )
        
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force rotation even if not expired'
        )
        
        parser.add_argument(
            '--max-age-days',
            type=int,
            default=30,
            help='Maximum age in days before forcing rotation'
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """Execute credential rotation"""
        
        self.stdout.write(
            self.style.SUCCESS('🔄 Starting credential rotation...')
        )
        
        try:
            vault = get_credential_vault()
            
            if options['service'] and options['identifier']:
                # Rotate specific credential
                self._rotate_specific_credential(
                    vault, 
                    options['service'], 
                    options['identifier'],
                    options['test_only'],
                    options['force']
                )
            else:
                # Rotate expired/aging credentials
                self._rotate_aging_credentials(
                    vault,
                    options['service'],
                    options['max_age_days'],
                    options['test_only'],
                    options['force']
                )
                
            # Show rotation summary
            self._show_rotation_summary(vault)
            
            self.stdout.write(
                self.style.SUCCESS('✅ Credential rotation complete!')
            )
            
        except Exception as e:
            raise CommandError(f"Rotation failed: {e}") from e
            
    def _rotate_specific_credential(self, vault: CredentialVault, service_type: str, identifier: str, test_only: bool, force: bool) -> None:
        """Rotate a specific credential"""
        self.stdout.write(f'🎯 Rotating {service_type}:{identifier}...')
        
        if test_only:
            self.stdout.write(
                self.style.WARNING('⚠️ TEST MODE: No actual rotation will occur')
            )
            
            # Just test if credential exists and can be accessed
            result = vault.get_credential(
                service_type=service_type,
                service_identifier=identifier,
                reason='Rotation test'
            )
            
            if result.is_ok():
                self.stdout.write(
                    self.style.SUCCESS('✅ Credential found and accessible')
                )
            else:
                self.stdout.write(
                    self.style.ERROR(f'❌ Credential test failed: {result.unwrap_err()}')
                )
            return
            
        # Perform actual rotation
        result = vault.rotate_credential(
            service_type=service_type,
            service_identifier=identifier,
            reason='Manual rotation via management command'
        )
        
        if result.is_ok():
            self.stdout.write(
                self.style.SUCCESS(f'✅ Successfully rotated {service_type}:{identifier}')
            )
        else:
            self.stdout.write(
                self.style.ERROR(f'❌ Rotation failed: {result.unwrap_err()}')
            )
            
    def _rotate_aging_credentials(self, vault: CredentialVault, service_filter: str | None, max_age_days: int, test_only: bool, force: bool) -> None:
        """Rotate credentials that are aging or expired"""
        
        # Find credentials that need rotation
        cutoff_date = timezone.now() - timedelta(days=max_age_days)
        
        query = EncryptedCredential.objects.filter(is_active=True)
        
        if service_filter:
            query = query.filter(service_type=service_filter)
            
        if force:
            # Force rotation of all matching credentials
            credentials_to_rotate = list(query)
        else:
            # Only rotate expired or old credentials
            credentials_to_rotate = list(
                query.filter(
                    models.Q(expires_at__lt=timezone.now()) |  # Expired
                    models.Q(created_at__lt=cutoff_date)       # Old
                )
            )
            
        if not credentials_to_rotate:
            self.stdout.write('✅ No credentials need rotation')
            return
            
        self.stdout.write(f'🔄 Found {len(credentials_to_rotate)} credentials to rotate')
        
        if test_only:
            self.stdout.write(
                self.style.WARNING('⚠️ TEST MODE: Listing credentials that would be rotated')
            )
            for cred in credentials_to_rotate:
                age_days = (timezone.now() - cred.created_at).days
                status = "EXPIRED" if cred.is_expired else f"{age_days} days old"
                self.stdout.write(f'  • {cred} - {status}')
            return
            
        # Perform rotations
        success_count = 0
        failure_count = 0
        
        for cred in credentials_to_rotate:
            self.stdout.write(f'🔄 Rotating {cred}...')
            
            result = vault.rotate_credential(
                service_type=cred.service_type,
                service_identifier=cred.service_identifier,
                reason='Automatic rotation due to age/expiration'
            )
            
            if result.is_ok():
                success_count += 1
                self.stdout.write(
                    self.style.SUCCESS('  ✅ Success')
                )
            else:
                failure_count += 1
                self.stdout.write(
                    self.style.ERROR(f'  ❌ Failed: {result.unwrap_err()}')
                )
                
        self.stdout.write(
            self.style.SUCCESS(f'📊 Rotation Summary: {success_count} success, {failure_count} failed')
        )
        
    def _show_rotation_summary(self, vault: CredentialVault) -> None:
        """Show rotation status and health"""
        self.stdout.write('\n📊 Rotation Health Summary:')
        
        # Get overall vault status
        status = vault.get_vault_health_status()
        
        # Show key metrics
        self.stdout.write(f'🟢 Active Credentials: {status["active_credentials"]}')
        self.stdout.write(f'🔴 Expired: {status["expired_credentials"]}')
        self.stdout.write(f'🟡 Expiring Soon: {status["expiring_soon"]}')
        
        if status["failed_rotations"] > 0:
            self.stdout.write(
                self.style.ERROR(f'❌ Failed Rotations: {status["failed_rotations"]}')
            )
            
            # Show which credentials have rotation failures
            failed_creds = EncryptedCredential.objects.filter(
                rotation_failure_count__gt=0,
                is_active=True
            )
            
            self.stdout.write('\n🚨 Credentials with rotation failures:')
            for cred in failed_creds:
                self.stdout.write(
                    f'  • {cred} - {cred.rotation_failure_count} failures'
                )
                
        # Show credentials expiring soon
        expiring = vault.get_credentials_expiring_soon()
        if expiring:
            self.stdout.write('\n⏰ Credentials Expiring Soon:')
            for cred in expiring:
                days_left = cred.days_until_expiry
                urgency_icon = '🚨' if days_left <= CRITICAL_EXPIRY_DAYS else '⚠️' if days_left <= WARNING_EXPIRY_DAYS else '🟡'
                self.stdout.write(f'  {urgency_icon} {cred} - {days_left} days')
                
        # Rotation recommendations
        self.stdout.write('\n💡 Recommendations:')
        
        if status["expired_credentials"] > 0:
            self.stdout.write('  • Run immediate rotation for expired credentials')
            
        if status["expiring_soon"] > 0:
            self.stdout.write('  • Schedule rotation for credentials expiring soon')
            
        if status["failed_rotations"] > 0:
            self.stdout.write('  • Investigate and fix rotation failures')
            
        if status["vault_healthy"]:
            self.stdout.write('  ✅ Vault is healthy - continue regular monitoring')
