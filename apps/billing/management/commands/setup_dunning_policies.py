"""
Management command to set up payment retry policies for dunning campaigns.
Creates standard retry schedules for different customer tiers and payment scenarios.
"""

from django.core.management.base import BaseCommand
from apps.billing.models import PaymentRetryPolicy


class Command(BaseCommand):
    help = 'Set up payment retry policies for failed payment recovery'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force recreation of existing policies',
        )

    def handle(self, *args, **options):
        """Set up standard payment retry policies"""
        
        force = options.get('force', False)
        created_count = 0
        updated_count = 0
        
        self.stdout.write("💳 Setting up payment retry policies...")
        
        # Standard retry policies for different scenarios
        policies = [
            {
                'name': 'Standard Hosting',
                'description': 'Default policy for regular hosting customers',
                'retry_intervals_days': [1, 3, 7, 14],  # 4 attempts over 2 weeks
                'max_attempts': 4,
                'suspend_service_after_days': 21,  # 3 weeks
                'terminate_service_after_days': 60,  # 2 months
                'send_dunning_emails': True,
                'email_template_prefix': 'dunning_standard',
                'is_default': True,
                'is_active': True,
                'meta': {
                    'description': 'Balanced approach for most customers',
                    'target_segment': 'Individual and small business customers',
                    'recovery_rate': 'Expected 25-30%'
                }
            },
            {
                'name': 'VIP Customer',
                'description': 'Extended grace period for VIP customers',
                'retry_intervals_days': [1, 3, 7, 14, 21, 30],  # 6 attempts over 1 month
                'max_attempts': 6,
                'suspend_service_after_days': 45,  # 6+ weeks
                'terminate_service_after_days': 90,  # 3 months
                'send_dunning_emails': True,
                'email_template_prefix': 'dunning_vip',
                'is_default': False,
                'is_active': True,
                'meta': {
                    'description': 'Extended grace for high-value customers',
                    'target_segment': 'Enterprise and VIP customers',
                    'recovery_rate': 'Expected 35-40%'
                }
            },
            {
                'name': 'Low Value Service',
                'description': 'Aggressive collection for low-value services',
                'retry_intervals_days': [1, 3, 7],  # 3 attempts over 1 week
                'max_attempts': 3,
                'suspend_service_after_days': 14,  # 2 weeks
                'terminate_service_after_days': 30,  # 1 month
                'send_dunning_emails': True,
                'email_template_prefix': 'dunning_basic',
                'is_default': False,
                'is_active': True,
                'meta': {
                    'description': 'Quick resolution for low-value services',
                    'target_segment': 'Customers with services < €10/month',
                    'recovery_rate': 'Expected 20-25%'
                }
            },
            {
                'name': 'Trial Customer',
                'description': 'Gentle approach for trial customers',
                'retry_intervals_days': [2, 5, 10],  # 3 attempts over 10 days
                'max_attempts': 3,
                'suspend_service_after_days': 15,  # 2+ weeks
                'terminate_service_after_days': 30,  # 1 month
                'send_dunning_emails': True,
                'email_template_prefix': 'dunning_trial',
                'is_default': False,
                'is_active': True,
                'meta': {
                    'description': 'Educational approach for new customers',
                    'target_segment': 'Customers in trial period',
                    'recovery_rate': 'Expected 15-20%'
                }
            },
            {
                'name': 'Domain Only',
                'description': 'Domain service specific policy',
                'retry_intervals_days': [1, 7, 14, 30],  # 4 attempts over 1 month
                'max_attempts': 4,
                'suspend_service_after_days': 45,  # Before domain expires
                'terminate_service_after_days': None,  # Manual intervention
                'send_dunning_emails': True,
                'email_template_prefix': 'dunning_domain',
                'is_default': False,
                'is_active': True,
                'meta': {
                    'description': 'Domain-specific with expiration awareness',
                    'target_segment': 'Domain registration customers',
                    'recovery_rate': 'Expected 30-35%',
                    'notes': 'Careful timing to avoid domain expiration'
                }
            },
            {
                'name': 'High Risk',
                'description': 'Fast collection for high-risk customers',
                'retry_intervals_days': [1, 2, 5],  # 3 attempts over 5 days
                'max_attempts': 3,
                'suspend_service_after_days': 7,   # 1 week
                'terminate_service_after_days': 14, # 2 weeks
                'send_dunning_emails': True,
                'email_template_prefix': 'dunning_risk',
                'is_default': False,
                'is_active': True,
                'meta': {
                    'description': 'Rapid collection for fraud risk',
                    'target_segment': 'Customers flagged as high risk',
                    'recovery_rate': 'Expected 10-15%'
                }
            },
            {
                'name': 'Test Policy',
                'description': 'Testing and development policy - DO NOT USE IN PRODUCTION',
                'retry_intervals_days': [1],  # 1 attempt only
                'max_attempts': 1,
                'suspend_service_after_days': 3,
                'terminate_service_after_days': 7,
                'send_dunning_emails': False,  # No emails in test
                'email_template_prefix': 'dunning_test',
                'is_default': False,
                'is_active': False,  # Inactive by default
                'meta': {
                    'description': 'For testing dunning system only',
                    'target_segment': 'Internal testing',
                    'recovery_rate': 'N/A - Testing only'
                }
            }
        ]
        
        # Create or update policies
        for policy_data in policies:
            existing = PaymentRetryPolicy.objects.filter(
                name=policy_data['name']
            ).first()
            
            if existing and not force:
                self.stdout.write(f"  ⏭️  Skipping existing: {existing.name}")
                continue
            
            if existing and force:
                # Update existing policy
                for key, value in policy_data.items():
                    setattr(existing, key, value)
                existing.save()
                updated_count += 1
                self.stdout.write(f"  🔄 Updated: {existing.name}")
            else:
                # Create new policy
                policy = PaymentRetryPolicy.objects.create(**policy_data)
                created_count += 1
                self.stdout.write(f"  ✅ Created: {policy.name}")
        
        # Ensure only one default policy
        default_policies = PaymentRetryPolicy.objects.filter(is_default=True)
        if default_policies.count() > 1:
            self.stdout.write("⚠️  Multiple default policies found, fixing...")
            # Keep first, remove default from others
            for policy in default_policies[1:]:
                policy.is_default = False
                policy.save()
                self.stdout.write(f"  🔧 Removed default from: {policy.name}")
        
        # Summary
        self.stdout.write("\n" + "="*60)
        self.stdout.write(f"📋 Payment Retry Policies Setup Complete!")
        self.stdout.write(f"   ✅ Created: {created_count} new policies")
        if updated_count > 0:
            self.stdout.write(f"   🔄 Updated: {updated_count} existing policies")
        self.stdout.write(f"   📊 Total policies: {PaymentRetryPolicy.objects.count()}")
        
        # Show active policies
        self.stdout.write("\n💳 Active Retry Policies:")
        active_policies = PaymentRetryPolicy.objects.filter(is_active=True).order_by('name')
        for policy in active_policies:
            attempts = len(policy.retry_intervals_days)
            max_days = max(policy.retry_intervals_days) if policy.retry_intervals_days else 0
            default_marker = " [DEFAULT]" if policy.is_default else ""
            self.stdout.write(f"   • {policy.name}{default_marker}")
            self.stdout.write(f"     └─ {attempts} attempts over {max_days} days")
            if policy.suspend_service_after_days:
                self.stdout.write(f"     └─ Suspend after {policy.suspend_service_after_days} days")
        
        # Show default policy details
        default_policy = PaymentRetryPolicy.objects.filter(is_default=True).first()
        if default_policy:
            self.stdout.write(f"\n🎯 Default Policy: {default_policy.name}")
            self.stdout.write(f"   Retry schedule: {default_policy.retry_intervals_days}")
            self.stdout.write(f"   Service suspension: {default_policy.suspend_service_after_days} days")
            self.stdout.write(f"   Service termination: {default_policy.terminate_service_after_days} days")
        
        self.stdout.write("\n💡 Next steps:")
        self.stdout.write("   1. Configure email templates for dunning campaigns")
        self.stdout.write("   2. Set up cron job for: python manage.py run_payment_collection")
        self.stdout.write("   3. Test with failed payments: python manage.py test_dunning_system")
        self.stdout.write("   4. Monitor collection runs in Django admin")
