"""
===============================================================================
🎯 GENERATE RANDOM AUDIT EVENTS - PRAHO Platform
===============================================================================
Management command to generate random audit events for pagination testing.
Creates realistic Romanian hosting provider audit trail with diverse events.
"""

import random
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.audit.models import AuditEvent

User = get_user_model()


class Command(BaseCommand):
    """Generate random audit events for testing pagination."""
    
    help = 'Generate random audit events for pagination testing'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--count',
            type=int,
            default=30,
            help='Number of random events to generate (default: 30)'
        )
        
    def handle(self, *args, **options):
        count = options['count']
        
        self.stdout.write(f"🎯 Generating {count} random audit events...")
        
        # Get some users for realistic events
        users = list(User.objects.all()[:5])  # Get up to 5 users
        if not users:
            self.stdout.write(
                self.style.WARNING("⚠️  No users found. Creating a test user...")
            )
            test_user = User.objects.create_user(
                email='test@example.com',
                first_name='Test',
                last_name='User'
            )
            users = [test_user]
        
        # Get content types for realistic object references
        content_types = list(ContentType.objects.all()[:10])
        
        # Sample IP addresses (Romanian hosting provider context)
        ip_addresses = [
            '192.168.1.100',
            '10.0.0.50', 
            '172.16.0.25',
            '94.177.232.15',  # Romanian IP range
            '89.136.15.44',   # Romanian IP range
            '31.14.128.22',   # Romanian IP range
        ]
        
        # Sample user agents
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0',
            'curl/7.68.0',  # API access
            'PostmanRuntime/7.32.3',  # API testing
        ]
        
        # Romanian business context descriptions
        descriptions = [
            'Customer login from București office',
            'Invoice generated for hosting services',
            'Domain renewal processed successfully',
            'SSL certificate installed for client domain',
            'Backup restoration completed',
            'Server maintenance window started',
            'Payment processed via Romanian bank transfer',
            'VAT compliance report generated',
            'Customer support ticket resolved',
            'Email hosting configuration updated',
            'DNS records modified for domain migration',
            'Hosting package upgraded to premium',
            'Security scan completed - no issues found',
            'Database backup verification successful',
            'Control panel access granted to customer',
            'Hosting service provisioned automatically',
            'Customer data export request processed',
            'GDPR compliance audit completed',
            'Server resource utilization monitored',
            'Customer notification email sent',
        ]
        
        events_created = 0
        
        for i in range(count):
            try:
                # Random timestamp within last 30 days
                days_ago = random.randint(0, 30)
                hours_ago = random.randint(0, 23)
                minutes_ago = random.randint(0, 59)
                
                timestamp = timezone.now() - timedelta(
                    days=days_ago, 
                    hours=hours_ago, 
                    minutes=minutes_ago
                )
                
                # Create random audit event
                event = AuditEvent.objects.create(
                    timestamp=timestamp,
                    user=random.choice(users) if random.random() > 0.1 else None,  # 10% system events
                    actor_type=random.choice(['user', 'system', 'api']),
                    action=random.choice([choice[0] for choice in AuditEvent.ACTION_CHOICES]),
                    content_type=random.choice(content_types),
                    object_id=str(random.randint(1, 1000)),  # Random object ID
                    ip_address=random.choice(ip_addresses),
                    user_agent=random.choice(user_agents),
                    description=random.choice(descriptions),
                    request_id=str(uuid.uuid4()),
                    session_key=f"session_{random.randint(100000, 999999)}",
                    old_values={
                        'status': random.choice(['active', 'pending', 'inactive']),
                        'value': random.randint(10, 500),
                    } if random.random() > 0.5 else {},
                    new_values={
                        'status': random.choice(['active', 'completed', 'verified']),
                        'value': random.randint(10, 500),
                        'updated_by': f'staff_{random.randint(1, 10)}',
                    } if random.random() > 0.3 else {},
                    metadata={
                        'source': random.choice(['web', 'api', 'system', 'mobile']),
                        'location': random.choice(['București', 'Cluj-Napoca', 'Timișoara', 'Iași']),
                        'severity': random.choice(['low', 'medium', 'high']),
                        'automated': random.choice([True, False]),
                    }
                )
                
                events_created += 1
                
                # Progress indicator
                if events_created % 10 == 0:
                    self.stdout.write(f"✅ Created {events_created}/{count} events...")
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"❌ Error creating event {i+1}: {e}")
                )
                continue
        
        self.stdout.write(
            self.style.SUCCESS(
                f"🎉 Successfully generated {events_created} random audit events!"
            )
        )
        
        # Show pagination info
        total_events = AuditEvent.objects.count()
        pages = (total_events + 49) // 50  # Ceiling division for 50 per page
        
        self.stdout.write(
            self.style.SUCCESS(
                f"📄 Total audit events: {total_events} (will show {pages} pages)"
            )
        )
        
        if total_events > 50:
            self.stdout.write(
                self.style.SUCCESS(
                    "🎯 Pagination will now be visible in the audit logs interface!"
                )
            )
