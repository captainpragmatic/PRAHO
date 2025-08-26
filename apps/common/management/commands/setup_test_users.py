"""
Test user setup command - only for testing environments
"""
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

User = get_user_model()

class Command(BaseCommand):
    help = 'Create test users for E2E testing (test environments only)'

    def handle(self, *args, **options):
        # Strict test-only enforcement
        if not settings.DEBUG:
            raise CommandError("❌ This command only runs in DEBUG mode")
        
        if 'test' not in settings.DATABASES['default']['NAME'].lower():
            raise CommandError("❌ This command requires a test database")

        # Create consistent test users
        self._create_test_admin()
        self._create_test_support()
        
        self.stdout.write(
            self.style.SUCCESS('✅ Test users created successfully')
        )

    def _create_test_admin(self):
        """Create admin user for E2E tests"""
        email = 'admin@example.com'
        if not User.objects.filter(email=email).exists():
            User.objects.create_user(
                email=email,
                password='admin123',  # Only for tests
                first_name='Test',
                last_name='Admin',
                is_superuser=True,
                is_staff=True
            )
            self.stdout.write(f'✓ Test admin: {email}')

    def _create_test_support(self):
        """Create support user for E2E tests"""
        email = 'support@example.com'
        if not User.objects.filter(email=email).exists():
            User.objects.create_user(
                email=email,
                password='support123',  # Only for tests
                first_name='Test',
                last_name='Support',
                role='support'
            )
            self.stdout.write(f'✓ Test support: {email}')
