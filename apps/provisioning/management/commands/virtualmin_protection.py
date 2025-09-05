"""
Management command to manage Virtualmin account deletion protection.

Usage:
    python manage.py virtualmin_protection --enable --all
    python manage.py virtualmin_protection --disable --domain example.com
    python manage.py virtualmin_protection --status
"""

from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.provisioning.virtualmin_models import VirtualminAccount


class Command(BaseCommand):
    help = "Manage Virtualmin account deletion protection"

    def add_arguments(self, parser: Any) -> None:
        """Add command arguments"""
        parser.add_argument(
            '--enable',
            action='store_true',
            help='Enable deletion protection'
        )
        
        parser.add_argument(
            '--disable',
            action='store_true',
            help='Disable deletion protection'
        )
        
        parser.add_argument(
            '--status',
            action='store_true',
            help='Show protection status for all accounts'
        )
        
        parser.add_argument(
            '--all',
            action='store_true',
            help='Apply to all accounts'
        )
        
        parser.add_argument(
            '--domain',
            type=str,
            help='Apply to specific domain'
        )
        
        parser.add_argument(
            '--confirm',
            action='store_true',
            help='Confirm dangerous operations'
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """Handle the command"""
        if options['status']:
            self._show_status()
            return
            
        if options['enable'] and options['disable']:
            raise CommandError("Cannot enable and disable at the same time")
            
        if not options['enable'] and not options['disable']:
            raise CommandError("Must specify either --enable or --disable")
            
        if not options['all'] and not options['domain']:
            raise CommandError("Must specify either --all or --domain")
            
        if options['enable']:
            self._enable_protection(options)
        else:
            self._disable_protection(options)

    def _show_status(self) -> None:
        """Show protection status for all accounts"""
        accounts = VirtualminAccount.objects.select_related('server').order_by('domain')
        
        if not accounts.exists():
            self.stdout.write("No Virtualmin accounts found.")
            return
            
        self.stdout.write("\n🛡️  Virtualmin Account Protection Status\n")
        self.stdout.write("=" * 60)
        
        protected_count = 0
        unprotected_count = 0
        
        for account in accounts:
            status_icon = "🔒" if account.protected_from_deletion else "🔓"
            status_text = "PROTECTED" if account.protected_from_deletion else "UNPROTECTED"
            
            if account.protected_from_deletion:
                protected_count += 1
            else:
                unprotected_count += 1
                
            self.stdout.write(
                f"{status_icon} {account.domain:<30} {status_text:<12} [{account.status}]"
            )
        
        self.stdout.write("\n" + "=" * 60)
        self.stdout.write(f"Protected: {protected_count} | Unprotected: {unprotected_count}")

    @transaction.atomic
    def _enable_protection(self, options: dict[str, Any]) -> None:
        """Enable deletion protection"""
        accounts = self._get_accounts(options)
        
        if not accounts.exists():
            self.stdout.write("No accounts found matching criteria.")
            return
            
        updated_count = accounts.update(protected_from_deletion=True)
        
        self.stdout.write(
            self.style.SUCCESS(
                f"✅ Enabled deletion protection for {updated_count} account(s)"
            )
        )

    @transaction.atomic
    def _disable_protection(self, options: dict[str, Any]) -> None:
        """Disable deletion protection"""
        if not options['confirm']:
            raise CommandError(
                "⚠️  Disabling deletion protection is dangerous! "
                "Add --confirm flag to proceed."
            )
            
        accounts = self._get_accounts(options)
        
        if not accounts.exists():
            self.stdout.write("No accounts found matching criteria.")
            return
            
        # Show what will be affected
        display_limit = 10  # Maximum number of accounts to show in list
        self.stdout.write("⚠️  Will disable protection for:")
        for account in accounts[:display_limit]:  
            self.stdout.write(f"   • {account.domain} ({account.status})")
        
        if accounts.count() > display_limit:
            self.stdout.write(f"   ... and {accounts.count() - display_limit} more")
            
        # Final confirmation
        confirm = input("\nType 'I really am sure I want to do this!' to confirm: ")
        if confirm != "I really am sure I want to do this!":
            self.stdout.write("❌ Operation cancelled")
            return
            
        updated_count = accounts.update(protected_from_deletion=False)
        
        self.stdout.write(
            self.style.WARNING(
                f"⚠️  Disabled deletion protection for {updated_count} account(s)"
            )
        )

    def _get_accounts(self, options: dict[str, Any]) -> Any:
        """Get accounts based on options"""
        if options['all']:
            return VirtualminAccount.objects.all()
        elif options['domain']:
            return VirtualminAccount.objects.filter(domain=options['domain'])
        else:
            return VirtualminAccount.objects.none()
