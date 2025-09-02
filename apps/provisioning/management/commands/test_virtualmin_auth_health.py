"""
Management command to test Virtualmin authentication health across all servers.

This command implements the testing strategy from virtualmin_review.md
to validate all authentication methods and detect ACL failures early.

Usage:
    python manage.py test_virtualmin_auth_health
    python manage.py test_virtualmin_auth_health --server-id <uuid>
    python manage.py test_virtualmin_auth_health --method acl
"""

from django.core.management.base import BaseCommand, CommandError

from apps.provisioning.virtualmin_auth_manager import get_virtualmin_auth_manager, test_acl_authentication_health
from apps.provisioning.virtualmin_models import VirtualminServer


class Command(BaseCommand):
    """Test Virtualmin authentication health across all servers."""
    
    help = 'Test Virtualmin authentication methods and detect ACL failures'

    def add_arguments(self, parser) -> None:
        """Add command arguments."""
        parser.add_argument(
            '--server-id',
            type=str,
            help='Test specific server by UUID'
        )
        
        parser.add_argument(
            '--method',
            type=str,
            choices=['acl', 'master_proxy', 'ssh_sudo'],
            help='Test specific authentication method'
        )
        
        parser.add_argument(
            '--fix-failures',
            action='store_true',
            help='Attempt to fix authentication failures automatically'
        )

    def handle(self, *args, **options) -> None:
        """Execute the authentication health test."""
        
        self.stdout.write(
            self.style.SUCCESS("🔐 Testing Virtualmin Authentication Health...")
        )
        
        if options['server_id']:
            self._test_single_server(options['server_id'], options)
        else:
            self._test_all_servers(options)
            
    def _test_single_server(self, server_id: str, options: dict) -> None:
        """Test authentication on a single server."""
        try:
            server = VirtualminServer.objects.get(id=server_id)
        except VirtualminServer.DoesNotExist as e:
            raise CommandError(f"Server with ID {server_id} not found") from e
            
        self.stdout.write(f"Testing server: {server.hostname}")
        
        with get_virtualmin_auth_manager(server) as auth_manager:
            health_results = auth_manager.health_check_all_methods()
            
            self._display_server_results(server, health_results, options)
            
    def _test_all_servers(self, options: dict) -> None:
        """Test authentication on all active servers."""
        
        # Get overall health summary
        health_summary = test_acl_authentication_health()
        
        self._display_summary(health_summary)
        
        # Display detailed results for each server
        for server_detail in health_summary['server_details']:
            self.stdout.write(f"\n📊 Server: {server_detail['hostname']}")
            
            # Get the server object for detailed testing
            try:
                server = VirtualminServer.objects.get(id=server_detail['server_id'])
                
                if options.get('fix_failures') and server_detail['status'] != 'acl_healthy':
                    self._attempt_fix(server, server_detail)
                    
            except VirtualminServer.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f"❌ Server {server_detail['server_id']} not found in database")
                )
                continue
                
    def _display_summary(self, health_summary: dict) -> None:
        """Display overall health summary."""
        
        self.stdout.write("\n" + "="*60)
        self.stdout.write("🎯 AUTHENTICATION HEALTH SUMMARY")
        self.stdout.write("="*60)
        
        total = health_summary['servers_tested']
        acl_working = health_summary['acl_working']
        acl_failed = health_summary['acl_failed']
        fallback_working = health_summary['fallback_working']
        completely_failed = health_summary['completely_failed']
        
        # Overall health percentage
        healthy_percentage = (acl_working / total * 100) if total > 0 else 0
        
        if healthy_percentage >= 90:
            status_style = self.style.SUCCESS
            status_emoji = "✅"
        elif healthy_percentage >= 70:
            status_style = self.style.WARNING
            status_emoji = "⚠️"
        else:
            status_style = self.style.ERROR
            status_emoji = "🚨"
            
        self.stdout.write(
            status_style(f"{status_emoji} Overall ACL Health: {healthy_percentage:.1f}%")
        )
        
        self.stdout.write(f"📈 Servers tested: {total}")
        self.stdout.write(
            self.style.SUCCESS(f"✅ ACL working: {acl_working}")
        )
        
        if acl_failed > 0:
            self.stdout.write(
                self.style.ERROR(f"❌ ACL failed: {acl_failed}")
            )
            
        if fallback_working > 0:
            self.stdout.write(
                self.style.WARNING(f"🔄 Fallback available: {fallback_working}")
            )
            
        if completely_failed > 0:
            self.stdout.write(
                self.style.ERROR(f"🔥 Complete failures: {completely_failed}")
            )
            
        # Risk assessment
        if acl_failed > 0:
            self.stdout.write("\n🚨 ACL AUTHENTICATION RISK DETECTED!")
            self.stdout.write(
                self.style.ERROR(
                    f"   {acl_failed} servers have failed ACL authentication."
                )
            )
            self.stdout.write(
                "   This suggests Virtualmin may have 'fixed' the ACL workaround."
            )
            self.stdout.write(
                "   Consider migrating to supported authentication methods."
            )
            
    def _display_server_results(
        self, 
        server: VirtualminServer, 
        health_results: dict, 
        options: dict
    ) -> None:
        """Display detailed results for a single server."""
        
        self.stdout.write(f"\n🖥️  Server: {server.hostname}")
        self.stdout.write(f"   Status: {server.status}")
        self.stdout.write(f"   API Port: {server.api_port}")
        
        for method_name, result in health_results.items():
            if options.get('method') and method_name != options['method']:
                continue
                
            if result.success:
                response_time = f" ({result.response_time_ms}ms)" if result.response_time_ms else ""
                self.stdout.write(
                    self.style.SUCCESS(f"   ✅ {method_name}: Working{response_time}")
                )
            else:
                self.stdout.write(
                    self.style.ERROR(f"   ❌ {method_name}: {result.error}")
                )
                
        # Overall server assessment
        working_methods = sum(1 for result in health_results.values() if result.success)
        
        if working_methods == 0:
            self.stdout.write(
                self.style.ERROR("   🔥 CRITICAL: No authentication methods working!")
            )
        elif not health_results.get('acl', {}).success:
            self.stdout.write(
                self.style.WARNING("   ⚠️  ACL authentication failed - using fallback")
            )
        else:
            self.stdout.write(
                self.style.SUCCESS("   🎯 All authentication methods healthy")
            )
            
    def _attempt_fix(self, server: VirtualminServer, server_detail: dict) -> None:
        """Attempt to fix authentication failures automatically."""
        
        self.stdout.write(f"🔧 Attempting to fix authentication for {server.hostname}...")
        
        # This is where you'd implement automatic fixes:
        # 1. Check if ACL user exists and recreate if needed
        # 2. Verify SSH keys are properly deployed
        # 3. Test sudo permissions
        # 4. Update cached authentication preferences
        
        # For now, just display what would be done
        self.stdout.write(
            self.style.WARNING("   Fix mode not yet implemented - would:")
        )
        self.stdout.write("   - Verify ACL user permissions")
        self.stdout.write("   - Check SSH key deployment") 
        self.stdout.write("   - Validate sudo rules")
        self.stdout.write("   - Update authentication cache")
