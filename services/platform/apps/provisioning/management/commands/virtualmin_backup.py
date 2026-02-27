"""
Virtualmin Management Commands - PRAHO Platform
Django management commands for Virtualmin backup/restore operations.
"""

from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.provisioning.virtualmin_backup_service import BackupConfig, RestoreConfig, VirtualminBackupService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer


class Command(BaseCommand):
    """Manage Virtualmin backups and restores via command line."""

    help = "Manage Virtualmin domain backups and restores"

    def add_arguments(self, parser: ArgumentParser) -> None:
        subparsers = parser.add_subparsers(dest="action", help="Available actions")

        # Backup command
        backup_parser = subparsers.add_parser("backup", help="Create domain backup")
        backup_parser.add_argument("domain", help="Domain name to backup")
        backup_parser.add_argument(
            "--type", choices=["full", "incremental", "config_only"], default="full", help="Backup type"
        )
        backup_parser.add_argument("--no-email", action="store_true", help="Exclude email data")
        backup_parser.add_argument("--no-databases", action="store_true", help="Exclude databases")
        backup_parser.add_argument("--no-files", action="store_true", help="Exclude web files")
        backup_parser.add_argument("--no-ssl", action="store_true", help="Exclude SSL certificates")
        backup_parser.add_argument("--server", help="Specific server hostname")

        # Restore command
        restore_parser = subparsers.add_parser("restore", help="Restore domain from backup")
        restore_parser.add_argument("domain", help="Domain name to restore")
        restore_parser.add_argument("backup_id", help="Backup ID to restore from")
        restore_parser.add_argument("--no-email", action="store_true", help="Skip email restore")
        restore_parser.add_argument("--no-databases", action="store_true", help="Skip database restore")
        restore_parser.add_argument("--no-files", action="store_true", help="Skip files restore")
        restore_parser.add_argument("--no-ssl", action="store_true", help="Skip SSL restore")
        restore_parser.add_argument("--target-server", help="Target server hostname")

        # List backups command
        list_parser = subparsers.add_parser("list", help="List available backups")
        list_parser.add_argument("--domain", help="Filter by domain")
        list_parser.add_argument("--type", help="Filter by backup type")
        list_parser.add_argument("--max-age", type=int, default=90, help="Maximum age in days")

        # Delete backup command
        delete_parser = subparsers.add_parser("delete", help="Delete backup")
        delete_parser.add_argument("backup_id", help="Backup ID to delete")
        delete_parser.add_argument("--confirm", action="store_true", help="Confirm deletion")

        # Status command
        status_parser = subparsers.add_parser("status", help="Check backup/restore status")
        status_parser.add_argument("operation_id", help="Backup or restore operation ID")

    def handle(self, *args: Any, **options: Any) -> None:
        action = options.get("action")

        if not action:
            self.print_help("manage.py", "virtualmin_backup")
            return

        try:
            if action == "backup":
                self._handle_backup(options)
            elif action == "restore":
                self._handle_restore(options)
            elif action == "list":
                self._handle_list(options)
            elif action == "delete":
                self._handle_delete(options)
            elif action == "status":
                self._handle_status(options)
            else:
                raise CommandError(f"Unknown action: {action}")

        except Exception as e:
            raise CommandError(f"Command failed: {e}") from e

    def _handle_backup(self, options: dict[str, Any]) -> None:
        """Handle backup command."""
        domain = options["domain"]

        # Find Virtualmin account
        try:
            account = VirtualminAccount.objects.select_related("service").get(domain=domain)
        except VirtualminAccount.DoesNotExist as e:
            raise CommandError(f"Virtualmin account for domain '{domain}' not found") from e

        # Get server
        server = account.server
        if options.get("server"):
            try:
                server = VirtualminServer.objects.get(hostname=options["server"])
            except VirtualminServer.DoesNotExist as e:
                raise CommandError(f"Server '{options['server']}' not found") from e

        # Initialize backup service
        backup_service = VirtualminBackupService(server)

        # Execute backup
        self.stdout.write(f"Starting {options['type']} backup for domain: {domain}")

        config = BackupConfig(
            backup_type=options["type"],
            include_email=not options.get("no_email", False),
            include_databases=not options.get("no_databases", False),
            include_files=not options.get("no_files", False),
            include_ssl=not options.get("no_ssl", False),
        )
        result = backup_service.backup_domain(account=account, config=config)

        if result.is_err():
            raise CommandError(f"Backup failed: {result.unwrap_err()}")

        backup_info = result.unwrap()
        self.stdout.write(self.style.SUCCESS("Backup completed successfully!"))
        self.stdout.write(f"Backup ID: {backup_info['backup_id']}")
        self.stdout.write(f"Created: {backup_info['created_at']}")

    def _handle_restore(self, options: dict[str, Any]) -> None:
        """Handle restore command."""
        domain = options["domain"]
        backup_id = options["backup_id"]

        # Find Virtualmin account
        try:
            account = VirtualminAccount.objects.select_related("service").get(domain=domain)
        except VirtualminAccount.DoesNotExist as e:
            raise CommandError(f"Virtualmin account for domain '{domain}' not found") from e

        # Get target server
        target_server = account.server
        if options.get("target_server"):
            try:
                target_server = VirtualminServer.objects.get(hostname=options["target_server"])
            except VirtualminServer.DoesNotExist as e:
                raise CommandError(f"Target server '{options['target_server']}' not found") from e

        # Initialize backup service
        backup_service = VirtualminBackupService(target_server)

        # Execute restore
        self.stdout.write(f"Starting restore for domain: {domain}")
        self.stdout.write(f"From backup: {backup_id}")

        restore_config = RestoreConfig(
            backup_id=backup_id,
            restore_email=not options.get("no_email", False),
            restore_databases=not options.get("no_databases", False),
            restore_files=not options.get("no_files", False),
            restore_ssl=not options.get("no_ssl", False),
        )
        result = backup_service.restore_domain(account=account, config=restore_config, target_server=target_server)

        if result.is_err():
            raise CommandError(f"Restore failed: {result.unwrap_err()}")

        restore_info = result.unwrap()
        self.stdout.write(self.style.SUCCESS("Restore completed successfully!"))
        self.stdout.write(f"Restore ID: {restore_info['restore_id']}")
        self.stdout.write(f"Completed: {restore_info['completed_at']}")

    def _find_account_by_domain(self, domain: str) -> VirtualminAccount | None:
        """Find VirtualminAccount by domain name."""
        if not domain:
            return None
        try:
            return VirtualminAccount.objects.get(domain=domain)
        except VirtualminAccount.DoesNotExist as e:
            raise CommandError(f"Domain '{domain}' not found") from e

    def _get_active_server(self) -> VirtualminServer:
        """Get an active Virtualmin server for backup operations."""
        try:
            server = VirtualminServer.objects.filter(status="active").first()
            if not server:
                raise CommandError("No active Virtualmin servers found")
            return server
        except Exception as e:
            raise CommandError("No Virtualmin servers configured") from e

    def _get_backup_features(self, backup: dict[str, Any]) -> list[str]:
        """Extract enabled features from backup metadata."""
        features = []
        feature_map = {
            "include_email": "email",
            "include_databases": "databases",
            "include_files": "files",
            "include_ssl": "ssl",
        }

        for key, name in feature_map.items():
            if backup.get(key):
                features.append(name)
        return features

    def _display_backup_info(self, backup: dict[str, Any]) -> None:
        """Display information for a single backup."""
        self.stdout.write(f"Backup ID: {backup['backup_id']}")
        self.stdout.write(f"  Domain: {backup['domain']}")
        self.stdout.write(f"  Type: {backup['backup_type']}")
        self.stdout.write(f"  Created: {backup['created_at']}")
        self.stdout.write(f"  Status: {backup['status']}")

        features = self._get_backup_features(backup)
        if features:
            self.stdout.write(f"  Features: {', '.join(features)}")
        self.stdout.write("")

    def _handle_list(self, options: dict[str, Any]) -> None:
        """Handle list backups command."""
        domain = options.get("domain")
        account = self._find_account_by_domain(domain or "")
        server = self._get_active_server()
        backup_service = VirtualminBackupService(server)

        # List backups
        result = backup_service.list_backups(
            account=account, backup_type=options.get("type"), max_age_days=options["max_age"]
        )

        if result.is_err():
            raise CommandError(f"Failed to list backups: {result.unwrap_err()}")

        backups = result.unwrap()

        if not backups:
            self.stdout.write("No backups found matching criteria")
            return

        self.stdout.write(f"\nFound {len(backups)} backup(s):\n")

        for backup in backups:
            self._display_backup_info(backup)

    def _handle_delete(self, options: dict[str, Any]) -> None:
        """Handle delete backup command."""
        backup_id = options["backup_id"]

        if not options.get("confirm"):
            self.stdout.write(
                self.style.WARNING(f"Are you sure you want to delete backup '{backup_id}'? Add --confirm to proceed.")
            )
            return

        # Use any server for deletion (backups are centralized in S3)
        try:
            server = VirtualminServer.objects.filter(status="active").first()
            if not server:
                raise CommandError("No active Virtualmin servers found")
        except Exception as e:
            raise CommandError("No Virtualmin servers configured") from e

        backup_service = VirtualminBackupService(server)

        # Delete backup
        result = backup_service.delete_backup(backup_id)

        if result.is_err():
            raise CommandError(f"Failed to delete backup: {result.unwrap_err()}")

        delete_info = result.unwrap()
        self.stdout.write(self.style.SUCCESS(f"Backup '{backup_id}' deleted successfully!"))
        self.stdout.write(f"Deleted {delete_info['deleted_objects']} objects")

    def _handle_status(self, options: dict[str, Any]) -> None:
        """Handle status check command."""
        operation_id = options["operation_id"]

        # Use any server for status check
        try:
            server = VirtualminServer.objects.filter(status="active").first()
            if not server:
                raise CommandError("No active Virtualmin servers found")
        except Exception as e:
            raise CommandError("No Virtualmin servers configured") from e

        backup_service = VirtualminBackupService(server)

        # Check both backup and restore status
        backup_status = backup_service.get_backup_status(operation_id)
        restore_status = backup_service.get_restore_status(operation_id)

        if backup_status["status"] != "unknown":
            self.stdout.write(f"Backup Status for '{operation_id}':")
            self.stdout.write(f"  Status: {backup_status['status']}")
            self.stdout.write(f"  Progress: {backup_status['progress']}%")
            if "updated_at" in backup_status:
                self.stdout.write(f"  Updated: {backup_status['updated_at']}")

        elif restore_status["status"] != "unknown":
            self.stdout.write(f"Restore Status for '{operation_id}':")
            self.stdout.write(f"  Status: {restore_status['status']}")
            self.stdout.write(f"  Progress: {restore_status['progress']}%")
            if "updated_at" in restore_status:
                self.stdout.write(f"  Updated: {restore_status['updated_at']}")

        else:
            self.stdout.write(f"No status found for operation '{operation_id}'")
