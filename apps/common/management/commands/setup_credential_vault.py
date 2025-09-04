"""
Management command to set up credential vault and migrate environment variables.

This implements the migration strategy from virtualmin_review.md:
- Migrate existing environment variables to encrypted vault
- Test vault functionality
- Provide rollback capability

Usage:
    python manage.py setup_credential_vault
    python manage.py setup_credential_vault --migrate-env-vars
    python manage.py setup_credential_vault --test-vault
"""

from argparse import ArgumentParser
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.common.credential_vault import (
    CredentialData,
    CredentialVault,
    CredentialVaultError,
    EncryptedCredential,
    get_credential_vault,
)
from apps.provisioning.virtualmin_models import VirtualminServer


@dataclass
class MigrationCredential:
    """Data class to encapsulate credential migration parameters"""

    vault: Any  # CredentialVault
    service_type: str
    identifier: str
    username: str
    password: str
    description: str
    force: bool = False


class Command(BaseCommand):
    """Set up credential vault and migrate existing credentials."""

    help = "Set up credential vault and migrate environment variables"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("--migrate-env-vars", action="store_true", help="Migrate environment variables to vault")

        parser.add_argument("--test-vault", action="store_true", help="Test vault functionality")

        parser.add_argument("--force", action="store_true", help="Force migration even if credentials exist")

    def handle(self, *args: Any, **options: Any) -> None:
        """Execute credential vault setup"""

        self.stdout.write(self.style.SUCCESS("🔐 Setting up Credential Vault..."))

        try:
            # Initialize vault
            vault = get_credential_vault()

            if options["test_vault"]:
                self._test_vault(vault)

            if options["migrate_env_vars"]:
                self._migrate_environment_variables(vault, options["force"])

            # Show vault status
            self._show_vault_status(vault)

            self.stdout.write(self.style.SUCCESS("✅ Credential Vault setup complete!"))

        except CredentialVaultError as e:
            raise CommandError(f"Credential Vault error: {e}") from e
        except Exception as e:
            raise CommandError(f"Setup failed: {e}") from e

    def _test_vault(self, vault: CredentialVault) -> None:
        """Test vault functionality"""
        self.stdout.write("🧪 Testing credential vault...")

        # Test basic encryption/decryption
        test_service = "test"
        test_identifier = "vault_test"
        test_username = "test_user"
        test_password = "test_password_123"

        # Store test credential
        credential_data = CredentialData(
            service_type=test_service,
            service_identifier=test_identifier,
            username=test_username,
            password=test_password,
            reason="Vault functionality test",
        )
        store_result = vault.store_credential(credential_data)

        if store_result.is_err():
            raise CommandError(f"Store test failed: {store_result.unwrap_err()}")

        # Retrieve test credential
        get_result = vault.get_credential(
            service_type=test_service, service_identifier=test_identifier, reason="Vault functionality test"
        )

        if get_result.is_err():
            raise CommandError(f"Retrieve test failed: {get_result.unwrap_err()}")

        retrieved_username, retrieved_password, metadata = get_result.unwrap()

        if retrieved_username != test_username or retrieved_password != test_password:
            raise CommandError("Credential round-trip test failed")

        # Clean up test credential
        EncryptedCredential.objects.filter(service_type=test_service, service_identifier=test_identifier).delete()  # type: ignore[attr-defined]

        self.stdout.write(self.style.SUCCESS("✅ Vault functionality test passed"))

    def _migrate_environment_variables(self, vault: CredentialVault, force: bool = False) -> None:
        """Migrate environment variables to vault"""
        self.stdout.write("🔄 Migrating environment variables to vault...")

        migrated_count = 0

        # Migrate global Virtualmin credentials
        global_username = getattr(settings, "VIRTUALMIN_USERNAME", None)
        global_password = getattr(settings, "VIRTUALMIN_PASSWORD", None)

        if global_username and global_password:
            migration_cred = MigrationCredential(
                vault=vault,
                service_type="virtualmin",
                identifier="global",
                username=global_username,
                password=global_password,
                description="Global Virtualmin credentials",
                force=force,
            )
            self._migrate_credential(migration_cred)
            migrated_count += 1

        # Migrate multi-path auth credentials
        master_username = getattr(settings, "VIRTUALMIN_MASTER_USERNAME", None)
        master_password = getattr(settings, "VIRTUALMIN_MASTER_PASSWORD", None)

        if master_username and master_password:
            migration_cred = MigrationCredential(
                vault=vault,
                service_type="virtualmin",
                identifier="master_admin",
                username=master_username,
                password=master_password,
                description="Virtualmin master admin credentials",
                force=force,
            )
            self._migrate_credential(migration_cred)
            migrated_count += 1

        # Migrate SSH credentials
        ssh_username = getattr(settings, "VIRTUALMIN_SSH_USERNAME", None)
        ssh_password = getattr(settings, "VIRTUALMIN_SSH_PASSWORD", None)

        if ssh_username and ssh_password:
            migration_cred = MigrationCredential(
                vault=vault,
                service_type="ssh",
                identifier="virtualmin_servers",
                username=ssh_username,
                password=ssh_password,
                description="Virtualmin SSH credentials",
                force=force,
            )
            self._migrate_credential(migration_cred)
            migrated_count += 1

        # Migrate per-server credentials
        for server in VirtualminServer.objects.all():
            if server.api_username:
                try:
                    password = server.get_api_password()
                    if password:
                        migration_cred = MigrationCredential(
                            vault=vault,
                            service_type="virtualmin",
                            identifier=server.hostname,
                            username=server.api_username,
                            password=password,
                            description=f"Server {server.hostname} credentials",
                            force=force,
                        )
                        self._migrate_credential(migration_cred)
                        migrated_count += 1
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f"⚠️ Failed to migrate {server.hostname}: {e}"))

        self.stdout.write(self.style.SUCCESS(f"✅ Migrated {migrated_count} credentials to vault"))

        if migrated_count > 0:
            self.stdout.write(
                self.style.WARNING("⚠️ Remember to remove environment variables after testing vault integration!")
            )

    def _migrate_credential(self, migration_cred: MigrationCredential) -> None:
        """Migrate a single credential to vault"""

        # Check if credential already exists
        existing = migration_cred.vault.get_credential(
            service_type=migration_cred.service_type,
            service_identifier=migration_cred.identifier,
            reason="Migration check",
        )

        if existing.is_ok() and not migration_cred.force:
            self.stdout.write(self.style.WARNING(f"⚠️ Credential already exists: {migration_cred.description}"))
            return

        # Store credential in vault
        credential_data = CredentialData(
            service_type=migration_cred.service_type,
            service_identifier=migration_cred.identifier,
            username=migration_cred.username,
            password=migration_cred.password,
            reason="Environment variable migration",
        )
        result = migration_cred.vault.store_credential(credential_data)

        if result.is_ok():
            self.stdout.write(self.style.SUCCESS(f"✅ Migrated: {migration_cred.description}"))
        else:
            self.stdout.write(
                self.style.ERROR(f"❌ Failed to migrate {migration_cred.description}: {result.unwrap_err()}")
            )

    def _show_vault_status(self, vault: CredentialVault) -> None:
        """Show current vault status"""
        self.stdout.write("\n📊 Credential Vault Status:")

        status = vault.get_vault_health_status()

        # Health indicator
        health_icon = "✅" if status["vault_healthy"] else "❌"
        self.stdout.write(f"{health_icon} Vault Health: {'Healthy' if status['vault_healthy'] else 'Issues Detected'}")

        # Statistics
        self.stdout.write(f"📊 Total Credentials: {status['total_credentials']}")
        self.stdout.write(f"🟢 Active: {status['active_credentials']}")
        self.stdout.write(f"🔴 Expired: {status['expired_credentials']}")
        self.stdout.write(f"🟡 Expiring Soon: {status['expiring_soon']}")
        self.stdout.write(f"📈 Recent Access (24h): {status['recent_accesses_24h']}")

        if status["failed_rotations"] > 0:
            self.stdout.write(self.style.WARNING(f"⚠️ Failed Rotations: {status['failed_rotations']}"))

        # List expiring credentials
        expiring = vault.get_credentials_expiring_soon()
        if expiring:
            self.stdout.write("\n⏰ Credentials Expiring Soon:")
            for cred in expiring:
                days_left = cred.days_until_expiry
                self.stdout.write(f"  • {cred} - {days_left} days")

        self.stdout.write(f"\n🕐 Last Check: {status['last_check']}")
