"""Post-encryption upgrade status report.

Reports the state of data after the AES-256-GCM encryption upgrade,
showing what needs to be re-provisioned.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Report post-encryption upgrade status: what needs re-provisioning"

    def handle(self, *args: Any, **options: Any) -> None:
        self.stdout.write(self.style.MIGRATE_HEADING("\nPost-Encryption Upgrade Status Report"))
        self.stdout.write("=" * 60)

        self._report_2fa()
        self._report_servers()
        self._report_settings()
        self._report_oauth()
        self._report_vault()
        self._report_domain_credentials()

        self.stdout.write("\n" + "=" * 60)
        self.stdout.write(self.style.SUCCESS("Report complete."))

    def _report_2fa(self) -> None:
        from apps.users.models import User  # noqa: PLC0415

        total_users = User.objects.count()
        with_2fa = User.objects.filter(two_factor_enabled=True).count()
        without_secret = User.objects.filter(two_factor_enabled=False, _two_factor_secret="").count()

        self.stdout.write("\n2FA Status:")
        self.stdout.write(f"  Total users: {total_users}")
        self.stdout.write(f"  Active 2FA: {with_2fa}")
        self.stdout.write(f"  Need re-enrollment: {without_secret} (2FA was cleared)")

    def _report_servers(self) -> None:
        try:
            from apps.provisioning.service_models import Server  # noqa: PLC0415
            from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer  # noqa: PLC0415

            servers_empty = VirtualminServer.objects.filter(encrypted_api_password=b"").count()
            servers_total = VirtualminServer.objects.count()
            accounts_empty = VirtualminAccount.objects.filter(encrypted_password=b"").count()
            accounts_total = VirtualminAccount.objects.count()

            self.stdout.write("\nProvisioning Credentials:")
            self.stdout.write(f"  Servers needing API password: {servers_empty}/{servers_total}")
            self.stdout.write(f"  Accounts needing password: {accounts_empty}/{accounts_total}")

            mgmt_total = Server.objects.count()
            mgmt_empty = Server.objects.filter(management_api_key="").count()
            self.stdout.write(f"  Servers needing management API key: {mgmt_empty}/{mgmt_total}")
        except Exception as e:
            self.stdout.write(f"\nProvisioning: Could not check ({e})")

    def _report_settings(self) -> None:
        from apps.settings.models import SystemSetting  # noqa: PLC0415

        sensitive_total = SystemSetting.objects.filter(is_sensitive=True).count()
        sensitive_empty = SystemSetting.objects.filter(is_sensitive=True, value__isnull=True).count()

        self.stdout.write("\nSensitive Settings:")
        self.stdout.write(f"  Total sensitive: {sensitive_total}")
        self.stdout.write(f"  Need re-configuration: {sensitive_empty}")

    def _report_oauth(self) -> None:
        try:
            from apps.billing.efactura.token_storage import OAuthToken  # noqa: PLC0415

            total = OAuthToken.objects.count()
            empty = OAuthToken.objects.filter(access_token="").count()

            self.stdout.write("\ne-Factura OAuth Tokens:")
            self.stdout.write(f"  Total tokens: {total}")
            self.stdout.write(f"  Need re-authentication: {empty}")
        except Exception as e:
            self.stdout.write(f"\ne-Factura: Could not check ({e})")

    def _report_vault(self) -> None:
        try:
            from apps.common.credential_vault import EncryptedCredential  # noqa: PLC0415

            total = EncryptedCredential.objects.count()
            self.stdout.write("\nCredential Vault:")
            self.stdout.write(f"  Stored credentials: {total}")
            if total > 0:
                self.stdout.write(self.style.WARNING(f"  {total} credential(s) may need re-seeding"))
        except Exception as e:
            self.stdout.write(f"\nCredential Vault: Could not check ({e})")

    def _report_domain_credentials(self) -> None:
        try:
            from apps.domains.models import Domain, Registrar  # noqa: PLC0415

            reg_total = Registrar.objects.count()
            reg_empty = Registrar.objects.filter(api_key="").count()
            epp_total = Domain.objects.exclude(epp_code="").count()

            self.stdout.write("\nDomain Registrar Credentials:")
            self.stdout.write(f"  Registrars needing API keys: {reg_empty}/{reg_total}")
            self.stdout.write(f"  Domains with EPP codes: {epp_total}")
        except Exception as e:
            self.stdout.write(f"\nDomain Credentials: Could not check ({e})")
