"""
Node Registration Service

Registers deployed nodes in the PRAHO platform as VirtualminServer instances.
Creates the necessary database records for the provisioning system to manage
the deployed infrastructure.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.db import transaction

from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment
    from apps.provisioning.virtualmin_models import VirtualminServer
    from apps.users.models import User

logger = logging.getLogger(__name__)


class NodeRegistrationService:
    """
    📝 Node Registration Service

    Registers deployed infrastructure nodes in the PRAHO platform.
    Creates VirtualminServer records that integrate with the existing
    provisioning system.
    """

    def register_node(
        self,
        deployment: NodeDeployment,
        admin_username: str = "root",
        admin_password: str | None = None,
        user: User | None = None,
    ) -> Result[VirtualminServer, str]:
        """
        Register a deployed node as a VirtualminServer.

        Args:
            deployment: Completed NodeDeployment instance
            admin_username: Webmin admin username (default: root)
            admin_password: Webmin admin password (will be stored in CredentialVault)
            user: User performing the registration

        Returns:
            Result with VirtualminServer instance or error
        """
        # Import here to avoid circular imports
        from apps.provisioning.virtualmin_models import VirtualminServer
        from apps.common.credential_vault import CredentialData, get_credential_vault

        # Validate deployment status
        if deployment.status != "completed" and deployment.status != "registering":
            return Err(f"Cannot register node in status '{deployment.status}'")

        if not deployment.ipv4_address:
            return Err("Deployment has no IP address assigned")

        if deployment.virtualmin_server:
            return Err(f"Node already registered as: {deployment.virtualmin_server}")

        logger.info(f"📝 [Registration] Registering node: {deployment.hostname}")

        try:
            with transaction.atomic():
                # Check if VirtualminServer already exists for this hostname
                if VirtualminServer.objects.filter(hostname=deployment.fqdn).exists():
                    return Err(f"VirtualminServer with hostname '{deployment.fqdn}' already exists")

                # Create VirtualminServer record
                server = VirtualminServer.objects.create(
                    hostname=deployment.fqdn,
                    ip_address=deployment.ipv4_address,
                    port=10000,
                    use_ssl=True,
                    verify_ssl=False,  # Self-signed initially
                    is_active=True,
                    description=f"Auto-deployed node: {deployment.hostname}",
                    max_domains=deployment.node_size.max_domains if deployment.node_size else 50,
                    max_bandwidth_gb=deployment.node_size.max_bandwidth_gb if deployment.node_size else 1000,
                )

                # Store credentials in vault if password provided
                if admin_password:
                    vault = get_credential_vault()
                    credential_data = CredentialData(
                        service_type="virtualmin",
                        service_identifier=deployment.fqdn,
                        username=admin_username,
                        password=admin_password,
                        metadata={
                            "deployment_id": str(deployment.id),
                            "deployment_hostname": deployment.hostname,
                            "server_id": str(server.id),
                            "auto_registered": True,
                        },
                        expires_in_days=365,
                        user=user,
                        reason=f"Auto-registration for node deployment: {deployment.hostname}",
                    )
                    vault_result = vault.store_credential(credential_data)

                    if vault_result.is_err():
                        logger.warning(
                            f"📝 [Registration] Could not store credentials in vault: {vault_result.unwrap_err()}"
                        )
                    else:
                        logger.info(f"📝 [Registration] Stored credentials in vault for: {deployment.fqdn}")

                # Link deployment to server
                deployment.virtualmin_server = server
                deployment.save(update_fields=["virtualmin_server", "updated_at"])

                logger.info(
                    f"📝 [Registration] Successfully registered node: "
                    f"{deployment.hostname} -> VirtualminServer(id={server.id})"
                )

                return Ok(server)

        except Exception as e:
            logger.error(f"🚨 [Registration] Failed to register node {deployment.hostname}: {e}")
            return Err(f"Registration failed: {e}")

    def unregister_node(
        self,
        deployment: NodeDeployment,
        delete_server: bool = False,
        user: User | None = None,
    ) -> Result[bool, str]:
        """
        Unregister a node (typically before destruction).

        Args:
            deployment: NodeDeployment instance
            delete_server: If True, delete the VirtualminServer record
            user: User performing the unregistration

        Returns:
            Result with success status or error
        """
        if not deployment.virtualmin_server:
            logger.info(f"📝 [Registration] Node {deployment.hostname} has no VirtualminServer to unregister")
            return Ok(True)

        server = deployment.virtualmin_server

        logger.info(f"📝 [Registration] Unregistering node: {deployment.hostname}")

        try:
            with transaction.atomic():
                # Remove credentials from vault
                from apps.common.credential_vault import get_credential_vault

                vault = get_credential_vault()
                # Deactivate credential if it exists
                from apps.common.credential_vault import EncryptedCredential

                try:
                    credential = EncryptedCredential.objects.get(
                        service_type="virtualmin",
                        service_identifier=deployment.fqdn,
                        is_active=True,
                    )
                    credential.is_active = False
                    credential.save(update_fields=["is_active", "updated_at"])
                    logger.info(f"📝 [Registration] Deactivated credentials for: {deployment.fqdn}")
                except EncryptedCredential.DoesNotExist:
                    pass

                # Unlink from deployment
                deployment.virtualmin_server = None
                deployment.save(update_fields=["virtualmin_server", "updated_at"])

                # Optionally delete the server record
                if delete_server:
                    # Check for existing accounts first
                    if hasattr(server, "accounts") and server.accounts.exists():
                        logger.warning(
                            f"📝 [Registration] VirtualminServer has accounts, deactivating instead of deleting"
                        )
                        server.is_active = False
                        server.save(update_fields=["is_active", "updated_at"])
                    else:
                        server_id = server.id
                        server.delete()
                        logger.info(f"📝 [Registration] Deleted VirtualminServer(id={server_id})")
                else:
                    # Just deactivate
                    server.is_active = False
                    server.save(update_fields=["is_active", "updated_at"])
                    logger.info(f"📝 [Registration] Deactivated VirtualminServer(id={server.id})")

                return Ok(True)

        except Exception as e:
            logger.error(f"🚨 [Registration] Failed to unregister node {deployment.hostname}: {e}")
            return Err(f"Unregistration failed: {e}")

    def update_server_from_deployment(
        self,
        deployment: NodeDeployment,
    ) -> Result[VirtualminServer, str]:
        """
        Update VirtualminServer record with deployment information.
        Used when deployment details change (e.g., IP address update).

        Args:
            deployment: NodeDeployment instance

        Returns:
            Result with updated VirtualminServer or error
        """
        if not deployment.virtualmin_server:
            return Err(f"Node {deployment.hostname} has no VirtualminServer registered")

        server = deployment.virtualmin_server

        try:
            # Update fields that might have changed
            updates = []

            if deployment.ipv4_address and server.ip_address != deployment.ipv4_address:
                server.ip_address = deployment.ipv4_address
                updates.append("ip_address")

            if deployment.fqdn and server.hostname != deployment.fqdn:
                server.hostname = deployment.fqdn
                updates.append("hostname")

            if deployment.node_size:
                if server.max_domains != deployment.node_size.max_domains:
                    server.max_domains = deployment.node_size.max_domains
                    updates.append("max_domains")
                if server.max_bandwidth_gb != deployment.node_size.max_bandwidth_gb:
                    server.max_bandwidth_gb = deployment.node_size.max_bandwidth_gb
                    updates.append("max_bandwidth_gb")

            if updates:
                updates.append("updated_at")
                server.save(update_fields=updates)
                logger.info(f"📝 [Registration] Updated VirtualminServer fields: {updates}")

            return Ok(server)

        except Exception as e:
            logger.error(f"🚨 [Registration] Failed to update VirtualminServer: {e}")
            return Err(f"Update failed: {e}")


# Module-level singleton
_registration_service: NodeRegistrationService | None = None


def get_registration_service() -> NodeRegistrationService:
    """Get global registration service instance"""
    global _registration_service
    if _registration_service is None:
        _registration_service = NodeRegistrationService()
    return _registration_service
