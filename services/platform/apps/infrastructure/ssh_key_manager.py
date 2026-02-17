"""
SSH Key Manager for Node Deployment

Handles SSH key generation, storage, and retrieval for infrastructure deployments.
Integrates with CredentialVault for secure key storage.

Features:
- ED25519 key pair generation
- Per-deployment key storage in CredentialVault
- Master key fallback from environment
- Key retrieval for Terraform and Ansible
"""

from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from apps.common.credential_vault import (
    CredentialData,
    CredentialVault,
    EncryptedCredential,
    get_credential_vault,
)
from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment
    from apps.users.models import User

logger = logging.getLogger(__name__)

# Service type for SSH keys in CredentialVault
SSH_SERVICE_TYPE = "ssh"

# Environment variable for master SSH key fallback
MASTER_SSH_KEY_ENV = "INFRASTRUCTURE_MASTER_SSH_KEY"
MASTER_SSH_KEY_PATH_ENV = "INFRASTRUCTURE_MASTER_SSH_KEY_PATH"


@dataclass
class SSHKeyPair:
    """SSH key pair data structure"""

    public_key: str  # OpenSSH format public key
    private_key: str  # PEM format private key
    fingerprint: str  # SHA256 fingerprint


@dataclass
class SSHKeyInfo:
    """SSH key information for deployment"""

    credential_id: str  # CredentialVault credential ID
    public_key: str  # OpenSSH format for Terraform
    fingerprint: str
    has_master_fallback: bool


class SSHKeyManager:
    """
    🔑 SSH Key Manager for Node Deployments

    Manages SSH key pairs for infrastructure provisioning:
    - Generates unique ED25519 key pairs per deployment
    - Stores keys securely in CredentialVault
    - Provides master key fallback for emergency access
    - Handles key retrieval for Terraform and Ansible
    """

    def __init__(self) -> None:
        """Initialize SSH key manager"""
        self._vault: CredentialVault | None = None

    @property
    def vault(self) -> CredentialVault:
        """Lazy load credential vault"""
        if self._vault is None:
            self._vault = get_credential_vault()
        return self._vault

    def generate_key_pair(self) -> SSHKeyPair:
        """
        Generate new ED25519 SSH key pair.

        Returns:
            SSHKeyPair with public key, private key, and fingerprint
        """
        # Generate private key
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize private key to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        # Serialize public key to OpenSSH format
        public_key_openssh = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        ).decode("utf-8")

        # Calculate fingerprint (using SHA256)
        import base64  # noqa: PLC0415
        import hashlib  # noqa: PLC0415

        # The public key bytes in raw format for fingerprint
        raw_public = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        fingerprint_hash = hashlib.sha256(raw_public).digest()
        fingerprint = f"SHA256:{base64.b64encode(fingerprint_hash).decode('utf-8').rstrip('=')}"

        logger.debug(f"🔑 [SSH Manager] Generated ED25519 key pair, fingerprint: {fingerprint}")

        return SSHKeyPair(
            public_key=public_key_openssh,
            private_key=private_key_pem,
            fingerprint=fingerprint,
        )

    def generate_deployment_key(
        self,
        deployment: NodeDeployment,
        user: User | None = None,
    ) -> Result[SSHKeyInfo, str]:
        """
        Generate and store SSH key pair for a deployment.

        Args:
            deployment: NodeDeployment instance
            user: User initiating the generation

        Returns:
            Result with SSHKeyInfo or error message
        """
        try:
            # Generate new key pair
            key_pair = self.generate_key_pair()

            # Create service identifier using deployment hostname
            service_identifier = f"node-{deployment.hostname}"

            # Store in CredentialVault
            # Public key as "username", private key as "password"
            credential_data = CredentialData(
                service_type=SSH_SERVICE_TYPE,
                service_identifier=service_identifier,
                username=key_pair.public_key,
                password=key_pair.private_key,
                metadata={
                    "deployment_id": str(deployment.id),
                    "hostname": deployment.hostname,
                    "fingerprint": key_pair.fingerprint,
                    "key_type": "ed25519",
                    "purpose": "node_deployment",
                },
                expires_in_days=365,  # SSH keys valid for 1 year
                user=user,
                reason=f"SSH key for node deployment: {deployment.hostname}",
            )

            result = self.vault.store_credential(credential_data)

            if result.is_err():
                return Err(f"Failed to store SSH key: {result.unwrap_err()}")

            credential = result.unwrap()

            # Update deployment with credential ID
            deployment.ssh_key_credential_id = str(credential.id)
            deployment.save(update_fields=["ssh_key_credential_id", "updated_at"])

            logger.info(
                f"🔑 [SSH Manager] Generated and stored SSH key for deployment: "
                f"{deployment.hostname}, fingerprint: {key_pair.fingerprint}"
            )

            return Ok(
                SSHKeyInfo(
                    credential_id=str(credential.id),
                    public_key=key_pair.public_key,
                    fingerprint=key_pair.fingerprint,
                    has_master_fallback=self.has_master_key(),
                )
            )

        except Exception as e:
            logger.error(f"🚨 [SSH Manager] Key generation failed: {e}")
            return Err(f"SSH key generation failed: {e}")

    def get_deployment_key(
        self,
        deployment: NodeDeployment,
        user: User | None = None,
        reason: str = "Deployment key access",
    ) -> Result[SSHKeyPair, str]:
        """
        Retrieve SSH key pair for a deployment.

        Args:
            deployment: NodeDeployment instance
            user: User requesting access
            reason: Reason for key access

        Returns:
            Result with SSHKeyPair or error message
        """
        if not deployment.ssh_key_credential_id:
            return Err(f"No SSH key configured for deployment: {deployment.hostname}")

        service_identifier = f"node-{deployment.hostname}"

        result = self.vault.get_credential(
            service_type=SSH_SERVICE_TYPE,
            service_identifier=service_identifier,
            user=user,
            reason=reason,
            allow_expired=False,
        )

        if result.is_err():
            return Err(f"Failed to retrieve SSH key: {result.unwrap_err()}")

        public_key, private_key, metadata = result.unwrap()
        fingerprint = metadata.get("fingerprint", "unknown") if metadata else "unknown"

        logger.debug(f"🔑 [SSH Manager] Retrieved SSH key for: {deployment.hostname}")

        return Ok(
            SSHKeyPair(
                public_key=public_key,
                private_key=private_key,
                fingerprint=fingerprint,
            )
        )

    def get_public_key(
        self,
        deployment: NodeDeployment,
        user: User | None = None,
    ) -> Result[str, str]:
        """
        Get just the public key for a deployment (for Terraform).

        Args:
            deployment: NodeDeployment instance
            user: User requesting access

        Returns:
            Result with public key string or error
        """
        result = self.get_deployment_key(deployment, user, "Public key for Terraform")

        if result.is_err():
            return Err(result.unwrap_err())

        return Ok(result.unwrap().public_key)

    def get_private_key_file(
        self,
        deployment: NodeDeployment,
        user: User | None = None,
    ) -> Result[Path, str]:
        """
        Get private key written to a temporary file (for Ansible).

        The caller is responsible for cleaning up the file.

        Args:
            deployment: NodeDeployment instance
            user: User requesting access

        Returns:
            Result with Path to temporary key file or error
        """
        result = self.get_deployment_key(deployment, user, "Private key for Ansible")

        if result.is_err():
            return Err(result.unwrap_err())

        key_pair = result.unwrap()

        try:
            # Create secure temporary file
            fd, path = tempfile.mkstemp(prefix="praho_ssh_", suffix=".key")
            with os.fdopen(fd, "w") as f:
                f.write(key_pair.private_key)

            # Set proper permissions (owner read only)
            os.chmod(path, 0o600)

            logger.debug(f"🔑 [SSH Manager] Wrote private key to temp file: {path}")

            return Ok(Path(path))

        except Exception as e:
            logger.error(f"🚨 [SSH Manager] Failed to write key file: {e}")
            return Err(f"Failed to write key file: {e}")

    def delete_deployment_key(
        self,
        deployment: NodeDeployment,
        user: User | None = None,
        reason: str = "Deployment destruction",
    ) -> Result[bool, str]:
        """
        Delete SSH key for a destroyed deployment.

        Args:
            deployment: NodeDeployment instance
            user: User requesting deletion
            reason: Reason for deletion

        Returns:
            Result with success status or error
        """
        if not deployment.ssh_key_credential_id:
            logger.warning(f"🔑 [SSH Manager] No SSH key to delete for: {deployment.hostname}")
            return Ok(True)

        try:
            # Deactivate the credential (soft delete)
            credential = EncryptedCredential.objects.get(id=deployment.ssh_key_credential_id)
            credential.is_active = False
            credential.save(update_fields=["is_active", "updated_at"])

            # Clear the reference on deployment
            deployment.ssh_key_credential_id = ""
            deployment.save(update_fields=["ssh_key_credential_id", "updated_at"])

            logger.info(f"🔑 [SSH Manager] Deleted SSH key for: {deployment.hostname}")

            return Ok(True)

        except EncryptedCredential.DoesNotExist:
            logger.warning(f"🔑 [SSH Manager] SSH key credential not found: {deployment.ssh_key_credential_id}")
            return Ok(True)  # Already deleted

        except Exception as e:
            logger.error(f"🚨 [SSH Manager] Failed to delete SSH key: {e}")
            return Err(f"Failed to delete SSH key: {e}")

    # Master key fallback methods

    def has_master_key(self) -> bool:
        """Check if master SSH key is configured"""
        return bool(self._get_master_key_content())

    def _get_master_key_content(self) -> str | None:
        """
        Get master SSH key content from environment.

        Checks:
        1. INFRASTRUCTURE_MASTER_SSH_KEY - Direct key content
        2. INFRASTRUCTURE_MASTER_SSH_KEY_PATH - Path to key file
        """
        # Try direct key content first
        key_content = os.environ.get(MASTER_SSH_KEY_ENV)
        if key_content:
            return key_content

        # Try key file path
        key_path = os.environ.get(MASTER_SSH_KEY_PATH_ENV)
        if key_path and os.path.exists(key_path):
            try:
                with open(key_path) as f:
                    return f.read()
            except Exception as e:
                logger.warning(f"🔑 [SSH Manager] Could not read master key file: {e}")

        return None

    def get_master_key(self) -> Result[str, str]:
        """
        Get master SSH private key for emergency access.

        Returns:
            Result with private key content or error
        """
        key_content = self._get_master_key_content()

        if not key_content:
            return Err(
                f"Master SSH key not configured. "
                f"Set {MASTER_SSH_KEY_ENV} or {MASTER_SSH_KEY_PATH_ENV} environment variable."
            )

        logger.info("🔑 [SSH Manager] Master SSH key accessed (fallback)")

        return Ok(key_content)

    def get_master_key_file(self) -> Result[Path, str]:
        """
        Get master SSH key written to a temporary file.

        The caller is responsible for cleaning up the file.

        Returns:
            Result with Path to temporary key file or error
        """
        result = self.get_master_key()

        if result.is_err():
            return Err(result.unwrap_err())

        key_content = result.unwrap()

        try:
            fd, path = tempfile.mkstemp(prefix="praho_master_ssh_", suffix=".key")
            with os.fdopen(fd, "w") as f:
                f.write(key_content)

            os.chmod(path, 0o600)

            return Ok(Path(path))

        except Exception as e:
            return Err(f"Failed to write master key file: {e}")

    def get_effective_key_for_deployment(
        self,
        deployment: NodeDeployment,
        user: User | None = None,
        prefer_master: bool = False,
    ) -> Result[SSHKeyPair, str]:
        """
        Get effective SSH key for deployment, with master key fallback.

        Args:
            deployment: NodeDeployment instance
            user: User requesting access
            prefer_master: If True, use master key if available

        Returns:
            Result with SSHKeyPair or error
        """
        # If preferring master and it's available, use it
        if prefer_master and self.has_master_key():
            master_result = self.get_master_key()
            if master_result.is_ok():
                return Ok(
                    SSHKeyPair(
                        public_key="",  # Not available for master key
                        private_key=master_result.unwrap(),
                        fingerprint="master",
                    )
                )

        # Try deployment-specific key
        result = self.get_deployment_key(deployment, user)

        if result.is_ok():
            return result

        # Fallback to master key if deployment key failed
        if self.has_master_key():
            logger.warning(f"🔑 [SSH Manager] Falling back to master key for: {deployment.hostname}")
            master_result = self.get_master_key()
            if master_result.is_ok():
                return Ok(
                    SSHKeyPair(
                        public_key="",
                        private_key=master_result.unwrap(),
                        fingerprint="master",
                    )
                )

        return result  # Return original error


# Module-level singleton
_ssh_key_manager: SSHKeyManager | None = None


def get_ssh_key_manager() -> SSHKeyManager:
    """Get global SSH key manager instance"""
    global _ssh_key_manager  # noqa: PLW0603
    if _ssh_key_manager is None:
        _ssh_key_manager = SSHKeyManager()
    return _ssh_key_manager
