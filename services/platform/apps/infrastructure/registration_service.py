"""
Node Registration Service

Registers deployed nodes in the PRAHO platform as VirtualminServer instances.
Creates the necessary database records for the provisioning system to manage
the deployed infrastructure.
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import DatabaseError, InterfaceError, transaction
from django.db.models import ProtectedError

from apps.common.outbound_http import OutboundSecurityError, normalize_tls_cert_fingerprint
from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.infrastructure.deployment_lifecycle import OperationLease
    from apps.infrastructure.models import NodeDeployment
    from apps.provisioning.virtualmin_models import VirtualminServer
    from apps.users.models import User

logger = logging.getLogger(__name__)


def _public_address_or_none(value: object, version: int) -> str | None:
    """A deployment address as the server stores it: normalised when public, else empty.

    A lab or private-network node registers like any other; DNS for account names is simply never
    published to an address the Internet cannot reach.
    """
    from apps.infrastructure.panel_cert_probes import public_address  # noqa: PLC0415  # Deferred: imports dnspython

    if not isinstance(value, str) or not value:
        return None
    try:
        return public_address(value, version)
    except ValueError:
        logger.warning("⚠️ [Registration] Address %s is not a public IPv%d address; left empty", value, version)
        return None


class NodeRegistrationService:
    """
    📝 Node Registration Service

    Registers deployed infrastructure nodes in the PRAHO platform.
    Creates VirtualminServer records that integrate with the existing
    provisioning system.
    """

    def verify_provisioned_api(self, deployment: NodeDeployment) -> Result[bool, str]:
        """Prove the durable dedicated credential and SSH-pinned TLS before restricting root."""
        from apps.common.credential_vault import get_credential_vault  # noqa: PLC0415 -- service boundary
        from apps.provisioning.virtualmin_gateway import (  # noqa: PLC0415 -- avoids app cycle
            VirtualminConfig,
            VirtualminGateway,
            get_virtualmin_config,
        )

        stored = get_credential_vault().get_credential(
            service_type="virtualmin",
            service_identifier=deployment.fqdn,
            reason="Verify durable API identity before Webmin lockdown",
        )
        if stored.is_err():
            return Err("Durable API identity is unavailable; root access has not been restricted")
        username, password, _ = stored.unwrap()
        if not username or username == "root" or not password:
            return Err("A dedicated non-root API identity must be enrolled before lockdown")
        fingerprint = self._trusted_certificate_fingerprint(deployment)
        if fingerprint.is_err():
            return Err("The panel certificate could not be pinned over the enrolled SSH connection")
        config = VirtualminConfig.from_credentials(
            hostname=deployment.fqdn,
            username=username,
            password=password,
            port=10000,
            use_ssl=True,
            verify_ssl=False,
            cert_fingerprint=fingerprint.unwrap(),
            timeout=get_virtualmin_config()["timeout"],
        )
        result = VirtualminGateway(config).check_api()
        if result.is_err():
            failure = result.unwrap_err()
            failure_messages = {
                "unreachable": (
                    f"The panel at {config.server.hostname}:{config.server.api_port} could not be reached "
                    f"({failure.detail}); root access has not been restricted"
                ),
                "rejected": (
                    "The durable dedicated API credential did not authenticate; root access has not been restricted"
                ),
                "refused": "The panel refused the API check; root access has not been restricted",
                "failed": f"The panel check failed ({failure.detail}); root access has not been restricted",
            }
            return Err(failure_messages[failure.kind])
        return Ok(True)

    @staticmethod
    def _registration_validation_error(deployment: NodeDeployment) -> str | None:
        """Return a preflight error without opening a database transaction or SSH session."""
        if deployment.status not in {"completed", "registering"}:
            return f"Cannot register node in status '{deployment.status}'"
        if not deployment.ipv4_address:
            return "Deployment has no IP address assigned"
        if deployment.virtualmin_server:
            return f"Node already registered as: {deployment.virtualmin_server}"

        from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

        if VirtualminServer.objects.filter(hostname=deployment.fqdn).exists():
            return f"VirtualminServer with hostname '{deployment.fqdn}' already exists"
        return None

    @staticmethod
    def _trusted_certificate_fingerprint(deployment: NodeDeployment) -> Result[str, str]:
        """Obtain and validate the Webmin pin through the trusted SSH channel."""
        from apps.infrastructure.validation_service import get_validation_service  # noqa: PLC0415

        fingerprint_result = get_validation_service().get_webmin_certificate_fingerprint(deployment)
        if fingerprint_result.is_err():
            return Err(f"Could not verify Webmin certificate fingerprint: {fingerprint_result.unwrap_err()}")
        try:
            return Ok(normalize_tls_cert_fingerprint(fingerprint_result.unwrap()))
        except OutboundSecurityError as exc:
            return Err(f"Could not verify Webmin certificate fingerprint: {exc}")

    def register_node(
        self,
        deployment: NodeDeployment,
        admin_username: str = "root",
        admin_password: str | None = None,
        user: User | None = None,
        *,
        operation_lease: OperationLease | None = None,
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
        from apps.common.credential_vault import (  # Circular: cross-app  # noqa: PLC0415  # Deferred: avoids circular import
            CredentialData,
            get_credential_vault,
        )
        from apps.infrastructure.node_maintenance_gate import locked_deployment_gate  # noqa: PLC0415
        from apps.provisioning.virtualmin_models import (  # Circular: cross-app  # noqa: PLC0415  # Deferred: avoids circular import
            VirtualminServer,
        )

        validation_error = self._registration_validation_error(deployment)
        if validation_error:
            return Err(validation_error)

        logger.info(f"📝 [Registration] Registering node: {deployment.hostname}")

        fingerprint_result = self._trusted_certificate_fingerprint(deployment)
        if fingerprint_result.is_err():
            return Err(fingerprint_result.unwrap_err())
        ssl_cert_fingerprint = fingerprint_result.unwrap()

        try:
            # The SSH pin probe above holds no database lock. Recheck its exact
            # resource under the shared admission gate before publishing any row.
            with locked_deployment_gate(deployment.pk) as current:
                if refusal := self._registration_ownership_refusal(deployment, current, operation_lease):
                    return Err(refusal)
                assert current is not None
                original = deployment
                deployment = current
                # Check if VirtualminServer already exists for this hostname
                if VirtualminServer.objects.filter(hostname=deployment.fqdn).exists():
                    return Err(f"VirtualminServer with hostname '{deployment.fqdn}' already exists")

                # Register as 'disabled', NOT 'active': the admin password is
                # generated here and stored in the vault, but nothing has
                # configured a Virtualmin ACL user with it on the node yet, so the
                # first API call would fail authentication. _select_best_server
                # only places on status='active' servers, so a disabled server is
                # never auto-selected — an operator activates it after configuring
                # and verifying the API credentials on the node.
                server = VirtualminServer.objects.create(
                    name=f"Node: {deployment.hostname}",
                    hostname=deployment.fqdn,
                    ssh_port=deployment.ssh_port,
                    api_port=10000,
                    use_ssl=True,
                    ssl_verify=False,  # Self-signed initially
                    ssl_cert_fingerprint=ssl_cert_fingerprint,
                    status="disabled",
                    api_username=admin_username,
                    encrypted_api_password=b"",  # Stored in CredentialVault instead
                    max_domains=deployment.node_size.max_domains if deployment.node_size else 50,
                    max_bandwidth_gb=deployment.node_size.max_bandwidth_gb if deployment.node_size else 1000,
                    # The addresses account names point at (ADR-0061); a private one stays empty.
                    ipv4_address=_public_address_or_none(deployment.ipv4_address, 4),
                    ipv6_address=_public_address_or_none(deployment.ipv6_address, 6),
                )

                # Store credentials in vault if password provided
                if admin_password:
                    vault = get_credential_vault()
                    credential_data = CredentialData(
                        service_type="virtualmin",
                        # Couple the vault WRITE key to server.hostname — the exact key the gateway
                        # resolver READS by (resolve_server_credentials → get_credential by
                        # server.hostname). Equal to deployment.fqdn today, but binding them to the
                        # same attribute prevents a future hostname-derivation change from silently
                        # desynchronizing writes and reads (fleet-wide fail-closed 401s otherwise).
                        service_identifier=server.hostname,
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
                original.virtualmin_server = server

                logger.info(
                    f"📝 [Registration] Registered node {deployment.hostname} -> "
                    f"VirtualminServer(id={server.id}, status=disabled). Configure and verify the "
                    f"Virtualmin API credentials on the node, then activate it before it can host domains."
                )

                return Ok(server)

        except Exception as e:
            logger.error(f"🚨 [Registration] Failed to register node {deployment.hostname}: {e}")
            return Err(f"Registration failed: {e}")

    @staticmethod
    def _registration_ownership_refusal(  # noqa: PLR0911  # Each resource/owner gate names the actionable refusal.
        probed: NodeDeployment, current: NodeDeployment | None, lease: OperationLease | None
    ) -> str | None:
        from apps.infrastructure.node_maintenance_gate import ACTIVE_EXECUTIONS  # noqa: PLC0415
        from apps.infrastructure.node_maintenance_models import NodeMaintenanceExecution  # noqa: PLC0415

        if current is None:
            return "The deployment no longer exists"
        if any(
            getattr(current, field) != getattr(probed, field)
            for field in (
                "correlation_id",
                "external_node_id",
                "ipv4_address",
                "ssh_port",
                "hostname",
                "virtualmin_server_id",
            )
        ):
            return "The deployment resource changed during certificate verification; reload before registration"
        if current.virtualmin_server_id or current.status not in {"completed", "registering"}:
            return "The deployment is no longer available for registration"
        if NodeMaintenanceExecution.objects.filter(deployment=current, phase__in=ACTIVE_EXECUTIONS).exists():
            return "A native operation owns this deployment; verify its outcome before registration"
        if current.operation_reserved_at is not None:
            return "A queued deployment operation owns this deployment"
        if lease is not None:
            if (
                lease.deployment_id != current.pk
                or lease.token != current.operation_token
                or lease.kind != current.operation_kind
                or current.status != "registering"
            ):
                return "The registration operation no longer owns this deployment"
        elif current.status == "registering" and current.operation_token is not None:
            return "Registration requires the current deployment operation's lease"
        return None

    def _panel_trust_refusal(self, server: VirtualminServer) -> str | None:
        """None = affirmatively trusted; otherwise the refusal reason (#436)."""
        deployment = getattr(server, "node_deployment", None)
        if deployment is None:
            return (
                f"Trusted-certificate policy: {server.hostname} has no managed node_deployment; "
                "cannot evaluate the panel certificate"
            )
        from .validation_service import get_validation_service  # noqa: PLC0415

        probe = get_validation_service()._probe_tls_trust(deployment)
        if probe.get("trusted") is True and probe.get("trust_evaluated") is True:
            return None
        if probe.get("trust_evaluated") is True:
            return (
                f"Panel certificate for {server.hostname} is NOT CA-trusted: "
                f"{probe.get('trust_error') or 'verification failed'}"
            )
        return (
            f"Panel certificate trust for {server.hostname} could not be evaluated "
            f"({probe.get('error') or probe.get('trust_error') or 'probe failed'}); refusing under the strict policy"
        )

    def verify_and_activate(self, server: VirtualminServer) -> Result[VirtualminServer, str]:  # noqa: C901, PLR0911  # Guarded credential, native policy and activation workflow.
        """
        #347 GAP 2: confirm the API credential provisioned on the node actually
        authenticates, then transition the server disabled -> active so placement
        can use it. A failed handshake leaves it disabled with a clear reason —
        PRAHO never activates a server it cannot authenticate to. Requires an
        AFFIRMATIVE health result (#325 posture): a missing/non-True 'healthy' is
        not proof and does not activate.
        """
        from django.utils import timezone  # noqa: PLC0415  # Deferred: local use

        from apps.common.credential_vault import (  # noqa: PLC0415  # Circular: cross-app  # Deferred: avoids circular import
            get_credential_vault,
        )
        from apps.provisioning.virtualmin_gateway import (  # noqa: PLC0415  # Circular: cross-app  # Deferred: avoids circular import
            VirtualminConfig,
            VirtualminGateway,
            get_virtualmin_config,
        )
        from apps.provisioning.virtualmin_models import (  # noqa: PLC0415  # Circular: cross-app  # Deferred: avoids circular import
            VirtualminServer as VMServer,
        )

        try:
            # Fetch the credential PRODUCTION will use: register_node stores it in the
            # vault (keyed by hostname) and leaves encrypted_api_password=b"", so the
            # server's own get_api_password() is empty. Verifying against the vault
            # credential means activation proves the node accepts EXACTLY the credential
            # every later API call will present. A vault miss (register_node tolerates a
            # failed store) leaves the node disabled — never activated blind.
            vault_result = get_credential_vault().get_credential(
                service_type="virtualmin",
                service_identifier=server.hostname,
                reason="Node activation credential check (#347)",
            )
            if vault_result.is_err():
                return Err(f"No vault credential for {server.hostname}, leaving disabled: {vault_result.unwrap_err()}")
            vault_username, vault_password, _meta = vault_result.unwrap()
            if not vault_username or not vault_password:
                return Err(f"Empty vault credential for {server.hostname}, leaving disabled")

            config_data = get_virtualmin_config()
            # Probe with the vault credential via from_credentials. It carries an
            # active-status probe object, so the gateway's non-active guard (which exists
            # to stop routing to not-yet-live servers) does not block the one call whose
            # purpose is to verify a not-yet-active node. This still makes a REAL
            # authenticated `info` call to the real node over the pinned-cert TLS policy.
            config = VirtualminConfig.from_credentials(
                hostname=server.hostname,
                username=vault_username,
                password=vault_password,
                port=server.api_port,
                use_ssl=server.use_ssl,
                verify_ssl=server.ssl_verify,
                timeout=config_data["timeout"],
                cert_fingerprint=server.ssl_cert_fingerprint or config_data.get("pinned_cert_sha256", ""),
            )
            health = VirtualminGateway(config).test_connection()

            if health.is_err():
                return Err(f"Credential check failed for {server.hostname}, leaving disabled: {health.unwrap_err()}")
            if health.unwrap().get("healthy") is not True:
                return Err(f"Server {server.hostname} did not report healthy, leaving disabled: {health.unwrap()}")

            policy_evidence = None
            policy_cidrs: list[str] = []
            if getattr(server, "node_deployment", None) is not None:
                from apps.infrastructure.ansible_service import (  # noqa: PLC0415 -- native policy boundary
                    node_admin_allowed_cidrs,
                )
                from apps.provisioning.virtualmin_node_capability import (  # noqa: PLC0415 -- app boundary
                    record_generated_policy,
                )
                from apps.provisioning.virtualmin_security_tasks import (  # noqa: PLC0415 -- read-only qualification boundary
                    collect_inspection,
                )

                if vault_username != server.api_username or vault_username == "root":
                    return Err("Generated node needs its durable dedicated API identity before activation")
                try:
                    policy_evidence = collect_inspection(server)
                    policy_cidrs = node_admin_allowed_cidrs()
                except (ValidationError, ValueError) as error:
                    return Err(f"Node web-only policy is not verified, leaving disabled: {error}")

            # #436 (flag-gated, default off): under the strict policy, activation
            # additionally requires an AFFIRMATIVE CA-trust verdict on the panel
            # certificate. Indeterminate probes refuse too (fail-closed under an
            # explicitly strict flag; the operator retries). Refusal keeps the
            # server disabled — it never discards the deployment.
            from apps.settings.services import SettingsService  # noqa: PLC0415  # Circular

            if SettingsService.get_boolean_setting("infrastructure.require_trusted_panel_certificate", False):
                trust_error = self._panel_trust_refusal(server)
                if trust_error is not None:
                    from apps.common.validators import log_security_event  # noqa: PLC0415  # Circular

                    log_security_event(
                        "virtualmin_activation_refused_untrusted_cert",
                        {"server_id": str(server.pk), "hostname": server.hostname, "detail": trust_error},
                    )
                    return Err(trust_error)

            # CAS: only a still-'disabled' server may be activated — never resurrect a
            # 'failed'/'maintenance' server, and never race a concurrent transition.
            from apps.infrastructure.node_maintenance_execution import (  # noqa: PLC0415  # Native write authority is local to this result.
                current_native_server_write_guard,
            )

            with current_native_server_write_guard(server.pk), transaction.atomic():
                locked_server = VMServer.objects.select_for_update().get(pk=server.pk)
                if policy_evidence is not None:
                    # Rebind the evidence under the SAME lock as activation. Remote
                    # inspection and CA probes must not leave a credential/endpoint
                    # change window between proof and admission.
                    record_generated_policy(locked_server, policy_evidence, policy_cidrs)
                updated = VMServer.objects.filter(pk=server.pk, status="disabled").update(
                    status="active", updated_at=timezone.now()
                )
            if not updated:
                # Narrow on purpose: the row may have been deleted concurrently, or the connection
                # may hiccup. `InterfaceError` is named alongside `DatabaseError` because it is a
                # SIBLING of it under PEP 249's `Error`, not a subclass - a closed connection is
                # precisely the hiccup this tolerates. Anything else is a bug and should surface.
                with contextlib.suppress(ObjectDoesNotExist, DatabaseError, InterfaceError):
                    server.refresh_from_db()
                return Err(f"Server {server.hostname} left 'disabled' before activation (now '{server.status}')")
        except Exception as e:
            # Any DB/gateway error during verification OR activation is a Result, never a raise: a
            # transient failure must leave the node DISABLED (fail-safe) and NEVER crash the caller's
            # deployment (#348 finding #7). If the CAS above already committed, the node is active
            # regardless of this Err (still usable); a later reconcile syncs the in-memory row.
            return Err(f"Credential verification raised for {server.hostname}: {e}")

        # Activation committed. The final refresh is cosmetic — a hiccup here must NOT turn a
        # successful activation into a reported failure. Same three exceptions as above, and for the
        # same reason: a concurrent delete or a connection blip is expected, an AttributeError is not.
        # This site is past the CAS commit, so an escape here would turn a node that IS active into
        # a raised exception - the exact outcome the comment above promises cannot happen.
        with contextlib.suppress(ObjectDoesNotExist, DatabaseError, InterfaceError):
            server.refresh_from_db()
        logger.info(f"✅ [Registration] Node {server.hostname} credential-verified and activated")
        return Ok(server)

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
            from apps.infrastructure.node_maintenance_gate import (  # noqa: PLC0415  # Server before deployment
                locked_deployment_gate,
                teardown_maintenance_refusal,
            )
            from apps.provisioning.component_migration_models import retained_source_refusal  # noqa: PLC0415
            from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

            with locked_deployment_gate(deployment.pk) as current:
                if current is None or current.virtualmin_server_id != server.pk:
                    return Err("The deployment's server binding changed; reload before unregistering it")
                deployment = current
                server = VirtualminServer.objects.get(pk=current.virtualmin_server_id)
                if refusal := retained_source_refusal(server.pk):
                    return Err(refusal)
                if refusal := teardown_maintenance_refusal(server.pk):
                    return Err(refusal)
                # Remove credentials from vault
                from apps.common.credential_vault import (  # Circular: cross-app  # noqa: PLC0415  # Deferred: avoids circular import
                    get_credential_vault,
                )

                get_credential_vault()
                # Deactivate credential if it exists
                from apps.common.credential_vault import (  # Circular: cross-app  # noqa: PLC0415  # Deferred: avoids circular import
                    EncryptedCredential,
                )

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
                            "📝 [Registration] VirtualminServer has accounts, deactivating instead of deleting"
                        )
                        server.status = "disabled"
                        server.save(update_fields=["status", "updated_at"])
                    else:
                        server_id = server.id
                        try:
                            with transaction.atomic():
                                server.delete()
                            logger.info(f"📝 [Registration] Deleted VirtualminServer(id={server_id})")
                        except ProtectedError:
                            # Drain, migration and bridge history keep the record; the node is gone.
                            server.status = "disabled"
                            server.save(update_fields=["status", "updated_at"])
                            logger.info(f"📝 [Registration] Kept VirtualminServer(id={server_id}) for its history")
                else:
                    # Just deactivate
                    server.status = "disabled"
                    server.save(update_fields=["status", "updated_at"])
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
    global _registration_service  # noqa: PLW0603  # Module-level singleton pattern
    if _registration_service is None:
        _registration_service = NodeRegistrationService()
    return _registration_service
