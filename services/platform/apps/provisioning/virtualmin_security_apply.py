"""Approved conversion: persist, enroll, prove API, transition SSH, harden, then attest."""

from __future__ import annotations

import re
import secrets
from typing import TYPE_CHECKING, cast

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from apps.common.credential_vault import CredentialData, get_credential_vault
from apps.common.ssh import parse_ssh_host_keys
from apps.infrastructure.ansible_service import AnsibleService
from apps.infrastructure.imported_backup_transport import imported_identity

from .virtualmin_gateway import PanelCheckFailure, VirtualminConfig, VirtualminGateway
from .virtualmin_models import VirtualminServer
from .virtualmin_security import connection_identity
from .virtualmin_security_execution import complete_hardening, owns_hardening
from .virtualmin_security_policy import verify_network_ingress

if TYPE_CHECKING:
    from .virtualmin_security_models import NodeSecurityExecution, NodeSecurityReview


def dedicated_username(server: VirtualminServer) -> str:
    return server.api_username if server.api_username != "root" else "praho-api-" + server.pk.hex[:10]


def _run(server: VirtualminServer, run: NodeSecurityExecution, playbook: str, variables: dict[str, object]) -> str:
    if not owns_hardening(server, str(run.pk)):
        raise ValidationError(_("Hardening execution ownership changed."))
    expected_after_ssh = _identity_after_ssh(server) if playbook == "ssh-hardening.yml" else ""
    result = AnsibleService().run_server_playbook(
        server, playbook, variables, timeout_seconds=1200, security_execution=str(run.pk)
    )
    if result.is_err() or not result.unwrap().success:
        raise ValidationError(
            _("Hardening did not complete. Inspect the node and reconcile this attempt before retrying.")
        )
    if expected_after_ssh:
        with transaction.atomic():
            locked = VirtualminServer.objects.select_for_update().get(pk=server.pk)
            if locked.security_operation != run.pk or connection_identity(locked) != expected_after_ssh:
                raise ValidationError(_("Node identity changed during the SSH transition."))
            run.expected_identity = expected_after_ssh
            run.save(update_fields=["expected_identity", "updated_at"])
    return result.unwrap().stdout


def _identity_after_ssh(server: VirtualminServer) -> str:
    owner = getattr(server, "node_deployment", None) or server
    previous = owner.ssh_port
    try:
        owner.ssh_port = 9876
        return connection_identity(server)
    finally:
        owner.ssh_port = previous


def _preserve_imported_trust(server: VirtualminServer, run: NodeSecurityExecution) -> None:
    if getattr(server, "node_deployment", None) is not None:
        return
    identity = imported_identity(server)
    public_keys = "\n".join(line.split(" ", 1)[1] for line in identity.trusted_keys)
    parse_ssh_host_keys(public_keys)
    with transaction.atomic():
        locked = VirtualminServer.objects.select_for_update().get(pk=server.pk)
        if locked.security_operation != run.pk or locked.effective_ssh_port != identity.port:
            raise ValidationError(_("Node transport changed before hardening."))
        if connection_identity(locked) != run.expected_identity:
            raise ValidationError(_("Node identity changed before hardening."))
        locked.imported_ssh_host_keys = public_keys
        locked.save(update_fields=["imported_ssh_host_keys", "updated_at"])
        server.imported_ssh_host_keys = public_keys
        run.expected_identity = connection_identity(locked)
        run.save(update_fields=["expected_identity", "updated_at"])


def _reviewed_firewall_hooks(run: NodeSecurityExecution) -> dict[str, str]:
    proposals = cast("list[str]", run.decision.review.evidence["proposed_changes"])
    hooks = {}
    for proposal in proposals:
        matched = re.fullmatch(
            r"Firewall reload hook (/etc/ufw/(?:before|after)\.init): sha256=([0-9a-f]{64}), executable=True",
            proposal,
        )
        if matched:
            hooks[matched[1]] = matched[2]
    return hooks


def _panel_check_error(failure: PanelCheckFailure, server: VirtualminServer) -> ValidationError:
    if failure.kind == "unreachable":
        return ValidationError(
            _(
                "The panel at %(host)s:%(port)s could not be reached (%(detail)s); "
                "interactive access has not been restricted"
            )
            % {"host": server.hostname, "port": server.api_port, "detail": failure.detail}
        )
    if failure.kind == "rejected":
        return ValidationError(_("Dedicated API authentication failed; interactive access has not been restricted."))
    if failure.kind == "refused":
        return ValidationError(_("The panel refused the API check; interactive access has not been restricted"))
    return ValidationError(
        _("The panel check failed (%(detail)s); interactive access has not been restricted")
        % {"detail": failure.detail}
    )


def apply_hardening(run: NodeSecurityExecution) -> NodeSecurityReview:
    from .virtualmin_security_tasks import collect_inspection  # noqa: PLC0415 -- collection and execution boundaries

    if run.server_id is None:
        raise ValidationError(_("The node has been removed."))
    server = VirtualminServer.objects.get(pk=run.server_id)
    if not owns_hardening(server, str(run.pk)):
        raise ValidationError(_("Hardening execution ownership changed."))
    verify_network_ingress(cast("list[str]", run.decision.review.evidence["firewall"]))
    username = dedicated_username(server)
    try:
        AnsibleService.operator_public_keys()
    except (OSError, ValueError) as error:
        raise ValidationError(_("Prepare the approved operator SSH key bundle before conversion.")) from error
    if not re.fullmatch(r"[a-z][a-z0-9_-]{2,31}", username):
        raise ValidationError(_("Choose a supported dedicated API login before conversion."))
    password = secrets.token_urlsafe(32)
    vault = get_credential_vault()
    staged = vault.store_credential(
        CredentialData(
            service_type="virtualmin",
            service_identifier=f"security:{run.pk}",
            username=username,
            password=password,
            metadata={"server_id": str(server.pk), "execution_id": str(run.pk)},
            reason="Persist approved API enrollment before node mutation",
        )
    )
    if staged.is_err():
        raise ValidationError(_("Could not persist the dedicated API credential; node access has not been changed."))
    _preserve_imported_trust(server, run)
    output = _run(
        server,
        run,
        "virtualmin_security_enroll.yml",
        {
            "praho_api_user": username,
            "praho_api_password": password,
            "security_hardening_approved": True,
        },
    )
    fingerprints = re.findall(r"PRAHO_PANEL_CERT=([0-9a-f]{64})", output)
    if len(fingerprints) != 1:
        raise ValidationError(_("Could not prove the panel certificate through the enrolled SSH connection."))
    config = VirtualminConfig.from_credentials(
        hostname=server.hostname,
        username=username,
        password=password,
        port=server.api_port,
        use_ssl=True,
        verify_ssl=False,
        cert_fingerprint=fingerprints[0],
    )
    api = VirtualminGateway(config).check_api()
    if api.is_err():
        raise _panel_check_error(api.unwrap_err(), server)
    with transaction.atomic():
        locked = VirtualminServer.objects.select_for_update().get(pk=server.pk)
        if locked.security_operation != run.pk or connection_identity(locked) != run.expected_identity:
            raise ValidationError(_("Hardening execution ownership changed."))
        installed = vault.store_credential(
            CredentialData(
                service_type="virtualmin",
                service_identifier=server.hostname,
                username=username,
                password=password,
                metadata={"server_id": str(server.pk), "execution_id": str(run.pk)},
                reason="Activate the SSH-proven dedicated API identity",
            )
        )
        if installed.is_err():
            raise ValidationError(
                _("Could not activate the durable API credential; interactive access has not been restricted.")
            )
        locked.api_username = username
        locked.set_api_password(password)
        locked.ssl_cert_fingerprint = fingerprints[0]
        locked.use_ssl, locked.ssl_verify = True, False
        locked.save(
            update_fields=[
                "api_username",
                "encrypted_api_password",
                "ssl_cert_fingerprint",
                "use_ssl",
                "ssl_verify",
                "updated_at",
            ]
        )
        run.expected_identity = connection_identity(locked)
        run.save(update_fields=["expected_identity", "updated_at"])
    server.refresh_from_db()
    reviewed_hooks = _reviewed_firewall_hooks(run)
    # Deal with the exact reviewed UFW hooks before the SSH role adds rules:
    # an executable hook can otherwise run during its preparatory ufw calls.
    _run(server, run, "virtualmin_firewall.yml", {"security_reviewed_firewall_hooks": reviewed_hooks})
    _run(server, run, "ssh-hardening.yml", {})
    server.refresh_from_db()
    _run(
        server,
        run,
        "virtualmin_harden.yml",
        {
            "security_hardening_approved": True,
            "praho_api_user": username,
            "security_reviewed_firewall_hooks": reviewed_hooks,
        },
    )
    return complete_hardening(run.pk, collect_inspection(server))
