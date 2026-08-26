"""
Node Validation Service

Validates that deployed nodes are healthy and functioning correctly.
Performs health checks on:
- SSH connectivity
- Virtualmin API accessibility
- Required ports
- SSL certificate status
"""

from __future__ import annotations

import hashlib
import io
import logging
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

import paramiko

from apps.common.outbound_http import (
    OutboundPolicy,
    OutboundSecurityError,
    normalize_tls_cert_fingerprint,
    safe_urlopen,
)
from apps.common.ssh import configure_strict_host_key_checking
from apps.common.types import Err, Ok, Result
from apps.infrastructure.ssh_key_manager import get_ssh_key_manager

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment

logger = logging.getLogger(__name__)

WEBMIN_PORT = 10000

VIRTUALMIN_CHECK_POLICY = OutboundPolicy(
    name="virtualmin_check",
    require_https=False,
    verify_tls=False,
    allowed_schemes=frozenset({"https"}),
    allowed_ports=frozenset({10000}),
    timeout_seconds=30.0,
    blocked_ports=frozenset(),  # Override: don't block 10000
)


@dataclass
class ValidationResult:
    """Result of a single validation check"""

    check_name: str
    passed: bool
    message: str
    details: dict[str, Any] | None = None


@dataclass
class NodeValidationReport:
    """Complete validation report for a node"""

    deployment_id: int
    hostname: str
    ip_address: str
    all_passed: bool
    checks: list[ValidationResult]
    summary: str


class NodeValidationService:
    """
    🔍 Node Validation Service

    Validates deployed nodes to ensure they are healthy and ready for use.
    Performs multiple validation checks:
    - SSH connectivity
    - Virtualmin API accessibility
    - Required ports open
    - SSL certificate validity
    """

    # Required ports for a Virtualmin hosting server
    REQUIRED_PORTS: ClassVar[list[tuple[int, str]]] = [
        (22, "SSH"),
        (80, "HTTP"),
        (443, "HTTPS"),
        (10000, "Webmin/Virtualmin"),
    ]

    # Optional ports (warn if not open)
    OPTIONAL_PORTS: ClassVar[list[tuple[int, str]]] = [
        (25, "SMTP"),
        (993, "IMAPS"),
        (995, "POP3S"),
    ]

    def __init__(self, timeout: int = 10) -> None:
        """Initialize validation service"""
        self.timeout = timeout
        self._ssh_manager = get_ssh_key_manager()

    def validate_node(
        self,
        deployment: NodeDeployment,
        checks: list[str] | None = None,
    ) -> Result[NodeValidationReport, str]:
        """
        Perform comprehensive validation of a deployed node.

        Args:
            deployment: NodeDeployment instance
            checks: Optional list of specific checks to run
                   Default: ["ssh", "ports", "virtualmin", "ssl"]

        Returns:
            Result with NodeValidationReport or error
        """
        if not deployment.ipv4_address:
            return Err(f"Node {deployment.hostname} has no IP address assigned")

        all_checks = checks or ["ssh", "ports", "virtualmin", "ssl"]
        results: list[ValidationResult] = []

        logger.info(f"🔍 [Validation] Starting validation for: {deployment.hostname}")

        # Run each validation check
        for check_name in all_checks:
            try:
                if check_name == "ssh":
                    result = self._check_ssh(deployment)
                elif check_name == "ports":
                    result = self._check_ports(deployment)
                elif check_name == "virtualmin":
                    result = self._check_virtualmin(deployment)
                elif check_name == "ssl":
                    result = self._check_ssl(deployment)
                else:
                    result = ValidationResult(
                        check_name=check_name,
                        passed=False,
                        message=f"Unknown check: {check_name}",
                    )
                results.append(result)
            except Exception as e:
                logger.error(f"🚨 [Validation] Check '{check_name}' failed with exception: {e}")
                results.append(
                    ValidationResult(
                        check_name=check_name,
                        passed=False,
                        message=f"Check failed with exception: {e}",
                    )
                )

        # Calculate overall result
        all_passed = all(r.passed for r in results)
        passed_count = sum(1 for r in results if r.passed)
        total_count = len(results)

        summary = f"All {total_count} checks passed" if all_passed else f"{passed_count}/{total_count} checks passed"

        report = NodeValidationReport(
            deployment_id=deployment.id,
            hostname=deployment.hostname,
            ip_address=deployment.ipv4_address,
            all_passed=all_passed,
            checks=results,
            summary=summary,
        )

        log_level = logging.INFO if all_passed else logging.WARNING
        logger.log(
            log_level,
            f"🔍 [Validation] {deployment.hostname}: {summary}",
        )

        return Ok(report)

    def _check_ssh(self, deployment: NodeDeployment) -> ValidationResult:
        """Check SSH connectivity"""
        try:
            # Get SSH key for this deployment
            key_result = self._ssh_manager.get_deployment_key(
                deployment,
                reason="Node validation - SSH check",
            )

            if key_result.is_err():
                # Try master key as fallback
                logger.warning(
                    "🔑 [Validation] Deployment SSH key unavailable for %s — falling back to master key",
                    getattr(deployment, "hostname", "unknown"),
                )
                master_result = self._ssh_manager.get_master_key()
                if master_result.is_err():
                    return ValidationResult(
                        check_name="ssh",
                        passed=False,
                        message=f"Could not get SSH key: {key_result.unwrap_err()}",
                    )
                private_key_content = master_result.unwrap()
            else:
                private_key_content = key_result.unwrap().private_key

            # Create SSH client
            client = paramiko.SSHClient()
            configure_strict_host_key_checking(client)

            # Load private key

            key_file = io.StringIO(private_key_content)
            pkey = paramiko.Ed25519Key.from_private_key(key_file)

            # Connect
            client.connect(
                hostname=deployment.ipv4_address,  # type: ignore[arg-type]
                port=22,
                username="root",
                pkey=pkey,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
            )

            # Test command execution
            _stdin, stdout, _stderr = client.exec_command("hostname", timeout=self.timeout)
            output = stdout.read().decode().strip()
            client.close()

            return ValidationResult(
                check_name="ssh",
                passed=True,
                message=f"SSH connection successful, hostname: {output}",
                details={"hostname": output},
            )

        except paramiko.AuthenticationException as e:
            return ValidationResult(
                check_name="ssh",
                passed=False,
                message=f"SSH authentication failed: {e}",
            )
        except paramiko.SSHException as e:
            return ValidationResult(
                check_name="ssh",
                passed=False,
                message=f"SSH connection failed: {e}",
            )
        except TimeoutError:
            return ValidationResult(
                check_name="ssh",
                passed=False,
                message="SSH connection timed out",
            )
        except Exception as e:
            return ValidationResult(
                check_name="ssh",
                passed=False,
                message=f"SSH check failed: {e}",
            )

    def get_webmin_certificate_fingerprint(  # noqa: PLR0911  # Explicit fail-closed exits per error class
        self, deployment: NodeDeployment
    ) -> Result[str, str]:
        """Read the certificate actually served by Webmin over the trusted SSH channel."""
        if not deployment.ipv4_address:
            return Err("Node has no IP address assigned")

        key_result = self._ssh_manager.get_deployment_key(
            deployment,
            reason="Node registration - verify Webmin TLS certificate",
        )
        if key_result.is_err():
            logger.warning(
                "🔑 [Validation] Deployment SSH key unavailable for %s (%s) — falling back to master key",
                deployment.hostname,
                key_result.unwrap_err(),
            )
            master_result = self._ssh_manager.get_master_key()
            if master_result.is_err():
                return Err(f"Could not get SSH key: {key_result.unwrap_err()}")
            private_key_content = master_result.unwrap()
        else:
            private_key_content = key_result.unwrap().private_key

        client: paramiko.SSHClient | None = None
        try:
            client = paramiko.SSHClient()
            configure_strict_host_key_checking(client)
            pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(private_key_content))
            client.connect(
                hostname=deployment.ipv4_address,
                port=22,
                username="root",
                pkey=pkey,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
            )

            command = (
                "openssl s_client -connect 127.0.0.1:10000 </dev/null 2>/dev/null "
                "| openssl x509 -noout -fingerprint -sha256"
            )
            _stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
            output = stdout.read().decode().strip()
            if stdout.channel.recv_exit_status() != 0:
                error_output = stderr.read().decode().strip()
                return Err(f"Could not read Webmin certificate: {error_output or 'openssl failed'}")

            _label, separator, raw_fingerprint = output.partition("=")
            if not separator or not raw_fingerprint.strip():
                return Err("Could not parse Webmin SHA-256 certificate fingerprint")
            fingerprint = normalize_tls_cert_fingerprint(raw_fingerprint)
            return Ok(fingerprint)
        except paramiko.BadHostKeyException as exc:
            # The node's SSH host key does not match the pinned known_hosts entry.
            # This is the MITM signal this verified-SSH path exists to catch — never
            # flatten it into generic connection friction.
            logger.error(
                "🚨 [Security] SSH host-key mismatch reading Webmin certificate for %s — "
                "possible man-in-the-middle; refusing to trust the served certificate: %s",
                deployment.ipv4_address,
                exc,
            )
            return Err(f"SSH host-key mismatch for {deployment.hostname} — possible MITM, certificate not trusted")
        except Exception as exc:
            logger.warning(
                "⚠️ [Validation] Could not read Webmin certificate over SSH for %s: %s",
                deployment.hostname,
                exc,
            )
            return Err(f"Could not verify Webmin certificate fingerprint over SSH: {exc}")
        finally:
            if client is not None:
                client.close()

    def _check_ports(self, deployment: NodeDeployment) -> ValidationResult:
        """Check required ports are open"""
        ip = deployment.ipv4_address
        open_ports: list[tuple[int, str]] = []
        closed_ports: list[tuple[int, str]] = []

        for port, name in self.REQUIRED_PORTS:
            if self._is_port_open(ip, port):  # type: ignore[arg-type]
                open_ports.append((port, name))
            else:
                closed_ports.append((port, name))

        passed = len(closed_ports) == 0

        if passed:
            message = f"All {len(self.REQUIRED_PORTS)} required ports are open"
        else:
            closed_names = [f"{name}({port})" for port, name in closed_ports]
            message = f"Closed ports: {', '.join(closed_names)}"

        return ValidationResult(
            check_name="ports",
            passed=passed,
            message=message,
            details={
                "open_ports": [{"port": p, "name": n} for p, n in open_ports],
                "closed_ports": [{"port": p, "name": n} for p, n in closed_ports],
            },
        )

    def _check_virtualmin(  # noqa: PLR0911  # Complexity: multi-step business logic
        self, deployment: NodeDeployment
    ) -> ValidationResult:  # Complexity: multi-step workflow  # Complexity: multi-step business logic
        """Check Virtualmin API is accessible"""

        url = f"https://{deployment.ipv4_address}:10000/"

        try:
            response = safe_urlopen(
                url,
                policy=VIRTUALMIN_CHECK_POLICY,
                method="HEAD",
                timeout=self.timeout,
            )
            status_code = response.getcode()

            # Webmin typically returns 200 or 401 (needs auth)
            if status_code in (200, 401, 403):
                return ValidationResult(
                    check_name="virtualmin",
                    passed=True,
                    message=f"Webmin/Virtualmin accessible (status: {status_code})",
                    details={"status_code": status_code, "url": url},
                )
            else:
                return ValidationResult(
                    check_name="virtualmin",
                    passed=False,
                    message=f"Unexpected status code: {status_code}",
                    details={"status_code": status_code},
                )

        except OutboundSecurityError as e:
            return ValidationResult(
                check_name="virtualmin",
                passed=False,
                message=f"Security check failed: {e}",
            )
        except urllib.error.HTTPError as e:
            # 401/403 means Webmin is running (just needs auth)
            if e.code in (401, 403):
                return ValidationResult(
                    check_name="virtualmin",
                    passed=True,
                    message=f"Webmin/Virtualmin accessible (auth required, status: {e.code})",
                    details={"status_code": e.code},
                )
            return ValidationResult(
                check_name="virtualmin",
                passed=False,
                message=f"HTTP error: {e.code} {e.reason}",
            )
        except urllib.error.URLError as e:
            return ValidationResult(
                check_name="virtualmin",
                passed=False,
                message=f"Connection failed: {e.reason}",
            )
        except TimeoutError:
            return ValidationResult(
                check_name="virtualmin",
                passed=False,
                message="Connection timed out",
            )
        except Exception as e:
            return ValidationResult(
                check_name="virtualmin",
                passed=False,
                message=f"Check failed: {e}",
            )

    def _check_ssl(self, deployment: NodeDeployment) -> ValidationResult:
        """Check the Webmin TLS listener, and REPORT whether its certificate is CA-trusted.

        #436 item 3: this check used ``verify_mode=CERT_NONE`` + ``check_hostname=False``
        and then passed on ``ssock.version()`` alone, so **any** TLS listener passed —
        self-signed, wrong-SAN, expired, all reported as "SSL/TLS enabled". A node could
        reach ``active`` while serving a self-signed panel certificate and nothing said so.

        This now performs a real trust-chain handshake (system trust store,
        ``CERT_REQUIRED``, SNI/hostname validation against the deployment fqdn) and records
        the verdict in ``details`` and the message.

        It deliberately does **not** fail the check on an untrusted certificate. Per #436
        that flip is a rollout decision requiring a staging drill against a real node and
        Let's Encrypt staging — every node currently serving a self-signed cert would start
        failing validation the moment it lands. Reporting first makes the true per-node
        state visible (and gives the drill something to read) at zero rollout risk.
        """
        try:
            trust = self._probe_tls_trust(deployment)
        except TimeoutError:
            return ValidationResult(
                check_name="ssl",
                passed=False,
                message="SSL connection timed out",
            )
        except OSError as e:
            return ValidationResult(
                check_name="ssl",
                passed=False,
                message=f"SSL check failed: {e}",
            )

        if not trust["tls_available"]:
            return ValidationResult(
                check_name="ssl",
                passed=False,
                message=f"SSL error: {trust['error']}",
            )

        if trust["trusted"]:
            message = f"SSL/TLS enabled and certificate is CA-trusted for {trust['expected_hostname']}"
        elif not trust["trust_evaluated"]:
            # No verdict was reached. Reporting this as "not trusted" would be a false
            # accusation against the certificate — the distinction matters precisely because
            # this check exists to be READ, and an operator who learns the report cries wolf
            # will stop reading it.
            message = (
                f"SSL/TLS enabled ({trust['protocol']}) but CA trust could NOT be evaluated "
                f"for {trust['expected_hostname']}: {trust['trust_error']} — see #436"
            )
        else:
            # Explicit about WHY, so the operator/drill can tell self-signed from
            # wrong-SAN from expired without re-probing by hand.
            message = (
                f"SSL/TLS enabled ({trust['protocol']}) but the certificate is NOT CA-trusted "
                f"for {trust['expected_hostname']}: {trust['trust_error']} — see #436"
            )

        # The verdict has to reach a human. The report's per-check message and details are
        # dropped by every live consumer -- deployment_service logs only report.summary, and
        # since an untrusted certificate still passes, that summary reads "All 4 checks
        # passed". Without this line the check is invisible in exactly the flow it was built
        # to inform, which is what "gives the drill something to read" depends on.
        if not trust["trusted"]:
            logger.warning(
                "⚠️ [Validation] %s panel certificate is not CA-trusted for %s (%s): %s",
                deployment.hostname,
                trust["expected_hostname"],
                "verdict reached" if trust["trust_evaluated"] else "verdict NOT reached",
                trust["trust_error"],
            )

        return ValidationResult(
            check_name="ssl",
            passed=True,  # #436: reporting only; do not gate deployments until the staging drill
            message=message,
            details={
                "protocol": trust["protocol"],
                "cipher": trust["cipher"],
                "trusted": trust["trusted"],
                "trust_evaluated": trust["trust_evaluated"],
                "expected_hostname": trust["expected_hostname"],
                "trust_error": trust["trust_error"],
                # Expiry is the most actionable datum in a TLS report and was absent: a
                # certificate with three days left read identically to one with a year.
                "not_after": trust["not_after"],
                "cert_sha256": trust["cert_sha256"],
            },
        )

    def _probe_tls_trust(self, deployment: NodeDeployment) -> dict[str, Any]:
        """Handshake twice: unverified first (for liveness), then verified (for the verdict).

        Two handshakes because a verified handshake that fails tells us nothing about the
        connection — an untrusted certificate and a dead port both raise. The unverified
        pass establishes that TLS is actually being served and captures protocol/cipher;
        the verified pass answers only "is this certificate trusted for the fqdn".
        """
        host = deployment.ipv4_address
        expected_hostname = deployment.fqdn or host

        result: dict[str, Any] = {
            "tls_available": False,
            "protocol": None,
            "cipher": None,
            "trusted": False,
            # False means "we asked and the answer was no". Absent this flag, a network
            # fault between the two connections was indistinguishable from a bad
            # certificate, and both rendered as "NOT CA-trusted".
            "trust_evaluated": False,
            "expected_hostname": expected_hostname,
            "trust_error": None,
            "not_after": None,
            "cert_sha256": None,
            "error": None,
        }

        # Pass 1 — liveness (unverified). Mirrors the previous behaviour exactly.
        unverified = ssl.create_default_context()
        unverified.check_hostname = False
        unverified.verify_mode = ssl.CERT_NONE
        try:
            with (
                socket.create_connection((host, WEBMIN_PORT), timeout=self.timeout) as sock,
                # SNI here too (verification is still off): without it CPython sends no
                # server_name at all, so on a name-based vhost the two passes can be handed
                # DIFFERENT certificates -- and the protocol/cipher reported would describe
                # a connection other than the one the verdict came from.
                unverified.wrap_socket(sock, server_hostname=expected_hostname) as ssock,
            ):
                result["tls_available"] = True
                result["protocol"] = ssock.version()
                result["cipher"] = ssock.cipher()
        except ssl.SSLError as e:
            result["error"] = str(e)
            return result

        # Pass 2 — trust verdict (verified, with SNI). A failure here is a finding, not an
        # error: it is the answer to the question, so it must never propagate as an exception.
        verified = ssl.create_default_context()
        verified.check_hostname = True
        verified.verify_mode = ssl.CERT_REQUIRED
        try:
            with (
                socket.create_connection((host, WEBMIN_PORT), timeout=self.timeout) as sock,
                verified.wrap_socket(sock, server_hostname=expected_hostname) as ssock,
            ):
                result["trusted"] = True
                result["trust_evaluated"] = True
                self._record_cert_identity(result, ssock)
        except ssl.SSLCertVerificationError as e:
            # The only arm that is genuinely a verdict ABOUT the certificate.
            result["trust_evaluated"] = True
            result["trust_error"] = e.verify_message or str(e)
        except (ssl.SSLError, OSError, ValueError) as e:
            # Everything else is a failed PROBE, not a failed certificate: a Webmin restart
            # between the two connections, a reset, a rate limit, a timeout (TimeoutError is
            # an OSError, so it never reaches the caller's handler). Leaving trust_evaluated
            # False keeps "we could not tell" out of the "the certificate is bad" bucket.
            result["trust_error"] = str(e)

        return result

    @staticmethod
    def _record_cert_identity(result: dict[str, Any], ssock: ssl.SSLSocket) -> None:
        """Capture expiry and a digest so a report is actionable and reconcilable.

        Expiry gives the drill lead time; the SHA-256 lets a network-path verdict be
        reconciled later against the SSH-read pin stored on VirtualminServer.
        """
        try:
            peer = ssock.getpeercert() or {}
            result["not_after"] = peer.get("notAfter")
            der = ssock.getpeercert(binary_form=True)
            if der:
                result["cert_sha256"] = hashlib.sha256(der).hexdigest()
        except (ValueError, OSError):  # identity is a bonus; never fail the probe over it
            pass

    def _is_port_open(self, host: str, port: int) -> bool:
        """Check if a TCP port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def quick_health_check(self, deployment: NodeDeployment) -> bool:
        """
        Quick health check - just verify SSH and port 10000.
        Used for periodic monitoring.
        """
        if not deployment.ipv4_address:
            return False

        ssh_ok = self._is_port_open(deployment.ipv4_address, 22)
        webmin_ok = self._is_port_open(deployment.ipv4_address, 10000)

        return ssh_ok and webmin_ok


# Module-level singleton
_validation_service: NodeValidationService | None = None


def get_validation_service() -> NodeValidationService:
    """Get global validation service instance"""
    global _validation_service  # noqa: PLW0603  # Module-level singleton pattern
    if _validation_service is None:
        _validation_service = NodeValidationService()
    return _validation_service
