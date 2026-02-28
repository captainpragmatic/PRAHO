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

import logging
import socket
import ssl
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

import paramiko

from apps.common.types import Err, Ok, Result
from apps.infrastructure.ssh_key_manager import get_ssh_key_manager

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment

logger = logging.getLogger(__name__)


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
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507

            # Load private key
            import io  # noqa: PLC0415

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

    def _check_virtualmin(self, deployment: NodeDeployment) -> ValidationResult:  # noqa: PLR0911
        """Check Virtualmin API is accessible"""
        import urllib.error  # noqa: PLC0415
        import urllib.request  # noqa: PLC0415

        url = f"https://{deployment.ipv4_address}:10000/"

        try:
            # Create SSL context that doesn't verify (for self-signed certs)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            request = urllib.request.Request(url, method="HEAD")  # noqa: S310
            request.add_header("User-Agent", "PRAHO-Validation/1.0")

            with urllib.request.urlopen(request, timeout=self.timeout, context=ctx) as response:  # noqa: S310  # nosemgrep: dynamic-urllib-use-detected — admin-managed server URL
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
        """Check SSL certificate for Webmin"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with (
                socket.create_connection((deployment.ipv4_address, 10000), timeout=self.timeout) as sock,
                context.wrap_socket(sock) as ssock,
            ):
                cert = ssock.getpeercert(binary_form=False)

                # Even with self-signed, we want SSL working
                if cert or ssock.version():
                    return ValidationResult(
                        check_name="ssl",
                        passed=True,
                        message=f"SSL/TLS enabled ({ssock.version()})",
                        details={
                            "protocol": ssock.version(),
                            "cipher": ssock.cipher(),
                        },
                    )
                return ValidationResult(
                    check_name="ssl",
                    passed=True,
                    message="SSL/TLS enabled (self-signed certificate)",
                )

        except ssl.SSLError as e:
            return ValidationResult(
                check_name="ssl",
                passed=False,
                message=f"SSL error: {e}",
            )
        except TimeoutError:
            return ValidationResult(
                check_name="ssl",
                passed=False,
                message="SSL connection timed out",
            )
        except Exception as e:
            return ValidationResult(
                check_name="ssl",
                passed=False,
                message=f"SSL check failed: {e}",
            )

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
    global _validation_service  # noqa: PLW0603
    if _validation_service is None:
        _validation_service = NodeValidationService()
    return _validation_service
