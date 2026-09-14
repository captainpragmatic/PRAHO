"""Scoped prerequisites for #436's future Hetzner / Virtualmin certificate drill.

No deployment, DNS record, credential, pin, or activation setting is changed.
Credential resolution retains its ordinary vault access audit.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from apps.infrastructure.cloud_gateway import CloudProviderGateway, get_cloud_gateway
from apps.infrastructure.deployment_preflight import validate_deployment_dns_zone, validate_deployment_fqdn
from apps.infrastructure.dns_gateway import get_dns_gateway
from apps.infrastructure.models import CloudProvider, NodeDeployment
from apps.infrastructure.panel_cert_probes import (
    PROBE_TIMEOUT,
    AuthoritativeAnswer,
    authoritative_addresses,
    observe_http,
    public_address,
)
from apps.infrastructure.provider_config import get_provider_token
from apps.infrastructure.validation_service import NodeValidationService
from apps.settings.services import SettingsService

CheckStatus = Literal["pass", "fail", "unknown", "not_run"]
LIMITATION = (
    "Read-only prerequisites only. HTTP-01 nonce validation, issuance, installation, renewal, "
    "and activation are NOT proven. No certificate or setting is changed."
)


@dataclass(frozen=True)
class PreflightCheck:
    check_id: str
    status: CheckStatus
    message: str


@dataclass(frozen=True)
class CertificateObservation:
    status: Literal["trusted", "untrusted", "indeterminate", "not_run"] = "not_run"
    message: str = "No existing node selected; certificate observation not run."
    address: str = ""
    fqdn: str = ""
    cert_sha256: str | None = None
    not_after: str | None = None


@dataclass
class PanelCertPreflightReport:
    mode: Literal["provider", "deployment"]
    target_id: int
    checks: list[PreflightCheck] = field(default_factory=list)
    dns_answers: list[AuthoritativeAnswer] = field(default_factory=list)
    certificate: CertificateObservation = field(default_factory=CertificateObservation)

    @property
    def prerequisites_pass(self) -> bool:
        return bool(self.checks) and all(check.status == "pass" for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, **asdict(self), "prerequisites_pass": self.prerequisites_pass, "scope": LIMITATION}

    def add(self, check_id: str, status: CheckStatus, message: str) -> None:
        self.checks.append(PreflightCheck(check_id, status, message))


class PanelCertPreflightService:
    """Independent checks continue after failures; dependent checks stay visibly unrun."""

    def run(self, provider: CloudProvider, deployment: NodeDeployment | None = None) -> PanelCertPreflightReport:
        report = PanelCertPreflightReport(
            mode="deployment" if deployment else "provider", target_id=deployment.pk if deployment else provider.pk
        )
        for tool in ("ansible-playbook", "ssh", "ssh-keygen", "ssh-keyscan"):
            available = shutil.which(tool) is not None
            report.add(
                f"controller.{tool}",
                "pass" if available else "fail",
                f"{tool}: available" if available else f"Install {tool} on this controller",
            )
        gateway = self._check_provider(report, provider)
        zone = self._check_dns_config(report, deployment)
        if deployment is not None:
            if gateway is None:
                report.add(
                    "provider.node", "not_run", "Provider server lookup requires an available gateway and credential"
                )
            else:
                self._check_server(report, gateway, deployment)
            self._check_node(report, deployment, zone)
        return report

    @staticmethod
    def _check_provider(report: PanelCertPreflightReport, provider: CloudProvider) -> CloudProviderGateway | None:
        report.add(
            "provider.active",
            "pass" if provider.is_active else "fail",
            "Provider enabled" if provider.is_active else "Enable the selected provider before the drill",
        )
        # #436's paid drill is Hetzner-specific. Other SDKs do not yet expose the
        # bounded, no-retry read contract; do not silently use their normal budgets.
        if provider.provider_type != "hetzner":
            report.add("provider.authentication", "not_run", "This drill preflight supports Hetzner providers only")
            return None
        try:
            token_result = get_provider_token(provider)
            if token_result.is_err() or not token_result.unwrap().strip():
                report.add(
                    "provider.authentication",
                    "fail",
                    "Cannot resolve provider credential; check the configured vault entry (environment is bootstrap-only)",
                )
                return None
            gateway = get_cloud_gateway("hetzner", token_result.unwrap(), timeout=PROBE_TIMEOUT, max_retries=0)
            # This authenticated read neither creates a resource nor reserves capacity.
            result = gateway.get_locations()
            if result.is_err():
                report.add(
                    "provider.authentication",
                    "unknown",
                    "Provider read failed; check credential validity, permissions, connectivity and rate limits",
                )
            else:
                report.add(
                    "provider.authentication",
                    "pass",
                    "Authenticated provider read succeeded; capacity and write permission remain unproven",
                )
            return gateway
        except Exception:
            # Gateway/vault exceptions can contain tokens or authenticated request
            # payloads. Never echo them, including in JSON or exception chaining.
            report.add(
                "provider.authentication",
                "unknown",
                "Provider probe unavailable; check credentials and controller connectivity",
            )
            return None

    @staticmethod
    def _check_server(
        report: PanelCertPreflightReport, gateway: CloudProviderGateway, deployment: NodeDeployment
    ) -> None:
        if not deployment.external_node_id:
            report.add("provider.node", "fail", "Deployment has no provider server ID")
            return
        try:
            result = gateway.get_server(deployment.external_node_id)
        except Exception:
            report.add("provider.node", "unknown", "Provider server probe unavailable; check access and connectivity")
            return
        if result.is_err():
            report.add(
                "provider.node", "unknown", "Cannot read the recorded provider server; check access and connectivity"
            )
        else:
            server = result.unwrap()
            if server is None:
                report.add("provider.node", "fail", "Recorded provider server does not exist")
                return
            report.add(
                "provider.node",
                "pass" if server.status == "running" else "fail",
                "Provider server is running" if server.status == "running" else "Provider server is not running",
            )

    @staticmethod
    def _setting(report: PanelCertPreflightReport, key: str, check_id: str) -> str:
        try:
            return str(SettingsService.get_setting(key) or "").strip()
        except Exception:
            report.add(check_id, "unknown", f"Cannot read {key}; check settings access")
            return ""

    def _check_dns_config(self, report: PanelCertPreflightReport, deployment: NodeDeployment | None) -> str:
        token = self._setting(report, "node_deployment.dns_cloudflare_api_token", "dns.token_read")
        zone_id = self._setting(report, "node_deployment.dns_cloudflare_zone_id", "dns.zone_id_read")
        raw_zone = (
            deployment.dns_zone
            if deployment
            else self._setting(report, "node_deployment.dns_default_zone", "dns.zone_read")
        )
        zone_result = validate_deployment_dns_zone(raw_zone)
        zone = zone_result.unwrap() if zone_result.is_ok() else ""
        report.add(
            "dns.token",
            "pass" if token else "fail",
            "Cloudflare credential configured" if token else "Configure node_deployment.dns_cloudflare_api_token",
        )
        valid_zone_id = bool(re.fullmatch(r"[0-9a-fA-F]{32}", zone_id))
        report.add(
            "dns.zone_id",
            "pass" if valid_zone_id else "fail",
            "Cloudflare zone ID has valid format"
            if valid_zone_id
            else "Configure a 32-character hexadecimal node_deployment.dns_cloudflare_zone_id",
        )
        report.add(
            "dns.zone",
            "pass" if zone else "fail",
            "Deployment DNS zone has valid format" if zone else "Configure a valid fully-qualified deployment DNS zone",
        )
        if not token or not valid_zone_id:
            report.add("dns.zone_access", "not_run", "Zone lookup requires a Cloudflare token and valid zone ID")
            report.add("dns.zone_containment", "not_run", "Zone containment requires an accessible Cloudflare zone")
            return zone
        try:
            gateway = get_dns_gateway("cloudflare", token, timeout=PROBE_TIMEOUT)
            result = gateway.get_zone_name(zone_id)
            if result.is_err():
                report.add(
                    "dns.zone_access",
                    "unknown",
                    "Cloudflare zone read failed; check token validity, Zone Read permission, zone ID and connectivity",
                )
                report.add("dns.zone_containment", "not_run", "Zone containment requires a successful zone read")
                return zone
            actual_zone = result.unwrap().lower().rstrip(".")
            report.add(
                "dns.zone_access", "pass", "Cloudflare zone read succeeded; DNS write permission remains unproven"
            )
            contained = bool(zone) and (zone == actual_zone or zone.endswith(f".{actual_zone}"))
            report.add(
                "dns.zone_containment",
                "pass" if contained else "fail",
                "Configured deployment zone is inside the Cloudflare zone"
                if contained
                else "Deployment zone is not inside the selected Cloudflare zone; correct the zone settings",
            )
        except Exception:
            report.add("dns.zone_access", "unknown", "Cloudflare probe unavailable; check credentials and connectivity")
            report.add("dns.zone_containment", "not_run", "Zone containment requires a successful zone read")
        return zone

    def _check_node(self, report: PanelCertPreflightReport, deployment: NodeDeployment, zone: str) -> None:
        supported = deployment.panel_type.panel_type == "virtualmin"
        report.add(
            "node.panel",
            "pass" if supported else "fail",
            "Virtualmin panel selected" if supported else "Select a Virtualmin deployment for this drill",
        )
        fqdn_result = validate_deployment_fqdn(deployment.hostname, zone)
        if fqdn_result.is_err():
            report.add("node.fqdn", "fail", "Deployment needs a valid public FQDN before network checks")
            report.add("dns.authoritative", "not_run", "DNS and HTTP probes require a valid node FQDN")
            report.certificate = CertificateObservation(message="Certificate probe requires a valid node FQDN")
            return
        fqdn = fqdn_result.unwrap()
        report.add("node.fqdn", "pass", f"Node FQDN: {fqdn}")
        expected = self._expected_addresses(report, deployment)
        report.dns_answers = authoritative_addresses(fqdn)
        published: set[str] = set()
        for answer in report.dns_answers:
            check_id = f"dns.authoritative.{answer.nameserver.rstrip('.')}.{answer.record_type}"
            if answer.error:
                report.add(check_id, "unknown", answer.error)
                continue
            published.update(answer.addresses)
            matches = set(answer.addresses) == expected.get(answer.record_type, set())
            report.add(
                check_id,
                "pass" if matches else "fail",
                f"{answer.record_type}: observed {list(answer.addresses)}, recorded {sorted(expected.get(answer.record_type, set()))}. "
                + ("Addresses match" if matches else "Fix missing, stale or unexpected records"),
            )
        self._check_http(report, fqdn, published)
        if supported and expected["A"]:
            report.certificate = self._certificate(deployment)
        else:
            report.certificate = CertificateObservation(
                message="Certificate probe requires Virtualmin and a recorded public IPv4 address"
            )

    @staticmethod
    def _expected_addresses(report: PanelCertPreflightReport, deployment: NodeDeployment) -> dict[str, set[str]]:
        expected: dict[str, set[str]] = {"A": set(), "AAAA": set()}
        for record_type, raw, version in (("A", deployment.ipv4_address, 4), ("AAAA", deployment.ipv6_address, 6)):
            if not raw and record_type == "AAAA":
                report.add("node.AAAA", "pass", "No recorded IPv6 address; authoritative AAAA must be empty")
                continue
            try:
                expected[record_type].add(public_address(raw or "", version))
            except ValueError:
                report.add(
                    f"node.{record_type}", "fail", f"Record a valid public IPv{version} address on the deployment"
                )
            else:
                report.add(f"node.{record_type}", "pass", f"Recorded IPv{version}: {raw}")
        return expected

    @staticmethod
    def _check_http(report: PanelCertPreflightReport, fqdn: str, addresses: set[str]) -> None:
        if not addresses:
            report.add("http.routing", "not_run", "No authoritative node addresses available for HTTP routing probes")
        for address in sorted(addresses):
            try:
                status = observe_http(fqdn, address)
            except ValueError:
                report.add(f"http.routing.{address}", "fail", "Published address is not public; HTTP probe refused")
                continue
            report.add(
                f"http.routing.{address}",
                "pass" if status is not None else "unknown",
                f"Port 80 returned HTTP {status} with the node Host header; redirects were not followed. Actual HTTP-01 nonce remains untested"
                if status is not None
                else "No HTTP response; check firewall, web service and controller IPv4/IPv6 routing",
            )

    @staticmethod
    def _certificate(deployment: NodeDeployment) -> CertificateObservation:
        try:
            result = NodeValidationService(timeout=PROBE_TIMEOUT)._probe_tls_trust(deployment)
        except (OSError, ValueError):
            result = {}
        status: Literal["trusted", "untrusted", "indeterminate"] = "indeterminate"
        if result.get("trust_evaluated"):
            status = "trusted" if result.get("trusted") else "untrusted"
        return CertificateObservation(
            status=status,
            message="Current panel certificate observation only; a self-signed certificate is expected before issuance",
            address=deployment.ipv4_address or "",
            fqdn=deployment.fqdn,
            cert_sha256=result.get("cert_sha256"),
            not_after=result.get("not_after"),
        )
