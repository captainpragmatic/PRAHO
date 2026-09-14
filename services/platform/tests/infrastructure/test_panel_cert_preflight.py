"""Read-only drill diagnostics: real decision logic, mocked external transports."""

from __future__ import annotations

import io
import json
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.resolver
import dns.rrset
import requests
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import SimpleTestCase, TestCase

from apps.common.types import Err, Ok
from apps.infrastructure.cloud_gateway import CloudProviderGateway, ServerInfo
from apps.infrastructure.dns_gateway import CLOUDFLARE_POLICY, CloudflareDnsGateway
from apps.infrastructure.hcloud_service import HcloudService
from apps.infrastructure.models import CloudProvider, NodeDeployment, PanelType
from apps.infrastructure.panel_cert_preflight import PanelCertPreflightService
from apps.infrastructure.panel_cert_probes import (
    HTTP_PROBE_PATH,
    AuthoritativeAnswer,
    authoritative_addresses,
    observe_http,
    public_address,
)
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment

SERVICE = "apps.infrastructure.panel_cert_preflight"
PROBES = "apps.infrastructure.panel_cert_probes"
IPV4 = "8.8.8.8"
IPV6 = "2606:4700:4700::1111"
FQDN = "node.example.com"
CLOUD_SECRET = "private-cloud-credential"
DNS_SECRET = "private-dns-credential"
SETTINGS = {
    "node_deployment.dns_cloudflare_api_token": DNS_SECRET,
    "node_deployment.dns_cloudflare_zone_id": "a" * 32,
    "node_deployment.dns_default_zone": "nodes.example.com",
}


class PreflightTests(SimpleTestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.provider = CloudProvider(
            pk=1, provider_type="hetzner", is_active=True, credential_identifier="vault-entry"
        )
        self.deployment = NodeDeployment(
            pk=2,
            provider=self.provider,
            panel_type=PanelType(panel_type="virtualmin"),
            hostname="node",
            dns_zone="example.com",
            ipv4_address=IPV4,
            external_node_id="42",
        )
        self.settings = SETTINGS.copy()
        self.stack.enter_context(patch(f"{SERVICE}.SettingsService.get_setting", side_effect=self.settings.get))
        self.tools = self.stack.enter_context(patch(f"{SERVICE}.shutil.which", return_value="/usr/bin/tool"))
        self.vault = self.stack.enter_context(patch("apps.common.credential_vault.get_credential_vault")).return_value
        self.vault.get_credential.return_value = Ok(("", CLOUD_SECRET, {}))
        self.cloud = MagicMock(spec=CloudProviderGateway)
        self.cloud.get_locations.return_value = Ok([])
        self.cloud.get_server.return_value = Ok(ServerInfo("42", "node", "running", IPV4))
        self.cloud_factory = self.stack.enter_context(patch(f"{SERVICE}.get_cloud_gateway", return_value=self.cloud))
        self.dns = MagicMock(spec=CloudflareDnsGateway)
        self.dns.get_zone_name.return_value = Ok("example.com")
        self.dns_factory = self.stack.enter_context(patch(f"{SERVICE}.get_dns_gateway", return_value=self.dns))
        self.answers = self.stack.enter_context(
            patch(
                f"{SERVICE}.authoritative_addresses",
                return_value=[
                    AuthoritativeAnswer("ns1.example.com.", "A", (IPV4,)),
                    AuthoritativeAnswer("ns1.example.com.", "AAAA"),
                    AuthoritativeAnswer("ns2.example.com.", "A", (IPV4,)),
                    AuthoritativeAnswer("ns2.example.com.", "AAAA"),
                ],
            )
        )
        self.http = self.stack.enter_context(patch(f"{SERVICE}.observe_http", return_value=404))
        self.tls = self.stack.enter_context(
            patch(
                f"{SERVICE}.NodeValidationService._probe_tls_trust",
                return_value={
                    "trust_evaluated": True,
                    "trusted": False,
                },
            )
        )

    def run_report(self, *, node=False):
        return PanelCertPreflightService().run(self.provider, self.deployment if node else None)

    def status(self, report, check_id):
        return next(check.status for check in report.checks if check.check_id == check_id)

    def test_provider_mode_only_checks_configuration_and_authenticated_reads(self):
        report = self.run_report()
        self.assertTrue(report.prerequisites_pass)
        self.assertEqual(report.certificate.status, "not_run")
        self.answers.assert_not_called()
        self.http.assert_not_called()
        self.tls.assert_not_called()
        self.assertEqual([call[0] for call in self.cloud.method_calls], ["get_locations"])
        self.assertEqual([call[0] for call in self.dns.method_calls], ["get_zone_name"])
        self.cloud_factory.assert_called_once_with("hetzner", CLOUD_SECRET, timeout=10, max_retries=0)
        self.dns_factory.assert_called_once_with("cloudflare", DNS_SECRET, timeout=10)
        self.assertIn("NOT proven", report.to_dict()["scope"])

    def test_vault_precedes_environment_and_failed_lookup_does_not_fall_back(self):
        with patch.dict("os.environ", {"HCLOUD_TOKEN": "environment-secret"}):
            self.run_report()
            self.assertEqual(self.cloud_factory.call_args.args[1], CLOUD_SECRET)
            self.cloud_factory.reset_mock()
            self.vault.get_credential.return_value = Err("missing")
            report = self.run_report()
        self.assertEqual(self.status(report, "provider.authentication"), "fail")
        self.cloud_factory.assert_not_called()
        self.dns.get_zone_name.assert_called()

    def test_bootstrap_environment_only_when_no_vault_identifier(self):
        self.provider.credential_identifier = ""
        with patch.dict("os.environ", {"HCLOUD_TOKEN": "bootstrap-secret"}):
            report = self.run_report()
        self.assertTrue(report.prerequisites_pass)
        self.vault.get_credential.assert_not_called()
        self.assertEqual(self.cloud_factory.call_args.args[1], "bootstrap-secret")

    def test_vault_failure_does_not_leak_into_logs(self):
        self.vault.get_credential.return_value = Err(CLOUD_SECRET)
        with self.assertLogs("apps.infrastructure.provider_config", level="ERROR") as logs:
            report = self.run_report()
        self.assertNotIn(CLOUD_SECRET, " ".join(logs.output))
        self.assertNotIn(CLOUD_SECRET, json.dumps(report.to_dict()))

    def test_missing_configuration_completes_independent_checks(self):
        self.settings.clear()
        self.tools.return_value = None
        report = self.run_report(node=True)
        self.assertFalse(report.prerequisites_pass)
        for check_id in ("dns.token", "dns.zone_id", "controller.ansible-playbook", "controller.ssh-keyscan"):
            self.assertEqual(self.status(report, check_id), "fail")
        self.assertEqual(self.status(report, "dns.zone_access"), "not_run")
        self.answers.assert_called_once_with(FQDN)
        self.tls.assert_called_once_with(self.deployment)
        self.dns.get_zone_name.assert_not_called()

    def test_api_failures_and_exceptions_never_echo_credentials(self):
        for throws in (False, True):
            with self.subTest(throws=throws):
                if throws:
                    self.cloud.get_locations.side_effect = RuntimeError(CLOUD_SECRET)
                    self.dns.get_zone_name.side_effect = RuntimeError(DNS_SECRET)
                else:
                    self.cloud.get_locations.return_value = Err(f"403 Authorization: Bearer {CLOUD_SECRET}")
                    self.dns.get_zone_name.return_value = Err(f"401 Authorization: Bearer {DNS_SECRET}")
                report = self.run_report(node=True)
                rendered = json.dumps(report.to_dict())
                self.assertNotIn(CLOUD_SECRET, rendered)
                self.assertNotIn(DNS_SECRET, rendered)
                self.assertFalse(report.prerequisites_pass)
                self.assertEqual(self.status(report, "provider.authentication"), "unknown")
                self.assertEqual(self.status(report, "dns.zone_access"), "unknown")
                ids = [check.check_id for check in report.checks]
                self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(self.http.call_count, 2)

    def test_zone_containment_checks_label_boundary(self):
        for zone in ("someone-else.com", "notexample.com", "example.com.attacker.com"):
            with self.subTest(zone=zone):
                self.settings["node_deployment.dns_default_zone"] = zone
                report = self.run_report()
                self.assertEqual(self.status(report, "dns.zone_containment"), "fail")

    def test_invalid_zone_and_path_in_zone_id_block_api_request(self):
        self.settings["node_deployment.dns_default_zone"] = "not a zone"
        self.settings["node_deployment.dns_cloudflare_zone_id"] = "../user/tokens"
        report = self.run_report()
        self.assertEqual(self.status(report, "dns.zone"), "fail")
        self.assertEqual(self.status(report, "dns.zone_id"), "fail")
        self.dns.get_zone_name.assert_not_called()

    def test_settings_read_failure_is_reported_and_other_checks_continue(self):
        with patch(f"{SERVICE}.SettingsService.get_setting", side_effect=RuntimeError(DNS_SECRET)):
            report = self.run_report(node=True)
        self.assertEqual(self.status(report, "dns.token_read"), "unknown")
        self.assertNotIn(DNS_SECRET, json.dumps(report.to_dict()))
        self.assertEqual(self.status(report, "node.fqdn"), "pass")

    def test_unsupported_or_inactive_provider_is_never_green(self):
        self.provider.provider_type = "digitalocean"
        self.provider.is_active = False
        report = self.run_report()
        self.assertEqual(self.status(report, "provider.authentication"), "not_run")
        self.assertEqual(self.status(report, "provider.active"), "fail")
        self.cloud_factory.assert_not_called()

    def test_existing_node_self_signed_observation_does_not_block_prerequisites(self):
        report = self.run_report(node=True)
        self.assertTrue(report.prerequisites_pass)
        self.assertEqual(report.certificate.status, "untrusted")
        self.http.assert_called_once_with(FQDN, IPV4)  # same address on two NS, probed once
        self.assertEqual([call[0] for call in self.cloud.method_calls], ["get_locations", "get_server"])
        self.assertEqual([call[0] for call in self.dns.method_calls], ["get_zone_name"])

    def test_certificate_verdicts_and_identity_remain_separate(self):
        self.tls.return_value = {
            "trust_evaluated": True,
            "trusted": True,
            "cert_sha256": "f" * 64,
            "not_after": "expiry",
        }
        report = self.run_report(node=True)
        self.assertEqual(report.certificate.status, "trusted")
        self.assertEqual(report.certificate.cert_sha256, "f" * 64)
        self.assertEqual(report.certificate.not_after, "expiry")
        self.tls.side_effect = TimeoutError("TLS timed out")
        report = self.run_report(node=True)
        self.assertEqual(report.certificate.status, "indeterminate")
        self.assertTrue(report.prerequisites_pass)

    def test_disagreement_and_stale_ipv6_still_probe_all_published_addresses(self):
        self.answers.return_value[2] = AuthoritativeAnswer("ns2.example.com.", "A", ("9.9.9.9",))
        self.answers.return_value[3] = AuthoritativeAnswer("ns2.example.com.", "AAAA", (IPV6,))
        report = self.run_report(node=True)
        self.assertEqual(self.status(report, "dns.authoritative.ns2.example.com.A"), "fail")
        self.assertEqual(self.status(report, "dns.authoritative.ns2.example.com.AAAA"), "fail")
        self.assertEqual({call.args[1] for call in self.http.call_args_list}, {IPV4, IPV6, "9.9.9.9"})
        self.assertFalse(report.prerequisites_pass)

    def test_ipv6_unavailable_from_controller_is_indeterminate(self):
        self.deployment.ipv6_address = IPV6
        self.answers.return_value = [
            AuthoritativeAnswer("ns1", "A", (IPV4,)),
            AuthoritativeAnswer("ns1", "AAAA", (IPV6,)),
        ]
        self.http.side_effect = lambda fqdn, address: None if address == IPV6 else 200
        report = self.run_report(node=True)
        self.assertEqual(self.status(report, f"http.routing.{IPV6}"), "unknown")
        self.assertFalse(report.prerequisites_pass)

    def test_missing_addresses_and_dns_failures_are_not_empty_success(self):
        self.deployment.ipv4_address = ""
        self.answers.return_value = [AuthoritativeAnswer("discovery", "NS", error="timed out")]
        report = self.run_report(node=True)
        self.assertEqual(self.status(report, "node.A"), "fail")
        self.assertEqual(self.status(report, "http.routing"), "not_run")
        self.assertEqual(report.certificate.status, "not_run")
        self.assertFalse(report.prerequisites_pass)

    def test_invalid_node_and_unsupported_panel_do_not_probe_tls(self):
        self.deployment.hostname = "not/valid"
        report = self.run_report(node=True)
        self.assertEqual(self.status(report, "node.fqdn"), "fail")
        self.answers.assert_not_called()
        self.deployment.hostname = "node"
        self.deployment.panel_type.panel_type = "cpanel"
        report = self.run_report(node=True)
        self.assertEqual(self.status(report, "node.panel"), "fail")
        self.tls.assert_not_called()

    def test_provider_node_must_exist_and_be_running(self):
        for result in (Ok(None), Ok(ServerInfo("42", "node", "stopped", IPV4)), Err("timeout")):
            with self.subTest(result=result):
                self.cloud.get_server.return_value = result
                report = self.run_report(node=True)
                self.assertFalse(report.prerequisites_pass)
        self.cloud.get_server.side_effect = RuntimeError(CLOUD_SECRET)
        report = self.run_report(node=True)
        self.assertEqual(self.status(report, "provider.node"), "unknown")
        self.assertNotIn(CLOUD_SECRET, json.dumps(report.to_dict()))
        self.deployment.external_node_id = ""
        report = self.run_report(node=True)
        self.assertEqual(self.status(report, "provider.node"), "fail")

    def test_private_published_address_is_refused(self):
        self.answers.return_value = [AuthoritativeAnswer("ns1", "A", ("127.0.0.1",))]
        self.http.side_effect = ValueError("private")
        report = self.run_report(node=True)
        self.assertEqual(self.status(report, "http.routing.127.0.0.1"), "fail")


class AuthoritativeDnsTests(SimpleTestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.resolver = self.stack.enter_context(patch(f"{PROBES}.dns.resolver.Resolver")).return_value
        self.stack.enter_context(
            patch(f"{PROBES}.dns.resolver.zone_for_name", return_value=dns.name.from_text("example.com."))
        )
        self.resolver.resolve.side_effect = self.resolve
        self.query = self.stack.enter_context(patch(f"{PROBES}.dns.query.tcp", side_effect=self.answer))

    @staticmethod
    def resolve(name, record_type, **kwargs):
        name = str(name)
        if record_type == "NS":
            return dns.rrset.from_text(name, 60, "IN", "NS", "ns1.example.com.", "ns2.example.com.")
        return dns.rrset.from_text(name, 60, "IN", "A", "1.1.1.1" if name.startswith("ns1") else "9.9.9.9")

    @staticmethod
    def answer(query, address, **kwargs):
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        if query.question[0].rdtype == dns.rdatatype.A:
            response.answer.append(dns.rrset.from_text(f"{FQDN}.", 60, "IN", "A", IPV4))
        else:
            response.authority.append(
                dns.rrset.from_text(
                    "example.com", 60, "IN", "SOA", "ns1.example.com. hostmaster.example.com. 1 2 3 4 5"
                )
            )
        return response

    def test_queries_every_authority_for_both_families_with_no_recursion(self):
        answers = authoritative_addresses(FQDN)
        self.assertEqual(len(answers), 4)
        self.assertTrue(all(not answer.error for answer in answers))
        self.assertEqual(answers[0].addresses, (IPV4,))
        self.assertEqual(answers[1].addresses, ())
        for call in self.query.call_args_list:
            self.assertFalse(call.args[0].flags & dns.flags.RD)
            self.assertEqual(call.kwargs["timeout"], 10)

    def test_one_server_timeout_does_not_suppress_other_answers(self):
        self.query.side_effect = lambda query, address, **kwargs: (
            self.answer(query, address) if address == "9.9.9.9" else (_ for _ in ()).throw(dns.exception.Timeout())
        )
        answers = authoritative_addresses(FQDN)
        self.assertEqual(sum(bool(answer.error) for answer in answers), 2)
        self.assertEqual(answers[2].addresses, (IPV4,))
        self.assertEqual(self.query.call_count, 4)

    def test_nonauthoritative_alias_and_empty_unproven_answers_are_errors(self):
        for kind in ("recursive", "alias", "empty", "servfail", "nxdomain"):
            with self.subTest(kind=kind):

                def bad_answer(query, address, kind=kind, **kwargs):
                    response = dns.message.make_response(query)
                    if kind != "recursive":
                        response.flags |= dns.flags.AA
                    if kind == "alias":
                        response.answer.append(dns.rrset.from_text(FQDN, 60, "IN", "CNAME", "elsewhere.example.com."))
                    if kind == "servfail":
                        response.set_rcode(dns.rcode.SERVFAIL)
                    if kind == "nxdomain":
                        response.set_rcode(dns.rcode.NXDOMAIN)
                        response.authority.append(
                            dns.rrset.from_text(
                                "example.com.", 60, "IN", "SOA", "ns1.example.com. hostmaster.example.com. 1 2 3 4 5"
                            )
                        )
                    return response

                self.query.side_effect = bad_answer
                self.assertTrue(all(answer.error for answer in authoritative_addresses(FQDN)))

    def test_failed_discovery_and_nameserver_resolution_remain_visible(self):
        self.resolver.resolve.side_effect = dns.exception.Timeout()
        self.assertTrue(authoritative_addresses(FQDN)[0].error)
        self.resolver.resolve.side_effect = lambda name, rdtype, **kw: (
            self.resolve(name, rdtype) if rdtype == "NS" else (_ for _ in ()).throw(dns.exception.Timeout())
        )
        answers = authoritative_addresses(FQDN)
        self.assertEqual(len(answers), 2)
        self.assertTrue(all(answer.error for answer in answers))

    def test_ipv6_only_nameserver_and_private_nameserver_addresses(self):
        def resolve(name, record_type, **kwargs):
            if record_type == "NS":
                return self.resolve(name, record_type)
            if record_type == "A":
                raise dns.resolver.NoAnswer()
            return dns.rrset.from_text(str(name), 60, "IN", "AAAA", IPV6)

        self.resolver.resolve.side_effect = resolve
        answers = authoritative_addresses(FQDN)
        self.assertTrue(all(not answer.error for answer in answers))
        self.assertEqual({call.args[1] for call in self.query.call_args_list}, {IPV6})
        self.query.reset_mock()
        self.resolver.resolve.side_effect = lambda name, record_type, **kwargs: (
            self.resolve(name, record_type)
            if record_type == "NS"
            else dns.rrset.from_text(str(name), 60, "IN", record_type, "127.0.0.1" if record_type == "A" else "::1")
        )
        self.assertTrue(all(answer.error for answer in authoritative_addresses(FQDN)))
        self.query.assert_not_called()

    def test_unrelated_zone_root_and_empty_delegation_are_not_success(self):
        for zone in ("elsewhere.com.", "."):
            with (
                self.subTest(zone=zone),
                patch(f"{PROBES}.dns.resolver.zone_for_name", return_value=dns.name.from_text(zone)),
            ):
                self.assertTrue(authoritative_addresses(FQDN)[0].error)
        self.resolver.resolve.return_value = []
        self.resolver.resolve.side_effect = None
        self.assertTrue(authoritative_addresses(FQDN)[0].error)
        self.query.assert_not_called()


class TransportTests(SimpleTestCase):
    def test_hetzner_sdk_times_out_without_automatic_retry(self):
        service = HcloudService("test-token", timeout=10, max_retries=0)
        with (
            patch.object(service.client._client._session, "request", side_effect=requests.Timeout()) as request,
            patch("hcloud._client.time.sleep") as sleep,
        ):
            self.assertTrue(service.get_locations().is_err())
        request.assert_called_once()
        self.assertEqual(request.call_args.kwargs["timeout"], 10)
        sleep.assert_not_called()

    def test_cloudflare_timeout_override_is_local_to_preflight_client(self):
        with patch("apps.infrastructure.dns_gateway.safe_request", side_effect=requests.Timeout()) as request:
            self.assertTrue(CloudflareDnsGateway("secret", timeout=10).get_zone_name("a" * 32).is_err())
        self.assertEqual(request.call_args.kwargs["policy"].timeout_seconds, 10)
        self.assertFalse(request.call_args.kwargs["policy"].retry_connection_errors)
        self.assertEqual(CLOUDFLARE_POLICY.timeout_seconds, 30)
        self.assertEqual(request.call_count, 1)

    def test_http_uses_each_ip_and_host_without_redirects_bodies_or_retries(self):
        for address in (IPV4, IPV6):
            for status in (200, 301, 404, 503):
                with self.subTest(address=address, status=status), patch(f"{PROBES}.safe_request") as request:
                    response = request.return_value.__enter__.return_value
                    response.status_code = status
                    self.assertEqual(observe_http(FQDN, address), status)
                    policy = request.call_args.kwargs["policy"]
                    self.assertFalse(policy.allow_redirects)
                    self.assertFalse(policy.retry_connection_errors)
                    self.assertEqual(policy.max_retries, 0)
                    self.assertEqual(policy.timeout_seconds, 10)
                    self.assertEqual(request.call_args.kwargs["headers"], {"Host": FQDN})
                    self.assertTrue(request.call_args.kwargs["stream"])
                    self.assertTrue(request.call_args.args[1].endswith(HTTP_PROBE_PATH))
                    self.assertIn(f"[{IPV6}]" if address == IPV6 else IPV4, request.call_args.args[1])
                    request.assert_called_once()

    def test_http_timeout_and_private_destinations(self):
        with patch(f"{PROBES}.safe_request", side_effect=requests.Timeout()) as request:
            self.assertIsNone(observe_http(FQDN, IPV6))
            request.assert_called_once()
        for value in ("127.0.0.1", "169.254.169.254", "::1", "fe80::1", "224.0.0.1", "not-an-ip"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                public_address(value)


class PreflightCommandTests(TestCase):
    def setUp(self):
        self.deployment = _create_deployment("installing_panel", "42")
        self.deployment.ipv4_address = IPV4
        self.deployment.save(update_fields=["ipv4_address"])

    def test_json_failure_is_nonzero_complete_and_has_no_operational_writes(self):
        output = io.StringIO()
        before = NodeDeployment.objects.values().get(pk=self.deployment.pk)

        def read_only(execute, sql, params, many, context):
            self.assertFalse(sql.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE")), sql)
            return execute(sql, params, many, context)

        with (
            connection.execute_wrapper(read_only),
            patch(f"{SERVICE}.get_provider_token", return_value=Err("secret")),
            patch(f"{SERVICE}.SettingsService.get_setting", return_value=""),
            patch(f"{SERVICE}.shutil.which", return_value=None),
            patch(
                f"{SERVICE}.authoritative_addresses",
                return_value=[AuthoritativeAnswer("discovery", "NS", error="unavailable")],
            ),
            patch(f"{SERVICE}.NodeValidationService._probe_tls_trust", side_effect=TimeoutError()),
            self.assertRaises(CommandError),
        ):
            call_command("panel_cert_preflight", deployment_id=self.deployment.pk, json=True, stdout=output)
        report = json.loads(output.getvalue())
        self.assertFalse(report["prerequisites_pass"])
        self.assertEqual(report["certificate"]["status"], "indeterminate")
        self.assertNotIn("secret", output.getvalue())
        self.assertEqual(before, NodeDeployment.objects.values().get(pk=self.deployment.pk))

    def test_success_and_text_output(self):
        fixture = PreflightTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for use_json in (False, True):
            with self.subTest(json=use_json):
                output = io.StringIO()
                call_command(
                    "panel_cert_preflight", provider_id=self.deployment.provider_id, json=use_json, stdout=output
                )
                if use_json:
                    self.assertTrue(json.loads(output.getvalue())["prerequisites_pass"])
                else:
                    self.assertIn("Scoped prerequisites: PASS", output.getvalue())
                    self.assertIn("NOT proven", output.getvalue())

    def test_invalid_target_and_mutually_exclusive_arguments(self):
        for args in (
            ("--provider-id", "0"),
            ("--deployment-id", "0"),
            (),
            ("--provider-id", "1", "--deployment-id", "2"),
        ):
            with self.subTest(args=args), self.assertRaises(CommandError):
                call_command("panel_cert_preflight", *args, stdout=io.StringIO(), stderr=io.StringIO())
