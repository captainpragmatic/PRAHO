"""Regression tests for trusted Virtualmin certificate pin registration."""

from __future__ import annotations

from io import StringIO
from unittest.mock import MagicMock, patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from apps.common.types import Err, Ok
from apps.infrastructure.registration_service import NodeRegistrationService
from apps.provisioning.virtualmin_models import VirtualminServer


class NodeRegistrationTLSPinTests(TestCase):
    """Auto-registered self-signed nodes must remain reachable without trusting TOFU."""

    def _deployment(self) -> MagicMock:
        deployment = MagicMock()
        deployment.status = "registering"
        deployment.ipv4_address = "203.0.113.10"
        deployment.virtualmin_server = None
        deployment.hostname = "prd-sha-tst-de-tst1-001"
        deployment.fqdn = "prd-sha-tst-de-tst1-001.example.com"
        deployment.id = 1
        deployment.node_size.max_domains = 50
        deployment.node_size.max_bandwidth_gb = 1000
        return deployment

    @patch("apps.provisioning.virtualmin_models.VirtualminServer")
    @patch("apps.infrastructure.validation_service.get_validation_service")
    def test_registration_persists_certificate_pin_read_over_trusted_ssh(
        self,
        mock_get_validation: MagicMock,
        mock_server_model: MagicMock,
    ) -> None:
        fingerprint = "ab" * 32
        mock_get_validation.return_value.get_webmin_certificate_fingerprint.return_value = Ok(fingerprint)
        mock_server_model.objects.filter.return_value.exists.return_value = False
        mock_server_model.objects.create.return_value = MagicMock(id=7)

        result = NodeRegistrationService().register_node(self._deployment())

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.assertEqual(
            mock_server_model.objects.create.call_args.kwargs["ssl_cert_fingerprint"],
            fingerprint,
        )

    @patch("apps.provisioning.virtualmin_models.VirtualminServer")
    @patch("apps.infrastructure.validation_service.get_validation_service")
    def test_registration_fails_closed_when_certificate_pin_cannot_be_verified(
        self,
        mock_get_validation: MagicMock,
        mock_server_model: MagicMock,
    ) -> None:
        mock_server_model.objects.filter.return_value.exists.return_value = False
        mock_get_validation.return_value.get_webmin_certificate_fingerprint.return_value = Err("SSH trust failed")

        result = NodeRegistrationService().register_node(self._deployment())

        self.assertTrue(result.is_err())
        self.assertIn("certificate fingerprint", result.unwrap_err())
        mock_server_model.objects.create.assert_not_called()

    @patch("apps.provisioning.virtualmin_models.VirtualminServer")
    @patch("apps.infrastructure.validation_service.get_validation_service")
    def test_registration_creates_disabled_server_until_credentials_configured(
        self,
        mock_get_validation: MagicMock,
        mock_server_model: MagicMock,
    ) -> None:
        """#328-4: the admin password is generated + vaulted but never configured
        on the node, so the server must NOT be registered 'active' (which would
        make _select_best_server place domains on it and fail auth). It is
        'disabled' until an operator configures and verifies the credentials."""
        mock_get_validation.return_value.get_webmin_certificate_fingerprint.return_value = Ok("cd" * 32)
        mock_server_model.objects.filter.return_value.exists.return_value = False
        mock_server_model.objects.create.return_value = MagicMock(id=9)

        result = NodeRegistrationService().register_node(self._deployment())

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.assertEqual(mock_server_model.objects.create.call_args.kwargs["status"], "disabled")


class VirtualminCertificatePinCommandTests(TestCase):
    """Existing self-signed node records have an explicit trusted migration path."""

    @patch("apps.infrastructure.management.commands.pin_virtualmin_certificates.get_validation_service")
    @patch("apps.infrastructure.management.commands.pin_virtualmin_certificates.VirtualminServer.objects.filter")
    def test_command_pins_existing_server_from_trusted_deployment(
        self,
        mock_filter: MagicMock,
        mock_get_validation: MagicMock,
    ) -> None:
        server = MagicMock(id=7, hostname="node.example.com", node_deployment=MagicMock())
        mock_filter.return_value = [server]
        fingerprint = "cd" * 32
        mock_get_validation.return_value.get_webmin_certificate_fingerprint.return_value = Ok(fingerprint)
        stdout = StringIO()

        call_command("pin_virtualmin_certificates", stdout=stdout)

        self.assertEqual(server.ssl_cert_fingerprint, fingerprint)
        server.save.assert_called_once_with(update_fields=["ssl_cert_fingerprint", "updated_at"])
        self.assertIn("Pinned 1 Virtualmin certificate", stdout.getvalue())


class VirtualminPinBackfillGapTests(TestCase):
    """#337: rows the SSH pin path cannot reach must be visible and remediable.

    Database-backed on purpose. The pre-existing command test mocks
    ``VirtualminServer.objects.filter`` wholesale, so it never exercises the real
    ``use_ssl/ssl_verify/ssl_cert_fingerprint`` candidate predicate — which is exactly
    the predicate that decides who gets stranded when #334's fail-closed guard ships.
    """

    def _server(self, name: str, **overrides: object) -> VirtualminServer:
        defaults: dict[str, object] = {
            "name": name,
            "hostname": f"{name}.example.com",
            "api_username": "api_user",
            "api_port": 10000,
            "status": "active",
            "max_domains": 100,
            "use_ssl": True,
            "ssl_verify": False,
            "ssl_cert_fingerprint": "",
        }
        defaults.update(overrides)
        server = VirtualminServer.objects.create(**defaults)
        server.set_api_password("pw")
        server.save()
        return server

    def test_dry_run_excludes_servers_that_cannot_be_pinned(self) -> None:
        """The count must reflect what a real run would achieve, not the raw candidate set."""
        self._server("stranded-node")  # no NodeDeployment
        stdout, stderr = StringIO(), StringIO()

        call_command("pin_virtualmin_certificates", "--dry-run", stdout=stdout, stderr=stderr)

        self.assertIn("Would pin 0 Virtualmin certificate", stdout.getvalue())
        self.assertIn("no linked node deployment", stderr.getvalue())
        self.assertIn("stranded-node.example.com", stderr.getvalue())

    def test_dry_run_lists_plain_http_servers_that_no_pin_can_fix(self) -> None:
        """use_ssl=False rows fail the same guard but are not pin candidates (#337 class 1)."""
        self._server("http-node", use_ssl=False, ssl_verify=True)
        stderr = StringIO()

        call_command("pin_virtualmin_certificates", "--dry-run", stdout=StringIO(), stderr=stderr)

        output = stderr.getvalue()
        self.assertIn("plain HTTP", output)
        self.assertIn("http-node.example.com", output)

    def test_operator_supplied_fingerprint_pins_a_stranded_server(self) -> None:
        """The escape hatch for legacy rows with no deployment (#337 class 2)."""
        server = self._server("manual-node")
        digest = "ab" * 32
        stdout = StringIO()

        call_command(
            "pin_virtualmin_certificates",
            "--server-id",
            str(server.pk),
            "--fingerprint",
            digest,
            stdout=stdout,
        )

        server.refresh_from_db()
        self.assertEqual(server.ssl_cert_fingerprint, digest)
        self.assertIn("operator-supplied digest", stdout.getvalue())

    def test_operator_fingerprint_accepts_colon_separated_openssl_output(self) -> None:
        """The digest half of openssl's output (AA:BB:...) needs no hand-reformatting.

        openssl actually prints `sha256 Fingerprint=AA:BB:...`; the runbook pipes it through
        `cut -d= -f2`, so what reaches the command is this colon-separated tail. The label
        form is rejected — covered by test_operator_fingerprint_rejects_the_openssl_label.
        """
        server = self._server("colon-node")
        digest = ":".join(["ab"] * 32).upper()

        call_command(
            "pin_virtualmin_certificates",
            "--server-id",
            str(server.pk),
            "--fingerprint",
            digest,
            stdout=StringIO(),
        )

        server.refresh_from_db()
        self.assertEqual(server.ssl_cert_fingerprint, "ab" * 32)

    def test_operator_fingerprint_rejects_a_malformed_digest(self) -> None:
        """Fail closed: a bad pin would brick the row just as surely as no pin."""
        server = self._server("bad-digest-node")

        with self.assertRaises(CommandError):
            call_command(
                "pin_virtualmin_certificates",
                "--server-id",
                str(server.pk),
                "--fingerprint",
                "not-a-sha256",
                stdout=StringIO(),
            )

        server.refresh_from_db()
        self.assertEqual(server.ssl_cert_fingerprint, "")

    def test_operator_fingerprint_requires_a_server_id(self) -> None:
        """A pin is per-host; applying one digest to every candidate would be nonsense."""
        with self.assertRaises(CommandError):
            call_command("pin_virtualmin_certificates", "--fingerprint", "ab" * 32, stdout=StringIO())

    def test_operator_fingerprint_refuses_a_plain_http_server(self) -> None:
        """Pinning an HTTP row looks remediated but still fails the HTTPS guard."""
        server = self._server("http-only-node", use_ssl=False)

        with self.assertRaises(CommandError):
            call_command(
                "pin_virtualmin_certificates",
                "--server-id",
                str(server.pk),
                "--fingerprint",
                "ab" * 32,
                stdout=StringIO(),
            )

        server.refresh_from_db()
        self.assertEqual(server.ssl_cert_fingerprint, "")

    def test_operator_fingerprint_dry_run_writes_nothing(self) -> None:
        server = self._server("dry-node")

        call_command(
            "pin_virtualmin_certificates",
            "--server-id",
            str(server.pk),
            "--fingerprint",
            "ab" * 32,
            "--dry-run",
            stdout=StringIO(),
        )

        server.refresh_from_db()
        self.assertEqual(server.ssl_cert_fingerprint, "")

    def test_server_id_accepts_a_uuid(self) -> None:
        """#337: --server-id was declared type=int against a UUIDField primary key.

        argparse rejected every real id before the command body ran, so the option could
        never be used. Pinning it here because the failure was invisible: nothing called
        it with a real id, and the one existing test mocked the queryset away entirely.
        """
        target = self._server("uuid-target")
        other = self._server("uuid-other")
        stdout, stderr = StringIO(), StringIO()

        call_command(
            "pin_virtualmin_certificates", "--server-id", str(target.pk), "--dry-run", stdout=stdout, stderr=stderr
        )

        self.assertIn("uuid-target.example.com", stderr.getvalue())
        self.assertNotIn("uuid-other.example.com", stderr.getvalue())
        self.assertNotIn(str(other.pk), stderr.getvalue())

    def test_malformed_server_id_is_a_clean_error(self) -> None:
        """A bad UUID must be a CommandError, not a ValidationError traceback."""
        with self.assertRaises(CommandError):
            call_command(
                "pin_virtualmin_certificates",
                "--server-id",
                "not-a-uuid",
                "--fingerprint",
                "ab" * 32,
                stdout=StringIO(),
            )


class VirtualminPinHardeningTests(VirtualminPinBackfillGapTests):
    """Review findings on the remediation path itself.

    The theme is that a remediation command an operator reaches for mid-incident must not
    have failure modes that read as success, and must not let one mis-paste retarget a
    healthy node's trust anchor.
    """

    _DIGEST = "a" * 64
    _OTHER_DIGEST = "b" * 64

    def test_openssl_label_is_rejected_rather_than_silently_mangled(self) -> None:
        """`sha256 Fingerprint=AA:BB:...` must fail loudly, not normalize to something wrong.

        The runbook pipes openssl through `cut -d= -f2` for this reason. If the label form
        were ever silently accepted it would produce a pin that can never match.
        """
        server = self._server("labelled")
        with self.assertRaises(CommandError):
            call_command(
                "pin_virtualmin_certificates",
                "--server-id", str(server.id),
                "--fingerprint", f"sha256 Fingerprint={':'.join(['aa'] * 32)}",
            )
        server.refresh_from_db()
        self.assertEqual(server.ssl_cert_fingerprint, "")

    def test_malformed_server_id_is_a_clean_error_in_the_backfill_path(self) -> None:
        """Dropping the (wrong) type=int made a typo'd id reach the ORM as a traceback."""
        with self.assertRaises(CommandError):
            call_command("pin_virtualmin_certificates", "--server-id", "not-a-uuid")

    def test_targeted_run_matching_no_candidate_fails_instead_of_reporting_success(self) -> None:
        """A wrong id previously printed a green 'Pinned 0' and exited 0.

        Indistinguishable from 'remediated' — the worst possible output for a command an
        operator runs to confirm a node is fixed.
        """
        server = self._server("already-pinned")
        server.ssl_cert_fingerprint = self._DIGEST
        server.save(update_fields=["ssl_cert_fingerprint"])

        with self.assertRaises(CommandError) as ctx:
            call_command("pin_virtualmin_certificates", "--server-id", str(server.id))
        self.assertIn("already pinned", str(ctx.exception))

    def test_existing_pin_is_not_replaced_without_force(self) -> None:
        """One mis-pasted UUID must not silently retarget a healthy node's trust anchor.

        The fleet run cannot heal it either: its candidate filter requires an EMPTY pin, so
        recovery needs a targeted re-pin with the correct digest.
        """
        server = self._server("healthy")
        server.ssl_cert_fingerprint = self._DIGEST
        server.save(update_fields=["ssl_cert_fingerprint"])

        with self.assertRaises(CommandError) as ctx:
            call_command(
                "pin_virtualmin_certificates",
                "--server-id", str(server.id), "--fingerprint", self._OTHER_DIGEST,
            )

        self.assertIn("--force", str(ctx.exception))
        server.refresh_from_db()
        self.assertEqual(server.ssl_cert_fingerprint, self._DIGEST)

    def test_force_replaces_the_pin_and_audits_the_previous_value(self) -> None:
        """Rotation is allowed explicitly, and must leave the old digest recoverable.

        VirtualminServer is allowlisted out of signal-based audit, so without this event a
        wrong pin would be unrecoverable — nothing would record what it used to be.
        """
        server = self._server("rotating")
        server.ssl_cert_fingerprint = self._DIGEST
        server.save(update_fields=["ssl_cert_fingerprint"])

        with patch(
            "apps.infrastructure.management.commands.pin_virtualmin_certificates.log_security_event"
        ) as audit:
            call_command(
                "pin_virtualmin_certificates",
                "--server-id", str(server.id), "--fingerprint", self._OTHER_DIGEST, "--force",
                stdout=StringIO(),
            )

        server.refresh_from_db()
        self.assertEqual(server.ssl_cert_fingerprint, self._OTHER_DIGEST)
        self.assertTrue(audit.called)
        event_type, details = audit.call_args[0][0], audit.call_args[0][1]
        self.assertEqual(event_type, "virtualmin_cert_pin_set_manually")
        self.assertEqual(details["old_fingerprint"], self._DIGEST)
        self.assertEqual(details["new_fingerprint"], self._OTHER_DIGEST)

    def test_first_pin_is_audited_too(self) -> None:
        server = self._server("first-pin")
        with patch(
            "apps.infrastructure.management.commands.pin_virtualmin_certificates.log_security_event"
        ) as audit:
            call_command(
                "pin_virtualmin_certificates",
                "--server-id", str(server.id), "--fingerprint", self._DIGEST,
                stdout=StringIO(),
            )
        self.assertTrue(audit.called)
        self.assertEqual(audit.call_args[0][1]["replaced_existing"], False)

    def test_decommissioned_http_rows_are_not_reported_as_outstanding_work(self) -> None:
        """A disabled node is not remediation work; listing it forever trains operators to skim."""
        live = self._server("live-http", use_ssl=False)
        self._server("dead-http", use_ssl=False, status="disabled")
        stdout, stderr = StringIO(), StringIO()

        call_command("pin_virtualmin_certificates", "--dry-run", stdout=stdout, stderr=stderr)

        report = stderr.getvalue()
        self.assertIn(str(live.id), report)
        self.assertNotIn("dead-http", report)

    def test_a_manual_pin_actually_reaches_the_tls_policy(self) -> None:
        """The remediation claim is 'the gateway can talk to the node again', not 'a column changed'.

        Every other test here asserts on the field. That would still pass if the config
        stopped defaulting cert_fingerprint from the row, at which point remediation would
        silently stop working — so follow the value through to the object the request uses.
        """
        from apps.provisioning.virtualmin_gateway import VirtualminConfig  # noqa: PLC0415

        server = self._server("end-to-end")
        call_command(
            "pin_virtualmin_certificates",
            "--server-id", str(server.id), "--fingerprint", self._DIGEST,
            stdout=StringIO(),
        )
        server.refresh_from_db()

        config = VirtualminConfig(server=server)

        self.assertEqual(config.cert_fingerprint, self._DIGEST)
        self.assertFalse(config.verify_ssl)
