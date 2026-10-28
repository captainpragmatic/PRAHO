"""Placeholder creation uses a provisioning budget without changing ambiguous mutation handling."""

import os
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, override_settings

from apps.common.types import Err, Ok, Retriability
from apps.provisioning.virtualmin_gateway import VirtualminResponse
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService


class MigrationRpcTimeoutTests(SimpleTestCase):
    def setUp(self):
        self.service = object.__new__(VirtualminMigrationService)
        self.service.backup_timeout = 1800
        self.migration = SimpleNamespace(account=SimpleNamespace(domain="timeout.example.test"))
        self.server = object()
        self.gateway = Mock()
        self.enterContext(patch.object(self.service, "_gateway", return_value=self.gateway))
        self.enterContext(patch("apps.settings.services.SettingsService.get_integer_setting", return_value=30))
        self.calls = []

        def transport(program, params, *, timeout_seconds):
            self.calls.append((program, timeout_seconds))
            if program == "create-domain" and timeout_seconds < 120:
                return Err("create response exceeded the short request deadline", retriability=Retriability.UNKNOWN)
            return Ok(
                VirtualminResponse(
                    success=True,
                    data={"status": "success"},
                    raw_response='{"status":"success"}',
                    http_status=200,
                    execution_time=0.0,
                    program=program,
                    server_hostname="node.example.test",
                )
            )

        self.gateway.call.side_effect = transport

    @override_settings(VIRTUALMIN_TIMEOUTS={"PROVISIONING_TIMEOUT": 120})
    def test_held_placeholder_uses_the_configured_provisioning_budget(self):
        # The native lab created a valid domain after the ordinary 30s budget expired.
        with patch.dict(os.environ, {"VIRTUALMIN_PROVISIONING_TIMEOUT": "120"}):
            self.service._command(self.migration, self.server, "create-domain")
        self.assertEqual(self.calls, [("create-domain", 120)])

    def test_restore_and_small_mutations_keep_their_existing_budgets(self):
        self.service._command(self.migration, self.server, "restore-domain")
        self.service._command(self.migration, self.server, "disable-domain")
        self.assertEqual(self.calls, [("restore-domain", 1800), ("disable-domain", 30)])

    def test_unknown_create_outcome_is_propagated_without_a_second_attempt(self):
        self.gateway.call.side_effect = None
        self.gateway.call.return_value = Err("response lost", retriability=Retriability.UNKNOWN)
        with self.assertRaisesRegex(RuntimeError, "Ambiguous create-domain"):
            self.service._command(self.migration, self.server, "create-domain")
        self.gateway.call.assert_called_once()
