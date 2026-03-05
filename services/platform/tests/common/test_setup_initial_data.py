"""
Tests for the setup_initial_data management command orchestrator.
"""

from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase


class SetupInitialDataTestCase(TestCase):
    """Tests for setup_initial_data orchestration logic."""

    @patch("apps.common.management.commands.setup_initial_data.call_command")
    def test_core_tier_runs_all_core_commands(self, mock_call: object) -> None:
        """Default invocation runs all 5 core commands."""
        out = StringIO()
        call_command("setup_initial_data", stdout=out)

        called_commands = [c[0][0] for c in mock_call.call_args_list]
        self.assertIn("setup_settings_categories", called_commands)
        self.assertIn("setup_default_settings", called_commands)
        self.assertIn("setup_scheduled_tasks", called_commands)
        self.assertIn("setup_email_templates", called_commands)
        self.assertIn("ensure_superuser", called_commands)

    @patch("apps.common.management.commands.setup_initial_data.call_command")
    def test_business_tier_auto_detects_prod(self, mock_call: object) -> None:
        """With prod settings module, business tier runs automatically."""
        out = StringIO()
        with patch.dict("os.environ", {"DJANGO_SETTINGS_MODULE": "config.settings.prod"}):
            call_command("setup_initial_data", stdout=out)

        called_commands = [c[0][0] for c in mock_call.call_args_list]
        self.assertIn("setup_tax_rules", called_commands)
        self.assertIn("setup_dunning_policies", called_commands)

    @patch("apps.common.management.commands.setup_initial_data.call_command")
    def test_business_tier_skipped_in_dev(self, mock_call: object) -> None:
        """With dev settings module, business tier is not auto-run."""
        out = StringIO()
        with patch.dict("os.environ", {"DJANGO_SETTINGS_MODULE": "config.settings.dev"}):
            call_command("setup_initial_data", stdout=out)

        called_commands = [c[0][0] for c in mock_call.call_args_list]
        self.assertNotIn("setup_tax_rules", called_commands)
        self.assertNotIn("setup_dunning_policies", called_commands)

    @patch("apps.common.management.commands.setup_initial_data.call_command")
    def test_include_business_flag(self, mock_call: object) -> None:
        """--include-business adds business tier even in dev."""
        out = StringIO()
        with patch.dict("os.environ", {"DJANGO_SETTINGS_MODULE": "config.settings.dev"}):
            call_command("setup_initial_data", include_business=True, stdout=out)

        called_commands = [c[0][0] for c in mock_call.call_args_list]
        self.assertIn("setup_tax_rules", called_commands)
        self.assertIn("setup_dunning_policies", called_commands)

    @patch("apps.common.management.commands.setup_initial_data.call_command")
    def test_dry_run_does_not_execute(self, mock_call: object) -> None:
        """--dry-run prints the plan but calls no sub-commands."""
        out = StringIO()
        call_command("setup_initial_data", dry_run=True, stdout=out)

        mock_call.assert_not_called()
        output = out.getvalue()
        self.assertIn("DRY RUN", output)

    @patch("apps.common.management.commands.setup_initial_data.call_command")
    def test_tier_flag_overrides_auto_detect(self, mock_call: object) -> None:
        """--tier=core in prod skips business tier."""
        out = StringIO()
        with patch.dict("os.environ", {"DJANGO_SETTINGS_MODULE": "config.settings.prod"}):
            call_command("setup_initial_data", tier="core", stdout=out)

        called_commands = [c[0][0] for c in mock_call.call_args_list]
        self.assertIn("setup_settings_categories", called_commands)
        self.assertNotIn("setup_tax_rules", called_commands)

    @patch("apps.common.management.commands.setup_initial_data.call_command")
    def test_sub_command_failure_continues_then_raises(self, mock_call: object) -> None:
        """If one sub-command raises, the rest still run, then CommandError is raised."""

        def side_effect(cmd_name: str, **kwargs: object) -> None:
            if cmd_name == "setup_default_settings":
                raise RuntimeError("DB down")

        mock_call.side_effect = side_effect
        out = StringIO()

        with self.assertRaises(CommandError) as ctx:
            call_command("setup_initial_data", stdout=out)

        # Commands after the failure should still have been called
        called_commands = [c[0][0] for c in mock_call.call_args_list]
        self.assertIn("setup_scheduled_tasks", called_commands)
        self.assertIn("ensure_superuser", called_commands)
        self.assertIn("1 setup command(s) failed", str(ctx.exception))

    @patch("apps.common.management.commands.setup_initial_data.call_command")
    def test_all_flag_runs_both_tiers(self, mock_call: object) -> None:
        """--all runs core + business regardless of settings module."""
        out = StringIO()
        with patch.dict("os.environ", {"DJANGO_SETTINGS_MODULE": "config.settings.dev"}):
            call_command("setup_initial_data", all=True, stdout=out)

        called_commands = [c[0][0] for c in mock_call.call_args_list]
        self.assertIn("setup_settings_categories", called_commands)
        self.assertIn("setup_tax_rules", called_commands)
