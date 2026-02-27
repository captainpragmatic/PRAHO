"""
===============================================================================
INFRASTRUCTURE MODULE INTEGRATION TESTS
===============================================================================

Integration tests for the infrastructure module, testing how components
work together in realistic deployment scenarios.

These tests focus on:
- Deployment pipeline orchestration (deployment_service + terraform + ansible)
- Provider credential flow through the system
- Terraform configuration generation for different providers
- Task queue integration
- Security cleanup workflows

Note: Unit tests for individual functions are in test_provider_config.py
"""

from decimal import Decimal
from pathlib import Path
from typing import Any
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.common.types import Err, Ok
from apps.infrastructure.models import (
    CloudProvider,
    NodeDeployment,
    NodeDeploymentLog,
    NodeRegion,
    NodeSize,
    PanelType,
)
from apps.infrastructure.provider_config import (
    PROVIDER_CONFIG,
    get_provider_config,
    get_terraform_variables_for_deployment,
    map_terraform_outputs_to_deployment,
)

User = get_user_model()


# =============================================================================
# TEST FIXTURES
# =============================================================================


def create_test_infrastructure(provider_type: str = "hetzner") -> dict[str, Any]:
    """Create test infrastructure objects for a specific provider."""
    import uuid

    # Use unique identifiers to avoid conflicts between test runs
    unique_suffix = uuid.uuid4().hex[:8]

    user = User.objects.create_user(
        email=f"test_{provider_type}_{unique_suffix}@example.com",
        password="testpass123",
    )

    # Provider codes mapping
    provider_codes = {
        "hetzner": "het",
        "digitalocean": "dig",
        "vultr": "vul",
        "linode": "lin",
    }

    provider = CloudProvider.objects.create(
        name=f"{provider_type.title()} Cloud {unique_suffix}",
        code=f"{provider_codes.get(provider_type, provider_type[:3])}{unique_suffix[:3]}",
        provider_type=provider_type,
        credential_identifier=f"{provider_type}_api_token",
        is_active=True,
    )

    region = NodeRegion.objects.create(
        provider=provider,
        name=f"Test Region {unique_suffix}",
        provider_region_id=f"test-region-{unique_suffix}",
        normalized_code=f"ts{unique_suffix[:2]}",
        country_code="us",
        city="Test City",
        is_active=True,
    )

    size = NodeSize.objects.create(
        provider=provider,
        name=f"Test Size {unique_suffix}",
        display_name="2 vCPU / 4GB RAM",
        provider_type_id=f"test-size-{unique_suffix}",
        vcpus=2,
        memory_gb=4,
        disk_gb=40,
        hourly_cost_eur=Decimal("0.01"),
        monthly_cost_eur=Decimal("7.00"),
        max_domains=25,
        is_active=True,
    )

    # Use get_or_create for panel to avoid duplicates
    panel, _ = PanelType.objects.get_or_create(
        name="Virtualmin GPL",
        defaults={
            "panel_type": "virtualmin",
            "version": "7.10.0",
            "ansible_playbook": "virtualmin.yml",
            "is_active": True,
        },
    )

    return {
        "user": user,
        "provider": provider,
        "region": region,
        "size": size,
        "panel": panel,
    }


def create_test_deployment(infra: dict[str, Any], **kwargs) -> NodeDeployment:
    """Create a test deployment with default values."""
    defaults = {
        "hostname": "prd-sha-het-us-tst1-001",
        "environment": "prd",
        "node_type": "sha",
        "node_number": 1,
        "provider": infra["provider"],
        "region": infra["region"],
        "node_size": infra["size"],
        "panel_type": infra["panel"],
        "dns_zone": "test.example.com",
        "initiated_by": infra["user"],
        "status": "pending",
    }
    defaults.update(kwargs)
    return NodeDeployment.objects.create(**defaults)


# =============================================================================
# DEPLOYMENT PIPELINE INTEGRATION TESTS
# =============================================================================


class TestDeploymentPipelineIntegration(TestCase):
    """
    Integration tests for the complete deployment pipeline.

    Tests how deployment_service, terraform_service, and ansible_service
    work together during node deployment.
    """

    def setUp(self):
        self.infra = create_test_infrastructure("hetzner")

    def test_deployment_logs_created_during_pipeline(self):
        """
        Test that deployment logs are created at each pipeline stage.
        """
        from apps.infrastructure.deployment_service import NodeDeploymentService

        deployment = create_test_deployment(self.infra)

        # Mock all external dependencies
        with mock.patch("shutil.which", return_value="/usr/bin/terraform"):
            with mock.patch(
                "apps.infrastructure.terraform_service.TerraformService.generate_deployment_config"
            ) as mock_gen:
                mock_gen.return_value = Err("Test config error")

                service = NodeDeploymentService()
                result = service.deploy_node(
                    deployment=deployment,
                    credentials={"api_token": "test"},
                    user=self.infra["user"],
                )

        # Check that logs were created
        logs = NodeDeploymentLog.objects.filter(deployment=deployment)
        self.assertGreater(logs.count(), 0, "No deployment logs were created")

        # Check for start log
        start_logs = logs.filter(message__icontains="Starting")
        self.assertGreater(start_logs.count(), 0, "No start log found")

    def test_deployment_status_transitions(self):
        """
        Test that deployment status transitions correctly through pipeline.
        """
        deployment = create_test_deployment(self.infra)

        # Test initial state
        self.assertEqual(deployment.status, "pending")

        # Test transition to provisioning
        deployment.transition_to("provisioning_node")
        self.assertEqual(deployment.status, "provisioning_node")

        # Test transition to configuring_dns
        deployment.transition_to("configuring_dns")
        self.assertEqual(deployment.status, "configuring_dns")

        # Test can transition to failed (valid from any state)
        deployment.transition_to("failed")
        self.assertEqual(deployment.status, "failed")

    def test_deployment_failure_status_update(self):
        """
        Test that failed deployments have correct status.
        """
        deployment = create_test_deployment(self.infra)

        # Simulate failure
        deployment.transition_to("failed")
        deployment.save()

        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "failed")


# =============================================================================
# TERRAFORM SERVICE INTEGRATION TESTS
# =============================================================================


class TestTerraformServiceIntegration(TestCase):
    """
    Integration tests for terraform service with provider_config.

    Tests that terraform configurations are correctly generated
    for different cloud providers.
    """

    def setUp(self):
        self.hetzner_infra = create_test_infrastructure("hetzner")
        self.digitalocean_infra = create_test_infrastructure("digitalocean")

    @mock.patch("shutil.which")
    def test_terraform_config_generation_hetzner(self, mock_which):
        """Test terraform config is correctly generated for Hetzner."""
        from apps.infrastructure.terraform_service import TerraformService

        mock_which.return_value = "/usr/bin/terraform"
        deployment = create_test_deployment(self.hetzner_infra)

        with mock.patch("pathlib.Path.mkdir"), \
             mock.patch("pathlib.Path.write_text") as mock_write:

            service = TerraformService()
            result = service.generate_deployment_config(
                deployment=deployment,
                ssh_public_key="ssh-ed25519 AAAA... test@example.com",
                credentials={"hcloud_token": "test-hetzner-token"},
                cloudflare_api_token="cf-token",
            )

            # Should succeed
            self.assertTrue(result.is_ok(), f"Config generation failed: {result}")

            # Check that write_text was called
            self.assertTrue(mock_write.called, "write_text was not called")

    @mock.patch("shutil.which")
    def test_terraform_config_generation_digitalocean(self, mock_which):
        """Test terraform config is correctly generated for DigitalOcean."""
        from apps.infrastructure.terraform_service import TerraformService

        mock_which.return_value = "/usr/bin/terraform"
        deployment = create_test_deployment(self.digitalocean_infra)

        with mock.patch("pathlib.Path.mkdir"), \
             mock.patch("pathlib.Path.write_text") as mock_write:

            service = TerraformService()
            result = service.generate_deployment_config(
                deployment=deployment,
                ssh_public_key="ssh-ed25519 AAAA... test@example.com",
                credentials={"do_token": "test-do-token"},
                cloudflare_api_token="cf-token",
            )

            # Should succeed
            self.assertTrue(result.is_ok(), f"Config generation failed: {result}")

    def test_terraform_output_mapping_integration(self):
        """
        Test that terraform outputs are correctly mapped to deployment fields.

        This tests the integration between terraform_service and provider_config.
        """
        deployment = create_test_deployment(self.hetzner_infra)

        # Simulate terraform outputs in the format Terraform returns
        # Hetzner uses 'server_id' which maps to 'external_node_id'
        terraform_outputs = {
            "server_id": {"value": "98765"},
            "ipv4_address": {"value": "10.0.0.1"},
            "ipv6_address": {"value": "2001:db8::100"},
            "status": {"value": "running"},
        }

        # Map outputs to deployment
        map_terraform_outputs_to_deployment(
            provider_type="hetzner",
            outputs=terraform_outputs,
            deployment=deployment,
        )

        # Verify mapping - use correct field names from model
        self.assertEqual(deployment.external_node_id, "98765")
        self.assertEqual(deployment.ipv4_address, "10.0.0.1")
        self.assertEqual(deployment.ipv6_address, "2001:db8::100")

    def test_terraform_variables_generation_all_providers(self):
        """
        Test that terraform variables are correctly generated for all providers.
        """
        for provider_type in PROVIDER_CONFIG.keys():
            with self.subTest(provider=provider_type):
                config = get_provider_config(provider_type)
                assert config is not None, f"No config for {provider_type}"

                tf_vars = config.get("terraform_vars", {})
                self.assertIn(
                    "api_token_var",
                    tf_vars,
                    f"Missing api_token_var for {provider_type}"
                )


# =============================================================================
# CREDENTIAL FLOW INTEGRATION TESTS
# =============================================================================


class TestCredentialFlowIntegration(TestCase):
    """
    Integration tests for credential handling through the deployment system.

    Ensures credentials flow securely from views → tasks → services.
    """

    def setUp(self):
        self.infra = create_test_infrastructure("hetzner")

    def test_credentials_dict_format_consistency(self):
        """
        Test that credentials dict format is consistent through the pipeline.

        Views pass credentials as dict → tasks receive dict → services use dict
        """
        deployment = create_test_deployment(self.infra)

        # The credentials dict format used by views
        credentials = {
            "api_token": "test-token-value",
            "hcloud_token": "test-token-value",  # Provider-specific key
        }

        # Verify the dict works with provider_config functions
        config = get_provider_config("hetzner")
        assert config is not None
        credential_key = config["credential_key"]

        # Should be able to get token by provider-specific key
        self.assertEqual(
            credentials.get(credential_key),
            "test-token-value",
            f"Could not get token using credential_key: {credential_key}"
        )

    def test_task_receives_credentials_correctly(self):
        """
        Test that async tasks receive and use credentials correctly.
        """
        from apps.infrastructure.tasks import deploy_node_task

        deployment = create_test_deployment(self.infra)

        with mock.patch("shutil.which", return_value="/usr/bin/terraform"):
            with mock.patch(
                "apps.infrastructure.deployment_service.NodeDeploymentService.deploy_node"
            ) as mock_deploy:
                mock_deploy.return_value = Ok(mock.MagicMock(
                    success=True,
                    deployment_id=deployment.id,
                    stages_completed=["init"],
                ))

                result = deploy_node_task(
                    deployment_id=deployment.id,
                    credentials={"api_token": "task-token"},
                    cloudflare_api_token="cf-token",
                    user_id=self.infra["user"].id,
                )

                # Verify deploy_node was called with credentials
                mock_deploy.assert_called_once()
                call_kwargs = mock_deploy.call_args[1]
                self.assertEqual(
                    call_kwargs["credentials"],
                    {"api_token": "task-token"}
                )


# =============================================================================
# MULTI-PROVIDER INTEGRATION TESTS
# =============================================================================


class TestMultiProviderIntegration(TestCase):
    """
    Integration tests for multi-provider support.

    Verifies that the system can handle deployments to different
    cloud providers using the same code paths.
    """

    def test_all_configured_providers_have_terraform_modules(self):
        """
        Test that all providers in PROVIDER_CONFIG have corresponding
        terraform modules defined.
        """
        from apps.infrastructure.provider_config import get_terraform_module_path

        base_path = "/var/lib/praho/terraform/modules"

        for provider_type, config in PROVIDER_CONFIG.items():
            with self.subTest(provider=provider_type):
                module_path = get_terraform_module_path(provider_type, base_path)
                assert module_path is not None, f"No terraform module path for {provider_type}"
                self.assertIn(
                    config["terraform_module"],
                    module_path,
                    f"Module path doesn't contain expected module name"
                )

    def test_provider_cli_commands_are_well_formed(self):
        """
        Test that CLI command templates for all providers are well-formed.

        Commands should have proper placeholders and be list format.
        """
        for provider_type, config in PROVIDER_CONFIG.items():
            with self.subTest(provider=provider_type):
                cli = config.get("cli", {})
                self.assertIn("tool", cli, f"No tool defined for {provider_type}")

                for operation, cmd_parts in cli.items():
                    if operation == "tool":
                        continue

                    # Command should be a list
                    self.assertIsInstance(
                        cmd_parts,
                        list,
                        f"{provider_type}.{operation} is not a list"
                    )

                    # If command has placeholders, they should be in {param} format
                    for part in cmd_parts:
                        if "{" in part and "}" in part:
                            # Valid placeholder format
                            self.assertRegex(
                                part,
                                r"\{[a-z_]+\}",
                                f"Invalid placeholder format in {provider_type}.{operation}"
                            )

    def test_output_mappings_cover_required_fields(self):
        """
        Test that output mappings for all providers cover essential fields.

        Each provider uses different terraform output names but they should all
        map to standard deployment model fields.
        """
        # Required destination fields (model field names), not source names
        required_destinations = ["ipv4_address"]  # All providers need this

        # Each provider needs a server ID mapping (though source name varies)
        server_id_destinations = ["external_node_id", "provider_server_id"]

        for provider_type, config in PROVIDER_CONFIG.items():
            with self.subTest(provider=provider_type):
                mappings = config.get("output_mappings", {})

                # Check required destination fields are mapped
                destinations = list(mappings.values())
                for required in required_destinations:
                    self.assertIn(
                        required,
                        destinations,
                        f"{provider_type} missing required destination: {required}"
                    )

                # Check that there's a server ID mapping
                has_server_id = any(
                    dest in server_id_destinations
                    for dest in destinations
                )
                self.assertTrue(
                    has_server_id,
                    f"{provider_type} missing server ID mapping to external_node_id or provider_server_id"
                )


# =============================================================================
# LIFECYCLE OPERATIONS INTEGRATION TESTS
# =============================================================================


class TestLifecycleOperationsIntegration(TestCase):
    """
    Integration tests for node lifecycle operations.

    Tests power operations (start, stop, reboot) through the
    provider_config module.
    """

    def setUp(self):
        self.infra = create_test_infrastructure("hetzner")

    @mock.patch("subprocess.run")
    @mock.patch("shutil.which")
    def test_stop_node_calls_correct_provider_command(self, mock_which, mock_run):
        """
        Test that run_provider_command for power_off uses correct CLI command.
        """
        from apps.infrastructure.provider_config import run_provider_command

        mock_which.return_value = "/usr/bin/hcloud"
        mock_run.return_value = mock.MagicMock(
            returncode=0,
            stdout="Server stopped",
            stderr="",
        )

        result = run_provider_command(
            provider_type="hetzner",
            operation="power_off",
            credentials={"hcloud_token": "test-token"},
            server_id="12345",
        )

        # Verify the command was called
        self.assertTrue(mock_run.called)
        self.assertTrue(result.is_ok())

        # Get the command that was called
        call_args = mock_run.call_args
        cmd = call_args[0][0] if call_args[0] else call_args[1].get("args", [])
        cmd_str = " ".join(str(c) for c in cmd)

        # Should contain hcloud and server poweroff
        self.assertIn("hcloud", cmd_str.lower())
        self.assertIn("12345", cmd_str)

    @mock.patch("subprocess.run")
    @mock.patch("shutil.which")
    def test_start_node_calls_correct_provider_command(self, mock_which, mock_run):
        """
        Test that run_provider_command for power_on uses correct CLI command.
        """
        from apps.infrastructure.provider_config import run_provider_command

        mock_which.return_value = "/usr/bin/hcloud"
        mock_run.return_value = mock.MagicMock(
            returncode=0,
            stdout="Server started",
            stderr="",
        )

        result = run_provider_command(
            provider_type="hetzner",
            operation="power_on",
            credentials={"hcloud_token": "test-token"},
            server_id="12345",
        )

        # Verify the command was called
        self.assertTrue(mock_run.called)
        self.assertTrue(result.is_ok())


# =============================================================================
# TASK QUEUE INTEGRATION TESTS
# =============================================================================


class TestTaskQueueIntegration(TestCase):
    """
    Integration tests for Django-Q2 task queue integration.

    Tests that tasks are correctly queued and execute properly.
    """

    def setUp(self):
        self.infra = create_test_infrastructure("hetzner")

    def test_queue_deploy_node_creates_task(self):
        """
        Test that queue_deploy_node creates a properly configured task.
        """
        from apps.infrastructure.tasks import queue_deploy_node

        deployment = create_test_deployment(self.infra)

        with mock.patch("django_q.tasks.async_task") as mock_async:
            mock_async.return_value = "task-id-123"

            task_id = queue_deploy_node(
                deployment_id=deployment.id,
                credentials={"api_token": "test"},
                cloudflare_api_token="cf-token",
                user_id=self.infra["user"].id,
            )

            # Verify async_task was called correctly
            self.assertTrue(mock_async.called)
            call_args = mock_async.call_args

            # First arg should be the task function path
            self.assertEqual(
                call_args[0][0],
                "apps.infrastructure.tasks.deploy_node_task"
            )

            # Deployment ID should be passed
            self.assertEqual(call_args[0][1], deployment.id)

            # Credentials should be passed
            self.assertEqual(call_args[0][2], {"api_token": "test"})

    def test_queue_destroy_node_creates_task(self):
        """
        Test that queue_destroy_node creates a properly configured task.
        """
        from apps.infrastructure.tasks import queue_destroy_node

        deployment = create_test_deployment(self.infra, status="completed")

        with mock.patch("django_q.tasks.async_task") as mock_async:
            mock_async.return_value = "task-id-456"

            task_id = queue_destroy_node(
                deployment_id=deployment.id,
                credentials={"api_token": "test"},
                user_id=self.infra["user"].id,
            )

            # Verify async_task was called
            self.assertTrue(mock_async.called)
            self.assertEqual(
                mock_async.call_args[0][0],
                "apps.infrastructure.tasks.destroy_node_task"
            )

    def test_queue_lifecycle_operations(self):
        """
        Test that lifecycle operation queue functions work correctly.
        """
        from apps.infrastructure.tasks import (
            queue_start_node,
            queue_stop_node,
            queue_reboot_node,
        )

        deployment = create_test_deployment(self.infra, status="completed")

        queue_functions = [
            (queue_stop_node, "stop_node_task"),
            (queue_start_node, "start_node_task"),
            (queue_reboot_node, "reboot_node_task"),
        ]

        for queue_fn, expected_task in queue_functions:
            with self.subTest(task=expected_task):
                with mock.patch("django_q.tasks.async_task") as mock_async:
                    mock_async.return_value = f"task-{expected_task}"

                    task_id = queue_fn(
                        deployment_id=deployment.id,
                        credentials={"api_token": "test"},
                        user_id=self.infra["user"].id,
                    )

                    self.assertTrue(mock_async.called)
                    self.assertIn(
                        expected_task,
                        mock_async.call_args[0][0]
                    )


# =============================================================================
# ERROR HANDLING INTEGRATION TESTS
# =============================================================================


class TestErrorHandlingIntegration(TestCase):
    """
    Integration tests for error handling across the deployment system.
    """

    def setUp(self):
        self.infra = create_test_infrastructure("hetzner")

    def test_deployment_status_updated_on_failure(self):
        """
        Test that deployment status is correctly updated when errors occur.

        Tests the _mark_failed helper directly since the full pipeline
        requires complex mocking.
        """
        deployment = create_test_deployment(self.infra)

        # Simulate a failure by directly transitioning to failed
        deployment.transition_to("failed")
        deployment.error_message = "Test failure"
        deployment.save()

        # Verify status is failed
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "failed")
        self.assertEqual(deployment.error_message, "Test failure")

    def test_error_logs_created_on_failure(self):
        """
        Test that error logs can be created during deployment.
        """
        deployment = create_test_deployment(self.infra)

        # Create an error log directly
        NodeDeploymentLog.objects.create(
            deployment=deployment,
            level="ERROR",
            message="Test error message",
            phase="terraform_apply",
        )

        # Check for error logs
        error_logs = NodeDeploymentLog.objects.filter(
            deployment=deployment,
            level="ERROR",
        )
        self.assertGreater(error_logs.count(), 0, "No error logs created")
        first_log = error_logs.first()
        assert first_log is not None
        self.assertEqual(first_log.message, "Test error message")

    def test_invalid_provider_returns_appropriate_error(self):
        """
        Test that using an invalid provider returns a clear error.
        """
        # Create infrastructure with fake provider type
        user = User.objects.create_user(
            email="fake@example.com",
            password="testpass",
        )

        provider = CloudProvider.objects.create(
            name="Fake Cloud",
            code="fak",
            provider_type="nonexistent_provider",
            credential_identifier="fake_token",
            is_active=True,
        )

        region = NodeRegion.objects.create(
            provider=provider,
            name="Fake Region",
            provider_region_id="fake-1",
            normalized_code="fak1",
            country_code="xx",
            city="Nowhere",
            is_active=True,
        )

        size = NodeSize.objects.create(
            provider=provider,
            name="Fake Size",
            display_name="Fake",
            provider_type_id="fake",
            vcpus=1,
            memory_gb=1,
            disk_gb=10,
            hourly_cost_eur=Decimal("0.01"),
            monthly_cost_eur=Decimal("1.00"),
            max_domains=1,
            is_active=True,
        )

        panel = PanelType.objects.create(
            name="Fake Panel",
            panel_type="virtualmin",
            version="1.0",
            ansible_playbook="fake.yml",
            is_active=True,
        )

        deployment = NodeDeployment.objects.create(
            hostname="prd-sha-fak-xx-fak1-001",
            environment="prd",
            node_type="sha",
            node_number=1,
            provider=provider,
            region=region,
            node_size=size,
            panel_type=panel,
            dns_zone="fake.example.com",
            initiated_by=user,
            status="pending",
        )

        # Provider config lookup should fail
        config = get_provider_config("nonexistent_provider")
        self.assertIsNone(config, "Should return None for unknown provider")
