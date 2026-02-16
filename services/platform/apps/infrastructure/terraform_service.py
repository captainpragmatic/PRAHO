"""
Terraform Service

Wrapper for executing Terraform commands for node provisioning.
Generates deployment configurations and manages state.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from apps.common.types import Err, Ok, Result
from apps.infrastructure.provider_config import (
    get_provider_config,
    get_terraform_provider_block,
)
from apps.settings.services import SettingsService

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment

logger = logging.getLogger(__name__)

# Path to terraform modules
TERRAFORM_BASE_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "terraform"
MODULES_PATH = TERRAFORM_BASE_PATH / "modules"
BACKENDS_PATH = TERRAFORM_BASE_PATH / "backends"
DEPLOYMENTS_PATH = TERRAFORM_BASE_PATH / "deployments"


@dataclass
class TerraformResult:
    """Result of a Terraform operation"""

    success: bool
    command: str
    stdout: str
    stderr: str
    return_code: int
    outputs: dict[str, Any] = field(default_factory=dict)


class TerraformService:
    """
    🏗️ Terraform Service

    Manages Terraform operations for node deployment:
    - Generates deployment configuration from templates
    - Runs init, plan, apply, destroy
    - Captures outputs for database storage
    - Manages state (local or S3)
    """

    def __init__(self, timeout: int = 600) -> None:
        """Initialize Terraform service"""
        self.timeout = timeout
        self._terraform_path = self._find_terraform()

    def _find_terraform(self) -> str:
        """Find terraform binary"""
        terraform_path = shutil.which("terraform")
        if not terraform_path:
            # Try common locations
            for path in ["/usr/local/bin/terraform", "/usr/bin/terraform", "~/.local/bin/terraform"]:
                expanded = os.path.expanduser(path)
                if os.path.exists(expanded):
                    return expanded
            raise RuntimeError("Terraform binary not found. Please install Terraform.")
        return terraform_path

    def generate_deployment_config(
        self,
        deployment: NodeDeployment,
        ssh_public_key: str,
        credentials: dict[str, str],
        cloudflare_api_token: str | None = None,
    ) -> Result[Path, str]:
        """
        Generate Terraform configuration for a deployment.

        Args:
            deployment: NodeDeployment instance
            ssh_public_key: SSH public key for the server
            credentials: Provider credentials dict (e.g., {"api_token": "xxx"})
            cloudflare_api_token: Cloudflare API token

        Returns:
            Result with path to deployment directory or error
        """
        try:
            # Create deployment directory
            deploy_dir = DEPLOYMENTS_PATH / str(deployment.id)
            deploy_dir.mkdir(parents=True, exist_ok=True)

            # Get settings
            dns_zone = SettingsService.get_setting("node_deployment.dns_default_zone", "")
            cloudflare_zone_id = SettingsService.get_setting("node_deployment.dns_cloudflare_zone_id", "")
            state_backend = SettingsService.get_setting("node_deployment.terraform_state_backend", "local")

            # Get provider config
            provider_type = deployment.provider.provider_type
            provider_config = get_provider_config(provider_type)
            if not provider_config:
                return Err(f"Unknown provider type: {provider_type}")

            # Generate main.tf
            main_tf = self._generate_main_tf(
                deployment=deployment,
                ssh_public_key=ssh_public_key,
                dns_zone=dns_zone,
                cloudflare_zone_id=cloudflare_zone_id,
                provider_config=provider_config,
            )
            (deploy_dir / "main.tf").write_text(main_tf)

            # Generate backend.tf
            backend_tf = self._generate_backend_tf(deployment, state_backend)
            (deploy_dir / "backend.tf").write_text(backend_tf)

            # Generate terraform.tfvars (sensitive - will be cleaned up)
            tfvars = self._generate_tfvars(
                credentials=credentials,
                cloudflare_api_token=cloudflare_api_token,
                ssh_public_key=ssh_public_key,
                provider_config=provider_config,
            )
            (deploy_dir / "terraform.tfvars").write_text(tfvars)

            # Store state path in deployment
            if state_backend == "local":
                deployment.terraform_state_path = str(deploy_dir / "terraform.tfstate")
            deployment.terraform_state_backend = state_backend
            deployment.save(update_fields=["terraform_state_path", "terraform_state_backend", "updated_at"])

            logger.info(f"🏗️ [Terraform] Generated config for: {deployment.hostname} at {deploy_dir}")

            return Ok(deploy_dir)

        except Exception as e:
            logger.error(f"🚨 [Terraform] Config generation failed: {e}")
            return Err(f"Failed to generate Terraform config: {e}")

    def _generate_main_tf(
        self,
        deployment: NodeDeployment,
        ssh_public_key: str,
        dns_zone: str,
        cloudflare_zone_id: str,
        provider_config: dict[str, Any],
    ) -> str:
        """Generate main.tf content - provider-agnostic"""
        # Get provider-specific values from config
        module_name = provider_config.get("terraform_module", "provider")
        tf_vars = provider_config.get("terraform_vars", {})
        api_token_var = tf_vars.get("api_token_var", "api_token")
        server_type_var = tf_vars.get("server_type_var", "server_type")
        region_var = tf_vars.get("region_var", "region")
        image_default = tf_vars.get("image_default", "ubuntu-22.04")

        # Get terraform provider block
        provider_block = get_terraform_provider_block(deployment.provider.provider_type) or ""

        return f"""# Auto-generated by PRAHO Node Deployment Service
# Deployment: {deployment.hostname}
# Provider: {deployment.provider.provider_type}
# Created: {deployment.created_at}

terraform {{
  required_version = ">= 1.5.0"

  required_providers {{{provider_block}
    cloudflare = {{
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }}
  }}
}}

# Cloud Provider Node
module "{module_name}_node" {{
  source = "{MODULES_PATH}/{module_name}"

  {api_token_var}    = var.{api_token_var}
  deployment_id      = "{deployment.id}"
  hostname           = "{deployment.hostname}"
  fqdn               = "{deployment.hostname}.{dns_zone}"
  environment        = "{deployment.environment}"
  node_type          = "{deployment.node_type}"
  {server_type_var}  = "{deployment.node_size.provider_type_id if deployment.node_size else ""}"
  server_image       = "{image_default}"
  {region_var}       = "{deployment.region.provider_region_id if deployment.region else ""}"
  ssh_public_key     = var.ssh_public_key
}}

# Cloudflare DNS
module "cloudflare_dns" {{
  source = "{MODULES_PATH}/cloudflare"

  cloudflare_api_token = var.cloudflare_api_token
  zone_id              = "{cloudflare_zone_id}"
  zone_name            = "{dns_zone}"
  deployment_id        = "{deployment.id}"
  hostname             = "{deployment.hostname}"
  ipv4_address         = module.{module_name}_node.ipv4_address
  ipv6_address         = module.{module_name}_node.ipv6_address
  create_mx_record     = true
}}

# Outputs - Standard interface for all providers
output "server_id" {{
  value = module.{module_name}_node.server_id
}}

output "ipv4_address" {{
  value = module.{module_name}_node.ipv4_address
}}

output "ipv6_address" {{
  value = module.{module_name}_node.ipv6_address
}}

output "fqdn" {{
  value = module.cloudflare_dns.fqdn
}}

output "dns_record_ids" {{
  value = module.cloudflare_dns.dns_record_ids
}}

output "ssh_key_fingerprint" {{
  value = module.{module_name}_node.ssh_key_fingerprint
}}
"""

    def _generate_backend_tf(self, deployment: NodeDeployment, backend: str) -> str:
        """Generate backend.tf content"""
        if backend == "s3":
            s3_bucket = SettingsService.get_setting("node_deployment.terraform_s3_bucket", "")
            s3_region = SettingsService.get_setting("node_deployment.terraform_s3_region", "eu-west-1")
            s3_prefix = SettingsService.get_setting("node_deployment.terraform_s3_key_prefix", "praho/nodes/")
            return f"""# S3 Backend - Generated by PRAHO
terraform {{
  backend "s3" {{
    bucket = "{s3_bucket}"
    key    = "{s3_prefix}{deployment.id}/terraform.tfstate"
    region = "{s3_region}"
    encrypt = true
  }}
}}
"""
        else:
            # Local backend
            return """# Local Backend - Generated by PRAHO
terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}
"""

    def _generate_tfvars(
        self,
        credentials: dict[str, str],
        cloudflare_api_token: str | None,
        ssh_public_key: str,
        provider_config: dict[str, Any],
    ) -> str:
        """Generate terraform.tfvars content - provider-agnostic"""
        tf_vars = provider_config.get("terraform_vars", {})
        api_token_var = tf_vars.get("api_token_var", "api_token")
        credential_key = provider_config.get("credential_key", "api_token")

        # Get the API token from credentials
        api_token = credentials.get(credential_key) or credentials.get("api_token", "")

        return f"""# Auto-generated - Contains sensitive data
# This file will be deleted after deployment

{api_token_var}      = "{api_token}"
cloudflare_api_token = "{cloudflare_api_token or ""}"
ssh_public_key       = "{ssh_public_key}"
"""

    def init(self, deploy_dir: Path) -> TerraformResult:
        """Run terraform init"""
        return self._run_command(deploy_dir, ["init", "-no-color", "-input=false"])

    def plan(self, deploy_dir: Path) -> TerraformResult:
        """Run terraform plan"""
        return self._run_command(
            deploy_dir,
            ["plan", "-no-color", "-input=false", "-var-file=terraform.tfvars"],
        )

    def apply(self, deploy_dir: Path) -> TerraformResult:
        """Run terraform apply"""
        result = self._run_command(
            deploy_dir,
            ["apply", "-no-color", "-input=false", "-auto-approve", "-var-file=terraform.tfvars"],
        )

        # Get outputs if apply succeeded
        if result.success:
            outputs_result = self._run_command(deploy_dir, ["output", "-json"])
            if outputs_result.success:
                try:
                    result.outputs = json.loads(outputs_result.stdout)
                except json.JSONDecodeError:
                    logger.warning("🏗️ [Terraform] Could not parse outputs JSON")

        return result

    def destroy(self, deploy_dir: Path) -> TerraformResult:
        """Run terraform destroy"""
        return self._run_command(
            deploy_dir,
            ["destroy", "-no-color", "-input=false", "-auto-approve", "-var-file=terraform.tfvars"],
        )

    def get_outputs(self, deploy_dir: Path) -> Result[dict[str, Any], str]:
        """Get terraform outputs"""
        result = self._run_command(deploy_dir, ["output", "-json"])
        if not result.success:
            return Err(f"Failed to get outputs: {result.stderr}")

        try:
            outputs = json.loads(result.stdout)
            # Extract values from terraform output format
            return Ok({k: v.get("value") for k, v in outputs.items()})
        except json.JSONDecodeError as e:
            return Err(f"Failed to parse outputs: {e}")

    def _run_command(self, deploy_dir: Path, args: list[str]) -> TerraformResult:
        """Execute terraform command"""
        cmd = [self._terraform_path, *args]
        cmd_str = " ".join(cmd)

        logger.info(f"🏗️ [Terraform] Running: {cmd_str} in {deploy_dir}")

        try:
            result = subprocess.run(  # noqa: PLW1510, S603
                cmd,
                cwd=deploy_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env={**os.environ, "TF_IN_AUTOMATION": "1"},
            )

            success = result.returncode == 0
            log_level = logging.INFO if success else logging.ERROR
            logger.log(log_level, f"🏗️ [Terraform] Command {'succeeded' if success else 'failed'}: {cmd_str}")

            if not success:
                logger.error(f"🏗️ [Terraform] stderr: {result.stderr[:500]}")

            return TerraformResult(
                success=success,
                command=cmd_str,
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
            )

        except subprocess.TimeoutExpired:
            logger.error(f"🚨 [Terraform] Command timed out after {self.timeout}s: {cmd_str}")
            return TerraformResult(
                success=False,
                command=cmd_str,
                stdout="",
                stderr=f"Command timed out after {self.timeout} seconds",
                return_code=-1,
            )
        except Exception as e:
            logger.error(f"🚨 [Terraform] Command failed: {e}")
            return TerraformResult(
                success=False,
                command=cmd_str,
                stdout="",
                stderr=str(e),
                return_code=-1,
            )

    def cleanup_sensitive_files(self, deploy_dir: Path) -> None:
        """Remove sensitive files after deployment"""
        tfvars_file = deploy_dir / "terraform.tfvars"
        if tfvars_file.exists():
            tfvars_file.unlink()
            logger.info(f"🏗️ [Terraform] Removed sensitive file: {tfvars_file}")


# Module-level singleton
_terraform_service: TerraformService | None = None


def get_terraform_service() -> TerraformService:
    """Get global Terraform service instance"""
    global _terraform_service  # noqa: PLW0603
    if _terraform_service is None:
        _terraform_service = TerraformService()
    return _terraform_service
