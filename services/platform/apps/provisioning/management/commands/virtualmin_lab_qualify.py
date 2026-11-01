"""Apply and prove the actual node policy on the disposable lab's two generated nodes."""

from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.infrastructure.ansible_service import AnsibleService
from apps.infrastructure.registration_service import NodeRegistrationService
from apps.provisioning.management.commands._virtualmin_lab import (
    lab_transport,
    load_state,
    refuse_unless_lab_settings,
)
from apps.provisioning.virtualmin_models import VirtualminServer


class Command(BaseCommand):
    help = "Harden and qualify disposable lab nodes before destination workflows (lab settings only)"

    def handle(self, *args: Any, **options: Any) -> None:
        refuse_unless_lab_settings()
        state = load_state()
        with lab_transport(state):
            for node in state.nodes:
                server = VirtualminServer.objects.get(hostname=node.server_hostname)
                if server.status != "disabled" or server.security_operation:
                    raise CommandError("Lab qualification requires freshly bootstrapped, disabled nodes")
                result = AnsibleService().run_playbook(
                    server.node_deployment,
                    "virtualmin_harden.yml",
                    {"security_hardening_approved": True, "praho_api_user": server.api_username},
                    timeout_seconds=1200,
                )
                if result.is_err() or not result.unwrap().success:
                    raise CommandError(f"Lab policy application failed on {node.key}; node remains disabled")
                activated = NodeRegistrationService().verify_and_activate(server)
                if activated.is_err():
                    raise CommandError(f"Lab qualification failed on {node.key}: {activated.unwrap_err()}")
                self.stdout.write(self.style.SUCCESS(f"Qualified {node.key}: live policy and dedicated API verified"))
