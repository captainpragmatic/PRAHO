"""Check that every lab node still presents the certificate PRAHO pinned (lab only).

A node restart regenerates its TLS identity (lab-node-identity.service), which invalidates the pin recorded on
its VirtualminServer row and every later lab test with it. The fault suite never restarts a node on purpose, but
it runs against one that may have to be: this command is how it finds out. Exit status 1 and the nodes named on
stdout mean `virtualmin_lab_bootstrap` and `lab.sh apply-credentials` must run again.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.provisioning.management.commands._virtualmin_lab import load_state, refuse_unless_lab_settings
from apps.provisioning.management.commands.virtualmin_lab_bootstrap import _certificate_sha256


class Command(BaseCommand):
    help = "Fail when a lab node no longer presents the certificate its VirtualminServer row pins (lab only)"

    def handle(self, *args: Any, **options: Any) -> None:
        from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

        refuse_unless_lab_settings()
        stale: list[str] = []
        for node in load_state().nodes:
            server = VirtualminServer.objects.get(hostname=node.server_hostname)
            live = _certificate_sha256(node.api_port)
            if live != server.ssl_cert_fingerprint:
                stale.append(node.key)
        if stale:
            raise CommandError(f"stale certificate pin: {' '.join(stale)}")
        self.stdout.write("Every lab node presents its pinned certificate")
