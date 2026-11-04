"""A real transport-schema peer; only the external RPC boundary is replaced."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast
from uuid import uuid4

from django.test import override_settings
from django.utils import timezone

from apps.common.crowdsec_transport import Endpoint
from apps.security import services
from apps.users.models import User
from tests.provisioning.test_node_security_policy import OPERATOR_KEY


class SecurityFixture:
    def setUp(self) -> None:
        super().setUp()
        self.directory = TemporaryDirectory(prefix="praho-security-mirror-")
        self.addCleanup(self.directory.cleanup)
        self.key = Path(self.directory.name) / "gateway-key"
        self.key.write_bytes(b"separately enrolled fixture private identity")
        configured = override_settings(
            DISABLE_AUDIT_SIGNALS=True,
            PRAHO_CROWDSEC_SYNC_ENABLED=True,
            PRAHO_CROWDSEC_SSH_PRIVATE_KEY_PATH=str(self.key),
        )
        configured.enable()
        self.addCleanup(configured.disable)
        self.admin = User.objects.create_superuser(email="security-mirror@example.test", password=None)
        self.config = services.SourceConfiguration(
            kind="portal",
            transport="ssh",
            hostname="portal.example.test",
            port=9876,
            host_keys=OPERATOR_KEY,
            installation_id=uuid4(),
            configuration_digest="c" * 64,
            sync_enabled=True,
        )
        self.source = services.enroll_source(self.config, self.admin)
        self.now = timezone.now()

    def decision(self, remote_id: int = 1, value: str = "198.51.100.8/30") -> dict[str, object]:
        return {
            "id": remote_id,
            "created_at": (self.now - timedelta(minutes=1)).isoformat(),
            "expires_at": (self.now + timedelta(hours=4)).isoformat(),
            "scenario": "crowdsecurity/ssh-bf",
            "type": "ban",
            "scope": "range" if "/" in value else "ip",
            "value": value,
            "origin": "crowdsec",
            "simulated": False,
        }

    def alert(self, remote_id: int = 1) -> dict[str, object]:
        return {
            "id": remote_id,
            "created_at": self.now.isoformat(),
            "scenario": "crowdsecurity/ssh-bf",
            "event_count": 8,
            "scope": "ip",
            "value": "198.51.100.8",
            "simulated": True,
        }

    def peer(
        self,
        decisions: list[dict[str, object]] | None = None,
        alerts: list[dict[str, object]] | None = None,
        *,
        watermark: int | None = None,
        has_more: bool = False,
        mutate: Callable[[dict[str, object]], None] | None = None,
    ) -> Callable[[Endpoint, bytes], dict[str, object]]:
        decisions = [self.decision()] if decisions is None else decisions
        alerts = [self.alert()] if alerts is None else alerts
        watermark = (cast("int", alerts[-1]["id"]) if alerts else 0) if watermark is None else watermark

        def rpc(endpoint: Endpoint, raw: bytes) -> dict[str, object]:
            request = json.loads(raw)
            if request["operation"] == "health":
                result = {
                    "observed_at": self.now.isoformat(),
                    "simulation": True,
                    "engine": {"active": True, "version": "1.8.2"},
                    "bouncer": {"active": False, "version": "0.0.36-praho.1"},
                    "firewall": {"qualified": True, "ban_sets_empty": True},
                    "configuration": {"qualified": True},
                    "clock": {
                        "synchronized": False,
                        "qualified": False,
                        "offset_seconds": None,
                        "maximum_error_seconds": None,
                        "estimated_error_seconds": None,
                    },
                }
            else:
                result = {
                    "observed_at": self.now.isoformat(),
                    "decisions": copy.deepcopy(decisions),
                    "alerts": copy.deepcopy(alerts),
                    "alert_watermark": watermark,
                    "has_more": has_more,
                }
            response = {key: value for key, value in request.items() if key != "payload"}
            response["result"] = result
            if mutate is not None:
                mutate(response)
            return response

        return rpc
