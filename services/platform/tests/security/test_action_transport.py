"""Action tasks cross the real adapter and wire parser before accepting host receipts."""

import json
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.test import TestCase, override_settings

from apps.common.crowdsec_transport import canonical_action_digest
from apps.security import action_services, action_tasks
from apps.security.models import SecurityManagedDecision
from tests.security.action_fixtures import ActionFixture


@override_settings(PRAHO_CROWDSEC_ACTIONS_ENABLED=True)
class SecurityActionTransportTests(ActionFixture, TestCase):
    @staticmethod
    def response(raw: bytes, result: dict[str, object]) -> dict[str, object]:
        request = json.loads(raw)
        return {**{key: value for key, value in request.items() if key != "payload"}, "result": result}

    def test_create_roundtrip_binds_actual_wire_digest_and_accepts_a_shorter_host_expiry(self) -> None:
        target = self.issue().targets.get()
        receipt = self.receipt(target)
        receipt["expires_at"] = (target.expires_at - timedelta(seconds=10)).isoformat()

        def host(_endpoint, raw):
            request = json.loads(raw)
            self.assertEqual(request["operation"], "ban_put")
            self.assertEqual(request["request_id"], str(target.request_id))
            self.assertEqual(request["payload"], target.payload)
            self.assertEqual(canonical_action_digest("ban_put", request["payload"]), target.payload_digest)
            return self.response(raw, receipt)

        with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=host) as rpc:
            result = action_tasks.run_target(str(target.pk))
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(rpc.call_count, 1)
        target.refresh_from_db()
        self.assertEqual(target.evidence["expires_at"], receipt["expires_at"])
        self.assertEqual(
            SecurityManagedDecision.objects.get(source=target.source, remote_id=90).provenance_id,
            target.provenance_id,
        )

    def test_absent_receipt_roundtrip_keeps_unknown_without_replaying_creation(self) -> None:
        target = self.issue().targets.get()
        with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=TimeoutError("after dispatch")):
            action_tasks.run_target(str(target.pk))

        def host(_endpoint, raw):
            request = json.loads(raw)
            self.assertEqual(request["operation"], "receipt_get")
            self.assertEqual(request["payload"], {"request_id": str(target.request_id)})
            return self.response(raw, {"status": "unknown", "evidence": "no_receipt"})

        with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=host) as rpc:
            self.assertEqual(action_tasks.run_target(str(target.pk))["state"], "unknown")
        self.assertEqual(rpc.call_count, 1)
        target.refresh_from_db()
        self.assertEqual(target.evidence, {"status": "unknown", "evidence": "no_receipt"})

    def test_receipt_lookup_roundtrip_rejects_changed_issuance_bindings_and_extended_expiry(self) -> None:
        target = self.issue().targets.get()
        with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=TimeoutError("after dispatch")):
            action_tasks.run_target(str(target.pk))
        for field, value in (
            ("payload_digest", "0" * 64),
            ("provenance_id", str(uuid4())),
            ("revision", target.revision + 1),
            ("operation", "revoke"),
            ("expires_at", (target.expires_at + timedelta(seconds=1)).isoformat()),
        ):
            with self.subTest(field=field):
                receipt = {**self.receipt(target), field: value}
                with patch(
                    "apps.common.crowdsec_transport.remote_rpc",
                    side_effect=lambda _endpoint, raw, receipt=receipt: self.response(raw, receipt),
                ) as rpc:
                    self.assertEqual(action_tasks.run_target(str(target.pk))["state"], "unknown")
                self.assertEqual(rpc.call_count, 1)
        self.assertFalse(SecurityManagedDecision.objects.filter(source=target.source).exists())

    def test_allowlist_roundtrip_waits_for_pending_create_then_repairs_only_positive_late_evidence(self) -> None:
        target = action_services.replace_allowlist(
            actor=self.admin,
            reason="Protect customer address",
            idempotency_key=uuid4(),
            source_id=self.source.pk,
            cidrs=["198.51.100.8/32"],
        ).targets.get()
        operations = []
        evidence = "pending_create"

        def host(_endpoint, raw):
            request = json.loads(raw)
            operations.append(request["operation"])
            if request["operation"] == "allowlist_replace":
                self.assertEqual(request["request_id"], str(target.request_id))
                self.assertEqual(request["payload"], target.payload)
                result = self.receipt(target, status="unknown", evidence=evidence)
                if evidence == "mutation_uncertain":
                    result = self.receipt(target)
            else:
                self.assertEqual(request["payload"], {"request_id": str(target.request_id)})
                result = self.receipt(target, status="unknown", evidence=evidence)
            return self.response(raw, result)

        with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=host):
            self.assertEqual(action_tasks.run_target(str(target.pk))["state"], "unknown")
            self.assertEqual(action_tasks.run_target(str(target.pk))["state"], "unknown")
            self.assertEqual(operations, ["allowlist_replace", "receipt_get"])
            evidence = "mutation_uncertain"
            self.assertEqual(action_tasks.run_target(str(target.pk))["state"], "succeeded")
        self.assertEqual(operations, ["allowlist_replace", "receipt_get", "receipt_get", "allowlist_replace"])
