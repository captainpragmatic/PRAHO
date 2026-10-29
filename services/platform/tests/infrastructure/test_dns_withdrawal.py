"""DNS withdrawal: the stored owner tag decides how a deployment's records are removed, and only proof clears them.

New deployments tag records with their correlation_id, unique across PRAHO databases, so withdrawal
by tag is safe and is confirmed by listing the tag again. Records written before that carry the
integer row id, which two databases sharing a zone can both use: those are deleted only by their
stored record id, after the record still matches the stored name, type and address. An entry with no
record id is ambiguous and is kept for reconciliation, never swept by tag.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import requests
from django.test import SimpleTestCase, TestCase

from apps.common.types import Err, Ok, retriability_of
from apps.infrastructure.deployment_service import NodeDeploymentService
from apps.infrastructure.dns_gateway import CloudflareDnsGateway, ExpectedDnsRecord, ReconcileOutcome
from apps.infrastructure.models import NodeDeployment
from tests.infrastructure.test_deployment_dns import _lease, _noop_log
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _make_service

_DNS_GW = "apps.infrastructure.deployment_service.get_dns_gateway"
_GET_SETTING = "apps.infrastructure.deployment_service.SettingsService.get_setting"
LEGACY_TAG = "praho:node-deploy:5"


def response(status: int, body: Any = None) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status
    resp._content = b"" if body is None else json.dumps(body).encode()
    return resp


def record(rid: str = "rA", content: str = "1.2.3.4", comment: str = LEGACY_TAG) -> dict[str, Any]:
    return {"id": rid, "type": "A", "name": "node.test.example.com", "content": content, "comment": comment}


def expected(rid: str = "rA") -> ExpectedDnsRecord:
    return ExpectedDnsRecord(
        record_id=rid, name="node.test.example.com", record_type="A", content="1.2.3.4", owner_tag=LEGACY_TAG
    )


class ValidatedDeleteTests(SimpleTestCase):
    def cloudflare(self, responses: list[requests.Response]) -> tuple[CloudflareDnsGateway, MagicMock]:
        gateway = CloudflareDnsGateway(token="tok")
        patcher = patch.object(gateway, "_request", side_effect=responses)
        request = patcher.start()
        self.addCleanup(patcher.stop)
        return gateway, request

    def test_a_matching_record_is_deleted_and_confirmed_gone(self) -> None:
        gateway, request = self.cloudflare(
            [response(200, {"success": True, "result": record()}), response(200, {"success": True}), response(404)]
        )

        result = gateway.delete_validated_records("z1", [expected()])

        self.assertEqual(result.unwrap(), ["rA"])
        self.assertEqual([call.args[0] for call in request.call_args_list], ["GET", "DELETE", "GET"])

    def test_a_record_that_no_longer_matches_is_refused(self) -> None:
        gateway, request = self.cloudflare([response(200, {"success": True, "result": record(content="9.9.9.9")})])

        result = gateway.delete_validated_records("z1", [expected()])

        self.assertTrue(result.is_err())
        self.assertNotIn("DELETE", [call.args[0] for call in request.call_args_list])

    def test_a_record_already_gone_needs_no_delete(self) -> None:
        gateway, request = self.cloudflare([response(404)])

        self.assertEqual(gateway.delete_validated_records("z1", [expected()]).unwrap(), ["rA"])
        self.assertEqual(request.call_count, 1)

    def test_a_record_still_present_after_delete_is_unconfirmed(self) -> None:
        gateway, _request = self.cloudflare(
            [
                response(200, {"success": True, "result": record()}),
                response(200, {"success": True}),
                response(200, {"success": True, "result": record()}),
            ]
        )

        result = gateway.delete_validated_records("z1", [expected()])

        self.assertTrue(result.is_err())
        self.assertIsNotNone(retriability_of(result))

    def test_tag_listing_confirms_absence(self) -> None:
        gateway, _request = self.cloudflare([response(200, {"success": True, "result": [record()], "result_info": {}})])

        self.assertFalse(gateway.confirm_no_owned_records("z1", LEGACY_TAG).unwrap())


def _entry(tag: str, rid: str = "rA", kind: str = "A") -> dict[str, str]:
    return {
        "provider": "cloudflare",
        "zone_id": "z1",
        "record_id": rid,
        "type": kind,
        "name": "node.test.example.com",
        "owner_tag": tag,
    }


class OwnerTagTests(TestCase):
    def test_a_new_deployment_tags_records_with_its_correlation_id(self) -> None:
        dep = _create_deployment("pending")

        self.assertEqual(NodeDeploymentService._dns_owner_tag(dep), f"praho:node-deploy:{dep.correlation_id}")

    def test_a_retry_keeps_the_tag_its_records_already_carry(self) -> None:
        dep = _create_deployment("provisioning_node")
        NodeDeployment.objects.filter(pk=dep.pk).update(dns_record_ids=[_entry(LEGACY_TAG)], ipv4_address="1.2.3.4")
        dep.refresh_from_db()
        gw = MagicMock()
        gw.get_zone_name.return_value = Ok("test.example.com")
        gw.reconcile_records.return_value = ReconcileOutcome(applied=[], error=None)

        with patch(_DNS_GW, return_value=gw):
            _make_service()._configure_dns(dep, "tok", "z1", _noop_log, _lease(dep))

        self.assertEqual(gw.reconcile_records.call_args.args[2], LEGACY_TAG)


class WithdrawalTests(TestCase):
    def _withdraw(self, dep: NodeDeployment, gw: MagicMock) -> Any:
        with patch(_DNS_GW, return_value=gw), patch(_GET_SETTING, return_value="tok"):
            return NodeDeploymentService._delete_owned_dns(dep)

    def _dep(self, entries: list[dict[str, str]]) -> NodeDeployment:
        dep = _create_deployment("completed")
        NodeDeployment.objects.filter(pk=dep.pk).update(dns_record_ids=entries)
        dep.refresh_from_db()
        return dep

    def test_two_deployments_sharing_an_integer_tag_never_delete_each_other(self) -> None:
        dep = self._dep([_entry(LEGACY_TAG, "rA")])
        gw = MagicMock()
        gw.delete_validated_records.return_value = Ok(["rA"])

        result = self._withdraw(dep, gw)

        self.assertTrue(result.is_ok(), result)
        gw.delete_owned_records.assert_not_called()
        sent = gw.delete_validated_records.call_args.args[1]
        self.assertEqual([(e.record_id, e.content) for e in sent], [("rA", "1.2.3.4")])
        dep.refresh_from_db()
        self.assertEqual(dep.dns_record_ids, [])

    def test_a_legacy_entry_without_a_record_id_is_kept_for_reconciliation(self) -> None:
        intent = {**_entry(LEGACY_TAG, ""), "type": "intent"}
        dep = self._dep([intent])
        gw = MagicMock()

        result = self._withdraw(dep, gw)

        self.assertTrue(result.is_err())
        gw.delete_owned_records.assert_not_called()
        gw.delete_validated_records.assert_not_called()
        dep.refresh_from_db()
        self.assertEqual(dep.dns_record_ids, [intent])
        self.assertTrue(dep.needs_reconciliation)

    def test_unique_tag_withdrawal_is_confirmed_before_clearing(self) -> None:
        dep = _create_deployment("completed")
        tag = f"praho:node-deploy:{dep.correlation_id}"
        NodeDeployment.objects.filter(pk=dep.pk).update(dns_record_ids=[_entry(tag)])
        dep.refresh_from_db()
        gw = MagicMock()
        gw.delete_owned_records.return_value = Ok(["rA"])
        gw.confirm_no_owned_records.return_value = Ok(False)

        result = self._withdraw(dep, gw)

        self.assertTrue(result.is_err())
        gw.delete_owned_records.assert_called_once_with("z1", tag)
        dep.refresh_from_db()
        self.assertEqual(len(dep.dns_record_ids), 1)

    def test_unique_tag_withdrawal_clears_once_confirmed(self) -> None:
        dep = _create_deployment("completed")
        tag = f"praho:node-deploy:{dep.correlation_id}"
        NodeDeployment.objects.filter(pk=dep.pk).update(dns_record_ids=[_entry(tag)])
        dep.refresh_from_db()
        gw = MagicMock()
        gw.delete_owned_records.return_value = Ok(["rA"])
        gw.confirm_no_owned_records.return_value = Ok(True)

        self.assertTrue(self._withdraw(dep, gw).is_ok())
        dep.refresh_from_db()
        self.assertEqual(dep.dns_record_ids, [])

    def test_a_failed_validated_delete_keeps_the_entry(self) -> None:
        dep = self._dep([_entry(LEGACY_TAG, "rA")])
        gw = MagicMock()
        gw.delete_validated_records.return_value = Err("record rA no longer matches")

        self.assertTrue(self._withdraw(dep, gw).is_err())
        dep.refresh_from_db()
        self.assertEqual(len(dep.dns_record_ids), 1)
