"""Audited mutations preserve uncertainty, fixed expiry and revocation fencing."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from types import ModuleType
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from test_crowdsec_gateway import enrolled, gateway

from apps.common.crowdsec_transport import CrowdSecRPCError, canonical_action_digest, parse_response

__all__ = ["enrolled", "gateway"]
INSTALLATION = "417ebf86-1d99-45ec-91bf-16a1a7878e7f"
ALLOWLIST_SCHEMA = {
    "allow_lists": "id INTEGER PRIMARY KEY,created_at datetime NOT NULL,updated_at datetime NOT NULL,name TEXT NOT NULL,"
    "from_console bool NOT NULL,description TEXT,allowlist_id TEXT",
    "allow_list_items": "id INTEGER PRIMARY KEY,created_at datetime NOT NULL,updated_at datetime NOT NULL,expires_at datetime,"
    "comment TEXT,value TEXT NOT NULL,start_ip INTEGER,end_ip INTEGER,start_suffix INTEGER,end_suffix INTEGER,ip_size INTEGER",
    "allow_list_allowlist_items": "allow_list_id INTEGER NOT NULL,allow_list_item_id INTEGER NOT NULL",
}
PORTAL_FILES = {
    "/etc/crowdsec/parsers/s01-parse/praho-portal-auth.yaml",
    "/etc/crowdsec/scenarios/praho-portal-auth-bf.yaml",
    "/etc/crowdsec/scenarios/praho-portal-auth-throttle.yaml",
}


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def rpc(module: ModuleType, operation: str, payload: dict[str, object], identifier: str | None = None) -> bytes:
    config = json.loads(module.CONFIG_PATH.read_text())
    return canonical(
        {
            "protocol": 1,
            "request_id": identifier or str(uuid4()),
            "installation_id": config["installation_id"],
            "configuration_digest": config["configuration_digest"],
            "operation": operation,
            "payload": payload,
        }
    ).encode()


def configure(module: ModuleType, config: dict[str, object], **changes: object) -> None:
    config.update({field: value for field, value in changes.items() if field != "host_kind"})
    for field in ("simulation", "host_kind"):
        if field in changes:
            config["policy"][field] = changes[field]
    config["configuration_digest"] = hashlib.sha256(canonical(config["policy"]).encode()).hexdigest()
    module.CONFIG_PATH.write_text(canonical(config))
    for service in ("engine", "bouncer"):
        (module.MANAGED_ROOT / f"var/lib/praho-crowdsec/{service}-applied.sha256").write_text(
            config["configuration_digest"] + "\n"
        )


def ban(**changes: object) -> dict[str, object]:
    return {
        "provenance_id": str(uuid4()),
        "revision": 1,
        "kind": "manual",
        "scope": "ip",
        "value": "198.51.100.9",
        "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        "source": None,
        **changes,
    }


class LocalAPI:
    """Only the external native API boundary is replaced; reconciliation reads real SQLite."""

    def __init__(self, module: ModuleType):
        self.module = module
        self.calls: list[tuple[str, str, object]] = []
        self.timeout_before = False
        self.timeout_after = False
        self.issued_receipt: dict[str, object] | None = None
        self.cli_calls: list[list[str]] = []
        self.skip_allowlist_expiry = False

    def __call__(self, method: str, path: str, body: object = None) -> tuple[int, object]:
        self.calls.append((method, path, body))
        if self.timeout_before:
            raise TimeoutError("unobservable local dispatch")
        now = datetime.now(UTC).isoformat()
        with sqlite3.connect(self.module.DATABASE_PATH) as connection:
            if method == "POST" and path == "/v1/alerts":
                alert = body[0]
                item = alert["decisions"][0]
                expiry = datetime.fromisoformat(alert["stop_at"]) + timedelta(seconds=float(item["duration"][:-1]))
                cursor = connection.execute(
                    "INSERT INTO alerts(created_at,updated_at,scenario,events_count,source_scope,source_value,simulated,kind,machine_alerts) "
                    "VALUES(?,?,?,?,?,?,0,'cscli',1)",
                    (now, now, alert["scenario"], 1, item["scope"], item["value"]),
                )
                connection.execute(
                    'INSERT INTO decisions(created_at,updated_at,"until",scenario,type,scope,value,origin,simulated,uuid,alert_decisions) '
                    "VALUES(?,?,?,?,?,?,?,?,0,?,?)",
                    (
                        now,
                        now,
                        expiry.isoformat(),
                        item["scenario"],
                        item["type"],
                        item["scope"],
                        item["value"],
                        item["origin"],
                        str(uuid4()),
                        cursor.lastrowid,
                    ),
                )
            elif method == "DELETE":
                filters = parse_qs(urlsplit(path).query)
                assert filters.get("uuid"), "Native revocation must bind the physical decision UUID"
                connection.execute('UPDATE decisions SET "until"=? WHERE uuid=?', (now, filters["uuid"][0]))
            else:
                raise AssertionError("Unexpected native mutation")
        if self.timeout_after:
            raise TimeoutError("reply lost after native commit")
        return (201, ["1"]) if method == "POST" else (200, {"nbDeleted": "1"})

    def cli(self, arguments: list[str], descriptor: int) -> None:
        assert descriptor >= 0
        self.cli_calls.append(arguments)
        name = arguments[2]
        now = datetime.now(UTC).isoformat()
        with sqlite3.connect(self.module.DATABASE_PATH) as connection:
            if arguments[1] == "create":
                connection.execute(
                    "INSERT INTO allow_lists(created_at,updated_at,name,from_console,description) VALUES(?,?,?,0,?)",
                    (now, now, name, arguments[4]),
                )
                return
            list_id = connection.execute("SELECT id FROM allow_lists WHERE name=?", (name,)).fetchone()[0]
            added = False
            for value in arguments[3:]:
                if arguments[1] == "add":
                    if connection.execute(
                        "SELECT 1 FROM allow_list_items i JOIN allow_list_allowlist_items e ON e.allow_list_item_id=i.id WHERE e.allow_list_id=? AND i.value=?",
                        (list_id, value),
                    ).fetchone():
                        continue
                    item = connection.execute(
                        "INSERT INTO allow_list_items(created_at,updated_at,value) VALUES(?,?,?)", (now, now, value)
                    )
                    connection.execute("INSERT INTO allow_list_allowlist_items VALUES(?,?)", (list_id, item.lastrowid))
                    added = True
                else:
                    connection.execute(
                        "DELETE FROM allow_list_allowlist_items WHERE allow_list_id=? AND allow_list_item_id IN (SELECT id FROM allow_list_items WHERE value=?)",
                        (list_id, value),
                    )
            if added and not self.skip_allowlist_expiry:
                allowed = [
                    ipaddress.ip_network(row[0])
                    for row in connection.execute(
                        "SELECT i.value FROM allow_list_items i JOIN allow_list_allowlist_items e ON e.allow_list_item_id=i.id"
                    )
                ]
                for identifier, value in connection.execute(
                    'SELECT id,value FROM decisions WHERE julianday("until")>julianday(?)', (now,)
                ).fetchall():
                    network = ipaddress.ip_network(value)
                    if any(network.version == item.version and network.overlaps(item) for item in allowed):
                        connection.execute('UPDATE decisions SET "until"=? WHERE id=?', (now, identifier))


@pytest.fixture
def actions(gateway: ModuleType, enrolled: dict[str, object], monkeypatch: pytest.MonkeyPatch) -> LocalAPI:
    manifest = gateway.MANAGED_ROOT / "etc/praho-crowdsec/artifacts.lock.json"
    contents = json.loads(manifest.read_text())
    contents["hub"]["replication_candidates"] = ["crowdsecurity/ssh-bf"]
    manifest.write_text(canonical(contents))
    manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    enrolled["policy"]["artifact_lock_sha256"] = manifest_digest
    enrolled["policy"]["managed_files"]["/etc/praho-crowdsec/artifacts.lock.json"] = manifest_digest
    configure(gateway, enrolled, simulation=False)
    with sqlite3.connect(gateway.DATABASE_PATH) as connection:
        for name, fields in ALLOWLIST_SCHEMA.items():
            connection.execute(f"CREATE TABLE {name}({fields})")
    native = LocalAPI(gateway)
    monkeypatch.setattr(gateway, "_local_api", native, raising=False)
    monkeypatch.setattr(gateway, "_action_cli", native.cli, raising=False)
    monkeypatch.setattr(gateway, "_clock", lambda: {"qualified": True})
    return native


def test_manual_creation_issuance_idempotency_and_immutable_expiry(actions: LocalAPI) -> None:
    module = actions.module
    payload = ban()
    raw = rpc(module, "ban_put", payload)
    first = module.handle(raw)["result"]
    assert first["status"] == "succeeded" and first["evidence"] == "decision_present"
    assert len(first["decision_ids"]) == 1
    assert datetime.fromisoformat(first["expires_at"]) == datetime.fromisoformat(payload["expires_at"])
    assert (
        first["payload_digest"]
        == hashlib.sha256(canonical({"operation": "ban_put", "payload": payload}).encode()).hexdigest()
    )
    again = module.handle(raw)["result"]
    assert again["status"] == "succeeded" and again["decision_ids"] == first["decision_ids"]
    assert len(actions.calls) == 1
    receipt = module.handle(rpc(module, "receipt_get", {"request_id": first["request_id"]}))["result"]
    assert receipt["status"] == "succeeded" and receipt["expires_at"] == first["expires_at"]
    changed = json.loads(raw)
    changed["payload"]["value"] = "198.51.100.10"
    with pytest.raises(module.GatewayError):
        module.handle(canonical(changed).encode())
    assert len(actions.calls) == 1


def test_issuance_is_durable_before_any_native_call(actions: LocalAPI, monkeypatch: pytest.MonkeyPatch) -> None:
    module = actions.module
    raw = rpc(module, "ban_put", ban())
    identifier = json.loads(raw)["request_id"]
    original = actions.__call__

    def native(method: str, path: str, body: object = None) -> tuple[int, object]:
        receipt = module.handle(rpc(module, "receipt_get", {"request_id": identifier}))["result"]
        assert receipt["request_id"] == identifier
        assert receipt["status"] == "unknown" and receipt["evidence"] == "operation_pending"
        return original(method, path, body)

    monkeypatch.setattr(module, "_local_api", native)
    assert module.handle(raw)["result"]["status"] == "succeeded"


@pytest.mark.parametrize("applied", [False, True])
def test_lost_reply_remains_unknown_until_read_only_reconciliation(actions: LocalAPI, applied: bool) -> None:
    module = actions.module
    actions.timeout_before, actions.timeout_after = not applied, applied
    raw = rpc(module, "ban_put", ban())
    result = module.handle(raw)["result"]
    assert result["status"] == "unknown" and result["evidence"] == "mutation_uncertain"
    assert module.handle(raw)["result"]["status"] == ("succeeded" if applied else "unknown")
    receipt = module.handle(rpc(module, "receipt_get", {"request_id": result["request_id"]}))["result"]
    assert receipt["status"] == ("succeeded" if applied else "unknown")
    assert len(actions.calls) == 1


@pytest.mark.parametrize("value", ["192.0.2.1", "192.0.0.0/16", "192.0.2.0/25", "2001:db8::1", "2001:db8::/32"])
def test_protected_overlaps_are_business_rejections(actions: LocalAPI, value: str) -> None:
    module = actions.module
    payload = ban(scope="range" if "/" in value else "ip", value=value)
    result = module.handle(rpc(module, "ban_put", payload))["result"]
    assert result["status"] == "rejected" and result["evidence"] == "protected_overlap"
    assert actions.calls == []


def test_simulation_refuses_creates_but_keeps_revocation(actions: LocalAPI) -> None:
    module = actions.module
    payload = ban()
    assert module.handle(rpc(module, "ban_put", payload))["result"]["status"] == "succeeded"
    config = json.loads(module.CONFIG_PATH.read_text())
    configure(module, config, simulation=True)
    denied = module.handle(rpc(module, "ban_put", ban()))["result"]
    assert denied["status"] == "rejected" and denied["evidence"] == "simulation"
    revoke = {"provenance_id": payload["provenance_id"], "revision": 2, "decision": None}
    assert module.handle(rpc(module, "revoke", revoke))["result"]["status"] == "succeeded"


def test_revisioned_tombstone_blocks_delayed_create(actions: LocalAPI) -> None:
    module = actions.module
    payload = ban()
    tombstone = {"provenance_id": payload["provenance_id"], "revision": 2, "decision": None}
    assert module.handle(rpc(module, "revoke", tombstone))["result"]["status"] == "succeeded"
    result = module.handle(rpc(module, "ban_put", payload))["result"]
    assert result["status"] == "superseded" and result["evidence"] == "revoked"
    assert actions.calls == []


def test_revoke_cannot_complete_while_an_absent_earlier_create_is_unresolved(actions: LocalAPI) -> None:
    module = actions.module
    actions.timeout_before = True
    payload = ban()
    assert module.handle(rpc(module, "ban_put", payload))["result"]["status"] == "unknown"
    actions.timeout_before = False
    result = module.handle(
        rpc(module, "revoke", {"provenance_id": payload["provenance_id"], "revision": 2, "decision": None})
    )["result"]
    assert result["status"] == "unknown" and result["evidence"] == "pending_create"
    assert len(actions.calls) == 1


def test_observed_uncertain_create_can_be_revoked_without_touching_an_unrelated_ban(actions: LocalAPI) -> None:
    module = actions.module
    unrelated = module.handle(rpc(module, "ban_put", ban(value="198.51.100.10")))["result"]["decision_ids"]
    actions.timeout_after = True
    payload = ban()
    assert module.handle(rpc(module, "ban_put", payload))["result"]["status"] == "unknown"
    actions.timeout_after = False
    result = module.handle(
        rpc(module, "revoke", {"provenance_id": payload["provenance_id"], "revision": 2, "decision": None})
    )["result"]
    assert result["status"] == "succeeded" and result["evidence"] == "decision_absent"
    active = module.handle(rpc(module, "snapshot", {"after_alert_id": 0}))["result"]["decisions"]
    assert [row["id"] for row in active] == unrelated


@pytest.mark.parametrize("kind,hours", [("node", 4), ("portal", 5 / 60)])
def test_first_admission_caps_expiry_and_never_renews(actions: LocalAPI, kind: str, hours: float) -> None:
    module = actions.module
    config = json.loads(module.CONFIG_PATH.read_text())
    configure(module, config, host_kind=kind)
    before = datetime.now(UTC)
    payload = ban(expires_at=(before + timedelta(days=1)).isoformat())
    first = module.handle(rpc(module, "ban_put", payload))["result"]
    assert before < datetime.fromisoformat(first["expires_at"]) <= datetime.now(UTC) + timedelta(hours=hours)
    assert module.handle(rpc(module, "ban_put", payload))["result"]["expires_at"] == first["expires_at"]
    assert len(actions.calls) == 1


def test_copy_requires_approved_scenario_distinct_source_and_qualified_clock(
    actions: LocalAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = actions.module
    source = {
        "installation_id": str(uuid4()),
        "decision_id": 9,
        "scenario": "crowdsecurity/ssh-bf",
        "configuration_digest": "e" * 64,
    }
    payload = ban(kind="replica", source=source)
    assert module.handle(rpc(module, "ban_put", payload))["result"]["status"] == "succeeded"
    for case, evidence in (
        ("loop", "source_loop"),
        ("scenario", "scenario_not_approved"),
        ("clock", "clock_unqualified"),
    ):
        candidate = ban(kind="replica", source={**source})
        if case == "loop":
            candidate["source"]["installation_id"] = INSTALLATION
        elif case == "scenario":
            candidate["source"]["scenario"] = "crowdsecurity/http-probing"
        else:
            monkeypatch.setattr(module, "_clock", lambda: {"qualified": False})
        result = module.handle(rpc(module, "ban_put", candidate))["result"]
        assert result["status"] == "rejected" and result["evidence"] == evidence
    assert len(actions.calls) == 1


def test_receipt_absence_remains_unknown(actions: LocalAPI) -> None:
    assert actions.module.handle(rpc(actions.module, "receipt_get", {"request_id": str(uuid4())}))["result"] == {
        "status": "unknown",
        "evidence": "no_receipt",
    }


def test_staff_allowlist_replacement_reports_broad_expiry_and_preserves_inventory(actions: LocalAPI) -> None:
    module = actions.module
    broad = module.handle(rpc(module, "ban_put", ban(scope="range", value="198.51.100.0/24")))["result"]["decision_ids"]
    unrelated = module.handle(rpc(module, "ban_put", ban(value="198.51.101.9")))["result"]["decision_ids"]
    actions.cli(
        ["allowlists", "create", "praho-inventory", "--description", "PRAHO immutable inventory protections"], 0
    )
    actions.cli(["allowlists", "add", "praho-inventory", "192.0.2.0/24"], 0)
    config = json.loads(module.CONFIG_PATH.read_text())
    configure(module, config, simulation=True)
    raw = rpc(module, "allowlist_replace", {"revision": 1, "cidrs": ["198.51.100.9/32"]})
    result = module.handle(raw)["result"]
    assert result["status"] == "succeeded" and result["evidence"] == "allowlist_matches"
    assert result["decision_ids"] == broad
    snapshot = module.handle(rpc(module, "snapshot", {"after_alert_id": 0}))["result"]
    assert [row["id"] for row in snapshot["decisions"]] == unrelated
    with sqlite3.connect(module.DATABASE_PATH) as connection:
        inventory = connection.execute(
            "SELECT i.value FROM allow_list_items i JOIN allow_list_allowlist_items e ON e.allow_list_item_id=i.id JOIN allow_lists l ON l.id=e.allow_list_id WHERE l.name='praho-inventory'"
        ).fetchall()
    assert inventory == [("192.0.2.0/24",)]
    before_calls = len(actions.cli_calls)
    assert module.handle(raw)["result"]["status"] == "succeeded"
    assert len(actions.cli_calls) == before_calls
    newer = module.handle(rpc(module, "allowlist_replace", {"revision": 2, "cidrs": []}))["result"]
    assert newer["status"] == "succeeded"
    assert module.handle(raw)["result"]["status"] == "superseded"
    assert len(module.handle(rpc(module, "snapshot", {"after_alert_id": 0}))["result"]["decisions"]) == 1


@pytest.mark.parametrize("repair_works", [False, True])
def test_allowlist_cli_success_does_not_hide_failed_existing_decision_expiry(
    actions: LocalAPI, repair_works: bool
) -> None:
    module = actions.module
    module.handle(rpc(module, "ban_put", ban()))
    actions.skip_allowlist_expiry = True
    actions.timeout_before = not repair_works
    raw = rpc(module, "allowlist_replace", {"revision": 1, "cidrs": ["198.51.100.0/24"]})
    result = module.handle(raw)["result"]
    assert result["status"] == ("succeeded" if repair_works else "unknown")
    before = len(actions.cli_calls)
    observed = module.handle(rpc(module, "receipt_get", {"request_id": result["request_id"]}))["result"]
    assert observed["status"] == ("succeeded" if repair_works else "unknown") and len(actions.cli_calls) == before


def test_late_applied_create_is_removed_by_revoke_replay_without_create_replay(actions: LocalAPI) -> None:
    module = actions.module
    payload = ban()
    actions.timeout_before = True
    module.handle(rpc(module, "ban_put", payload))
    pending_body = actions.calls[0][2]
    raw = rpc(module, "revoke", {"provenance_id": payload["provenance_id"], "revision": 2, "decision": None})
    assert module.handle(raw)["result"]["evidence"] == "pending_create"
    actions.timeout_before = False
    actions("POST", "/v1/alerts", pending_body)  # Completion of the already-dispatched external write.
    before_calls = len(actions.calls)
    assert (
        module.handle(rpc(module, "receipt_get", {"request_id": json.loads(raw)["request_id"]}))["result"]["status"]
        == "unknown"
    )
    assert len(actions.calls) == before_calls
    result = module.handle(raw)["result"]
    assert result["status"] == "succeeded" and result["evidence"] == "decision_absent"
    assert [value[0] for value in actions.calls] == ["POST", "POST", "DELETE"]


@pytest.mark.parametrize(
    "scope,value",
    [("ip", "::ffff:7f00:1"), ("ip", "::ffff:127.0.0.1"), ("ip", "fe80::1%eth0"), ("range", "fe80::%eth0/64")],
)
def test_mutation_addresses_reject_mapped_hosts_and_scope_identifiers(
    actions: LocalAPI, scope: str, value: str
) -> None:
    module = actions.module
    with pytest.raises(module.GatewayError):
        module.handle(rpc(module, "ban_put", ban(scope=scope, value=value)))
    assert actions.calls == []


@pytest.mark.parametrize("operation", ["ban_put", "revoke", "allowlist_replace"])
def test_transport_accepts_complete_bound_action_receipts(actions: LocalAPI, operation: str) -> None:
    module = actions.module
    payload = (
        ban()
        if operation == "ban_put"
        else (
            {"provenance_id": str(uuid4()), "revision": 1, "decision": None}
            if operation == "revoke"
            else {"revision": 1, "cidrs": []}
        )
    )
    raw = rpc(module, operation, payload)
    response = module.handle(raw)
    assert parse_response(canonical(response).encode(), raw) == response
    receipt_raw = rpc(module, "receipt_get", {"request_id": json.loads(raw)["request_id"]})
    receipt = module.handle(receipt_raw)
    assert parse_response(canonical(receipt).encode(), receipt_raw) == receipt


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", str(uuid4())),
        ("operation", "revoke"),
        ("payload_digest", "0" * 64),
        ("provenance_id", str(uuid4())),
        ("revision", True),
        ("decision_ids", [1, 1]),
        ("status", "probably"),
        ("evidence", "no_receipt"),
        ("evidence", []),
        ("observed_at", "2026-11-04"),
        ("expires_at", "0001-01-01T00:00:00+01:00"),
    ],
)
def test_transport_rejects_unbound_or_malformed_action_receipts(actions: LocalAPI, field: str, value: object) -> None:
    module = actions.module
    raw = rpc(module, "ban_put", ban())
    response = module.handle(raw)
    response["result"][field] = value
    with pytest.raises(CrowdSecRPCError):
        parse_response(canonical(response).encode(), raw)


def test_owned_native_fingerprint_requires_its_actual_global_provenance(actions: LocalAPI) -> None:
    module = actions.module
    payload = ban()
    module.handle(rpc(module, "ban_put", payload))
    summary = module.handle(rpc(module, "snapshot", {"after_alert_id": 0}))["result"]["decisions"][0]
    guessed = {"provenance_id": str(uuid4()), "revision": 2, "decision": summary}
    result = module.handle(rpc(module, "revoke", guessed))["result"]
    assert result["status"] == "rejected" and result["evidence"] == "immutable_conflict"
    assert len(actions.calls) == 1
    correct = {**guessed, "provenance_id": payload["provenance_id"]}
    assert module.handle(rpc(module, "revoke", correct))["result"]["status"] == "succeeded"


def test_owned_provenance_cannot_revoke_an_unrelated_native_fingerprint(actions: LocalAPI) -> None:
    module = actions.module
    payload = ban()
    created = module.handle(rpc(module, "ban_put", payload))["result"]
    original = actions.calls[0][2][0]
    foreign = {
        **original,
        "scenario": "crowdsecurity/ssh-bf",
        "decisions": [
            {
                **original["decisions"][0],
                "value": "198.51.100.10",
                "origin": "crowdsec",
                "scenario": "crowdsecurity/ssh-bf",
            }
        ],
    }
    actions("POST", "/v1/alerts", [foreign])
    rows = module.handle(rpc(module, "snapshot", {"after_alert_id": 0}))["result"]["decisions"]
    unrelated = next(item for item in rows if item["id"] not in created["decision_ids"])
    result = module.handle(
        rpc(module, "revoke", {"provenance_id": payload["provenance_id"], "revision": 2, "decision": unrelated})
    )["result"]
    assert result["status"] == "rejected" and result["evidence"] == "immutable_conflict"
    assert len(actions.calls) == 2
    assert len(module.handle(rpc(module, "snapshot", {"after_alert_id": 0}))["result"]["decisions"]) == 2


@pytest.mark.parametrize("changes", [{"scope": []}, {"expires_at": "0001-01-01T00:00:00+01:00"}])
def test_transport_malformed_action_types_are_rpc_errors(changes: dict[str, object]) -> None:
    with pytest.raises(CrowdSecRPCError):
        canonical_action_digest("ban_put", ban(**changes))


def test_native_manual_reason_remains_private_during_fingerprint_revocation(actions: LocalAPI) -> None:
    module = actions.module
    reason = "manual 'ban' from 'NEVER_EXPORT'"
    now = datetime.now(UTC).isoformat()
    actions(
        "POST",
        "/v1/alerts",
        [
            {
                "scenario": reason,
                "stop_at": now,
                "decisions": [
                    {
                        "duration": "3600s",
                        "scope": "Ip",
                        "value": "198.51.110.9",
                        "scenario": reason,
                        "type": "ban",
                        "origin": "cscli",
                    }
                ],
            }
        ],
    )
    summary = module.handle(rpc(module, "snapshot", {"after_alert_id": 0}))["result"]["decisions"][0]
    raw = rpc(module, "revoke", {"provenance_id": str(uuid4()), "revision": 1, "decision": summary})
    response = module.handle(raw)
    assert response["result"]["status"] == "succeeded"
    assert "NEVER_EXPORT" not in canonical(response)


@pytest.mark.parametrize("hours", [-1, 1])
def test_complete_staff_replacement_repairs_expiring_entries(actions: LocalAPI, hours: int) -> None:
    module = actions.module
    payload = {"revision": 1, "cidrs": ["198.51.100.9/32"]}
    assert module.handle(rpc(module, "allowlist_replace", payload))["result"]["status"] == "succeeded"
    with sqlite3.connect(module.DATABASE_PATH) as connection:
        connection.execute(
            "UPDATE allow_list_items SET expires_at=?", ((datetime.now(UTC) + timedelta(hours=hours)).isoformat(),)
        )
    result = module.handle(rpc(module, "allowlist_replace", {**payload, "revision": 2}))["result"]
    assert result["status"] == "succeeded"
    with sqlite3.connect(module.DATABASE_PATH) as connection:
        active = connection.execute(
            "SELECT i.expires_at FROM allow_list_items i JOIN allow_list_allowlist_items e ON e.allow_list_item_id=i.id JOIN allow_lists l ON l.id=e.allow_list_id WHERE l.name='praho-staff'"
        ).fetchall()
    assert active == [(None,)]


def portal_metadata(actions: LocalAPI, *, kind: str, malformed: str | None = None) -> None:
    module = actions.module
    config = json.loads(module.CONFIG_PATH.read_text())
    manifest = module.MANAGED_ROOT / "etc/praho-crowdsec/artifacts.lock.json"
    document = json.loads(manifest.read_text())
    content = b"# reviewed Portal parser or scenario\n"
    digest = hashlib.sha256(content).hexdigest()
    rows = [{"installed_path": name, "sha256": digest} for name in sorted(PORTAL_FILES)]
    if malformed == "path":
        rows[0]["installed_path"] = "/etc/crowdsec/../unreviewed.yaml"
    elif malformed == "hash":
        rows[0]["sha256"] = "not-a-digest"
    elif malformed == "missing":
        rows.pop()
    document["praho_portal"] = {"files": rows}
    manifest.write_text(canonical(document))
    manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    config["policy"]["artifact_lock_sha256"] = manifest_digest
    config["policy"]["managed_files"]["/etc/praho-crowdsec/artifacts.lock.json"] = manifest_digest
    if kind == "portal":
        for name in PORTAL_FILES:
            path = module.MANAGED_ROOT / name.removeprefix("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            config["policy"]["managed_files"][name] = digest
    configure(module, config, host_kind=kind)


@pytest.mark.parametrize("kind", ["node", "portal"])
def test_exact_portal_managed_leaves_are_scoped_by_host_policy(actions: LocalAPI, kind: str) -> None:
    portal_metadata(actions, kind=kind)
    response = actions.module.handle(rpc(actions.module, "health", {}))
    assert response["result"]["configuration"]["qualified"] is True


@pytest.mark.parametrize("malformed", ["path", "hash", "missing"])
def test_portal_lock_cannot_select_unreviewed_leaves(actions: LocalAPI, malformed: str) -> None:
    portal_metadata(actions, kind="portal", malformed=malformed)
    with pytest.raises(actions.module.GatewayError):
        actions.module.handle(rpc(actions.module, "snapshot", {"after_alert_id": 0}))


def test_legacy_mapped_native_fingerprint_can_be_revoked_without_creating_mapped_bans(actions: LocalAPI) -> None:
    module = actions.module
    now = datetime.now(UTC).isoformat()
    actions(
        "POST",
        "/v1/alerts",
        [
            {
                "scenario": "legacy/manual",
                "stop_at": now,
                "decisions": [
                    {
                        "duration": "3600s",
                        "scope": "Ip",
                        "value": "::ffff:198.51.110.9",
                        "scenario": "legacy/manual",
                        "type": "ban",
                        "origin": "cscli",
                    }
                ],
            }
        ],
    )
    summary = module.handle(rpc(module, "snapshot", {"after_alert_id": 0}))["result"]["decisions"][0]
    raw = rpc(module, "revoke", {"provenance_id": str(uuid4()), "revision": 1, "decision": summary})
    response = module.handle(raw)
    assert response["result"]["status"] == "succeeded"
    assert parse_response(canonical(response).encode(), raw) == response


def test_mapped_prefixes_keep_their_ipv6_family(actions: LocalAPI) -> None:
    value = str(ipaddress.ip_network("::ffff:198.51.110.0/120"))
    result = actions.module.handle(rpc(actions.module, "ban_put", ban(scope="range", value=value)))["result"]
    assert result["status"] == "succeeded"
    assert actions.calls[0][2][0]["decisions"][0]["scope"] == "Range"


def test_staff_allowlist_waits_for_earlier_unknown_create_then_repairs_late_commit(actions: LocalAPI) -> None:
    module = actions.module
    payload = ban()
    actions.timeout_before = True
    module.handle(rpc(module, "ban_put", payload))
    pending_body = actions.calls[0][2]
    actions.timeout_before = False
    raw = rpc(module, "allowlist_replace", {"revision": 1, "cidrs": ["198.51.100.0/24"]})
    first = module.handle(raw)["result"]
    assert first["status"] == "unknown" and first["evidence"] == "pending_create"
    actions("POST", "/v1/alerts", pending_body)
    before_calls = len(actions.calls)
    observed = module.handle(rpc(module, "receipt_get", {"request_id": first["request_id"]}))["result"]
    assert observed["status"] == "unknown" and observed["evidence"] == "mutation_uncertain"
    assert len(actions.calls) == before_calls
    repaired = module.handle(raw)["result"]
    assert repaired["status"] == "succeeded" and repaired["evidence"] == "allowlist_matches"
    assert len(repaired["decision_ids"]) == 1
    assert [value[0] for value in actions.calls] == ["POST", "POST", "DELETE"]
