"""Domain listings in the key form Virtualmin 8.3.0's JSON API actually emits.

`list-domains --multiline` over remote.cgi with json=1 returns each attribute
under a snake_case key ("username", "disabled"), not the text label
("Username", "Status"). An enabled domain has no status attribute at all; a
disabled one carries "disabled" (the text form prints "Disabled: Manually").
Recorded from the lab node (webmin-virtual-server 8.3.0-1-gpl); secrets such as
hashed_password and password_for_mysql are left out of the fixture.

Read with the old title-case keys, every owner was "" and every state None, so
restore verification, the restore target gate, migration admission and the
ownership probes all failed against a stock 8.3.0 node.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.test import TestCase

from apps.provisioning.virtualmin_migration_service import list_migration_domains
from tests.provisioning.test_cov_virtualmin_gateway_listing import gateway, http_response


def _row_8_3(name: str, username: str, *, disabled: bool = False) -> dict[str, Any]:
    values: dict[str, list[str]] = {
        "id": ["17919039172618"],
        "type": ["Top-level server"],
        "username": [username],
        "username_for_mysql": [username],
        "user_id": ["1002"],
        "home_directory": [f"/home/{username}"],
        "features": ["unix dir web ssl logrotate mysql webmin"],
        "template": ["Default Settings"],
        "plan": ["Default Plan"],
    }
    if disabled:
        values["disabled"] = ["Manually"]
        values["disabled_at"] = ["10/13/2026 03:06 PM"]
    return {"name": name, "values": values}


def _listing(*rows: dict[str, Any]) -> dict[str, Any]:
    return {"command": "list-domains", "status": "success", "data": list(rows)}


class VirtualminJsonListingKeysTests(TestCase):
    def setUp(self) -> None:
        self.gateway = gateway()
        self.payload = _listing(
            _row_8_3("roundtrip.praho.test", "roundtrip"),
            _row_8_3("paused.praho.test", "paused", disabled=True),
        )

    def _respond(self) -> Any:
        return patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            return_value=http_response(self.payload),
        )

    def test_migration_listing_reads_owner_and_state(self) -> None:
        with self._respond():
            rows = {row["domain"]: row for row in list_migration_domains(self.gateway).unwrap()}

        self.assertEqual(rows["roundtrip.praho.test"]["username"], "roundtrip")
        self.assertIs(rows["roundtrip.praho.test"]["enabled"], True)
        self.assertEqual(rows["paused.praho.test"]["username"], "paused")
        self.assertIs(rows["paused.praho.test"]["enabled"], False)

    def test_domain_state_reads_owner_and_state(self) -> None:
        with self._respond():
            enabled = self.gateway.get_domain_state("roundtrip.praho.test").unwrap()
            paused = self.gateway.get_domain_state("paused.praho.test").unwrap()

        self.assertEqual(enabled, {"exists": True, "enabled": True, "owner": "roundtrip"})
        self.assertEqual(paused, {"exists": True, "enabled": False, "owner": "paused"})

    def test_owner_probes_read_the_snake_case_username(self) -> None:
        with self._respond():
            owner = self.gateway.get_domain_owner("roundtrip.praho.test").unwrap()
            owners = self.gateway.list_domains_with_owners().unwrap()

        self.assertEqual(owner, "roundtrip")
        self.assertIn({"domain": "paused.praho.test", "username": "paused"}, owners)

    def test_title_case_rows_keep_working(self) -> None:
        self.payload = _listing(
            {"name": "legacy.example", "values": {"Username": ["legacy"], "Status": ["Enabled"]}},
            {"name": "off.example", "values": {"Username": ["off"], "Status": ["Disabled"]}},
        )
        with self._respond():
            rows = {row["domain"]: row for row in list_migration_domains(self.gateway).unwrap()}

        self.assertEqual((rows["legacy.example"]["username"], rows["legacy.example"]["enabled"]), ("legacy", True))
        self.assertEqual((rows["off.example"]["username"], rows["off.example"]["enabled"]), ("off", False))

    def test_state_is_unverifiable_without_identity_or_status(self) -> None:
        # No status, no disabled marker and no record id: nothing proves the
        # domain is enabled, so the state stays unknown (fail closed).
        self.payload = _listing({"name": "bare.example", "values": {"username": ["bare"]}})
        with self._respond():
            rows = list_migration_domains(self.gateway).unwrap()

        self.assertIsNone(rows[0]["enabled"])
