"""The node's database write hold: refuse by name, revoke exactly, release to the exact original bits (#776).

The helper runs against a Database seam. FakeDatabase models what the helper assumes about MariaDB; each of these
assumptions is qualified against a real server in tests/virtualmin_lab (7A.4):
- the stored mysql.db Db value is the exact REVOKE and GRANT target;
- MariaDB deletes a mysql.db row once every privilege on it is N;
- GRANT USAGE ... WITH GRANT OPTION restores only Grant_priv, and revoking a subset leaves the rest;
- KILL SOFT CONNECTION ends a session;
- a session whose current database (PROCESSLIST.DB) is a held one keeps that database's write privileges cached
  until it ends or changes database; a qualified statement or a fresh USE is checked against the grants again;
- information_schema.USER_PRIVILEGES lists every account with a global privilege beyond USAGE.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase

FILES = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files"
INSTALLATION = "12345678-1234-1234-1234-123456789abc"
HASH = "*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"


def _load():
    spec = importlib.util.spec_from_file_location("database_hold_node", FILES / "praho_database_hold.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # Dataclasses resolve their annotations through the module registry.
    spec.loader.exec_module(module)
    return module


hold = _load()
ALL = [*hold.REVOKED, *hold.KEPT]


def privileges(*names: str) -> dict[str, str]:
    """A mysql.db row image: Y for the named columns, N for every other known column."""
    return {column: "Y" if column in names else "N" for column in ALL}


def everything() -> dict[str, str]:
    return dict.fromkeys(ALL, "Y")


def _like(pattern: str, value: str) -> bool:
    expression, escaped = [], False
    for character in pattern:
        if escaped:
            expression.append(re.escape(character))
            escaped = False
        elif character == "\\":
            escaped = True
        else:
            expression.append(".*" if character == "%" else "." if character == "_" else re.escape(character))
    return re.fullmatch("".join(expression), value) is not None


class FakeDatabase:
    """In-memory MariaDB grant tables with the behaviours listed in the module docstring."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str, str], dict[str, str]] = {}
        self.hosts_of: dict[str, set[str]] = {}
        self.extra_grants: dict[tuple[str, str], list[str]] = {}
        self.object_rows = 0
        self.role_rows = 0
        self.proxy_rows = 0
        self.definers: dict[str, set[str]] = {}
        self.column_names = list(ALL)
        # id -> (user, current database) or (user, current database, command); a bare pair is an idle session.
        self.connections: dict[int, tuple] = {}
        self.global_accounts: set[tuple[str, str]] = {("root", "localhost"), ("mysql", "localhost")}
        self.sticky: set[int] = set()
        self.statements: list[str] = []
        self.fail_after: int | None = None
        self.crash_after: int | None = None
        self.ignored: set[str] = set()  # Privileges a GRANT silently fails to apply.
        self.after_revoke: list = []  # Callbacks run once each, after a REVOKE took effect.
        self.after_sessions: list = []  # Callbacks run once each, after a process list was read.
        self.sessions_fail = False
        for user, host in self.global_accounts:
            self.principal(user, host)

    # -- setup ------------------------------------------------------------------------------------------------
    def principal(self, user: str, host: str = "localhost") -> None:
        self.hosts_of.setdefault(user, set()).add(host)

    def grant_row(self, user: str, db: str, image: dict[str, str], host: str = "localhost") -> None:
        self.principal(user, host)
        self.rows[(user, host, db)] = dict(image)

    # -- the seam ---------------------------------------------------------------------------------------------
    def columns(self) -> list[str]:
        return list(self.column_names)

    def principals(self, databases: list[str]) -> set[tuple[str, str]]:
        return {(u, h) for (u, h, db) in self.rows if any(_like(db, name) for name in databases)}

    def hosts(self, user: str) -> set[str]:
        return set(self.hosts_of.get(user, ()))

    def global_privileges(self) -> set[tuple[str, str]]:
        found = set(self.global_accounts)
        for principal, lines in self.extra_grants.items():
            if any(re.fullmatch(r"GRANT (?!USAGE ).+ ON \*\.\* TO .*", line) for line in lines):
                found.add(principal)
        return found

    def grants(self, user: str, host: str) -> list[str]:
        lines = [f"GRANT USAGE ON *.* TO `{user}`@`{host}` IDENTIFIED BY PASSWORD '{HASH}'"]
        for (u, h, db), image in sorted(self.rows.items()):
            if (u, h) != (user, host):
                continue
            granted = [hold.SQL_NAMES[c] for c in ALL if image.get(c) == "Y" and c != "Grant_priv"]
            option = " WITH GRANT OPTION" if image.get("Grant_priv") == "Y" else ""
            lines.append(f"GRANT {', '.join(granted) or 'USAGE'} ON `{db}`.* TO `{user}`@`{host}`{option}")
        return lines + self.extra_grants.get((user, host), [])

    def principal_rows(self, user: str, host: str) -> list[tuple[str, dict[str, str]]]:
        return [(db, dict(image)) for (u, h, db), image in sorted(self.rows.items()) if (u, h) == (user, host)]

    def object_privileges(self, principals: list[tuple[str, str]]) -> int:
        return self.object_rows

    def roles_and_proxies(self, principals: list[tuple[str, str]]) -> tuple[int, int]:
        return self.role_rows, self.proxy_rows

    def definers_of(self, databases: list[str]) -> set[str]:
        return set().union(*(self.definers.get(name, set()) for name in databases)) if databases else set()

    def _step(self, statement: str) -> None:
        if self.fail_after is not None:
            if self.fail_after == 0:
                raise RuntimeError("the node died mid-statement")
            self.fail_after -= 1
        self.statements.append(statement)

    def _applied(self) -> None:
        """The statement took effect, then the node died before the helper could record it."""
        if self.crash_after is not None:
            if self.crash_after == 0:
                raise RuntimeError("the node died after the statement")
            self.crash_after -= 1

    def revoke(self, user: str, host: str, db: str, columns: list[str]) -> None:
        self._step(f"REVOKE {columns} {user}@{host} {db}")
        image = self.rows[(user, host, db)]
        for column in columns:
            image[column] = "N"
        if all(value == "N" for value in image.values()):
            del self.rows[(user, host, db)]  # MariaDB deletes a row once every privilege is gone.
        while self.after_revoke:
            self.after_revoke.pop(0)()
        self._applied()

    def grant(self, user: str, host: str, db: str, columns: list[str]) -> None:
        self._step(f"GRANT {columns} {user}@{host} {db}")
        image = self.rows.setdefault((user, host, db), privileges())
        for column in columns:
            if column not in self.ignored:
                image[column] = "Y"
        self._applied()

    def sessions_on(self, databases: list[str], users: list[str]) -> dict[int, str]:
        if self.sessions_fail:
            raise RuntimeError("the node died before the drain")
        found = {}
        for number, (user, db, *command) in self.connections.items():
            if db in databases or (user in users and (command or ["Sleep"])[0] != "Sleep"):
                found[number] = user
        while self.after_sessions:
            self.after_sessions.pop(0)()
        return found

    def kill_soft(self, number: int) -> None:
        self.statements.append(f"KILL SOFT CONNECTION {number}")
        if number not in self.sticky:
            self.connections.pop(number, None)


class HoldFixture(SimpleTestCase):
    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.paths = hold.Paths(
            run=self.root / "run",
            migration=self.root / "migration",
            component_fences=self.root / "component-fences",
            component_database_fences=self.root / "component-database-fences",
            state=self.root / "database-hold",
            domains=self.root / "domains",
            installation=self.root / "installation",
        )
        self.paths.domains.mkdir()
        self.paths.installation.write_text(INSTALLATION + "\n")
        self.write_domain("42", {"id": "42", "dom": "shop.test", "db_mysql": "shop_db shop_logs"})
        self.database = FakeDatabase()
        self.database.grant_row("shop", "shop\\_db", everything())
        self.database.grant_row("shop", "shop\\_logs", privileges("Select_priv", "Insert_priv"))
        self.database.connections = {}
        self.node = hold.DatabaseHold(self.paths, self.database, drain_seconds=0, sleep=lambda _s: None)
        self.identity = {"domain_id": "42", "domain": "shop.test", "installation": INSTALLATION}
        self.token = str(uuid4())

    def write_domain(self, identifier: str, fields: dict[str, str]) -> None:
        path = self.paths.domains / identifier
        path.write_text("".join(f"{key}={value}\n" for key, value in fields.items()))
        os.chmod(path, 0o600)

    def act(self, action: str, *, token: str | None = None, generation: int | None = 1, **identity: str) -> dict:
        request: dict[str, Any] = {"action": action, "identity": {**self.identity, **identity}}
        if action in {"probe", "hold", "fence"}:
            request["token"] = token or self.token
        if action != "fence":
            request["generation"] = generation
        return self.node.perform(request)

    def image(self, db: str, user: str = "shop") -> dict[str, str] | None:
        found = self.database.rows.get((user, "localhost", db))
        return dict(found) if found is not None else None

    def journal(self) -> dict:
        return json.loads((self.paths.state / INSTALLATION / "42" / "journal.json").read_text())


class HoldAndReleaseTests(HoldFixture):
    def test_a_hold_revokes_exactly_the_write_set_and_keeps_the_rest(self) -> None:
        receipt = self.act("hold")
        self.assertEqual(receipt["outcome"], "ok")
        self.assertEqual(receipt["phase"], "held")
        self.assertEqual(receipt["sessions_remaining"], [])
        self.assertEqual(self.image("shop\\_db"), {c: ("N" if c in hold.REVOKED else "Y") for c in ALL})
        # The second database had only SELECT and INSERT: INSERT goes, SELECT stays.
        self.assertEqual(self.image("shop\\_logs"), privileges("Select_priv"))
        self.assertEqual(self.journal()["phase"], "held")
        self.assertIsInstance(receipt["held_digest"], str)

    def test_create_tmp_table_is_revoked_and_trigger_is_kept(self) -> None:
        self.assertIn("Create_tmp_table_priv", hold.REVOKED)
        self.assertIn("Trigger_priv", hold.KEPT)
        self.assertEqual(set(hold.REVOKED) & set(hold.KEPT), set())

    def test_release_restores_the_exact_original_bits_including_a_row_mariadb_deleted(self) -> None:
        self.database.grant_row("shop", "shop\\_db", privileges("Insert_priv", "Grant_priv"))
        before = {db: self.image(db) for db in ("shop\\_db", "shop\\_logs")}
        self.act("hold")
        self.assertIsNone(self.image("shop\\_db"))  # Only write privileges: MariaDB removed the row.
        receipt = self.act("release", generation=1)
        self.assertEqual(receipt["phase"], "released")
        self.assertEqual({db: self.image(db) for db in ("shop\\_db", "shop\\_logs")}, before)
        self.assertEqual(self.journal()["phase"], "released")

    def test_release_puts_back_the_escaped_stored_value_not_a_wildcard(self) -> None:
        self.act("hold")
        self.act("release", generation=1)
        self.assertNotIn(("shop", "localhost", "shop_db"), self.database.rows)
        self.assertIn(("shop", "localhost", "shop\\_db"), self.database.rows)

    def test_release_is_idempotent_and_needs_no_token(self) -> None:
        self.assertEqual(self.act("release", generation=1)["phase"], "released")  # Nothing held yet.
        self.act("hold")
        self.act("fence")
        self.assertEqual(self.act("release", generation=1)["phase"], "released")
        self.assertEqual(self.act("release", generation=1)["phase"], "released")

    def test_a_re_hold_after_drift_keeps_the_original_before_image(self) -> None:
        original = {db: self.image(db) for db in ("shop\\_db", "shop\\_logs")}
        self.act("hold", generation=1)
        # Virtualmin re-grants ALL on a restore; the next sweep re-holds with a new generation.
        self.database.grant_row("shop", "shop\\_logs", everything())
        self.assertEqual(self.act("hold", token=str(uuid4()), generation=2)["phase"], "held")
        self.assertEqual(self.act("release", generation=2)["phase"], "released")
        self.assertEqual({db: self.image(db) for db in ("shop\\_db", "shop\\_logs")}, original)

    def test_a_new_principal_found_on_re_hold_records_its_own_current_state(self) -> None:
        self.act("hold", generation=1)
        self.database.grant_row("helper", "shop\\_db", privileges("Select_priv", "Insert_priv"))
        self.act("hold", token=str(uuid4()), generation=2)
        self.assertEqual(self.image("shop\\_db", "helper"), privileges("Select_priv"))
        self.act("release", generation=2)
        self.assertEqual(self.image("shop\\_db", "helper"), privileges("Select_priv", "Insert_priv"))


class InterruptionTests(HoldFixture):
    def test_a_hold_interrupted_at_every_statement_is_released_exactly(self) -> None:
        original = {db: self.image(db) for db in ("shop\\_db", "shop\\_logs")}
        for fail_after in range(2):
            with self.subTest(fail_after=fail_after):
                self.setUp()
                original = {db: self.image(db) for db in ("shop\\_db", "shop\\_logs")}
                self.database.fail_after = fail_after
                with self.assertRaises(RuntimeError):
                    self.act("hold")
                self.database.fail_after = None
                self.assertEqual(self.journal()["phase"], "holding")
                self.assertEqual(self.act("release", generation=1)["phase"], "released")
                self.assertEqual({db: self.image(db) for db in ("shop\\_db", "shop\\_logs")}, original)

    def test_a_hold_that_died_just_after_a_revoke_took_effect_is_released_exactly(self) -> None:
        # The REVOKE applied, but the node died before the helper journalled the row as held.
        for crash_after in range(2):
            with self.subTest(crash_after=crash_after):
                self.setUp()
                original = {db: self.image(db) for db in ("shop\\_db", "shop\\_logs")}
                self.database.crash_after = crash_after
                with self.assertRaises(RuntimeError):
                    self.act("hold")
                self.database.crash_after = None
                self.assertEqual(self.act("release", generation=1)["phase"], "released")
                self.assertEqual({db: self.image(db) for db in ("shop\\_db", "shop\\_logs")}, original)

    def test_an_interrupted_hold_resumes_with_the_same_token_and_generation(self) -> None:
        self.database.fail_after = 1
        with self.assertRaises(RuntimeError):
            self.act("hold")
        self.database.fail_after = None
        self.assertEqual(self.act("hold")["phase"], "held")
        self.assertEqual(self.image("shop\\_logs"), privileges("Select_priv"))

    def test_a_release_interrupted_part_way_completes_on_retry(self) -> None:
        original = {db: self.image(db) for db in ("shop\\_db", "shop\\_logs")}
        self.act("hold")
        self.database.fail_after = 1
        with self.assertRaises(RuntimeError):
            self.act("release", generation=1)
        self.database.fail_after = None
        self.assertEqual(self.act("release", generation=1)["phase"], "released")
        self.assertEqual({db: self.image(db) for db in ("shop\\_db", "shop\\_logs")}, original)

    def test_a_release_that_does_not_read_back_exactly_is_never_reported_released(self) -> None:
        self.act("hold")
        self.database.ignored = {"Insert_priv"}
        with self.assertRaises(ValueError):
            self.act("release", generation=1)
        self.assertEqual(self.journal()["phase"], "releasing")

    def test_a_row_that_is_neither_original_nor_held_needs_an_operator(self) -> None:
        self.act("hold")
        self.database.grant_row("shop", "shop\\_logs", privileges("Update_priv"))  # Someone else changed it.
        receipt = self.act("release", generation=1)
        self.assertEqual((receipt["outcome"], receipt["code"]), ("refused", "operator_inspection_required"))
        self.assertEqual(self.image("shop\\_logs"), privileges("Update_priv"))


class GenerationAndFenceTests(HoldFixture):
    def test_an_obsolete_generation_is_refused_for_hold_release_and_verify(self) -> None:
        self.act("hold", generation=5)
        for action in ("hold", "release", "verify"):
            with self.subTest(action=action):
                receipt = self.act(action, token=str(uuid4()), generation=4)
                self.assertEqual((receipt["outcome"], receipt["code"]), ("refused", "obsolete_generation"))
        self.assertEqual(self.journal()["phase"], "held")

    def test_the_same_generation_with_another_token_is_a_conflict(self) -> None:
        self.act("hold")
        receipt = self.act("hold", token=str(uuid4()))
        self.assertEqual(receipt["code"], "generation_conflict")

    def test_a_fenced_token_can_never_hold(self) -> None:
        fenced = self.act("fence")
        self.assertEqual((fenced["outcome"], fenced["phase"]), ("ok", "fenced"))
        receipt = self.act("hold")
        self.assertEqual((receipt["outcome"], receipt["code"]), ("refused", "cancelled_token"))
        self.assertEqual(self.image("shop\\_logs"), privileges("Select_priv", "Insert_priv"))
        self.assertTrue((self.paths.state / INSTALLATION / "42" / f"cancelled-{self.token}.json").exists())

    def test_a_release_after_a_newer_hold_never_restores_over_it(self) -> None:
        self.act("hold", generation=3)
        self.assertEqual(self.act("release", generation=2)["code"], "obsolete_generation")
        self.assertEqual(self.image("shop\\_logs"), privileges("Select_priv"))
        self.act("release", generation=3)
        receipt = self.act("hold", token=str(uuid4()), generation=3)
        self.assertEqual(receipt["code"], "obsolete_generation")  # The release took generation 3 too.


class VerifyTests(HoldFixture):
    def test_verify_reports_regranted_privileges_and_new_principals_without_changing_anything(self) -> None:
        self.act("hold")
        self.assertEqual(self.act("verify")["drift"], [])
        self.database.grant_row("shop", "shop\\_logs", everything())
        self.database.grant_row("intruder", "shop\\_db", privileges("Insert_priv"))
        receipt = self.act("verify")
        self.assertEqual(receipt["phase"], "verified")
        self.assertIn("regranted:shop@localhost:shop\\_logs", receipt["drift"])
        self.assertIn("new_principal:intruder@localhost", receipt["drift"])
        self.assertEqual(self.image("shop\\_logs"), everything())

    def test_verify_without_a_hold_says_so(self) -> None:
        self.assertEqual(self.act("verify")["drift"], ["not_held"])
        self.act("hold")
        self.assertEqual(self.act("verify", generation=2)["drift"], ["not_held"])


class SessionTests(HoldFixture):
    """Sessions are matched by their current database: only a session sitting in a held database at revoke time
    keeps that database's write privileges cached (the MariaDB 11.8.3 experiment, a 7A.4 lab case)."""

    def test_held_only_once_every_session_in_a_held_database_at_revoke_time_is_gone(self) -> None:
        self.database.connections = {
            11: ("shop", "shop_db"),
            12: ("shop", "shop_logs"),
            13: ("helper", "shop_db"),  # Another user's session in the held database ends too.
            98: ("shop", "other_db"),  # A qualified statement from elsewhere is checked afresh.
            99: ("someone_else", "other_db"),
        }
        self.database.sticky = {12}
        receipt = self.act("hold")
        self.assertEqual((receipt["phase"], receipt["sessions_remaining"]), ("holding", [12]))
        self.assertNotIn(11, self.database.connections)
        self.assertNotIn(13, self.database.connections)
        self.assertIn(98, self.database.connections)
        self.assertIn(99, self.database.connections)
        self.assertEqual(
            [s for s in self.database.statements if s.startswith("KILL")],
            ["KILL SOFT CONNECTION 11", "KILL SOFT CONNECTION 12", "KILL SOFT CONNECTION 13"],
        )
        self.assertEqual(self.journal()["sessions"], [12])
        self.assertEqual(self.act("verify")["sessions_remaining"], [12])
        self.database.sticky.clear()
        self.database.connections.pop(12)
        self.assertEqual(self.act("verify")["sessions_remaining"], [])
        self.assertEqual(self.act("hold")["phase"], "held")

    def test_a_recorded_session_that_left_the_held_database_no_longer_counts(self) -> None:
        self.database.connections = {12: ("shop", "shop_db")}
        self.database.sticky = {12}
        self.assertEqual(self.act("hold")["sessions_remaining"], [12])
        self.database.connections[12] = ("shop", "other_db")  # USE elsewhere drops the cached write privileges.
        self.assertEqual(self.act("verify")["sessions_remaining"], [])

    def test_the_exact_dba_identities_are_exempt(self) -> None:
        self.database.connections = {1: ("root", "shop_db"), 2: ("mysql", "shop_logs"), 3: ("admin", "shop_db")}
        self.database.principal("admin", "localhost")
        self.assertEqual(self.act("hold")["phase"], "held")
        self.assertEqual(sorted(self.database.connections), [1, 2])
        self.assertEqual([s for s in self.database.statements if s.startswith("KILL")], ["KILL SOFT CONNECTION 3"])

    def test_a_dba_username_with_another_host_is_not_exempt(self) -> None:
        # Sessions show only the username: one of root's hosts outside the list means a session may be that one.
        self.database.principal("root", "%")
        self.database.connections = {1: ("root", "shop_db")}
        self.assertEqual(self.act("hold")["phase"], "held")
        self.assertNotIn(1, self.database.connections)

    def test_a_statement_in_flight_from_no_current_database_is_ended(self) -> None:
        # `INSERT INTO shop_db.t ...` started before the revoke keeps running after it; an in-scope username
        # can only be working on a held database, so its executing sessions are ended wherever they sit.
        self.database.connections = {
            31: ("shop", None, "Query"),
            32: ("shop", None),  # Idle: its next statement is checked against the held grants.
            33: ("someone_else", None, "Query"),
        }
        self.assertEqual(self.act("hold")["phase"], "held")
        self.assertEqual(sorted(self.database.connections), [32, 33])

    def test_a_refused_re_hold_stops_trusting_the_session_record(self) -> None:
        self.assertEqual(self.act("hold")["phase"], "held")
        # Write access appears for a while, a session enters, and the next hold refuses before changing anything.
        self.database.grant_row("helper", "shop\\_db", privileges("Insert_priv"))
        self.database.extra_grants[("helper", "localhost")] = ["GRANT INSERT ON *.* TO `helper`@`localhost`"]
        self.database.connections = {41: ("helper", "shop_db")}
        self.assertEqual(self.act("hold")["code"], "global_privilege")
        del self.database.rows[("helper", "localhost", "shop\\_db")]
        self.database.extra_grants.clear()
        self.assertEqual(self.act("verify")["sessions_remaining"], [41])

    def test_verify_never_ends_a_session(self) -> None:
        self.database.connections = {12: ("shop", "shop_db")}
        self.database.sticky = {12}
        self.act("hold")
        self.database.statements.clear()
        self.database.sticky.clear()
        self.assertEqual(self.act("verify")["sessions_remaining"], [12])
        self.assertEqual([s for s in self.database.statements if s.startswith("KILL")], [])
        self.assertIn(12, self.database.connections)


class RefusalTests(HoldFixture):
    def refused(self, code: str) -> None:
        before = {key: dict(image) for key, image in self.database.rows.items()}
        receipt = self.act("hold")
        self.assertEqual((receipt["outcome"], receipt["code"]), ("refused", code), receipt)
        self.assertEqual(self.database.rows, before)
        self.assertEqual([s for s in self.database.statements if s.startswith(("REVOKE", "GRANT"))], [])
        self.assertNotIn(HASH, json.dumps(receipt))

    def test_a_global_privilege_beyond_usage(self) -> None:
        self.database.extra_grants[("shop", "localhost")] = ["GRANT FILE ON *.* TO `shop`@`localhost`"]
        self.refused("global_privilege")

    def test_any_account_with_a_global_privilege_outside_the_dba_list(self) -> None:
        # Not in scope at all, yet a global write privilege reaches the held databases.
        self.database.global_accounts.add(("backup", "localhost"))
        self.refused("global_privilege")
        self.database.global_accounts.discard(("backup", "localhost"))
        self.database.global_accounts.add(("root", "%"))  # The DBA list is exact user@host, not usernames.
        self.refused("global_privilege")

    def test_role_membership_and_a_default_role(self) -> None:
        self.database.extra_grants[("shop", "localhost")] = ["GRANT `editors` TO `shop`@`localhost`"]
        self.refused("role")
        self.database.extra_grants[("shop", "localhost")] = ["SET DEFAULT ROLE `editors` FOR `shop`@`localhost`"]
        self.refused("default_role")
        self.database.extra_grants.clear()
        self.database.role_rows = 1
        self.refused("role")

    def test_proxy_grants(self) -> None:
        self.database.extra_grants[("shop", "localhost")] = ["GRANT PROXY ON ''@'%' TO `shop`@`localhost`"]
        self.refused("proxy")
        self.database.extra_grants.clear()
        self.database.proxy_rows = 1
        self.refused("proxy")

    def test_table_column_and_routine_privileges(self) -> None:
        self.database.extra_grants[("shop", "localhost")] = ["GRANT INSERT ON `shop_db`.`t` TO `shop`@`localhost`"]
        self.refused("object_privilege")
        self.database.extra_grants.clear()
        self.database.object_rows = 1
        self.refused("object_privilege")

    def test_a_shared_username(self) -> None:
        self.database.principal("shop", "%")
        self.refused("shared_username")

    def test_a_principal_with_rows_on_another_database(self) -> None:
        self.database.grant_row("shop", "other\\_db", privileges("Select_priv"))
        self.refused("outside_scope")

    def test_an_unescaped_wildcard_database_row(self) -> None:
        for stored in ("shop_db", "shop%"):
            with self.subTest(stored=stored):
                self.setUp()
                self.database.grant_row("shop", stored, privileges("Select_priv"))
                self.refused("wildcard_database")

    def test_a_definer_outside_the_scope(self) -> None:
        self.database.definers["shop_db"] = {"shop@localhost", "admin@localhost"}
        self.refused("definer_outside_scope")

    def test_an_unknown_privilege_column(self) -> None:
        self.database.column_names.append("Future_priv")
        self.refused("unknown_privilege_column")

    def test_an_unrecognised_grant_line(self) -> None:
        self.database.extra_grants[("shop", "localhost")] = ["GRANT SOMETHING NEW TO `shop`@`localhost`"]
        self.refused("unsupported_grant")

    def test_a_changed_or_foreign_identity(self) -> None:
        for change in ({"domain": "other.test"}, {"installation": "87654321-4321-4321-4321-cba987654321"}):
            with self.subTest(change=change):
                receipt = self.act("hold", **change)
                self.assertEqual(receipt["code"], "identity_mismatch")

    def test_a_journal_for_another_domain_with_the_same_id(self) -> None:
        self.act("hold")
        self.act("release", generation=1)
        self.write_domain("42", {"id": "42", "dom": "recreated.test", "db_mysql": "shop_db shop_logs"})
        receipt = self.act("hold", token=str(uuid4()), generation=2, domain="recreated.test")
        self.assertEqual(receipt["code"], "journal_mismatch")


class BarrierTests(HoldFixture):
    def marker(self, name: str) -> None:
        self.paths.migration.mkdir(exist_ok=True)
        (self.paths.migration / name).write_text("")

    def test_an_active_barrier_record_refuses_a_hold(self) -> None:
        saved = str(uuid4())
        self.marker(f"migration-42.{saved}.crontab")
        self.assertEqual(self.act("hold")["code"], "barrier_active")
        self.marker(f"migration-42.{saved}.release-started")
        self.marker(f"migration-42.cancelled.{saved}")
        self.assertEqual(self.act("hold")["code"], "barrier_active")  # A release in progress is still active.

    def test_retained_tombstones_never_block(self) -> None:
        released, abandoned = str(uuid4()), str(uuid4())
        self.marker(f"migration-42.{released}.release-completed")
        self.marker(f"migration-42.cancelled.{released}")
        self.marker(f"migration-42.{abandoned}.crontab")
        self.marker(f"migration-42.cancelled.{abandoned}")
        self.marker(f"migration-7.{uuid4()}.crontab")  # Another domain's barrier.
        self.assertEqual(self.act("hold")["phase"], "held")

    def test_a_rollback_then_a_successful_re_hold_on_the_source(self) -> None:
        saved = str(uuid4())
        self.act("hold")
        self.act("fence")
        self.act("release", generation=1)
        self.marker(f"migration-42.{saved}.crontab")
        self.assertEqual(self.act("hold", token=str(uuid4()), generation=2)["code"], "barrier_active")
        self.marker(f"migration-42.{saved}.release-started")
        self.marker(f"migration-42.{saved}.release-completed")
        (self.paths.migration / f"migration-42.{saved}.crontab").unlink()  # The rollback's release completed.
        self.assertEqual(self.act("hold", token=str(uuid4()), generation=2)["phase"], "held")

    def test_an_unreleased_component_fence_refuses_a_hold(self) -> None:
        for original in (self.paths.component_fences, self.paths.component_database_fences):
            with self.subTest(directory=original.name):
                self.setUp()
                directory = self.root / original.name
                directory.mkdir(mode=0o700, exist_ok=True)
                state = directory / "42.json"
                state.write_text(json.dumps({"phase": "held"}))
                state.chmod(0o600)
                self.assertEqual(self.act("hold")["code"], "component_fence_active")
                state.write_text(json.dumps({"phase": "released"}))
                self.assertEqual(self.act("hold")["phase"], "held")

    def test_every_action_takes_the_migration_lock_first(self) -> None:
        import fcntl  # noqa: PLC0415

        self.paths.run.mkdir(mode=0o700, exist_ok=True)
        descriptor = os.open(self.paths.run / "migration-42.lock", os.O_CREAT | os.O_WRONLY, 0o600)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        node = hold.DatabaseHold(self.paths, self.database, drain_seconds=0, sleep=lambda _s: None, lock_seconds=0)
        receipt = node.perform({"action": "verify", "identity": self.identity, "generation": 1})
        self.assertEqual(receipt["code"], "lock_busy")


class ProbeAndReceiptTests(HoldFixture):
    def test_probe_qualifies_without_changing_anything(self) -> None:
        before = dict(self.database.rows)
        receipt = self.act("probe")
        self.assertEqual((receipt["outcome"], receipt["phase"]), ("ok", "probed"))
        self.assertEqual(self.database.rows, before)
        self.assertEqual(self.database.statements, [])

    def test_every_receipt_echoes_the_request_identity(self) -> None:
        for action in ("probe", "hold", "verify", "fence", "release"):
            with self.subTest(action=action):
                receipt = self.act(action)
                self.assertEqual(receipt["action"], action)
                self.assertEqual(receipt["identity"], self.identity)
                self.assertEqual(set(receipt), hold.RECEIPT_KEYS)

    def test_requests_outside_the_closed_shape_are_rejected(self) -> None:
        for request in (
            {"action": "drop", "identity": self.identity, "generation": 1},
            {"action": "hold", "identity": self.identity, "generation": 1},  # No token.
            {"action": "hold", "identity": self.identity, "token": "x", "generation": 1},
            {"action": "release", "identity": self.identity, "generation": 0},
            {"action": "release", "identity": self.identity, "generation": True},
            {"action": "release", "identity": {**self.identity, "domain_id": "4/2"}, "generation": 1},
            {"action": "release", "identity": self.identity, "generation": 1, "extra": 1},
        ):
            with self.subTest(request=request), self.assertRaises(ValueError):
                self.node.perform(request)


class ReviewFindingTests(HoldFixture):
    """Each case a review found against the first version of the helper."""

    def test_a_hold_after_an_interrupted_release_keeps_the_original_images(self) -> None:
        original = {db: self.image(db) for db in ("shop\\_db", "shop\\_logs")}
        self.act("hold", generation=1)
        self.database.fail_after = 1
        with self.assertRaises(RuntimeError):
            self.act("release", generation=1)
        self.database.fail_after = None
        self.assertEqual(self.journal()["phase"], "releasing")
        self.assertEqual(self.act("hold", token=str(uuid4()), generation=2)["phase"], "held")
        self.assertEqual(self.act("release", generation=2)["phase"], "released")
        self.assertEqual({db: self.image(db) for db in ("shop\\_db", "shop\\_logs")}, original)

    def test_a_recorded_session_id_now_used_by_another_account_is_never_killed(self) -> None:
        self.database.connections = {12: ("shop", "shop_db")}
        self.database.sticky = {12}
        self.assertEqual(self.act("hold")["sessions_remaining"], [12])
        # MariaDB restarted: id 12 now belongs to another customer, in that customer's own database.
        self.database.connections = {12: ("someone_else", "other_db")}
        self.database.statements.clear()
        self.assertEqual(self.act("hold")["phase"], "held")
        self.assertNotIn("KILL SOFT CONNECTION 12", self.database.statements)
        self.assertIn(12, self.database.connections)

    def test_verify_requalifies_every_principal(self) -> None:
        self.act("hold")
        self.database.extra_grants[("shop", "localhost")] = ["GRANT INSERT ON *.* TO `shop`@`localhost`"]
        self.assertIn("unqualified:global_privilege", self.act("verify")["drift"])

    def test_verify_checks_every_live_row_not_only_the_journalled_ones(self) -> None:
        self.database.grant_row("helper", "shop\\_db", privileges("Select_priv"))
        self.act("hold")
        self.database.grant_row("helper", "shop\\_logs", privileges("Insert_priv"))
        self.assertIn("regranted:helper@localhost:shop\\_logs", self.act("verify")["drift"])

    def test_a_release_that_died_between_its_revoke_and_its_grant_completes_on_retry(self) -> None:
        # Statement 1 restores shop_db; statement 2 is shop_logs's REVOKE of the kept extras, before its GRANT.
        for crash_after in range(3):
            with self.subTest(crash_after=crash_after):
                self.setUp()
                original = {db: self.image(db) for db in ("shop\\_db", "shop\\_logs")}
                self.act("hold", generation=1)
                self.database.grant_row("shop", "shop\\_logs", everything())
                self.act("hold", token=str(uuid4()), generation=2)  # Now the release must both revoke and grant.
                self.database.crash_after = crash_after
                with self.assertRaises(RuntimeError):
                    self.act("release", generation=2)
                self.database.crash_after = None
                self.assertEqual(self.act("release", generation=2)["phase"], "released")
                self.assertEqual({db: self.image(db) for db in ("shop\\_db", "shop\\_logs")}, original)

    def test_a_host_whose_only_row_the_hold_deleted_stays_in_scope(self) -> None:
        self.database.grant_row("shop", "shop\\_db", privileges("Insert_priv"), host="%")
        original = self.image("shop\\_db", "shop")
        self.assertEqual(self.act("hold")["phase"], "held")
        self.assertNotIn(("shop", "%", "shop\\_db"), self.database.rows)
        self.assertEqual(self.act("hold")["phase"], "held")  # A retry does not refuse itself either.
        self.act("release", generation=1)
        self.assertEqual(self.database.rows[("shop", "%", "shop\\_db")], privileges("Insert_priv"))
        self.assertEqual(self.image("shop\\_db", "shop"), original)


class NativeStatementTests(SimpleTestCase):
    """Each revoke and grant is one statement, so a crash never leaves a half-applied row."""

    def native(self):
        database = hold.NativeDatabase()
        database.statements = []
        database.execute = lambda query: database.statements.append(query) or []
        return database

    def test_a_revoke_with_grant_option_is_one_statement(self) -> None:
        database = self.native()
        database.revoke("shop", "localhost", "shop\\_db", ["Insert_priv", "Grant_priv"])
        self.assertEqual(database.statements, ["REVOKE INSERT, GRANT OPTION ON `shop\\_db`.* FROM 'shop'@'localhost'"])

    def test_a_grant_with_grant_option_is_one_statement(self) -> None:
        database = self.native()
        database.grant("shop", "localhost", "shop\\_db", ["Insert_priv", "Grant_priv"])
        database.grant("shop", "localhost", "shop\\_db", ["Grant_priv"])
        self.assertEqual(
            database.statements,
            [
                "GRANT INSERT ON `shop\\_db`.* TO 'shop'@'localhost' WITH GRANT OPTION",
                "GRANT USAGE ON `shop\\_db`.* TO 'shop'@'localhost' WITH GRANT OPTION",
            ],
        )

    def test_sessions_are_read_by_exact_current_database_without_the_helpers_own(self) -> None:
        database = self.native()
        database.execute = lambda query: database.statements.append(query) or [("11", "shop"), ("x", "bad")]
        self.assertEqual(database.sessions_on(["shop_db", "bad'name", "shop_logs"], ["shop", "bad'user"]), {11: "shop"})
        (query,) = database.statements
        self.assertIn("ID <> CONNECTION_ID()", query)
        self.assertTrue(
            query.endswith("AND (BINARY DB IN ('shop_db','shop_logs') OR (USER IN ('shop') AND COMMAND <> 'Sleep'))"),
            query,
        )

    def test_every_grantee_with_a_global_privilege_is_an_identity(self) -> None:
        database = self.native()
        database.execute = lambda query: [("'root'@'localhost'",), ("'it''s'@'%'",)]
        self.assertEqual(database.global_privileges(), {("root", "localhost"), ("'it''s'@'%'", "")})


class RoundTwoFindingTests(HoldFixture):
    def test_a_crash_before_the_drain_leaves_every_in_scope_session_outstanding(self) -> None:
        self.database.connections = {11: ("shop", "shop_db")}
        self.database.sessions_fail = True
        with self.assertRaises(RuntimeError):
            self.act("hold")
        self.database.sessions_fail = False
        self.assertIs(self.journal()["sessions_recorded"], False)
        self.assertEqual(self.act("verify")["sessions_remaining"], [11])
        self.assertEqual(self.act("hold")["phase"], "held")
        self.assertNotIn(11, self.database.connections)
        self.assertIs(self.journal()["sessions_recorded"], True)

    def test_a_principal_added_during_the_hold_makes_it_uncertain_not_held(self) -> None:
        self.database.after_revoke.append(
            lambda: self.database.grant_row("helper", "shop\\_db", privileges("Select_priv", "Insert_priv"))
        )
        with self.assertRaises(ValueError):
            self.act("hold")
        self.assertEqual(self.journal()["phase"], "holding")
        # The new principal's row is on a held database, so verify reports its write privilege.
        self.assertIn("regranted:helper@localhost:shop\\_db", self.act("verify")["drift"])

    def test_a_refusal_found_after_a_change_is_uncertain_not_refused(self) -> None:
        self.database.after_revoke.append(lambda: self.database.definers.update({"shop_db": {"admin@localhost"}}))
        with self.assertRaises(ValueError):
            self.act("hold")
        self.assertEqual(self.journal()["phase"], "holding")

    def test_verify_reports_a_definer_outside_the_scope(self) -> None:
        self.act("hold")
        self.database.definers["shop_db"] = {"admin@localhost"}
        self.assertIn("unqualified:definer_outside_scope", self.act("verify")["drift"])


class DrainRecordTests(HoldFixture):
    def test_after_a_timed_out_drain_only_the_recorded_sessions_are_outstanding(self) -> None:
        self.database.connections = {11: ("shop", "shop_db")}
        self.database.sticky = {11}
        self.assertEqual(self.act("hold")["sessions_remaining"], [11])
        # 11 ends; 12 connects after the revoke, so its USE was checked against the held grants.
        self.database.connections = {12: ("shop", "shop_db")}
        self.assertEqual(self.act("verify")["sessions_remaining"], [])

    def test_a_session_record_is_trusted_only_once_the_whole_hold_succeeded(self) -> None:
        # The final scope read itself fails (an SQL error): the record written before it is never trusted.
        calls = {"count": 0}
        real = self.database.definers_of

        def failing(databases):
            calls["count"] += 1
            if calls["count"] == 2:  # The first is the qualification; the second, the final check.
                raise ValueError("the SQL client failed")
            return real(databases)

        self.database.definers_of = failing
        with self.assertRaises(ValueError):
            self.act("hold")
        self.assertIs(self.journal()["sessions_recorded"], False)

    def test_an_untrusted_record_counts_every_session_in_a_held_database(self) -> None:
        """Each way a hold can fail after its record (the cases the principal-keyed watch list once covered):
        a session that connected with a write grant added after the record is outstanding for verify, by its
        database alone, even once that grant is gone again."""

        def regranted_and_connected() -> None:
            self.database.rows[("shop", "localhost", "shop\\_logs")]["Insert_priv"] = "Y"
            self.database.connections[21] = ("shop", "shop_logs")

        def granted_new_principal_and_connected() -> None:
            self.database.grant_row("helper", "shop\\_db", privileges("Insert_priv"))
            self.database.connections[21] = ("helper", "shop_db")

        def granted_globally_and_connected() -> None:
            self.database.grant_row("helper", "shop\\_db", privileges("Insert_priv"))
            self.database.extra_grants[("helper", "localhost")] = ["GRANT INSERT ON *.* TO `helper`@`localhost`"]
            self.database.connections[21] = ("helper", "shop_db")

        def undo() -> None:
            self.database.rows.pop(("helper", "localhost", "shop\\_db"), None)
            self.database.extra_grants.clear()
            if ("shop", "localhost", "shop\\_logs") in self.database.rows:
                self.database.rows[("shop", "localhost", "shop\\_logs")]["Insert_priv"] = "N"

        for name, change in (
            ("regranted", regranted_and_connected),
            ("new principal", granted_new_principal_and_connected),
            ("global grant", granted_globally_and_connected),
        ):
            for sql_failure in (False, True):
                with self.subTest(change=name, sql_failure=sql_failure):
                    self.setUp()
                    self.database.after_sessions.append(change)
                    if sql_failure:
                        calls = {"count": 0}
                        real = self.database.definers_of

                        def failing(databases, calls=calls, real=real):
                            calls["count"] += 1
                            if calls["count"] == 2:
                                raise ValueError("the SQL client failed")
                            return real(databases)

                        self.database.definers_of = failing
                    with self.assertRaises(ValueError):
                        self.act("hold")
                    self.assertIs(self.journal()["sessions_recorded"], False)
                    if sql_failure:
                        self.database.definers_of = real
                    undo()
                    self.assertIn(21, self.act("verify")["sessions_remaining"])
                    self.assertEqual(self.act("hold")["phase"], "held")
                    self.assertNotIn(21, self.database.connections)

    def test_a_global_grant_left_behind_is_refused_after_its_schema_row_is_gone(self) -> None:
        def granted_globally() -> None:
            self.database.grant_row("helper", "shop\\_db", privileges("Insert_priv"))
            self.database.extra_grants[("helper", "localhost")] = ["GRANT INSERT ON *.* TO `helper`@`localhost`"]

        self.database.after_sessions.append(granted_globally)
        with self.assertRaises(ValueError):
            self.act("hold")
        del self.database.rows[("helper", "localhost", "shop\\_db")]  # The global grant stays.
        self.assertIn("unqualified:global_privilege", self.act("verify")["drift"])
        self.assertEqual(self.act("hold")["code"], "global_privilege")

    def test_a_retry_never_ends_sessions_of_a_username_now_used_elsewhere(self) -> None:
        self.act("hold")
        # The held principal is dropped, and the same username now serves another account's database.
        for key in [key for key in self.database.rows if key[0] == "shop"]:
            del self.database.rows[key]
        self.database.hosts_of["shop"] = {"remote"}
        self.database.grant_row("shop", "other\\_db", privileges("Select_priv"), host="remote")
        self.database.connections = {81: ("shop", "other_db")}
        receipt = self.act("hold")
        self.assertEqual((receipt["outcome"], receipt["phase"]), ("ok", "held"), receipt)
        self.assertIn(81, self.database.connections)
