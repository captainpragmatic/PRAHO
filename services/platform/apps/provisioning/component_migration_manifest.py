"""Bounded, secret-free native component evidence for an exact operator preview."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from uuid import UUID

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

MAX_MANIFEST_BYTES = 256 * 1024
MAX_COMPONENTS = 100
MAX_COMPONENT_BYTES = 2**63 - 1
MAX_PATH_LENGTH = 1024
MAX_PREPARATION_LENGTH = 2000
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,79}\Z")
_DOMAIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
_DATABASE = re.compile(r"[A-Za-z0-9_]{1,64}\Z")
_RESERVED = frozenset({"mail", "maildir", "homes", "domains", "logs", "etc", "tmp", "cgi-bin"})


def _refuse() -> None:
    raise ValidationError(_("Component inspection is incomplete or includes unsafe or unrecognized scope."))


def _object(value: object, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _refuse()
    assert isinstance(value, dict)
    return value


def _items(value: object, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list) or len(value) > MAX_COMPONENTS or (nonempty and not value):
        _refuse()
    assert isinstance(value, list)
    return value


def _matches(value: object, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        _refuse()


def _size(value: object) -> None:
    if type(value) is not int or not 0 <= value <= MAX_COMPONENT_BYTES:
        _refuse()


def _validate_source(value: object) -> None:
    source = _object(
        value, {"server_uuid", "connection_identity", "domain_id", "domain", "owner", "home", "webmin", "virtualmin"}
    )
    try:
        if str(UUID(source["server_uuid"])) != source["server_uuid"]:
            _refuse()
    except (ValueError, TypeError, AttributeError) as error:
        raise ValidationError(_("Component source identity is invalid.")) from error
    _matches(source["connection_identity"], _HASH)
    _matches(source["domain_id"], re.compile(r"[0-9]{1,30}\Z"))
    _matches(source["domain"], _DOMAIN)
    _matches(source["owner"], _NAME)
    if source["home"] != "/home/" + source["owner"]:
        _refuse()
    for name in ("webmin", "virtualmin"):
        _matches(source[name], re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?\Z"))


def _validate_paths(value: object) -> None:
    selected: list[str] = []
    for item in _items(value, nonempty=True):
        path = _object(item, {"relative", "purpose", "device", "inode", "bytes", "tree_digest"})
        relative = path["relative"]
        if not isinstance(relative, str) or not 1 <= len(relative) <= MAX_PATH_LENGTH:
            _refuse()
        parts = PurePosixPath(relative).parts
        if (
            not parts
            or PurePosixPath(relative).is_absolute()
            or any(part in {".", ".."} or part.startswith(".") for part in parts)
            or PurePosixPath(relative).as_posix() != relative
            or parts[0].lower() in _RESERVED
            or path["purpose"] not in {"application", "configuration", "uploads"}
        ):
            _refuse()
        for key in ("device", "inode", "bytes"):
            _size(path[key])
        _matches(path["tree_digest"], _HASH)
        if any(relative == old or relative.startswith(old + "/") or old.startswith(relative + "/") for old in selected):
            _refuse()
        selected.append(relative)


def _validate_databases(value: object) -> None:
    names: set[str] = set()
    for item in _items(value):
        database = _object(item, {"name", "bytes", "charset", "collation", "principals", "isolated"})
        _matches(database["name"], _DATABASE)
        if database["name"] in names:
            _refuse()
        names.add(database["name"])
        _size(database["bytes"])
        for key in ("charset", "collation"):
            _matches(database[key], _DATABASE)
        if type(database["isolated"]) is not bool:
            _refuse()
        for account in _items(database["principals"]):
            principal = _object(account, {"user", "host", "locked", "auth_digest", "grants_digest"})
            _matches(principal["user"], _NAME)
            _matches(principal["host"], re.compile(r"[A-Za-z0-9.%_:-]{1,255}\Z"))
            for key in ("auth_digest", "grants_digest"):
                _matches(principal[key], _HASH)
            if type(principal["locked"]) is not bool:
                _refuse()


def _validate_writers(value: object) -> None:
    for item in _items(value):
        writer = _object(item, {"kind", "identity", "digest"})
        if writer["kind"] not in {"php_fpm_pool", "cron_entry", "service", "unknown"}:
            _refuse()
        _matches(writer["identity"], _NAME)
        _matches(writer["digest"], _HASH)


@dataclass(frozen=True)
class ComponentManifest:
    _canonical: str

    @classmethod
    def parse(cls, value: object) -> ComponentManifest:
        try:
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (ValueError, TypeError, RecursionError) as error:
            raise ValidationError(_("Component inspection must be bounded JSON evidence.")) from error
        if len(encoded.encode()) > MAX_MANIFEST_BYTES:
            _refuse()
        data = _object(
            value, {"schema", "source", "paths", "databases", "writers", "routing", "retained", "preparation"}
        )
        if type(data["schema"]) is not int or data["schema"] != 1:
            _refuse()
        _validate_source(data["source"])
        _validate_paths(data["paths"])
        _validate_databases(data["databases"])
        _validate_writers(data["writers"])
        routing = _object(data["routing"], {"website_names", "digest"})
        for name in _items(routing["website_names"], nonempty=True):
            _matches(name, _DOMAIN)
        if len(set(routing["website_names"])) != len(routing["website_names"]):
            _refuse()
        _matches(routing["digest"], _HASH)
        retained = _object(data["retained"], {"services", "database_names", "digest"})
        for service in _items(retained["services"], nonempty=True):
            if service not in {"mail", "dns", "mysql", "authentication"}:
                _refuse()
        for name in _items(retained["database_names"]):
            _matches(name, _DATABASE)
        _matches(retained["digest"], _HASH)
        for reason in _items(data["preparation"]):
            if not isinstance(reason, str) or not 1 <= len(reason) <= MAX_PREPARATION_LENGTH:
                _refuse()
        return cls(encoded)

    def as_json(self) -> dict[str, Any]:
        return json.loads(self._canonical)  # type: ignore[no-any-return]  # Validated JSON object, fresh copy per caller.

    @property
    def digest(self) -> str:
        return hashlib.sha256(self._canonical.encode()).hexdigest()

    @property
    def authority_digest(self) -> str:
        """Consent covers these component roots and identities, including data present at fencing.

        Live website bytes and child files may change before quiescence. Fresh inspection must
        still qualify their links/writers and reserve their current transfer size. Replacing a
        root, principal, grant, job, route or retained dependency requires a new operator preview.
        """
        scope = self.as_json()
        scope["paths"] = [
            {key: value for key, value in path.items() if key not in {"bytes", "tree_digest"}}
            for path in scope["paths"]
        ]
        scope["databases"] = [
            {key: value for key, value in database.items() if key != "bytes"} for database in scope["databases"]
        ]
        encoded = json.dumps(scope, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(encoded.encode()).hexdigest()

    @property
    def transfer_bytes(self) -> int:
        data = self.as_json()
        return sum(item["bytes"] for item in (*data["paths"], *data["databases"]))

    @property
    def selected_paths(self) -> tuple[str, ...]:
        return tuple(item["relative"] for item in self.as_json()["paths"])

    @property
    def selected_databases(self) -> tuple[str, ...]:
        return tuple(item["name"] for item in self.as_json()["databases"])

    def assert_ready(self) -> None:
        data = self.as_json()
        if (data["source"]["webmin"], data["source"]["virtualmin"]) != ("2.670", "8.3.0"):
            raise ValidationError(
                _("Qualify the installed native backup and restore callbacks before migrating components.")
            )
        if data["preparation"] or any(writer["kind"] == "unknown" for writer in data["writers"]):
            raise ValidationError(_("Complete the listed source preparation steps and inspect again before migrating."))
        retained_databases = set(data["retained"]["database_names"])
        if any(
            not db["isolated"] or not db["principals"] or db["name"] in retained_databases for db in data["databases"]
        ):
            raise ValidationError(
                _("Selected databases need isolated, proven principals independent of retained services.")
            )
        domain = data["source"]["domain"]
        if any(name not in {domain, "www." + domain} for name in data["routing"]["website_names"]):
            raise ValidationError(
                _("Prepare separate mail, webmail and administration names before moving website routing.")
            )
