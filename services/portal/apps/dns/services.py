"""Signed Platform DNS calls and bounded public receipts; no DNS transport runs in Portal."""

import base64
import binascii
import re
from typing import Any, cast
from uuid import UUID

from apps.api_client.services import PlatformAPIClient, PlatformAPIError

MAX_ZONE_FILE_BYTES = 2 * 1024 * 1024
MAX_PAGE_SIZE = 100
MIN_NAMESERVERS = 2
MAX_NAMESERVERS = 16
RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA")


def _invalid() -> PlatformAPIError:
    return PlatformAPIError("DNS response is unavailable", status_code=503)


def _text(value: object, maximum: int = 4096) -> str:
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value:
        raise _invalid()
    return value


def _integer(value: object, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise _invalid()
    return value


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise _invalid()
    return value


def _uuid(value: object) -> str:
    text = _text(value, 36)
    try:
        return str(UUID(text))
    except ValueError as error:
        raise _invalid() from error


def _digest(value: object, *, optional: bool = False) -> str:
    text = _text(value, 64)
    if not (optional and not text) and re.fullmatch(r"[0-9a-f]{64}", text) is None:
        raise _invalid()
    return text


def _rows(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_PAGE_SIZE:
        raise _invalid()
    return [_record(item) for item in value]


def _record(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _invalid()
    # Inventory includes provider-owned SOA/NS and rejected import families. Show the complete
    # preview while the editor restricts writes to supported families.
    result: dict[str, Any] = {
        key: _text(value.get(key), maximum)
        for key, maximum in (("id", 36), ("name", 253), ("record_type", 16), ("rdata", 4096), ("managed_by", 20))
    }
    result.update(
        ttl=_integer(value.get("ttl")),
        managed=_boolean(value.get("managed")),
        infrastructure=_boolean(value.get("infrastructure", False)),
    )
    if result["id"]:
        result["id"] = _uuid(result["id"])
    if result["managed"] != (result["managed_by"] == "praho"):
        raise _invalid()
    line = value.get("line")
    if line is not None:
        result["line"] = _integer(line, minimum=1)
    return result


def _pagination(value: dict[str, Any]) -> dict[str, int]:
    result = {key: _integer(value.get(key), minimum=1) for key in ("page", "pages")}
    if result["page"] > result["pages"]:
        raise _invalid()
    return result


def _normalization(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _invalid()
    result: dict[str, Any] = {"kind": _text(value.get("kind"), 80)}
    if "before" in value:
        for key in ("before", "after"):
            result[key] = _rows(value.get(key))
            result[key + "_total"] = _integer(value.get(key + "_total"))
    else:
        result.update(_record(value))
    return result


def _import_error(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _invalid()
    code = _text(value.get("code"), 80)
    if re.fullmatch(r"[a-z][a-z0-9_]{0,79}", code) is None:
        raise _invalid()
    return {"code": code, "line": _integer(value.get("line"))}


def _zone(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1:
        raise _invalid()
    result: dict[str, Any] = {
        "version": 1,
        "id": _uuid(value.get("id")),
        "name": _text(value.get("name"), 253),
        "status": _text(value.get("status"), 24),
        "revision": _integer(value.get("revision"), minimum=1),
        "manifest_digest": _digest(value.get("manifest_digest")),
    }
    result.update(_pagination(value))
    for key in ("valid", "stale", "pending", "can_switch_registrar"):
        result[key] = _boolean(value.get(key))
    # The source check belongs to the import; a Platform that predates the flag offered it while importing.
    result["crosscheck_available"] = _boolean(value.get("crosscheck_available", result["status"] == "pending_import"))
    size = _integer(value.get("page_size"), minimum=1)
    if size > MAX_PAGE_SIZE:
        raise _invalid()
    result["page_size"] = size
    for key in ("inventory", "manifest", "records"):
        result[key] = _rows(value.get(key))
        result[key + "_total"] = _integer(value.get(key + "_total"))
        if len(result[key]) > result[key + "_total"]:
            raise _invalid()
    normalizations = value.get("normalizations")
    if not isinstance(normalizations, list) or len(normalizations) > MAX_PAGE_SIZE:
        raise _invalid()
    result["normalizations"] = [_normalization(item) for item in normalizations]
    result["normalizations_total"] = _integer(value.get("normalizations_total"))
    nameservers = value.get("nameservers")
    if not isinstance(nameservers, list) or len(nameservers) > MAX_NAMESERVERS:
        raise _invalid()
    result["nameservers"] = [_text(item, 253) for item in nameservers]
    if (
        nameservers
        and (
            result["stale"]
            or not result["valid"]
            or result["status"] not in {"awaiting_ns", "active"}
            or len(nameservers) < MIN_NAMESERVERS
        )
    ) or (result["can_switch_registrar"] and not nameservers):
        raise _invalid()
    result["export_digest"] = _digest(value.get("export_digest", ""), optional=True)
    # Render known status messages, never raw worker/provider errors or private evidence.
    result["has_error"] = bool(_text(value.get("error", ""), 200))
    errors = value.get("errors", [])
    if not isinstance(errors, list) or len(errors) > MAX_PAGE_SIZE:
        raise _invalid()
    result["errors"] = [_import_error(item) for item in errors]
    crosscheck = value.get("crosscheck")
    if not isinstance(crosscheck, dict):
        raise _invalid()
    result["crosscheck"] = {key: crosscheck.get(key) is True for key in ("complete", "ok")}
    dnssec = value.get("dnssec")
    if not isinstance(dnssec, dict):
        raise _invalid()
    result["dnssec"] = {key: _text(dnssec.get(key, ""), 4096) for key in ("status", "ds")}
    return result


class DnsAPIClient(PlatformAPIClient):
    def _call(
        self, customer_id: int, user_id: int, path: str, payload: dict[str, Any] | None = None, *, read: bool = False
    ) -> dict[str, Any]:
        response: object = self._make_request(
            "POST",
            "/dns/" + path,
            user_id=user_id,
            data={**(payload or {}), "customer_id": customer_id, "user_id": user_id},
            idempotent=read,
        )
        if (
            not isinstance(response, dict)
            or response.get("success") is not True
            or not isinstance(response.get("data"), dict)
        ):
            raise _invalid()
        return cast(dict[str, Any], response["data"])

    def zone_list(self, customer_id: int, user_id: int, *, page: int = 1) -> dict[str, Any]:
        data = self._call(customer_id, user_id, "zones/", {"page": page}, read=True)
        rows = data.get("zones")
        if not isinstance(rows, list) or len(rows) > MAX_PAGE_SIZE:
            raise _invalid()
        items = []
        for item in rows:
            if not isinstance(item, dict):
                raise _invalid()
            items.append(
                {
                    "id": _uuid(item.get("id")),
                    "name": _text(item.get("name"), 253),
                    "status": _text(item.get("status"), 24),
                    "revision": _integer(item.get("revision"), minimum=1),
                }
            )
        return {**_pagination(data), "total": _integer(data.get("total")), "zones": items}

    def zone_detail(self, customer_id: int, user_id: int, zone_id: UUID, *, page: int = 1) -> dict[str, Any]:
        return _zone(self._call(customer_id, user_id, f"zones/{zone_id}/", {"page": page}, read=True).get("zone"))

    def import_zone(self, customer_id: int, user_id: int, service_id: int, raw: bytes) -> dict[str, Any]:
        if not raw or len(raw) > MAX_ZONE_FILE_BYTES:
            raise PlatformAPIError("Invalid zone file", status_code=400)
        return _zone(
            self._call(
                customer_id,
                user_id,
                "zones/import/",
                {"service_id": service_id, "zone_file": base64.b64encode(raw).decode("ascii")},
            ).get("zone")
        )

    def zone_action(
        self, customer_id: int, user_id: int, zone_id: UUID, action: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        if action not in {"crosscheck", "confirm", "switch", "delete"}:
            raise ValueError("Invalid DNS action")
        return _zone(self._call(customer_id, user_id, f"zones/{zone_id}/{action}/", payload).get("zone"))

    def record_detail(self, customer_id: int, user_id: int, zone_id: UUID, record_id: UUID) -> dict[str, Any]:
        data = self._call(customer_id, user_id, f"zones/{zone_id}/records/{record_id}/detail/", read=True)
        return {"record": _record(data.get("record")), "revision": _integer(data.get("revision"), minimum=1)}

    def change_record(
        self, customer_id: int, user_id: int, zone_id: UUID, record_id: UUID | None, payload: dict[str, Any]
    ) -> dict[str, Any]:
        path = f"zones/{zone_id}/records/" + (f"{record_id}/" if record_id else "")
        return _zone(self._call(customer_id, user_id, path, payload).get("zone"))

    def export_zone(self, customer_id: int, user_id: int, zone_id: UUID) -> bytes:
        data = self._call(customer_id, user_id, f"zones/{zone_id}/export/")
        encoded = _text(data.get("zone_file"), 4 * ((MAX_ZONE_FILE_BYTES + 2) // 3))
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise _invalid() from error
        if not raw or len(raw) > MAX_ZONE_FILE_BYTES:
            raise _invalid()
        return raw


dns_api = DnsAPIClient()
