"""Bounded provider inventory and exact-ID operations, separate from ownership decisions.

Only authoritative complete responses describe absence. Names and attachments describe
relationships, never permission to delete. Provider payloads are reduced before persistence.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from http import HTTPStatus
from typing import Literal, Protocol, cast
from urllib.parse import parse_qs, quote, urlsplit

from apps.common.types import Err, Ok, Result

ResourceKind = Literal[
    "server",
    "primary_ip",
    "reserved_ip",
    "firewall",
    "ssh_key",
    "volume",
    "custom_image",
    "snapshot",
    "volume_snapshot",
    "backup",
]
MAX_RESOURCE_PAGES = 100
MAX_RESOURCES = 20000
MAX_RESOURCE_ID_LENGTH = 128
MAX_CURSOR_LENGTH = 4096


@dataclass(frozen=True)
class ResourceResponse:
    status: int
    payload: object


class ResourceRequest(Protocol):
    def __call__(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, object] | None = None,
        body: dict[str, object] | None = None,
    ) -> ResourceResponse: ...


@dataclass(frozen=True)
class CloudResource:
    kind: ResourceKind
    resource_id: str
    attached_to: tuple[str, ...] = ()
    source_ids: tuple[str, ...] = ()
    labels: dict[str, str] = field(default_factory=dict)
    name: str = ""
    state: str = ""
    attachments_known: bool = True
    auto_delete: bool = False
    protected: bool = False

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.resource_id}"


@dataclass(frozen=True)
class ResourceCapabilities:
    collections: tuple[str, ...]
    backup_retention: Literal["convert", "manual"]
    backup_deletion: Literal["delete", "parent", "expiry"]
    volume_snapshots: bool


CAPABILITIES = {
    "hetzner": ResourceCapabilities(
        ("servers", "primary_ips", "floating_ips", "firewalls", "ssh_keys", "volumes", "images"),
        "convert",
        "parent",
        False,
    ),
    "digitalocean": ResourceCapabilities(
        ("droplets", "reserved_ips", "firewalls", "account/keys", "volumes", "snapshots", "images"),
        "convert",
        "delete",
        True,
    ),
    "vultr": ResourceCapabilities(
        ("instances", "reserved-ips", "firewalls", "ssh-keys", "blocks", "blocks/snapshots", "snapshots", "backups"),
        "manual",
        "expiry",
        True,
    ),
}
_KINDS: dict[str, ResourceKind] = {
    "servers": "server",
    "droplets": "server",
    "instances": "server",
    "primary_ips": "primary_ip",
    "floating_ips": "reserved_ip",
    "reserved_ips": "reserved_ip",
    "reserved-ips": "reserved_ip",
    "firewalls": "firewall",
    "ssh_keys": "ssh_key",
    "account/keys": "ssh_key",
    "ssh-keys": "ssh_key",
    "volumes": "volume",
    "blocks": "volume",
    "blocks/snapshots": "volume_snapshot",
    "snapshots": "snapshot",
    "backups": "backup",
    "images": "custom_image",
}
_HOSTS = {"hetzner": "api.hetzner.cloud", "digitalocean": "api.digitalocean.com", "vultr": "api.vultr.com"}


def _identifier(value: object) -> str:
    if (
        isinstance(value, bool)
        or not isinstance(value, (str, int))
        or not str(value)
        or len(str(value)) > MAX_RESOURCE_ID_LENGTH
    ):
        raise ValueError("Provider resource ID is invalid")
    return str(value)


def _ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("Provider attachment list is invalid")
    return tuple(sorted({_identifier(item) for item in value}))


def _one(value: object) -> tuple[str, ...]:
    return () if value is None or value == "" else (_identifier(value),)


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError("Provider resource object is invalid")
    return value


class CloudResourceClient:
    def __init__(
        self,
        provider: str,
        request: ResourceRequest,
        *,
        poll_timeout: float = 300,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if provider not in CAPABILITIES:
            raise ValueError("Provider resource inventory is unsupported")
        self.provider = provider
        self.request = request
        self.capabilities = CAPABILITIES[provider]
        self.poll_timeout = poll_timeout
        self.sleep = sleep

    def _next(self, payload: dict[str, object], collection: str, page: object) -> object | None:
        meta = _mapping(payload.get("meta", {}))
        if self.provider == "hetzner":
            pagination = _mapping(meta.get("pagination", {}))
            if "next_page" not in pagination:
                raise ValueError("Provider pagination metadata is missing")
            next_page = pagination["next_page"]
            if next_page is not None and (type(next_page) is not int or next_page <= cast("int", page)):
                raise ValueError("Provider pagination did not advance")
            return next_page
        if self.provider == "vultr":
            links = _mapping(meta.get("links", {}))
            if "next" not in links:
                raise ValueError("Provider pagination metadata is missing")
            cursor = links["next"]
            if cursor in (None, ""):
                return None
            if not isinstance(cursor, str) or len(cursor) > MAX_CURSOR_LENGTH:
                raise ValueError("Provider pagination cursor is invalid")
            return cursor
        links = _mapping(payload.get("links", {}))
        next_url = _mapping(links.get("pages", {})).get("next")
        if next_url is None:
            return None
        if not isinstance(next_url, str):
            raise ValueError("Provider pagination link is invalid")
        parsed = urlsplit(next_url)
        query = parse_qs(parsed.query)
        if (
            parsed.scheme != "https"
            or parsed.netloc != _HOSTS[self.provider]
            or parsed.path != f"/v2/{collection}"
            or set(query) - {"page", "per_page", "private", "type"}
            or len(query.get("page", [])) != 1
        ):
            raise ValueError("Provider pagination link is untrusted")
        number = int(query["page"][0])
        if number <= cast("int", page):
            raise ValueError("Provider pagination did not advance")
        return number

    def _collection_key(self, collection: str) -> str:
        if collection not in self.capabilities.collections and not (
            self.provider == "digitalocean" and collection.startswith("droplets/") and collection.endswith("/backups")
        ):
            raise ValueError("Unsupported resource collection")
        key = "ssh_keys" if collection == "account/keys" else collection.rsplit("/", 1)[-1].replace("-", "_")
        if self.provider == "vultr" and collection == "firewalls":
            key = "firewall_groups"
        return key

    def _page_params(self, collection: str, page: object, backup_server_id: str | None) -> dict[str, object]:
        if backup_server_id is not None and (self.provider != "vultr" or collection != "backups"):
            raise ValueError("Provider backup filter is unsupported")
        params: dict[str, object] = {"per_page": 100}
        if backup_server_id is not None:
            params["instance_id"] = _identifier(backup_server_id)
        params["cursor" if self.provider == "vultr" else "page"] = page
        if self.provider == "digitalocean" and collection == "images":
            params["private"] = "true"
        return params

    def list_collection(self, collection: str, *, backup_server_id: str | None = None) -> list[CloudResource]:
        key = self._collection_key(collection)
        page: object = 1 if self.provider != "vultr" else ""
        seen_pages: set[str] = set()
        resources: dict[str, CloudResource] = {}
        for _ in range(MAX_RESOURCE_PAGES):
            if str(page) in seen_pages:
                raise ValueError("Provider pagination repeated")
            seen_pages.add(str(page))
            params = self._page_params(collection, page, backup_server_id)
            response = self.request("GET", f"/{collection}", params=params)
            if response.status != HTTPStatus.OK:
                raise ValueError(f"Provider inventory returned HTTP {response.status}")
            payload = _mapping(response.payload)
            rows = payload.get(key)
            if not isinstance(rows, list):
                raise ValueError(f"Provider inventory is missing {key}")
            for row in rows:
                resource = self._resource(collection, _mapping(row))
                if resource is None:
                    continue
                if backup_server_id is not None:
                    resource = replace(resource, source_ids=(backup_server_id,))
                if resource.key in resources:
                    raise ValueError("Provider inventory repeated a resource ID")
                resources[resource.key] = resource
                if len(resources) > MAX_RESOURCES:
                    raise ValueError("Provider inventory exceeds its resource bound")
            page = self._next(payload, collection, page)
            if page is None:
                return list(resources.values())
        raise ValueError("Provider inventory exceeds its page bound")

    def inventory(self, server_ids: tuple[str, ...]) -> Result[list[CloudResource], str]:
        try:
            resources: dict[str, CloudResource] = {}
            for collection in self.capabilities.collections:
                for resource in self.list_collection(collection):
                    resources.setdefault(resource.key, resource)
            if self.provider == "digitalocean":
                for server_id in server_ids:
                    # Already-absent servers have no live backup listing; persisted manifests retain their IDs.
                    if f"server:{server_id}" not in resources:
                        continue
                    for resource in self.list_collection(f"droplets/{quote(server_id, safe='')}/backups"):
                        resources[resource.key] = resource
            elif self.provider == "vultr":
                for server_id in server_ids:
                    if f"server:{server_id}" not in resources:
                        continue
                    for resource in self.list_collection("backups", backup_server_id=server_id):
                        resources[resource.key] = resource
            return Ok(sorted(resources.values(), key=lambda item: item.key))
        except Exception as error:
            return Err(f"Provider inventory incomplete: {type(error).__name__}")

    def _labels(self, collection: str, row: dict[str, object]) -> dict[str, str]:
        labels = row.get("labels", {})
        if self.provider in {"digitalocean", "vultr"}:
            tags = row.get("tags", [])
            if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
                raise ValueError("Provider resource tags are invalid")
            separator = "=" if self.provider == "vultr" else ":"
            labels = dict(tag.split(separator, 1) for tag in tags if separator in tag)
            if self.provider == "vultr" and collection == "instances" and row.get("label"):
                labels.setdefault("praho-deployment", str(row["label"]))
        labels = _mapping(labels)
        if not all(isinstance(value, str) for value in labels.values()):
            raise ValueError("Provider resource labels are invalid")
        return cast("dict[str, str]", labels)

    def _resource(self, collection: str, row: dict[str, object]) -> CloudResource | None:
        collection_kind = collection.rsplit("/", 1)[-1] if collection.endswith("/backups") else collection
        kind = _KINDS[collection_kind]
        sources: tuple[str, ...] = ()
        if collection_kind == "images":
            image_type = row.get("type")
            if self.provider == "hetzner" and image_type not in {"backup", "snapshot"}:
                return None  # System/base images are never owned teardown resources.
            if image_type in {"backup", "snapshot"}:
                kind = cast("ResourceKind", image_type)
            origin = row.get("created_from")
            if origin is not None:
                sources = _one(_mapping(origin).get("id"))
        if kind == "server" and isinstance(row.get("image"), dict):
            sources = _one(_mapping(row["image"]).get("id"))
        identifier = row.get("ip") if self.provider == "digitalocean" and kind == "reserved_ip" else row.get("id")
        protection = _mapping(row.get("protection", {}))
        resource = CloudResource(
            kind,
            _identifier(identifier),
            source_ids=sources,
            labels=self._labels(collection, row),
            name=str(row.get("name", row.get("description", row.get("label", ""))))[:255],
            state=str(row.get("status", row.get("state", ""))).lower()[:40],
            protected=protection.get("delete") is True,
        )
        if self.provider == "hetzner":
            return self._hetzner_relationships(resource, row)
        if self.provider == "digitalocean":
            if collection_kind == "images":
                return resource  # Prefer the snapshot view's origin when merging the distinct native schemas.
            if collection.endswith("/backups"):
                return replace(resource, kind="backup", source_ids=(collection.split("/")[1],))
            return self._digitalocean_relationships(resource, row)
        return self._vultr_relationships(resource, row)

    @staticmethod
    def _hetzner_relationships(resource: CloudResource, row: dict[str, object]) -> CloudResource:
        if resource.kind == "primary_ip":
            return replace(
                resource,
                attachments_known=row.get("assignee_type") in {"server", "unassigned"},
                attached_to=_one(row.get("assignee_id")),
                auto_delete=row.get("auto_delete") is True,
            )
        if resource.kind in {"reserved_ip", "volume"}:
            server = row.get("server")
            return replace(
                resource,
                attachments_known="server" in row,
                attached_to=_one(_mapping(server).get("id") if isinstance(server, dict) else server),
            )
        if resource.kind == "firewall":
            applied = row.get("applied_to")
            if not isinstance(applied, list) or any(_mapping(item).get("type") != "server" for item in applied):
                return replace(resource, attachments_known=False)
            return replace(
                resource,
                attached_to=tuple(sorted(_identifier(_mapping(_mapping(item)["server"])["id"]) for item in applied)),
            )
        return resource

    @staticmethod
    def _digitalocean_relationships(resource: CloudResource, row: dict[str, object]) -> CloudResource:
        if resource.kind == "reserved_ip":
            droplet = row.get("droplet")
            return replace(
                resource,
                attachments_known="droplet" in row,
                attached_to=_one(_mapping(droplet).get("id") if droplet else None),
            )
        if resource.kind in {"volume", "firewall"}:
            return replace(
                resource,
                attachments_known="droplet_ids" in row and not row.get("tags"),
                attached_to=_ids(row.get("droplet_ids", [])),
            )
        if resource.kind == "snapshot":
            if row.get("resource_type") not in {"droplet", "volume"}:
                raise ValueError("Unknown snapshot resource type")
            return replace(
                resource,
                kind="volume_snapshot" if row["resource_type"] == "volume" else "snapshot",
                source_ids=_one(row.get("resource_id")),
            )
        return resource

    @staticmethod
    def _vultr_relationships(resource: CloudResource, row: dict[str, object]) -> CloudResource:
        if resource.kind == "server":
            return replace(
                resource, source_ids=tuple(sorted(set(_one(row.get("snapshot_id")) + _one(row.get("image_id")))))
            )
        if resource.kind == "volume":
            return replace(
                resource,
                attachments_known="attached_to_instance" in row,
                attached_to=_one(row.get("attached_to_instance")),
                source_ids=_one(row.get("snapshot_id")),
            )
        if resource.kind == "reserved_ip":
            return replace(resource, attachments_known="instance_id" in row, attached_to=_one(row.get("instance_id")))
        if resource.kind == "firewall":
            return replace(resource, attachments_known=row.get("instance_count") == 0)
        source_field = {"backup": "instance_id", "volume_snapshot": "block_id"}.get(resource.kind)
        if source_field:
            return replace(resource, source_ids=_one(row.get(source_field)))
        return resource

    def _endpoint(self, kind: ResourceKind, resource_id: str) -> tuple[str, str]:
        routes = {
            "hetzner": {
                "server": ("servers", "server"),
                "primary_ip": ("primary_ips", "primary_ip"),
                "reserved_ip": ("floating_ips", "floating_ip"),
                "firewall": ("firewalls", "firewall"),
                "ssh_key": ("ssh_keys", "ssh_key"),
                "volume": ("volumes", "volume"),
                "snapshot": ("images", "image"),
                "backup": ("images", "image"),
            },
            "digitalocean": {
                "server": ("droplets", "droplet"),
                "reserved_ip": ("reserved_ips", "reserved_ip"),
                "firewall": ("firewalls", "firewall"),
                "ssh_key": ("account/keys", "ssh_key"),
                "volume": ("volumes", "volume"),
                "snapshot": ("snapshots", "snapshot"),
                "volume_snapshot": ("snapshots", "snapshot"),
                "backup": ("images", "image"),
                "custom_image": ("images", "image"),
            },
            "vultr": {
                "server": ("instances", "instance"),
                "reserved_ip": ("reserved-ips", "reserved_ip"),
                "firewall": ("firewalls", "firewall_group"),
                "ssh_key": ("ssh-keys", "ssh_key"),
                "volume": ("blocks", "block"),
                "volume_snapshot": ("blocks/snapshots", ""),
                "snapshot": ("snapshots", "snapshot"),
                "backup": ("backups", "backup"),
            },
        }
        if kind not in routes[self.provider]:
            raise ValueError("Provider resource operation requires manual preparation")
        path, key = routes[self.provider][kind]
        return f"/{path}/{quote(_identifier(resource_id), safe='')}", key

    def read_exact(self, kind: ResourceKind, resource_id: str) -> dict[str, object] | None:
        path, key = self._endpoint(kind, resource_id)
        reply = self.request("GET", path)
        if reply.status == HTTPStatus.NOT_FOUND:
            return None
        if reply.status != HTTPStatus.OK:
            raise ValueError(f"Provider resource lookup returned HTTP {reply.status}")
        payload = _mapping(reply.payload)
        row = _mapping(payload.get(key)) if key else payload
        identifier = row.get("ip") if self.provider == "digitalocean" and kind == "reserved_ip" else row.get("id")
        if _identifier(identifier) != resource_id:
            raise ValueError("Provider resource lookup returned a different ID")
        return row

    def delete_exact(self, kind: ResourceKind, resource_id: str) -> Result[bool, str]:
        try:
            if kind == "backup" and self.provider == "vultr":
                return Err("Provider backup expires under provider policy; manual action is required")
            path, _ = self._endpoint(kind, resource_id)
            reply = self.request("DELETE", path)
            if reply.status == HTTPStatus.NOT_FOUND:
                return Ok(True)
            if reply.status not in {200, 202, 204}:
                return Err(f"Provider deletion returned HTTP {reply.status}")
            deadline = time.monotonic() + self.poll_timeout
            while True:
                if self.read_exact(kind, resource_id) is None:
                    return Ok(True)
                if time.monotonic() >= deadline:
                    return Err("Provider accepted deletion but resource absence is unconfirmed")
                self.sleep(2)
        except Exception as error:
            return Err(f"Provider deletion unconfirmed: {type(error).__name__}")

    def retain_backup(self, backup_id: str) -> Result[str, str]:
        """Convert an existing restore point; never create a new final snapshot implicitly."""
        try:
            if self.capabilities.backup_retention != "convert":
                return Err("Convert the backup in the provider console and verify the durable snapshot mapping")
            image = self.read_exact("backup", backup_id)
            if image is None:
                return Err("Provider backup is missing")
            if image.get("type") == "backup":
                path = f"/images/{quote(_identifier(backup_id), safe='')}"
                method = "PUT"
                body: dict[str, object] = {"type": "snapshot"}
                if self.provider == "digitalocean":
                    method, path, body = "POST", f"{path}/actions", {"type": "convert"}
                reply = self.request(method, path, body=body)
                if reply.status not in {200, 201, 202}:
                    return Err(f"Backup conversion returned HTTP {reply.status}")
            deadline = time.monotonic() + self.poll_timeout
            while True:
                image = self.read_exact("backup", backup_id)
                if image and image.get("type") == "snapshot" and image.get("status") == "available":
                    return Ok(backup_id)
                if time.monotonic() >= deadline:
                    return Err("Backup conversion has not produced a verified durable snapshot")
                self.sleep(2)
        except Exception as error:
            return Err(f"Backup retention unconfirmed: {type(error).__name__}")
