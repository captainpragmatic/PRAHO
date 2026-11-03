"""Lease-fenced, resumable execution of an immutable provider resource decision."""

from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from apps.common.row_locks import lock_one_and_load
from apps.common.types import Err, Ok, Result

from .cloud_destroy_models import CloudResourceCleanup, NodeDestroyPlan
from .cloud_destroy_policy import RESTORE_POINT_KINDS, DestroyDecision, build_destroy_decisions
from .cloud_destroy_service import assert_resource_cleanup_owner, protect_retained_resource, resource_ownership
from .cloud_resource_inventory import CloudResource, CloudResourceClient, ResourceKind
from .deployment_lifecycle import OperationLease, OperationOwnershipLostError, provider_token_fingerprint
from .models import NodeDeployment
from .server_lifetimes import close_server_lifetimes


class ResourceDestroyExecution:
    def __init__(  # noqa: PLR0913 -- exact deployment, lease, approved scope, provider and compensation boundary
        self,
        deployment: NodeDeployment,
        lease: OperationLease,
        plan: NodeDestroyPlan,
        client: CloudResourceClient,
        api_token: str,
        *,
        provisioning_compensation: bool = False,
    ) -> None:
        self.deployment = deployment
        self.lease = lease
        self.plan = plan
        self.client = client
        self.fingerprint = provider_token_fingerprint(api_token)
        self.prepared = False
        self.servers_absent = False
        self.provisioning_compensation = provisioning_compensation

    def _guard(self, *, lock: bool = False) -> NodeDeployment:
        rows = NodeDeployment.objects.select_related("provider")
        current = lock_one_and_load(rows.filter(pk=self.deployment.pk)) if lock else rows.get(pk=self.deployment.pk)
        assert_resource_cleanup_owner(current, self.lease, provisioning_compensation=self.provisioning_compensation)
        if self.plan.deployment_id != current.pk or self.plan.deployment_correlation_id != current.correlation_id:
            raise OperationOwnershipLostError("The provider cleanup no longer owns this deployment")
        if (
            current.provider_id != self.plan.provider_id
            or current.provider.provider_type != self.plan.provider_type
            or self.fingerprint != self.plan.token_fingerprint
            or current.provider_token_fingerprint != self.fingerprint
        ):
            raise ValueError("The approved provider or creating credential no longer matches")
        return current

    @transaction.atomic
    def _record(self, decision: DestroyDecision, state: str, detail: str = "", snapshot_id: str = "") -> None:
        self._guard(lock=True)
        outcome, _created = CloudResourceCleanup.objects.get_or_create(
            plan=self.plan,
            kind=decision.kind,
            resource_id=decision.resource_id,
        )
        outcome.state, outcome.detail = state, detail[:2000]
        if snapshot_id:
            outcome.durable_snapshot_id = snapshot_id
        outcome.save()
        NodeDeployment.objects.filter(pk=self.deployment.pk, operation_token=self.lease.token).update(
            updated_at=timezone.now()
        )

    def _decisions(self) -> list[DestroyDecision]:
        return [DestroyDecision(**row) for row in self.plan.decisions]

    def _resources(self) -> dict[str, CloudResource]:
        resources = {}
        for row in self.plan.inventory:
            values = {**row, "source_ids": tuple(row["source_ids"]), "attached_to": tuple(row["attached_to"])}
            resource = CloudResource(**values)
            resources[resource.key] = resource
        return resources

    def _validate_scope(self) -> dict[str, CloudResource]:
        self._guard()
        result = self.client.inventory(tuple(self.plan.server_ids))
        if result.is_err():
            raise ValueError(f"Provider inventory incomplete: {result.unwrap_err()}")
        resources = result.unwrap()
        owned = set(resource_ownership(self.deployment, resources, self.fingerprint))
        current_decisions = build_destroy_decisions(
            resources, owned, tuple(self.plan.server_ids), self.plan.restore_point_policy, self.client.capabilities
        )
        allowed = {decision.key for decision in self._decisions()}
        # Conversion preserves the provider image ID; a crash before its receipt must be resumable.
        allowed.update(
            f"snapshot:{decision.resource_id}" for decision in self._decisions() if decision.action == "convert"
        )
        allowed.update(
            f"snapshot:{identifier}"
            for identifier in CloudResourceCleanup.objects.filter(plan=self.plan, state="retained")
            .exclude(durable_snapshot_id="")
            .values_list("durable_snapshot_id", flat=True)
        )
        if any(decision.key not in allowed for decision in current_decisions):
            raise ValueError("Provider resources changed after approval; review the new resources before teardown")
        expected = self._resources()
        # An unapproved consumer can make an existing restore point shared without
        # changing that restore point's own fields or adding a decision key.
        # Compare policy dispositions against the immutable approved inventory;
        # finalized plan decisions may intentionally include manual retention mappings.
        approved_resources = list(expected.values())
        approved_owned = set(resource_ownership(self.deployment, approved_resources, self.fingerprint))
        approved_dispositions = {
            decision.key: (decision.action, decision.blocks_parent)
            for decision in build_destroy_decisions(
                approved_resources,
                approved_owned,
                tuple(self.plan.server_ids),
                self.plan.restore_point_policy,
                self.client.capabilities,
            )
        }
        for decision in current_decisions:
            before = approved_dispositions.get(decision.key)
            after = (decision.action, decision.blocks_parent)
            # Auto-deleted primary IPs can briefly become unassigned after server deletion.
            if decision.kind == "primary_ip":
                if before is not None and before[0] in {"delete", "parent_delete"}:
                    before = ("delete", before[1])
                if after[0] in {"delete", "parent_delete"}:
                    after = ("delete", after[1])
            if before is not None and before != after:
                raise ValueError(f"Provider cleanup disposition changed for {decision.key}; review it again")
        for resource in resources:
            if resource.key not in allowed or resource.key not in expected:
                continue
            old = expected[resource.key]
            if (
                set(resource.attached_to) - set(old.attached_to)
                or resource.labels != old.labels
                or resource.protected != old.protected
                or resource.auto_delete != old.auto_delete
                or resource.attachments_known != old.attachments_known
                or (resource.source_ids and resource.source_ids != old.source_ids)
            ):
                raise ValueError(f"Provider ownership, protection or attachments changed for {resource.key}")
        return {resource.key: resource for resource in resources}

    def _verify_durable(self, kind: ResourceKind, resource_id: str) -> None:
        self._guard()
        # DO Droplet images expose authoritative readiness; its snapshot view omits status.
        lookup_kind: ResourceKind = (
            "backup" if self.plan.provider_type == "digitalocean" and kind == "snapshot" else kind
        )
        row = self.client.read_exact(lookup_kind, resource_id)
        if row is None:
            raise ValueError(f"The approved retained restore point {resource_id} is missing")
        ready = row.get("status") in {"available", "complete"}
        if self.plan.provider_type == "vultr" and kind == "volume_snapshot":
            ready = row.get("state") == "COMPLETE"
        if self.plan.provider_type == "digitalocean" and kind == "volume_snapshot":
            ready = row.get("resource_type") == "volume" and bool(row.get("created_at")) and bool(row.get("regions"))
        if not ready or row.get("type", "snapshot") != "snapshot":
            raise ValueError(f"Restore point {resource_id} is not a verified durable ready snapshot")

    def _retain(self, decision: DestroyDecision) -> None:
        if decision.action == "convert":
            self._guard()
            conversion = self.client.retain_backup(decision.resource_id)
            if conversion.is_err():
                raise ValueError(conversion.unwrap_err())
            identifier = conversion.unwrap()
            self._verify_durable("snapshot", identifier)
            # Retention registration shares the deployment lock with drift expiry.
            with transaction.atomic():
                self._guard(lock=True)
                protect_retained_resource(self.plan, "snapshot", identifier)
                self._record(decision, "retained", snapshot_id=identifier)
        else:
            self._verify_durable(decision.kind, decision.resource_id)
            with transaction.atomic():
                self._guard(lock=True)
                protect_retained_resource(self.plan, decision.kind, decision.resource_id)
                self._record(decision, "retained", snapshot_id=decision.resource_id)

    def prepare(self) -> Result[bool, str]:
        self.prepared = False
        decision: DestroyDecision | None = None
        try:
            self._guard()
            for decision in self._decisions():
                if decision.blocks_parent:
                    self._record(decision, "unresolved", decision.reason)
                    return Err(decision.reason)
            decision = None
            self._validate_scope()
            for decision in self._decisions():
                if decision.action in {"keep", "convert"}:
                    self._retain(decision)
            decision = None
            self._validate_scope()
            self.prepared = True
            return Ok(True)
        except OperationOwnershipLostError as error:
            return Err(str(error))
        except Exception as error:
            if decision is not None:
                try:
                    self._record(decision, "unresolved", str(error))
                except (OperationOwnershipLostError, ValueError):
                    return Err("Provider cleanup ownership changed while recording an uncertain outcome")
            return Err(f"Provider retention or scope is unconfirmed: {error}")

    def _recheck_retention(self) -> None:
        for decision in self._decisions():
            if decision.action not in {"keep", "convert"}:
                continue
            outcome = CloudResourceCleanup.objects.filter(
                plan=self.plan,
                kind=decision.kind,
                resource_id=decision.resource_id,
                state="retained",
            ).first()
            if outcome is None or not outcome.durable_snapshot_id:
                raise ValueError("Retained provider restore points have not been durably verified")
            kind: ResourceKind = "volume_snapshot" if decision.kind == "volume_snapshot" else "snapshot"
            self._verify_durable(kind, outcome.durable_snapshot_id)

    def _delete(self, decision: DestroyDecision) -> bool:
        self._validate_scope()
        self._guard()
        if decision.kind == "server":
            self._recheck_retention()
        row = self.client.read_exact(decision.kind, decision.resource_id)
        if row is None:
            self._record(decision, "deleted")
            return True
        if decision.action == "parent_delete" and decision.kind not in RESTORE_POINT_KINDS:
            result = self.client.confirm_absent(decision.kind, decision.resource_id)
            if result.is_ok():
                self._record(decision, "deleted")
                return True
            err = result.unwrap_err()
            raise ValueError(
                f"Provider resource {decision.key} was not confirmed absent after its server was deleted: {err}"
            )
        if decision.action == "delete":
            result = self.client.delete_exact(decision.kind, decision.resource_id)
            if result.is_err() or result.unwrap() is not True:
                raise ValueError(result.unwrap_err() if result.is_err() else "Provider deletion was not confirmed")
            if self.client.read_exact(decision.kind, decision.resource_id) is not None:
                raise ValueError("The resource is still visible after a claimed confirmed deletion")
            self._record(decision, "deleted")
            return True
        self._record(decision, "awaiting_expiry", decision.reason)
        return False

    def _unconfirmed(self, decision: DestroyDecision, error: Exception) -> str:
        try:
            self._record(decision, "unresolved", str(error))
        except (OperationOwnershipLostError, ValueError):
            return "Provider cleanup identity or ownership changed while recording its outcome"
        return f"Resource {decision.key} cleanup is unconfirmed: {error}"

    def _confirm_servers_absent(self) -> None:
        """End all confirmed/pending VM windows before less urgent dependency cleanup."""
        self._validate_scope()
        self._guard()
        if any(self.client.read_exact("server", identifier) is not None for identifier in self.plan.server_ids):
            raise ValueError("The approved server inventory is not proven absent")
        close_server_lifetimes(self.lease, self.deployment)
        self.servers_absent = True

    def delete_resources(self) -> Result[bool, str]:
        if not self.prepared:
            return Err("Secure and verify retained provider restore points before teardown")
        pending = False
        self.servers_absent = False
        decisions = sorted(self._decisions(), key=lambda item: (item.kind != "server", item.key))
        for decision in decisions:
            try:
                self._guard()
                if decision.kind != "server" and not self.servers_absent:
                    self._confirm_servers_absent()
                if decision.action in {"keep", "convert"}:
                    continue
                if decision.action == "manual":
                    self._record(decision, "preserved", decision.reason)
                    continue
                pending = not self._delete(decision) or pending
            except OperationOwnershipLostError as error:
                return Err(str(error))
            except Exception as error:
                return Err(self._unconfirmed(decision, error))
        try:
            if not self.servers_absent:
                self._confirm_servers_absent()
            self._validate_scope()
        except (OperationOwnershipLostError, ValueError) as error:
            return Err(str(error))
        if pending:
            return Err("VM teardown completed; provider restore points are awaiting verified expiry")
        return Ok(True)
