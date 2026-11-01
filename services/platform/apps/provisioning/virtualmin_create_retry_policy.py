"""Fresh authority for replaying an existing create, independent of native outcome."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from .domain_veto import blocking_domain_status
from .service_models import Service

if TYPE_CHECKING:
    from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob

_CREATE_INTENT_VERSION = 1
_PIPELINE_STATES = frozenset({"pending", "provisioning", "failed"})
_OFF_STATES = frozenset({"suspended", "terminated", "expired"})


@dataclass(frozen=True)
class CreateRetryPolicy:
    allowed: bool
    reason: str = ""
    review: bool = False
    customer_held: bool = False
    service_status: str = ""
    revoked: bool = False


def creation_intent(service_id: int, *, purpose: Literal["create", "reprovision"]) -> dict[str, object]:
    """Record the current DB identity/state when this concrete create job is minted."""
    service = Service.objects.values("id", "status").get(pk=service_id)
    return {
        "version": _CREATE_INTENT_VERSION,
        "service_id": service["id"],
        "service_status": service["status"],
        "purpose": purpose,
    }


def creation_service_binding_matches(service_id: int, job: VirtualminProvisioningJob) -> bool:
    """Missing pipeline history is distinct from an explicit foreign identity."""
    intent = (job.parameters or {}).get("creation_intent")
    if not isinstance(intent, dict) or "service_id" not in intent:
        return True
    return type(intent["service_id"]) is int and intent["service_id"] == service_id


def _intent_refusal(intent: object, service_id: int, status: str) -> str | None:
    if intent is None:
        return None if status == "active" else "Legacy non-active create has no reviewed creation intent"
    if (
        not isinstance(intent, dict)
        or type(intent.get("version")) is not int
        or intent.get("version") != _CREATE_INTENT_VERSION
        or type(intent.get("service_id")) is not int
        or intent.get("service_id") != service_id
        or not isinstance(intent.get("purpose"), str)
        or intent.get("purpose") not in ("create", "reprovision")
        or not isinstance(intent.get("service_status"), str)
        or intent.get("service_status") not in ({"active"} | _PIPELINE_STATES | _OFF_STATES)
    ):
        return "Create intent identity or format is invalid"
    if status == "active" or (status in _PIPELINE_STATES and status == intent["service_status"]):
        return None
    return f"Service moved from creation intent to '{status}'; review required"


def create_retry_policy(account: VirtualminAccount, job: VirtualminProvisioningJob) -> CreateRetryPolicy:
    """Read Service and its CURRENT owner in one SQL snapshot; never trust cached joins.

    The receipt preserves supported non-active direct creation inputs without
    interpreting a later provisioning failure/cancellation as a fresh recovery intent.
    Legacy active jobs require no invented historical Order association.
    """
    state = Service.objects.filter(pk=account.service_id).values("id", "status", "customer__status").first()
    if state is None:
        return CreateRetryPolicy(False, "Create intent has no current Service", review=True)
    status = str(state["status"])
    if not creation_service_binding_matches(state["id"], job):
        return CreateRetryPolicy(
            False, "Original create Service identity contradicts its account", review=True, service_status=status
        )
    if state["customer__status"] == "suspended":
        return CreateRetryPolicy(
            False,
            "Customer is suspended; create retry is held",
            customer_held=True,
            service_status=status,
            revoked=True,
        )
    if status in _OFF_STATES:
        return CreateRetryPolicy(
            False, f"Create superseded by Service state '{status}'", service_status=status, revoked=True
        )
    if blocking_domain_status(account) is not None:
        return CreateRetryPolicy(False, "A bound domain disables hosting", service_status=status, revoked=True)

    intent = (job.parameters or {}).get("creation_intent")
    refusal = _intent_refusal(intent, state["id"], status)
    valid_origin = isinstance(intent, dict) and _intent_refusal(intent, state["id"], "active") is None
    return CreateRetryPolicy(
        refusal is None,
        refusal or "",
        review=refusal is not None,
        service_status=status,
        revoked=refusal is not None and valid_origin,
    )
