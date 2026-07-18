"""Customer-controlled authorization for PRAHO-managed off-session collection."""

from __future__ import annotations

import hashlib

from django.db import transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.customers.models import Customer, CustomerPaymentMethod
from apps.users.models import CustomerMembership, User

from .gateways.base import PaymentGatewayFactory, SetupIntentStatusResult
from .recurring_models import RecurringPaymentAuthorization
from .subscription_models import Subscription

_CUSTOMER_BILLING_ROLES = frozenset({"owner", "billing"})
_REVOCATION_STAFF_ROLES = frozenset({"admin", "billing"})


class RecurringPaymentAuthorizationService:
    """Grant, withdraw, and revoke recurring-payment mandates with explicit authority."""

    TERMS_VERSION = "2026-07-17"
    TERMS_TEXT = (
        "I authorize PRAHO to charge this saved card when recurring services on my account become due. "
        "PRAHO may combine compatible services due in the same billing run into one variable-amount charge, "
        "after creating the corresponding proforma. I can disable automatic payment for individual services or "
        "withdraw this card authorization at any time. Withdrawal stops future automatic collection but does not "
        "cancel services, erase issued documents, or remove amounts already owed."
    )

    @staticmethod
    def _customer_billing_role(
        customer: Customer,
        actor: User,
        *,
        for_update: bool = False,
    ) -> str | None:
        if actor.is_staff_user:
            return None
        memberships = CustomerMembership.objects.filter(
            customer=customer,
            user=actor,
            is_active=True,
            role__in=_CUSTOMER_BILLING_ROLES,
        )
        if for_update:
            memberships = memberships.select_for_update()
        return memberships.values_list("role", flat=True).first()

    @classmethod
    def validate_customer_billing_principal(cls, customer: Customer, actor: User) -> Result[str, str]:
        """Authorize customer-facing mandate reads and writes consistently."""
        role = cls._customer_billing_role(customer, actor)
        if role is None:
            return Err("Only a customer billing principal may manage recurring payments")
        return Ok(role)

    @classmethod
    def _validate_principal_and_method(
        cls,
        *,
        customer: Customer,
        payment_method: CustomerPaymentMethod,
        actor: User,
        lock_principal: bool = False,
    ) -> Result[str, str]:
        billing_role = cls._customer_billing_role(customer, actor, for_update=lock_principal)
        if billing_role is None:
            return Err("Only a customer billing principal may grant recurring-payment authorization")
        if payment_method.customer_id != customer.id:
            return Err("Saved payment method does not belong to the customer")
        if not payment_method.is_active or payment_method.deleted_at is not None:
            return Err("Saved payment method is not active")
        if payment_method.method_type != "stripe_card" or not payment_method.stripe_payment_method_id:
            return Err("Recurring card authorization requires an attached Stripe payment method")
        if not payment_method.stripe_customer_id:
            return Err("Recurring card authorization requires an attached Stripe customer")
        return Ok(billing_role)

    @classmethod
    def _terms_text_hash(cls) -> str:
        return hashlib.sha256(cls.TERMS_TEXT.encode("utf-8")).hexdigest()

    @classmethod
    def _metadata(
        cls,
        customer: Customer,
        payment_method: CustomerPaymentMethod,
        actor: User,
    ) -> dict[str, str]:
        return {
            "praho_customer_id": str(customer.id),
            "praho_payment_method_id": str(payment_method.id),
            "praho_terms_version": cls.TERMS_VERSION,
            "praho_terms_text_hash": cls._terms_text_hash(),
            "praho_actor_id": str(actor.id),
        }

    @classmethod
    def _setup_intent_error(  # noqa: PLR0911  # One precise rejection per verified processor fact
        cls,
        *,
        facts: SetupIntentStatusResult,
        setup_intent_id: str,
        customer: Customer,
        payment_method: CustomerPaymentMethod,
        actor: User,
    ) -> str | None:
        """Return the first processor-fact mismatch without mutating consent state."""
        if not facts["success"]:
            return facts.get("error") or "Unable to verify recurring-payment authorization"
        if facts["setup_intent_id"] != setup_intent_id or facts["status"] != "succeeded":
            return "SetupIntent has not succeeded"
        if facts["customer_id"] != payment_method.stripe_customer_id:
            return "SetupIntent customer does not match the saved payment method"
        if facts["payment_method_id"] != payment_method.stripe_payment_method_id:
            return "SetupIntent payment method does not match the saved payment method"
        if facts["usage"] != "off_session":
            return "SetupIntent is not authorized for off-session use"
        expected_metadata = cls._metadata(customer, payment_method, actor)
        if any(facts["metadata"].get(key) != value for key, value in expected_metadata.items()):
            if facts["metadata"].get("praho_actor_id") != expected_metadata["praho_actor_id"]:
                return "SetupIntent belongs to a different billing principal"
            return "SetupIntent metadata does not match the requested authorization and terms"
        return None

    @classmethod
    def begin(
        cls,
        *,
        customer: Customer,
        payment_method: CustomerPaymentMethod,
        actor: User,
        terms_accepted: bool,
        accepted_terms_version: str,
    ) -> Result[dict[str, str], str]:
        """Create a processor-bound SetupIntent for explicit customer authorization."""
        if terms_accepted is not True or accepted_terms_version != cls.TERMS_VERSION:
            return Err("The current recurring-payment terms must be accepted")
        validation = cls._validate_principal_and_method(customer=customer, payment_method=payment_method, actor=actor)
        if validation.is_err():
            return Err(validation.unwrap_err())
        result = PaymentGatewayFactory.get_default_gateway().create_setup_intent(
            customer_id=payment_method.stripe_customer_id,
            payment_method_id=payment_method.stripe_payment_method_id,
            metadata=cls._metadata(customer, payment_method, actor),
        )
        if not result["success"] or not result["setup_intent_id"] or not result["client_secret"]:
            return Err(result.get("error") or "Unable to prepare recurring-payment authorization")
        return Ok(
            {
                "setup_intent_id": result["setup_intent_id"],
                "client_secret": result["client_secret"],
                "payment_method_id": payment_method.stripe_payment_method_id,
                "terms_version": cls.TERMS_VERSION,
                "terms_text": cls.TERMS_TEXT,
            }
        )

    @classmethod
    def complete(  # noqa: PLR0911, PLR0913
        cls,
        *,
        customer: Customer,
        payment_method: CustomerPaymentMethod,
        setup_intent_id: str,
        actor: User,
        ip_address: str | None = None,
        user_agent: str = "",
    ) -> Result[RecurringPaymentAuthorization, str]:
        """Activate a mandate only after verifying processor facts server-side."""
        validation = cls._validate_principal_and_method(customer=customer, payment_method=payment_method, actor=actor)
        if validation.is_err():
            return Err(validation.unwrap_err())
        if not setup_intent_id:
            return Err("SetupIntent is required")

        facts = PaymentGatewayFactory.get_default_gateway().retrieve_setup_intent(setup_intent_id)
        setup_intent_error = cls._setup_intent_error(
            facts=facts,
            setup_intent_id=setup_intent_id,
            customer=customer,
            payment_method=payment_method,
            actor=actor,
        )
        if setup_intent_error:
            return Err(setup_intent_error)

        terms_hash = cls._terms_text_hash()
        now = timezone.now()
        with transaction.atomic():
            locked_payment_method = (
                CustomerPaymentMethod.objects.select_for_update().filter(pk=payment_method.pk).first()
            )
            if locked_payment_method is None:
                return Err("Saved payment method is not active")
            locked_validation = cls._validate_principal_and_method(
                customer=customer,
                payment_method=locked_payment_method,
                actor=actor,
                lock_principal=True,
            )
            if locked_validation.is_err():
                return Err(locked_validation.unwrap_err())
            billing_role = locked_validation.unwrap()
            if (
                facts["customer_id"] != locked_payment_method.stripe_customer_id
                or facts["payment_method_id"] != locked_payment_method.stripe_payment_method_id
            ):
                return Err("Saved payment method changed while authorization was being verified")

            existing_setup_intent = (
                RecurringPaymentAuthorization.objects.select_for_update()
                .filter(setup_intent_id=setup_intent_id)
                .first()
            )
            if existing_setup_intent is not None:
                if (
                    existing_setup_intent.customer_id == customer.id
                    and existing_setup_intent.payment_method_id == locked_payment_method.id
                    and existing_setup_intent.terms_version == cls.TERMS_VERSION
                    and existing_setup_intent.terms_text_hash == terms_hash
                    and existing_setup_intent.status == "active"
                ):
                    return Ok(existing_setup_intent)
                return Err("SetupIntent is already bound to a different recurring-payment authorization")

            superseded = list(
                RecurringPaymentAuthorization.objects.select_for_update().filter(
                    customer=customer,
                    payment_method=locked_payment_method,
                    status="active",
                )
            )
            for previous in superseded:
                previous.withdraw(
                    actor=actor,
                    reason="Superseded by a newer authorization",
                    at=now,
                )
                previous.save(
                    update_fields=[
                        "status",
                        "withdrawn_at",
                        "withdrawn_by",
                        "withdrawal_reason",
                        "updated_at",
                    ]
                )
                Subscription.objects.filter(payment_authorization=previous).update(
                    auto_payment_enabled=False,
                    payment_authorization=None,
                    saved_payment_method=None,
                    updated_at=now,
                )

            authorization = RecurringPaymentAuthorization(
                customer=customer,
                payment_method=locked_payment_method,
                setup_intent_id=setup_intent_id,
                terms_version=cls.TERMS_VERSION,
                terms_text=cls.TERMS_TEXT,
                terms_text_hash=terms_hash,
                granted_by=actor,
                granted_by_role=billing_role,
                granted_at=now,
                grant_ip_address=ip_address,
                grant_user_agent=user_agent[:500],
            )
            authorization.activate()
            authorization.clean()
            authorization.save()
            return Ok(authorization)

    @classmethod
    def withdraw(
        cls,
        *,
        authorization: RecurringPaymentAuthorization,
        actor: User,
        reason: str,
    ) -> Result[RecurringPaymentAuthorization, str]:
        """Let a customer billing principal withdraw a mandate immediately."""
        with transaction.atomic():
            billing_role = cls._customer_billing_role(authorization.customer, actor, for_update=True)
            if billing_role is None:
                return Err("Only a customer billing principal may withdraw recurring-payment authorization")
            locked = RecurringPaymentAuthorization.objects.select_for_update().get(pk=authorization.pk)
            if locked.customer_id != authorization.customer_id:
                return Err("Recurring-payment authorization customer changed during withdrawal")
            if locked.status == "withdrawn":
                return Ok(locked)
            if locked.status != "active":
                return Err(f"Authorization in status '{locked.status}' cannot be withdrawn")

            now = timezone.now()
            locked.withdraw(actor=actor, reason=reason, at=now)
            locked.save(update_fields=["status", "withdrawn_at", "withdrawn_by", "withdrawal_reason", "updated_at"])
            Subscription.objects.filter(payment_authorization=locked).update(
                auto_payment_enabled=False,
                payment_authorization=None,
                saved_payment_method=None,
                updated_at=now,
            )
            return Ok(locked)

    @classmethod
    def set_subscription_auto_payment(  # noqa: PLR0911  # Keep each fail-closed consent rejection explicit
        cls,
        *,
        subscription: Subscription,
        authorization: RecurringPaymentAuthorization | None,
        enabled: bool,
        actor: User,
    ) -> Result[Subscription, str]:
        """Enroll or remove one subscription without changing its siblings."""
        with transaction.atomic():
            billing_role = cls._customer_billing_role(subscription.customer, actor, for_update=True)
            if billing_role is None:
                return Err("Only a customer billing principal may change automatic payment")

            locked_authorization = None
            if enabled:
                if authorization is None:
                    return Err("An active recurring-payment authorization is required")
                locked_authorization = (
                    RecurringPaymentAuthorization.objects.select_for_update()
                    .select_related("payment_method")
                    .get(pk=authorization.pk)
                )

            locked = Subscription.objects.select_for_update().get(pk=subscription.pk)
            if locked.customer_id != subscription.customer_id:
                return Err("Subscription customer changed while automatic payment was being updated")
            if not enabled:
                locked.auto_payment_enabled = False
                locked.payment_authorization = None
                locked.saved_payment_method = None
                locked.save(
                    update_fields=[
                        "auto_payment_enabled",
                        "payment_authorization",
                        "saved_payment_method",
                        "updated_at",
                    ]
                )
                return Ok(locked)

            assert locked_authorization is not None
            if locked_authorization.customer_id != locked.customer_id or not locked_authorization.is_active:
                return Err("Recurring-payment authorization is not active for this customer")
            if locked.status not in {"active", "trialing", "past_due"}:
                return Err(f"Subscription in status '{locked.status}' cannot use automatic payment")
            if locked.service_id is None:
                return Err("Subscription must have a linked service before automatic payment can be enabled")

            locked.payment_authorization = locked_authorization
            locked.saved_payment_method = locked_authorization.payment_method
            locked.auto_payment_enabled = True
            locked.save(
                update_fields=["payment_authorization", "saved_payment_method", "auto_payment_enabled", "updated_at"]
            )
            return Ok(locked)

    @staticmethod
    def revoke(
        *,
        authorization: RecurringPaymentAuthorization,
        actor: User,
        reason: str,
    ) -> Result[RecurringPaymentAuthorization, str]:
        """Let authorized billing staff revoke a mandate without impersonating consent."""
        if not actor.is_superuser and actor.staff_role not in _REVOCATION_STAFF_ROLES:
            return Err("Only billing administrators may revoke recurring-payment authorization")

        with transaction.atomic():
            locked = RecurringPaymentAuthorization.objects.select_for_update().get(pk=authorization.pk)
            if locked.status == "revoked":
                return Ok(locked)
            if locked.status != "active":
                return Err(f"Authorization in status '{locked.status}' cannot be revoked")

            now = timezone.now()
            locked.revoke(actor=actor, reason=reason, at=now)
            locked.save(update_fields=["status", "revoked_at", "revoked_by", "revocation_reason", "updated_at"])
            Subscription.objects.filter(payment_authorization=locked).update(
                auto_payment_enabled=False,
                payment_authorization=None,
                saved_payment_method=None,
                updated_at=now,
            )
            return Ok(locked)
