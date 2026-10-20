"""Stripe request and webhook rendering contracts; version upgrades are deliberate."""

STRIPE_API_VERSION = "2023-10-16"
STRIPE_REQUIRED_WEBHOOK_EVENTS = frozenset(
    {
        "payment_intent.succeeded",
        "payment_intent.payment_failed",
        "customer.created",
        "charge.dispute.created",
        "refund.created",
        "refund.updated",
        "refund.failed",
    }
)
