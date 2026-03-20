"""
Custom Django signals for billing cross-app communication.

These signals enable unidirectional coupling: Billing EMITS, other apps LISTEN.
Billing never imports from Orders or Provisioning.
"""

from django.dispatch import Signal

# Emitted after a proforma payment is recorded AND the proforma is converted to an invoice.
# Receivers: Orders app (to confirm the order and start provisioning).
# Args: proforma (ProformaInvoice), invoice (Invoice), payment (Payment)
proforma_payment_received = Signal()

# Emitted when an invoice refund is completed.
# Receivers: Provisioning app (to suspend/terminate services).
# Args: invoice (Invoice), refund_type (str: "full" or "partial")
invoice_refunded = Signal()

# Emitted when an invoice refund is fully confirmed (e.g., Stripe refund settled).
# Not yet implemented — planned for post-refund service hard-delete after the refund
# window expires (hard-deletes services instead of suspending them).
# Args: invoice (Invoice), refund (Refund)
invoice_refund_completed = Signal()
