# Order Lifecycle

> **Status**: Active reference
> **Last updated**: 2026-03-22
> **Source of truth**: `services/platform/apps/orders/models.py` (FSM transitions)

---

## State Machine

```mermaid
stateDiagram-v2
    [*] --> draft : Customer adds to cart

    draft --> awaiting_payment : Submit order (preflight validated, proforma created)
    draft --> cancelled : Customer/admin cancels

    awaiting_payment --> paid : Payment received (Stripe webhook / bank transfer)
    awaiting_payment --> cancelled : Customer/admin cancels
    awaiting_payment --> failed : Payment failed

    paid --> provisioning : Auto-advance (order below review threshold)
    paid --> in_review : High-value order flagged for admin review

    note right of paid
        Transient audit state — proves money
        received even if provisioning fails.
        confirm_order() advances atomically
        to provisioning or in_review.
    end note

    in_review --> provisioning : Admin approves
    in_review --> cancelled : Admin rejects

    provisioning --> completed : Provisioning successful
    provisioning --> failed : Provisioning failed
    provisioning --> cancelled : Admin force-cancels

    failed --> awaiting_payment : Retry order
    failed --> cancelled : Abandon order

    cancelled --> [*]
    completed --> [*]
```

> **Note on refunds:** `refunded` and `partially_refunded` exist on **Invoice** and **Payment** models, not on Order. An Order's financial reversal is tracked via its linked invoice and payment records.

## Status Definitions

| Status | Description | Editable | Customer-visible |
|--------|-------------|----------|-----------------|
| `draft` | Cart/quote stage — order can be freely modified | All fields | Yes (as "cart") |
| `awaiting_payment` | Submitted, proforma issued, waiting for payment | All fields | Yes |
| `paid` | Payment received — transient audit checkpoint before provisioning | Notes, delivery only | Yes |
| `in_review` | High-value order under admin review before provisioning | Notes only | Yes |
| `provisioning` | Services being provisioned (Virtualmin, DNS, etc.) | Notes only | Yes |
| `completed` | Fully provisioned and delivered | Read-only | Yes |
| `cancelled` | Cancelled by customer or admin (terminal) | Read-only | Yes |
| `failed` | Payment or provisioning failed | Read-only | Yes |

## Proforma Lifecycle

Every order that enters `awaiting_payment` gets a proforma invoice. Payment — regardless of method — flows through a single convergence point that converts the proforma to a tax invoice before the order advances.

```mermaid
stateDiagram-v2
    [*] --> draft : Created

    draft --> sent : Proforma emailed to customer
    sent --> accepted : Customer accepts
    sent --> expired : Due date passed without payment
    accepted --> converted : Payment received
    sent --> converted : Payment received (implicit accept)
    draft --> converted : Payment received via admin

    converted --> [*]
    expired --> [*]
```

| Proforma Event | When it happens |
|----------------|----------------|
| Created (`draft`) | Order transitions to `awaiting_payment` |
| Sent | Immediately after creation (email dispatched via `on_commit`) |
| Converted | Any payment path calls `ProformaPaymentService.record_payment_and_convert()` |

## Portal Order Flow (Customer-Facing)

```mermaid
flowchart LR
    A[Product Catalog] -->|Add to Cart| B[Cart Review]
    B -->|Calculate Totals| C[Checkout]
    C -->|Preflight Validation| D{Profile Complete?}
    D -->|No| E[Fix Profile]
    E --> C
    D -->|Yes| F{Payment Method?}
    F -->|Card| G[Stripe PaymentIntent]
    F -->|Bank Transfer| H[Create Order]
    G --> I[Order: awaiting_payment\nProforma created + emailed]
    H --> I
    I -->|Stripe webhook fires\nor confirm_order endpoint| J[ProformaPaymentService\nrecord_payment_and_convert]
    I -->|Staff records bank\ntransfer payment| J
    J --> K[Proforma → Invoice\nconverted]
    K --> L[Order: paid → provisioning]
    L --> M[Confirmation Page]
```

### Key Security Controls

1. **Cart versioning** — SHA-256 hash of cart contents prevents stale mutations
2. **HMAC price sealing** — Server-authoritative pricing, tamper-proof
3. **Preflight validation** — Profile completeness checked before `draft → awaiting_payment`
4. **Terms acceptance** — EU Directive 2011/83/EU compliance (agree_terms required)
5. **Idempotency keys** — Prevents duplicate order creation from client retries
6. **AJAX vs non-AJAX** — Cart version mismatch returns JSON 400 for HTMX, redirect for full-page

### Payment Flow Details

Both payment methods converge at `ProformaPaymentService.record_payment_and_convert()` — a single idempotent method that validates payment, creates the invoice, and emits `proforma_payment_received` via `on_commit`.

**Stripe (card):**
1. Checkout → `create_payment_intent_direct()` creates a Stripe PaymentIntent and a `Payment` record linked to the proforma
2. Stripe processes the card
3. `payment_intent.succeeded` webhook fires → calls `ProformaPaymentService.record_payment_and_convert()`
4. Proforma status: `sent → converted`; Invoice created; `proforma_payment_received` signal fires
5. Signal calls `OrderPaymentConfirmationService.confirm_order()` → order advances `awaiting_payment → paid → provisioning`

**Stripe (confirm_order endpoint fallback):**
- If the webhook hasn't arrived yet, the Portal's `confirm_order` endpoint calls `record_payment_and_convert()` itself (using the `Payment` record as `existing_payment`)
- `record_payment_and_convert()` is idempotent via `select_for_update` on the proforma — whichever path arrives first converts; the second finds `status == "converted"` and returns the existing invoice

**Bank Transfer:**
1. Order created → proforma emailed to customer
2. Customer makes bank transfer
3. Staff uses the **Process Proforma Payment** view (`billing/proformas/<pk>/pay/`) to record payment
4. Same convergence: `ProformaPaymentService.record_payment_and_convert()` → invoice created → order confirmed

All three paths emit `proforma_payment_received` which triggers `OrderPaymentConfirmationService.confirm_order()`.

### Provisioning ownership after confirmation

Card confirmation delegates to `OrderPaymentConfirmationService.confirm_order()` just as
webhook and bank-transfer confirmation do. Canonical confirmation reuses or creates each
service line's linked `OrderItem.service`, retains its purchased billing period and amount,
and enrolls recurring billing before queueing `apps.orders.tasks.provision_order_item`.
Domain lines remain with their registrar. Review-gated orders wait for staff approval.
Repeated confirmation or line delivery preserves the same Service and native account.

The API does not create another Service or dispatch the generic provisioning worker. Its
legacy `provisioning` response list is empty; the order detail shows line progress.
The `apps.provisioning.tasks.provision_service_task` callable remains available for stored
legacy queue payloads.

A historical failed Service without a retryable order line requires manual review of its
provisioning history, ownership and actual native state. A failed status does not establish
that a native account was never created. This change does not attach, retry, activate,
delete or refund historical orphaned Services based on JSON order identifiers. Linked
failures are reviewed on their order line; the existing policy decides whether retry is
safe, including refusal when a create job has an uncertain outcome (`attention`).

## FSM Implementation Notes

- **Protected field**: `FSMField(protected=True)` — direct `order.status = "xxx"` raises `AttributeError`
- **Concurrent transitions**: `Order` uses `ConcurrentTransitionMixin` (optimistic locking) — catch both `TransitionNotAllowed` and `ConcurrentTransition`
- **Test setup**: use `force_status(order, "target")` from `tests/helpers/fsm_helpers.py`
- **`paid` is transient**: `confirm_order()` advances atomically to `provisioning` or `in_review` in the same request; customers rarely see this state in the UI
- See `ADR-0034` for full FSM adoption rationale and `ADR-0038` for proforma payment convergence design
