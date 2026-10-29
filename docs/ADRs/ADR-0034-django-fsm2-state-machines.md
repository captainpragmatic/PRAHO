# ADR-0034: Adopt django-fsm-2 for State Machines

## Status
**Accepted** - March 2026

## Context

PRAHO has 10 status-driven models across 6 apps where status transitions are enforced only by developer discipline. Nothing prevents `order.status = "completed"; order.save()` — bypassing validation, audit trails, and business rules.

Issue #96 documented a concrete bypass: `confirm_order` does direct `order.status = "confirmed"` instead of calling `OrderService.update_order_status()`.

### Models affected (10 total)

| Model | App | States | Concurrent? |
|-------|-----|--------|-------------|
| Order | orders | 9 | Yes |
| OrderItem (provisioning_status) | orders | 5 | No |
| Invoice | billing | 6 | Yes |
| ProformaInvoice | billing | 4 | No |
| Payment | billing | 5 | Yes |
| Refund | billing | 7 | Yes |
| Subscription | billing | 7 | Yes |
| Service | provisioning | 7 | Yes |
| Domain | domains | 7 | Yes |
| Ticket | tickets | 4 | No |

### Bypass vectors identified

1. Direct `model.status = "xxx"` assignment in app code
2. `QuerySet.update(status="xxx")` bypassing model methods
3. `bulk_update()` with status fields
4. `__dict__["status"] = "xxx"` bypassing descriptors
5. Side effects in transition methods (Stripe/HTTP calls) that fail silently
6. Admin interface allowing arbitrary status edits

## Decision

Adopt **django-fsm-2** v4.x with `FSMField(protected=True)` on all 10 models, combined with defense-in-depth guardrails.

### Why django-fsm-2

- `FSMField(protected=True)` makes `model.status = "xxx"` raise `AttributeError` at runtime
- `@transition` decorators declare valid source/target states declaratively
- `ConcurrentTransitionMixin` provides optimistic locking for race-sensitive models
- Transition signals can expose an explicit source/target pair; auditing must describe the change that persists.
- `TransitionNotAllowed` exception integrates with Result pattern: catch and return `Err(...)`
- At the DB level, `FSMField` is just a `CharField` — trivially reversible

### Alternatives considered

1. **Custom StatusWorkflowMixin (#107)** — would duplicate FSM logic without the ecosystem
2. **django-viewflow** — full workflow engine, too heavy for status transitions
3. **django-river** — DB-driven workflows, unnecessary complexity for code-defined transitions

### Defense-in-depth layers

1. **Runtime**: `FSMField(protected=True)` blocks direct assignment
2. **Lint**: Pre-commit `lint_fsm_guardrails.py` catches `.status =`, `.update(status=)`, `bulk_update` with status
3. **Database**: `CHECK` constraints validate status values at DB level
4. **Audit**: Every business state change has the audit coverage required by ADR-0016. A transition signal,
   an audited orchestration service, or a save receiver that compares persisted state may provide it.
5. **Test**: `force_status()` helper is the ONLY allowed bypass (in test code only)

## Consequences

### Positive
- Illegal state transitions fail loudly at runtime
- Transition rules are declarative and discoverable on the model class
- Business state changes retain an explicit audit trail.
- Race conditions handled by `ConcurrentTransitionMixin` on Order, Service, Payment, Domain, Invoice, Refund, and Subscription

### Negative
- Test setup must use `force_status()` or `Model.objects.create(status="xxx")` instead of direct assignment
- Developers must learn the `@transition` decorator pattern
- Migration adds field type change (CharField -> FSMField, same at DB level)

### Reversibility
High. `FSMField` is a `CharField` subclass — removing django-fsm-2 requires changing the field type back and removing `@transition` decorators. No schema changes needed.

## Key Patterns

### Transition on model, orchestration in service
```python
# Model: declares valid transitions
class Order(ConcurrentTransitionMixin, models.Model):
    status = FSMField(protected=True, ...)

    @transition(field=status, source="draft", target="awaiting_payment",
                conditions=[lambda self: self.items.exists()])
    def submit(self) -> None:
        pass  # The service persists the transition and schedules external work after commit.

# Service: orchestrates and returns Result
def update_order_status(self, order, new_status):
    try:
        getattr(order, TRANSITION_MAP[new_status])()
        order.save()
        return Ok(order)
    except TransitionNotAllowed:
        return Err(f"Invalid transition: {order.status} -> {new_status}")
```

### Private transitions (Subscription pattern)
Some models use private `_method()` transition methods (prefixed with underscore) for internal-only state changes that should not be callable from outside the service layer. For example, `Subscription._cancel_now()` vs the public `cancel()` which schedules cancellation at period end.

### Exception handling — ConcurrentTransition
`ConcurrentTransitionMixin` raises `ConcurrentTransition` (a separate exception, NOT a subclass of `TransitionNotAllowed`) when the state field was modified between fetch and save. All handlers must catch both:
```python
from django_fsm import ConcurrentTransition, TransitionNotAllowed

try:
    order.confirm()
    order.save(update_fields=["status", "updated_at"])
except (TransitionNotAllowed, ConcurrentTransition):
    return Err("Transition failed — invalid state or concurrent modification")
```

### Test setup
```python
from tests.helpers.fsm_helpers import force_status

# Set up test state (bypasses FSM protection)
force_status(order, "paid")

# Test the actual transition
order.start_provisioning()
self.assertEqual(order.status, "provisioning")
```

## Implementation clarification (2026-10-27)

The ten-model inventory above records the original adoption scope. It is not a current model count.
Later business lifecycles, including migration bridges and hosted DNS zones, also use protected FSM fields
and optimistic concurrency where competing transitions are possible.

`post_transition` fires when the Python transition runs, before its save and transaction commit. It does
not by itself prove that the transition persisted. Current implementations also use audited services and
`pre_save`/`post_save` receivers; those receivers must honor `update_fields` and record the value actually
written. External calls continue to follow ADR-0045's committed side-effect boundary. This clarification
corrects the original claim that all models already used one universal transition audit receiver.

Worker leases, dispatch checkpoints and provider-operation outcomes are operational coordination, rather
than customer business lifecycles. Their bounded compare-and-swap writes can use ordinary fields, with a
specific `fsm-bypass` explanation where the guard requires one and an audited aggregate outcome. This
does not permit direct writes to a protected business FSM field or a blanket application-wide bypass.

## Related
- Issue #96: Direct status assignment bypass
- Issue #104: Security audit findings
- Issue #108: DB CHECK constraints
- Issue #109: Epic tracking this migration
- ADR-0003: Result pattern (Err for TransitionNotAllowed)
- ADR-0016: Audit trail enforcement
- ADR-0022: Strategic seams (model transitions, service orchestration)
