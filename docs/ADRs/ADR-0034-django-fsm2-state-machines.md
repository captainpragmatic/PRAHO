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
| Invoice | billing | 6 | No |
| ProformaInvoice | billing | 4 | No |
| Payment | billing | 5 | No |
| Refund | billing | 7 | No |
| Subscription | billing | 7 | No |
| Service | provisioning | 7 | Yes |
| Domain | domains | 7 | No |
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
- `post_transition` signal replaces fragile `post_save` status-diff patterns
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
4. **Audit**: `post_transition` signal logs every state change via `log_security_event()`
5. **Test**: `force_status()` helper is the ONLY allowed bypass (in test code only)

## Consequences

### Positive
- Illegal state transitions fail loudly at runtime
- Transition rules are declarative and discoverable on the model class
- Audit trail is automatic via `post_transition` signal
- Race conditions handled by `ConcurrentTransitionMixin` on Order and Service

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

    @transition(field=status, source="draft", target="pending",
                conditions=[lambda self: self.items.exists()])
    def submit(self) -> None:
        pass  # Side effects go in post_transition signal

# Service: orchestrates and returns Result
def update_order_status(self, order, new_status):
    try:
        getattr(order, TRANSITION_MAP[new_status])()
        order.save()
        return Ok(order)
    except TransitionNotAllowed:
        return Err(f"Invalid transition: {order.status} -> {new_status}")
```

### Test setup
```python
from tests.helpers.fsm_helpers import force_status

# Set up test state (bypasses FSM protection)
force_status(order, "confirmed")

# Test the actual transition
order.start_processing()
self.assertEqual(order.status, "processing")
```

## Related
- Issue #96: Direct status assignment bypass
- Issue #104: Security audit findings
- Issue #108: DB CHECK constraints
- Issue #109: Epic tracking this migration
- ADR-0003: Result pattern (Err for TransitionNotAllowed)
- ADR-0016: Audit trail enforcement
- ADR-0022: Strategic seams (model transitions, service orchestration)
