# ADR-0066: Customer Status Is a Lifecycle Label

- Status: Accepted
- Date: 2026-10-29
- Related: ADR-0016 (audit), ADR-0034 (FSM), ADR-0065 (customer view)

## Context

`Customer.status` is a protected FSM field with four values and five transitions. Three facts made it
harmful:

1. **Nothing moved it.** Self-registration created customers as `active`; customers created by staff took
   the model default, `prospect`. No code, form, admin action or page ever called a transition, so the
   handlers behind them (emails, the suspension cascade) had never run in production.
2. **Platform used it as an access gate.** Every customer-scoped API call refused a customer that was not
   `active`. A prospect could sign in but not price a cart, so it could never pay and never become active.
   An inactive or suspended customer could not pay either.
3. **Customer view copied the gate**, so staff could not open the portal of the customers who most needed
   help.

## Decision

**Status describes where a customer is in its relationship with us. It never decides who may use the
Portal.** Access is the member's user (active), the membership (active) and the customer (not deleted).

| Status | Meaning | Moved there by |
|---|---|---|
| `prospect` | No paid service yet | Creation by staff |
| `active` | Has paid | A first paid invoice (from `prospect`), a new paid invoice (from `inactive`), staff, unsuspension |
| `inactive` | No paid service any more | Staff |
| `suspended` | On hold | Staff, from `active` or `inactive` |

**What moves it.**

- A paid receivable invoice schedules, after the payment commits, an activation in its own transaction
  (`apps.customers.customer_service.activate_customer_after_payment`). It moves `prospect` and `inactive`
  to `active` and leaves everything else alone. It never raises: a failure costs only the label and its
  email, which staff can set by hand. A zero-total invoice counts as paid.
- Staff use the buttons on the customer page. Admins and managers may take every transition; support may
  suspend and unsuspend; billing staff and a bare staff flag may take none. The view enforces the same rule
  as the buttons, runs the real transition on the locked row, and the customer audit records the staff
  member with both statuses.

**What suspension does.** A suspended customer's people keep reading, paying and opening tickets.
Hosting and DNS publication stop until staff unsuspend:

- the suspension cascade suspends the customer's active services, and unsuspending resumes exactly those;
- order fulfilment holds every open service line; unsuspending queues them again, and recovery picks up any
  started line whose hosting never came on;
- a payment neither starts nor restores a suspended customer's service; a service already off for
  non-payment is handed to the suspension, so unsuspending resumes it once the money side is paid up;
- the customer's own DNS record changes, import confirmations and nameserver switches are refused, and
  publishing queued before the suspension waits; reads and exports work. Staff changes run, so staff can
  remove an abusive record during a suspension.

Every check of the suspension goes through `apps.customers.lifecycle`, and every one that turns hosting
back on locks the customer row first, customer before service as billing locks them. The cascades re-check
the status under that lock, so a suspension and an unsuspension in quick succession cannot leave services in
the wrong state.

**Customer view** (ADR-0065) works for a customer in any status: staff see whatever its people can see.

**To lock people out**, staff suspend the person (the member's Suspend button sets the user inactive
everywhere), remove the membership, or delete the customer. Customer suspension is not a lock-out.

## Consequences

- Staff-created customers can use the Portal and buy, and become active by paying.
- The five transitions and their handlers now run. Customer activation no longer switches on pending
  services: orders and billing turn services on, each for what was paid.
- A missed activation after a payment is not retried. It changes no access, and staff can correct it.
- Customer suspension does not stop a customer's people from signing in. A customer whose people must not
  sign in needs those people suspended too.
