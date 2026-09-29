# Customer recovery and service requests

## Password recovery

Customers request recovery at Portal `/password-reset/`. Portal sends a signed
request to Platform, which generates the token and sends the email through its
configured Django email backend. This path is synchronous and needs no queue worker.
Public acknowledgements do not confirm account existence or email delivery. Delivery,
template and configuration failures remain in Platform error logs for staff to diagnose.
Portal transport outages and unavailable rate-limit infrastructure still show a
temporary service error, independently of the submitted account.

Set Platform's existing `portal.public_base_url` setting to the public Portal
origin, with no path. HTTP is accepted only for loopback hosts. Host headers and
customer input cannot choose the email destination. Configure Platform's normal
`EMAIL_*` settings and `DEFAULT_FROM_EMAIL` for actual delivery.

The email opens `/password-reset/confirm/<uid>/<token>/` on Portal. Portal stores
the credentials in the recovery session and redirects to a form without the token
in its URL. Platform validates the token and password under a user-row lock. Tokens
expire according to `PASSWORD_RESET_TIMEOUT` (two hours by default), and a successful
reset makes the token unusable. MFA remains enabled. Successful recovery clears
login lockout and returns the customer to login.

Reset-email requests have separate limits of five per IP per 15 minutes and five
per normalized email per 30 minutes. Confirmation submissions have their own limit
of five per IP and per reset link per 15 minutes. IP limits apply only when clients
are distinguishable through the configured trusted proxies. These counters are independent of login attempts;
opening the link or form consumes no quota. Platform's existing authentication
throttle also applies; its IP limit is shared by requests from a Portal host.
Recovery dispatch retains the authentication middleware's 100–500 ms response floor
with jitter. This does not equalize synchronous mail calls that take longer than that target.

Existing Portal session-hash validation still rejects sessions created before a
password change. Native Platform recovery remains a separate staff-facing flow.

## Service requests

Active owners, billing members and technical members can request upgrades or
downgrades for their customer's active or suspended services. Suspension and
cancellation require an owner or billing role and a reason. Plan cards are informational; staff agrees the
requested plan and any billing effects with the customer through the ticket.

Portal calls `POST /api/services/<id>/actions/` with signed customer and user IDs,
action, reason, and a submission UUID. Platform creates the ticket and its
`ServiceRequest` record in one transaction. Retrying the same submission returns
the same receipt. Changing its payload returns a conflict instead of creating a
second ticket. The original customer, service, and requester remain on the request
even if someone edits the ticket's related-service field.
Portal retains an accepted submission UUID for POST retries after a lost redirect;
opening a fresh request form rotates it for the next request.
Bound POST retries also reach Platform after the service's status changes. Platform
returns a matching receipt while still checking current membership and ownership;
new submissions for inactive services remain rejected.

### Staff workflow

The Platform ticket includes a staff-only panel:

- **Approve** records approval and keeps the ticket in progress.
- **Reject** requires an internal explanation and closes the ticket.
- **Open service** opens the original service's Platform page.
- **Mark completed** records manual completion and closes an approved request.

Approval itself does not modify service status, provider resources, subscriptions,
prices, or invoices. Staff carries out and verifies the agreed change before
marking it completed. Unsupported automated plan changes remain unavailable.

Decisions and their notes are private. Customer APIs return only the submission
receipt and normal customer-visible ticket data. Staff sends any public explanation
using the existing reply form. Identical decision retries do not add duplicate notes;
changed or stale decisions return a conflict and require reloading the ticket.

Pending and approved requests cannot be closed through generic close actions,
reply-and-close, or the inactivity worker. Reopening a closed ticket does not reset
the request's internal review state.

## Deployment and verification

Deploy Platform and apply migrations before updating Portal. The migrations create
request storage; earlier failed submissions have no records to backfill.

Local browser verification uses the dedicated E2E databases and a file-based email
backend under `logs/e2e-mail/`. These messages are not sent externally. A production
delivery check must separately confirm the configured backend reaches an owned
mailbox and that the link opens the public HTTPS Portal origin.
