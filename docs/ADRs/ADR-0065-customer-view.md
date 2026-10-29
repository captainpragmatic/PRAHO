# ADR-0065: Customer View

- Status: Accepted
- Date: 2026-10-28
- Related: ADR-0016 (audit), ADR-0017 (portal sessions), ADR-0032 (dual HMAC)

## Decision

An administrator or support staff member may open a **customer view**: the customer portal as one
active member of one active customer, read-only, for at most 30 minutes and 10 idle minutes. It is a
Platform-owned portal session of its own tier (ADR-0017 section 6), never a second login, and it holds
no credential of the customer.

**Opening it.** The member card on the staff customer page links to a page that names the member,
explains anything that stops the view, and asks for a reason category, a reason of 10 to 500
characters and an optional ticket reference. Submitting it issues a grant: 32 random bytes, stored
only as a SHA-256 digest, valid for 60 seconds, consumed once by a conditional update. The answer is
a page that posts the code to the portal's `/customer-view/redeem/` in the request body, so the code
never appears in a URL, a log or browser history. Only that response widens `form-action` to the
portal's origin. The portal accepts the code only with Platform's exact `Origin`, exchanges it over
the signed channel, replaces the browser session, rotates CSRF and sets a cookie that ends with the
browser. A displaced portal session is ended on Platform when the browser sends it; across registrable
domains a `SameSite=Lax` cookie is withheld from that POST, so the replaced cookie's session is held
by no browser and ends at its own deadline.

**Who and whom.** The staff member must be active, have the `admin` or `support` role, have two-factor
authentication enrolled, and be in a console session whose login completed the second factor. The
target must be an active, non-staff member of an `active` customer. PRAHO customers start as
`prospect`; viewing them is deliberately out of scope until they are active. At most 20 grants per
staff member per rolling hour.

**While it lasts.** Every request re-reads, without locks, the authority that allowed it: the feature
switch, the staff member's role, second factor and console session, both people's credentials, the
membership and the customer's status. Any change ends the view at its next request, with its audit
event. Only `issue` and `consume` lock rows, users in primary-key order, then the customer, the
membership and the grant, so they cannot deadlock against credential writers.

**Read-only on both services.** Platform's HMAC middleware refuses every API call of a customer view
whose URL name and method are not on an explicit list of reads, and any customer id other than the
viewed one. The portal refuses every page that is not a reading page, public routes included, before
any view runs. Both lists are deny by default, and tests call every other route with a customer view
and expect a refusal. Logout and leaving are the only writes.

**What is recorded.** Issue, refused issue, start, every data access, every refusal on Platform and the
end are audit events with the staff member as actor, the customer member as subject, the reason and
the grant. A page the portal refuses never reaches Platform and is logged, not audited; any write it
would have made is refused on Platform too. Session ids appear only as keyed digests. A grant names
the staff console session that issued it and is deleted a day after its view ends.

**What the customer sees.** Nothing: no indicator, notification or email. The amber banner and
"Leave customer view" exist only in the staff browser.

**Switch.** `CUSTOMER_VIEW_ENABLED` on both services (default true). False refuses new grants and
redemptions and ends live views at their next request.

## Accepted risk

A stolen live staff console session that completed the second factor can open customer views
without a further prompt, within the hourly limit, for that session's lifetime. Every view is
audited with its reason. A per-grant second-factor prompt is a one-view change if this is not enough.

## Not in this version

Writes in a customer view (ticket replies, preferences), the customer's data-export entry for these
sessions, and alerting on unusual volume.

## Alternatives considered

A staff-side mirror of portal pages does not exercise the real portal. A separate assertion token per
request (as appstractor-platform uses) adds a second signing layer that buys nothing while the portal
is the trusted HMAC signer (ADR-0032); the session row is the binding.
