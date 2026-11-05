# Hosting usage warnings and temporary disk relief

Use when enabling #783, reviewing missing or repeated warnings, or granting and
recovering an expiring disk raise. This procedure adds no evidence that native
acceptance has run. Follow [ADR-0068](../ADRs/ADR-0068-observational-hosting-usage.md),
[paid-change recovery](PLATFORM_RESTORE.md#hosting-plan-change-recovery) and the
[owned native gates](../../tests/virtualmin_lab/native/README.md).

## Before enablement

Deploy additive Platform schema and current workers before Portal. Install the
current collector, quota, metadata and notification-policy helpers through the
reviewed native operation. An explicit node handover must verify customer-mail
suppression and Platform delivery readiness before Platform warning mail starts.
Import, a database capability flag or successful mocked transport is insufficient.

Keep broad customer activation off until its gates pass. In particular,
`provisioning.hosting_raises_enabled` stays false during initial qualification.
The warning handover check itself requires a running warning pipeline; use the
controlled canary sequence below rather than attempting handover with that
pipeline disabled. Qualification requires the supported Ubuntu/PHP/storage/database identities, native protocol 2,
actual UID/GID enforcement, neighbor isolation, reboot/update recovery and the
mail-sink controls. Preserve existing mailboxes, website mail and operator alerts;
do not disable the MTA to suppress Virtualmin operational mail.

Run the focused PostgreSQL tests, full integrated gates, real native workflows and
RO/EN browser checks on the final combined head. Pay particular attention to paid
upgrade while a raise is active, scheduled downgrade with a raise valid through
the boundary, held create/restore/migration during expiry, later credential
readoption and disputed commercial authority. New archive work must not use an
expiry-reduction exception.

Run `make test-portal-hosting-warnings-browser` for the English/Romanian warning,
raise and preference matrix at mobile, tablet and desktop widths. That gate uses
real Portal views, forms, CSRF and templates with Platform response doubles.
`make test-hosting-plan-checkout-full` exercises real Portal login, signed Platform
APIs, webhook verification and settlement on an isolated local PostgreSQL fixture;
Stripe/provider and initial native qualification remain explicit doubles. Both
browser gates are required in CI and complement the actual native acceptance above.

Confirm the hourly `virtualmin-usage-sync` publisher and five-minute
`hosting-warning-deliveries` delivery schedule are registered by the existing
scheduled-task setup. Confirm both active English and Romanian warning templates,
the preference field and the current final-send policy are installed. The delivery
readiness check must pass with actual deployed configuration. Native mail handover
sets a silent baseline before a bounded critical-first current-state rollout.

For the canary, use the isolated native Platform database and owned mail sink.
After deploying schema, templates, workers, collector and the configured backend,
enable `provisioning.quota_warnings_enabled` there while nodes remain native-owned;
the per-node ownership gate still refuses Platform warning sends. Perform the
reviewed native handover, verify suppression and Platform delivery through the
sink, and check the silent baseline and bounded rollout. A setting alone establishes
neither handover nor native proof. Only then plan controlled customer enablement.
If using a shared environment, first verify every non-canary node remains
native-owned: the global switch could otherwise release mail on already handed-over
nodes. Do not change existing customer mail ownership merely to satisfy a test.
Preserve operator-customized templates; review both stored text and HTML against
the current threshold, partial, pending-plan and raise/expiry wording.

## Customer and staff checks

- Portal service cards and details show 80/95/100 conditions against purchased
  operational allowance, with measurement age and partial/stale context. A pending
  upgrade shows the requested plan separately; it does not erase the old condition.
- The dashboard shows active high conditions only for the current customer. A
  cached bandwidth warning must expire at the real operator-month boundary.
- Customers manage optional quota-warning mail under **Company → Notifications**
  (`/company/notifications/`). Critical content still respects hard delivery and
  privacy refusals. Do not infer delivery authority from the preference alone.
- Staff service details show a bounded trend and owner-scoped delivery history.
  After ownership changes, old-owner warnings and recipient data must not appear,
  including a later transfer back to the same customer.
- Commercial upgrade links open the real customer quote/payment workflow. Technical
  users retain the support path. A resource exception or temporary raise does not
  accept a paid plan or change its recurring charge.

## Grant or extend temporary relief

An administrator or manager opens **Temporary disk relief** from the staff service
detail, checks fresh safety evidence, selects the same customer's ticket and gives
a reason. The form carries current base/overlay revisions and a submission UUID.
Explicitly acknowledge automatic removal at expiry, including if usage remains
above the purchased allowance. A queued read-only usage refresh performs no native
write in the HTTP request.

The requested R must fit its 25-percent/5-GiB bound and current shared-node capacity
admission. An active raise can extend expiry but cannot stack another R. The form
bounds expiry to the original seven-day limit and stops offering an extension at
that limit. A successful request means **pending verification**, not available
capacity. Verify the current native receipt before promising the capacity.

Normal warning thresholds continue to use purchased A during a raise. The public
raise states distinguish requested, verified, expired-awaiting-verification and
verified removed. Price, invoice evidence and recurring authorization stay intact.

## Expiry and recovery

The existing hosting-limit dispatcher sweeps due raises even with new acceptance
disabled. Expiry advances the persistent overlay revision and requests removal of
R against the current canonical operational base. It may reduce to the approved
base cap while usage is still above that cap; the original consent authorizes this
specific removal. It cannot authorize another commercial downgrade or cap increase.

When a newer desired plan is pending, remove the old operational R without applying
the unverified desire. When the newer base is already applied, obsolete cleanup
must stop. Reviewed parent snapshots remain immutable. Only bounded never-issued
work can transfer its reservation to a smaller reviewed successor; issued or
uncertain work needs its exact native fence. An elapsed lease never releases
uncertain capacity.

If a connection rotates, explicitly inspect and readopt the current qualified
connection before recovery. Historical connection credentials do not certify new
work; installation, filesystem, ownership, canonical node, current domain/UID/GID,
epoch and boot evidence must still match. A new installation or unknown current
qualification requires review.

Keep failed expiry visible and retain reservations, original issuance evidence and
fencing tokens. Use the existing recovery lane; do not clear FSM states, delete the
raise row, reset generations, run `quotaoff` or enable a suspended account. A
receipt from an expired raise cannot certify removal. Only a fresh verified
operational receipt can change the displayed expiry result.

## Delivery diagnosis and rollback

Trace accepted resource evidence → warning episode → intent → delivery version →
linked EmailLog → final dispatch result. Publication and delivery locks are
separate. Missing, unlimited or stale evidence creates no new crossing or reminder.
Two distinct accepted UTC hours below the rearm level are required before another
crossing; same-hour replay is insufficient.

For optional content, inspect both quota-category preference and global optional
email consent. For all content, inspect current owner, recipient, lifecycle,
suppression, native mail ownership and source period. Never copy a refused body
into a new message by hand. Only a proven never-dispatched version can be
re-batched; ambiguous provider acceptance retains uncertainty. Deleting a linked
EmailLog does not reopen an obligation.

Delivery snapshot version 2 binds the requested limit revision and finite
allowances as well as the operational warning denominator. A changed pending
request or a newly verified plan invalidates old pending-plan wording, including
when the disk amount happens to stay equal. An older queued snapshot fails closed;
only the existing proven-undispatched recovery path may rebuild it. Do not rewrite
stored bodies or reuse uncertain provider acceptance as a fresh send.

Disabling the warning flag stops new warning delivery; it must not be represented
as cancelling a provider acceptance that was already uncertain. Disabling new
raises leaves expiry and fenced recovery active. Preserve current workers, schema,
applied caps, immutable applications and delivery history. Monitor stale collection,
delivery refusal/uncertainty, pending paid changes, expiry attention and native mail
ownership. Resolve actual financial liabilities through the paid-change procedure.
