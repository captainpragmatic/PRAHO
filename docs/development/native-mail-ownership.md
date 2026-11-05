# Native customer-mail ownership

Platform customer-notification ownership requires a fresh explicit node handover.
Installing helpers, importing a node and adopting kernel quotas do not hand over
mail. Operator alerts, existing mailboxes and website/contact-form mail remain
separate. No part of this policy disables the MTA.

The closed native proof now contains **eleven** emitter checks, including
`os_quota_warnings`. Older ten-check evidence is incomplete and refuses Platform
ownership until the node is inspected and explicitly handed over again. Do not
manually add a successful field to historical evidence.

## OS quota warnings

Ubuntu 26.04's quota4.09-1build1 package defaults daily warnquota off, but package
upgrades preserve existing configuration. The stock daily route invokes
`warnquota -ug` when `run_warnquota=true` and quota appears in fstab. This is
independent of Virtualmin's `quotas.pl`. Equal soft/hard limits do not remove the
route: warnquota detects usage at or above the soft limit.

The native inspector reads protected, bounded cron/default files without sourcing
shell configuration. It recognizes the exact stock cron and simple bounded
assignment/comment forms. Enabled user warnings, dynamic/unknown syntax,
unreadable configuration and unknown cron content refuse handover. The inventory
digest binds both files, including absence. A running `/usr/sbin/warnquota` is
included in the native emitter drain before completed ownership is published.

No OS warning configuration is changed automatically. An enabled imported route
must be reviewed and remediated explicitly while preserving approved group/operator
alerts. Until then native ownership remains authoritative and Platform warning
mail is refused. This is not a promise to classify arbitrary root-installed
custom mail programs.

The exact stock cron bytes are escaped in
`services/platform/tests/fixtures/quota_4_09_cron_daily.json`, preserving upstream
tabs and trailing whitespace through source hooks. Its decoded SHA256 is
`e34d72322f0a58df9d06a0bfd68709efc4801964a8c9b64a7bc0b6e19d9e0f35`.
The packaging archive SHA256 is
`09f63e11efdbeb2a0ddd71f9c445c690bde1ee6e38afa33d5b9be67b2187599a`.
[Official Ubuntu packaging](https://archive.ubuntu.com/ubuntu/pool/main/q/quota/quota_4.09-1build1.debian.tar.xz).

## Restored ACME flags and scheduled backups

The exact-source ACME patch checks the protected persisted ownership marker before
the customer branch. A restored `letsencrypt_email=0` cannot send customer mail on
a handed-over node, including before a later archive-completion check. Explicit
master alerts remain in their separate branch. Missing ownership retains native
customer behavior; malformed, unreadable, unprotected or changed ownership refuses
the customer branch. The prior deployed master-only patch upgrades idempotently;
unknown or duplicated source shapes refuse modification.
Read-only inspection requires the exact installed guard/status patches and the
protected Platform marker, binding their source/ownership digests into inventory.
That witness makes an old restored owner flag safe without forcing a domain
rewrite. Domain flag2 alone cannot certify a missing or changed source guard.
After a native operation fails, first fence/reconcile its exact live claim and
retained holds through the existing operation workflow; node-wide handover remains
blocked while another native operation owns the lane.

Scheduled backup recipient authority is the frozen approved operator list. An
explicit backup `email` field is not implicitly operator-approved. Handover removes
unapproved recipients and the automatic owner flag, preserving approved recipients,
the enabled schedule, destination and `email_err` policy. In pinned Virtualmin8.3
`backup.pl`, the explicit send requires nonempty `email`, while owner sends require
`email_doms`; there is no fallback when both are empty/false.
[Pinned backup sender](https://github.com/virtualmin/virtualmin-gpl/blob/8.3.0/backup.pl#L244).

## Lifecycle verification

Restores and archive migrations inspect the installed protection before dispatch.
Completion checks also run where quota policy remains unadopted. A guarded old
archive can complete without changing its historical notification preference or
adopting quotas. Missing protection refuses dispatch; lost verification after an
issued restore keeps the existing uncertain outcome and never replays it.

Each check retains the operation's actual claim contract. Restores use their
execution token and deadline; creates and retries use their frozen account binding
and claimed/started timestamps, with nullable tokens. An old worker can park only
its own claim generation, preserving a newer worker's state and the native result.

## Evidence boundaries

Unit tests execute the actual patched Perl ACME branch with captured mail calls;
only filesystem ownership metadata and native/provider I/O are doubled. The exact
stock cron runs with relocated private paths and a recording warnquota sentinel;
that proves dispatch and policy refusal, not an actual over-limit kernel mail.
The owned full-mail fixture additionally exercises real Virtualmin backup and ACME
send attempts, mixed/customer-only explicit recipients, operator positives,
retained SMTP/IMAP/contact traffic and actual root OS-configuration refusal.
Its ten Virtualmin send scenarios and the separate OS refusal are reported
distinctly. It does not claim kernel quota acceptance.
The archive trajectory uses a separate disposable web-only account: actual backup
before handover, actual missing-domain recreation after handover, native flag0
readback and renewal emission before metadata repair. Retained mailbox accounts
are not deleted/restored. These new fixture trajectories remain unexecuted until
an owned run records acceptance; their source and unit tests are not runtime proof.

Physical quota denial, reboot/update qualification and complete public restore
acceptance remain their separate release gates. A configuration boolean, stored
EmailLog or userspace mail fixture must not be substituted for those results.
