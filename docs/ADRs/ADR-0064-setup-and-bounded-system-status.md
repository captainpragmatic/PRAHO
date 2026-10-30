# ADR-0064: Setup Configuration and Bounded Operational Status

- Status: Accepted
- Date: 2026-10-27
- Related: ADR-0016 (audit), ADR-0020 (Django-Q2), ADR-0059 (hosting backups), ADR-0060 (Virtualmin administration)

## Decision

Account usage has a separate hourly collection and six-hour attention clock
(ADR-0068); its source timestamps do not refresh node-health evidence. The
25-minute expiry below continues to apply to infrastructure observations.

Setup is a derived configuration checklist. Operational failures belong to System Status.
The dashboard remains the login landing page. Administrators see one compact attention
area linking to both pages, with health issues first. Optional branding and domain sales
do not prevent completing required setup.

Use the existing `praho-cluster` and its two execution workers. Reconcile the existing
system-status and node-health schedules to ten minutes. Long provisioning jobs may delay
checks. Display observations older than 25 minutes as Unknown rather than preserving green.
Manual checks are queued and coalesced. Rendering pages does not contact providers.

Persist two new technical models:

- `SystemCheckState`: one current observation per global check or node/check, including
  effective configuration identity, generation, attempt sequence, token and lease.
- `NodeResourceHourlySummary`: one row per node/UTC hour, with independent sum, count and
  maximum for CPU, memory and disk. Retain 30 days; store no individual samples.

Node metrics come from the existing Virtualmin `info` API. Its response may itself be
cached, so observation time means retrieval time. Missing metrics remain unknown. Network
rates are unavailable in this version. Manual refresh does not add an aggregate sample.
Scheduled samples contribute at most once per ten-minute slot.

Capture effective inputs before I/O. Lock node then current-state row before accepting
results, recheck identity/generation/token/sequence/lease, and fence existing automatic
failure/recovery writes in the same transaction. Reject obsolete results entirely.
Publish the dashboard cache after evidence commits, while holding the current publisher's
row lock, so failed or older writers cannot expose a newer-looking green result.

These models are bounded, mutable technical observations, not business audit events.
Do not create `AuditEvent` rows per poll or retain API telemetry in Q2 results. Existing
credential-access, configuration-change and backup-job security audits remain in force.
Signals only invalidate derived setup caches after commit. Periodic evaluation remains
the fallback for bulk updates and changes outside Django.

## Backup evidence

Setup checks that backup scheduling and off-server storage are configured. Health checks
actual outcomes against each backup schedule plus two hours. An empty node has no customer
backup due. Platform backup completion requires both database and media, remote checksum
readback and a manifest published last. Multipart ETags are not checksums.

Native Platform backups use a systemd one-shot service and timer with the deployed
EnvironmentFile and service account. Docker retains its host script and streams artifacts
to a fixed command inside Platform. Web workers need neither a Docker socket nor host
backup mounts. Local backups remain available when off-server publication fails.

Customer backups reuse Platform's durable backup jobs, private spool and S3 publication
pipeline. Admit at most one scheduler-owned pending/running job at a time. Do not distribute
S3 credentials to nodes. Existing local/direct-S3 settings remain until explicitly switched.
The node backup playbook retires only schedules that PRAHO owns.

Off-server Platform artifacts and their final manifest use conditional writes and cannot
overwrite an existing run. Validate the input before completing multipart uploads and verify
both remote objects before publishing the marker. A marker proves pair completeness; current
configuration and execution ownership separately fence the health result. Customer completion
proof binds to the same frozen storage configuration used to construct its client and bucket.
Changing that destination reopens health and scheduled coverage for the current cycle.

Imported servers use a separately configured root private key and exact hostname/port
entries in the operator's known_hosts file. Root is necessary for the current streaming
transfer playbooks. No passwords, ambient agent, bootstrap scan, managed-key fallback,
key generation or SSH port changes occur in this adapter. Managed nodes retain their
existing enrolled identity and trust path.

## Consequences

Storage stays around 720 aggregate rows per node over a normal 30-day window, plus
current-state rows. Cleanup is bounded and repeated. This is operational guidance rather
than a full monitoring system. Historical outage timelines, minute-level metrics, network
rates and separate monitoring workers are intentionally outside this decision.

Production rollout and an isolated full Platform restore rehearsal remain separate
operational acceptance steps.
