# System Status checks

The staff dashboard links to `/system-status/`. Administrators can open a node's detail view,
see the last 48 hours of hourly averages/peaks, and request a refresh. Both the existing
`apps.common.tasks.system_status_check` and Virtualmin health schedules run every ten minutes
on `praho-cluster`. Manual POST actions queue checks; GET requests do not contact providers.
Green means that the specific check passed, not that every operation in that subsystem was tested.

`/settings/setup/` is separate. It derives required configuration from current records and
links to canonical settings anchors. Missing configuration reopens an item; an outage does not.
Branding and domain sales remain optional. The dashboard remains the login landing page.
One administrator attention area links to health issues first, then incomplete setup.

| Item | What the check proves |
| --- | --- |
| Database | `SELECT 1` succeeds on the active connection. The detail names the actual engine. |
| Portal Auth | The running `PLATFORM_API_SECRET`, HMAC mode, registry and isolation requirements form a valid configuration. It does not make a portal round trip. Legacy uses the shared secret, audit supports registry/shared fallback, and enforce requires the registry. |
| Email | Console, file, in-memory and dummy backends are shown as local/disabled. SMTP opens and closes the configured TLS/SSL/authenticated connection without sending. SendGrid checks scopes including `mail.send`, Mailgun checks the sender domain in its configured region, and SES checks account sending readiness and sandbox status. These do not prove recipient delivery. |
| Stripe | Uses the enabled flag and keys from integration settings. The account API is read with the pinned API version; charging readiness, test/live key consistency and a missing webhook signing secret remain visible. No charge or webhook delivery is attempted. |
| e-Factura | Shown for Romanian operators. Uses effective enablement, OAuth configuration, environment and issuer tax identity. One page covering the last 24 hours is read using an existing matching token and the normal local quota reservation. Expired tokens are not refreshed and nothing is uploaded. The documented benign empty-window response is accepted explicitly; other error payloads cannot count as a successful listing. |
| Encryption | Validates every current/previous runtime key and performs an in-memory context-bound encrypt/decrypt self-test. Missing keys mean encrypted operations are unavailable, not plaintext fallback. |
| Credential Vault | Initializes a fresh vault with the actual master key and runs its in-memory integrity test. The legacy status-only `CREDENTIAL_VAULT_ENABLED` flag is not a runtime enablement gate. |
| Sentry | Distinguishes no DSN, a DSN without an active SDK, and an initialized client. Does not send a synthetic event or claim delivery. |
| Platform backups | Uses the applied runner's schedule/timezone and recorded off-server database/media publication. Both objects must pass remote checksum readback before the manifest is published. Failed attempts are red; missing completion becomes overdue after the schedule plus two hours. A changed destination cannot reuse the previous destination's success. |
| Customer hosting backups | Uses durable scheduled backup jobs and their completed S3 manifests, bound to the current storage configuration. An empty installation has no customer backups due. Missing or failed backups become health issues; they do not undo configured setup. |
| Virtualmin nodes | Existing `info` API provides connection health and CPU/RAM/disk. Retrieval time is shown because Virtualmin may cache measurements. Missing values stay unknown. Manual refresh contributes no stored sample. Network rates are unavailable. |
| FX rates | Re-runs the invoice exchange-rate resolver for today's configured currencies against the home currency, including provenance, age and the last fetch outcome. This row is recomputed on dashboard reads so yesterday's snapshot cannot hide today's missing rates. |

## Refresh limits and failure handling

Account usage is shown separately from node resource health. With
`provisioning.usage_sync_enabled`, hourly account observations retain their actual
source time; six hours without a valid disk observation raises usage attention.
Missing/unassigned node accounts are reported for staff review without importing
or remediating them. Unknown/partial monthly response bytes remain explicit in the
portal. The 25-minute node-health expiry and ten-minute health schedule are unchanged.

External probes run in short-lived subprocesses with a five-second deadline per provider and a shared twenty-second budget. The deadline includes DNS, connection, TLS, headers and body streaming. HTTP probes use the outbound HTTPS/DNS protections, accept at most 256 KiB of decoded response data, and neither redirect nor retry. Credentials travel through a private pipe, not command arguments. Probe output consists only of fixed result codes, not raw provider responses or exception text.

Only the configured email provider is contacted. Supported API endpoints are the standard SendGrid US/EU, Mailgun US/EU, Stripe, ANAF and regional SES endpoints. Custom endpoints/backends remain unverified. Restricted credentials can allow sending while denying a diagnostic API; a generic 403 is therefore “Access rejected”, not an invented claim that credentials or permissions are wrong.

Manual refresh uses the existing request limiter and a one-minute queue coalescing window.
The response acknowledges queuing. Refresh the page after the worker completes. A node detail
refresh queues only that node and uses the same configuration-bound observation protocol.

Observations older than 25 minutes display as Unknown, including old failures. Backup age is
evaluated against its own schedule, not against the telemetry window. Dashboard cache entries
expire after 48 hours, with stale rows visibly unverified. Production needs the configured shared
cache; the detailed page also reads durable current observations. Cache writes are confirmed by
readback and happen only after the observation transaction commits. Failed cache reads/writes
remain visible. Two busy Q2 workers can delay checks, which must not leave apparently fresh green.

Individual failures do not prevent other subsystem checks. FX errors remain red, and missing
results do not count as recovery. FX alert evaluation still runs if snapshot storage fails;
deduplication is best-effort during cache outages.

Current state is bounded to one row per check/node. Scheduled ten-minute resource observations
contribute once to each slot's hourly sum/count/peak. No raw samples or per-poll audit events are
stored. Hourly rows are retained for 30 days and pruned in bounded batches. Security and backup-job
audits remain intact. See [ADR-0064](../ADRs/ADR-0064-setup-and-bounded-system-status.md).

## Backup deployment

Configure private off-server S3 settings under **Backup Storage**, then enable
`backup.platform_offsite_enabled`. Customer backups additionally use
`node_deployment.backup_storage=platform`, an enabled backup flag and a valid five-field schedule.
Existing local/direct-S3 modes are retained until explicitly changed. Applying the node backup
playbook retires only PRAHO-owned duplicate schedules. S3 credentials stay on Platform.
Central admission covers Virtualmin accounts. Other panels, including Blesta, retain their local
backup and retention policy when the global storage selection is Platform-managed.

Native deployment installs `praho-backup.service` and `praho-backup.timer`, removes the replaced
named cron job and records the applied runner. Run a manual backup with:

```sh
sudo systemctl start --wait praho-backup.service
sudo journalctl -u praho-backup.service --since today
```

The one-shot runs as the PRAHO service user with the deployed EnvironmentFile. It keeps the local
database/media pair on off-server failure. Use the existing `make ansible-backup ENV=staging`
command for remote execution and optional fetching.

Docker keeps `deploy/scripts/backup.sh` on the host. It creates the normal restricted local pair
and recovery metadata, then streams through `docker exec -i` into the fixed
`upload_platform_backup` command. It does not mount host backups or the Docker socket into web
containers. After installing and verifying the host backup schedule, record its actual schedule
and host timezone, for example:

```sh
docker exec praho_platform python manage.py upload_platform_backup \
  --register-runner docker --schedule '0 2 * * *' --schedule-timezone UTC
```

Registration records applied configuration; it does not install cron or claim backup success.
Supply the timezone used by the host scheduler. Run `deploy/scripts/backup.sh` once and check
System Status. Off-server objects use `platform-backups/<source UUID>/<run UUID>/`; the last
object is `manifest.json`. Its artifacts include their formats, lengths and SHA-256 values.
Artifacts complete through conditional multipart writes, and the manifest uses a conditional
write too. Reusing a run ID cannot overwrite an existing object. Input hashes are checked
before multipart completion, and both remote artifacts are checked before the marker is
published. An unsupported conditional-write operation fails closed and keeps local backups.
The marker proves a complete pair at its recorded destination. Current configuration and
execution ownership are checked separately before System Status can report success.
Docker recovery metadata retains the source images and database major. Retain deployment
encryption keys separately. A complete isolated Platform restore rehearsal is still required
before treating a production backup policy as proven.

Changing the customer-backup destination invalidates old completion proof for current health
and permits the scheduler to create a backup at the new destination. Older backups remain
at their original destination. Missing or malformed legacy markers cannot certify completion.

## Imported Virtualmin servers

API monitoring works without SSH. Archive backup/restore additionally requires a root private
key readable by Platform/qcluster, mode 0600, configured through
`VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH`. Set the imported server's recorded SSH port, normally
9876 under the deployment policy. Enroll its verified host key in `PRAHO_SSH_KNOWN_HOSTS_PATH`
using the exact hostname and `[hostname]:9876` entry. Nondefault-port trust cannot fall back to
port 22. Containers need both files mounted read-only at their configured paths.

Only root key authentication is supported by this archive transport. Passwords, ambient agent
keys, scanning, key generation and managed-key fallback are disabled. A managed node with a
missing key remains a managed-key error. Missing imported key/trust is a definite configuration
refusal before remote work. Ordinary restore, pair restore/release, chain cancel and cleanup use
the same transport.
