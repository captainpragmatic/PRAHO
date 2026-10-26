# System Status checks

The staff dashboard shows a snapshot from the daily `apps.common.tasks.system_status_check` task or the staff-only POST refresh action. Hover over a result for its explanation and over its name for the individual check time. Green means that the specific check passed, not that every operation in that subsystem has been tested.

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
| Backup | Looks for an active command invoking this deployment's `scripts/backup.sh` or `deploy/scripts/backup.sh` in the service user's crontab. Comments and unrelated backup jobs do not count. “Scheduled” does not prove a completed or restorable backup. An unreadable crontab is unverified, with a warning when `DEBUG=False`. |
| FX rates | Re-runs the invoice exchange-rate resolver for today's configured currencies against the home currency, including provenance, age and the last fetch outcome. This row is recomputed on dashboard reads so yesterday's snapshot cannot hide today's missing rates. |

## Refresh limits and failure handling

External probes run in short-lived subprocesses with a five-second deadline per provider and a shared twenty-second budget. The deadline includes DNS, connection, TLS, headers and body streaming. HTTP probes use the outbound HTTPS/DNS protections, accept at most 256 KiB of decoded response data, and neither redirect nor retry. Credentials travel through a private pipe, not command arguments. Probe output consists only of fixed result codes, not raw provider responses or exception text.

Only the configured email provider is contacted. Supported API endpoints are the standard SendGrid US/EU, Mailgun US/EU, Stripe, ANAF and regional SES endpoints. Custom endpoints/backends remain unverified. Restricted credentials can allow sending while denying a diagnostic API; a generic 403 is therefore “Access rejected”, not an invented claim that credentials or permissions are wrong.

The refresh button is disabled while the request runs. The existing request limiter applies a one-minute cooldown per staff user when `RATE_LIMITING_ENABLED` is enabled. The response replaces the whole widget. Local checks and rendering can add time beyond the external-work budget.

Snapshots expire after 48 hours and are marked stale after 26 hours. Cached labels and messages are translated in the reader's language. Writes are confirmed by reading back the snapshot, including when the cache backend silently drops a write. A failed cache write still returns the newly computed rows with “Results not saved”. A failed cache read is visible. In local development with a process-local cache, worker snapshots are not shared with the web process; use the manual refresh. Production needs the configured shared cache for daily snapshots to be visible across processes.

Individual failures do not prevent the other rows from being checked. FX verification errors remain red, and missing results do not count as recovery. Daily FX alert evaluation still runs if snapshot storage fails. Deduplication is best-effort during a cache outage, so a repeated daily alert is possible until the cache recovers.
