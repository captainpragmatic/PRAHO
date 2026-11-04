# Native topology, deployment and recovery

Use `make deploy-prod`, `make deploy-staging`, `make deploy-dev-native`, `make deploy-caddy ENV=…`,
`make ssh-harden ENV=…`, `make ansible-backup ENV=…`, and `make rollback-native ENV=… VERSION=…`.
The controller decodes configuration as data, constructs a private connection inventory and resolves
the requested release once. Every application checkout must match that full SHA. Operator environment
files stay on the controller. Production and Terraform apply are separate operator actions.

`PRAHO_NATIVE_TOPOLOGY` accepts `split` and `combined`. Production defaults to split; dev and new staging
default to combined. Combined production must select `combined` explicitly. Both inventory role groups
then contain the same host. Incomplete split configuration always fails. The compatibility playbook
requires the validated launcher; direct invocation cannot bypass topology validation.

## Configuration

Copy the matching environment example. Configure the following before changing a host:

| Setting | Meaning |
| --- | --- |
| `PRAHO_PLATFORM_SERVER`, `PRAHO_PORTAL_SERVER` | SSH destinations; distinct hosts in split mode |
| `PRAHO_PLATFORM_PUBLIC_IPV4`, `PRAHO_PLATFORM_PUBLIC_IPV6` | Exact direct Platform ingress addresses |
| `PRAHO_PORTAL_PUBLIC_IPV4`, `PRAHO_PORTAL_PUBLIC_IPV6` | Exact direct Portal ingress addresses |
| `PRAHO_PORTAL_API_SOURCE_CIDRS` | Stable Portal egress addresses permitted to call Platform APIs |
| `PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS` | Stable Platform egress addresses permitted to call Portal callbacks |
| `PLATFORM_ALLOWED_CIDRS` | Staff/VPN access to Platform pages, static files and APIs |
| `PRAHO_MONITORING_CIDRS` | Independent remote health access; empty denies remote access |
| `PRAHO_ADDRESS_IPV4_DOMAIN`, `PRAHO_ADDRESS_IPV6_DOMAIN` | Optional paired address-check names on Portal; A-only and AAAA-only respectively |

CIDRs are space separated and canonical. World-open lists, including equivalent aggregates, are
rejected. Loopback probes remain available. DNS A/AAAA answers must exactly match declared ingress
addresses; CNAME/CDN/proxy origins are outside this version's contract. Set stable IPv4 **and** IPv6
egress CIDRs when hosts can select either address family. These are connection-peer restrictions;
forwarding headers do not grant access. Application HMAC, timestamp and replay checks remain required.

Shared SSH defaults are `PRAHO_SSH_USER`, `PRAHO_SSH_PORT`, `PRAHO_SSH_KEY`,
`PRAHO_SSH_PUBLIC_KEYS_FILE`, `PRAHO_DEPLOY_KNOWN_HOSTS_FILE`, and `PRAHO_SSH_ALLOWED_CIDRS`.
Prefix any suffix with `PRAHO_PLATFORM_` or `PRAHO_PORTAL_` to override it independently, for example
`PRAHO_PORTAL_SSH_PORT=22` and `PRAHO_PORTAL_DEPLOY_KNOWN_HOSTS_FILE=/private/operator/portal.known_hosts`.
Enroll host keys through a trusted console before use. Port recovery verifies the pinned identity;
it never accepts a new host key or silently falls back after failed authentication.

`PRAHO_SERVER_IP` / `PRAHO_DEV_IP` remain combined-mode inputs. Conflicting role targets are rejected.
Platform's full environment and libpq passfile never reach a Portal-only host. Portal receives its own
session key, HMAC peer credentials, public configuration and private session/log directories. Existing
Platform state or operator tooling on a Portal target causes refusal; deployment never deletes it.

Split Portal calls `https://<PLATFORM_DOMAIN>/api`, with certificate verification and no insecure HTTP
override. Platform calls `https://<PORTAL_DOMAIN>/order/payment/webhook/`, with that exact domain allowed
for internal outbound requests. Both services listen on loopback and trust only local Caddy.
Combined mode retains Portal's local HTTP connection. Production uses public Portal pages; staging
keeps its outer allowlist. Provider callbacks and unsubscribe links retain application verification.

Caddy obtains certificates through ACME by default. Operators managing certificates externally may
set paired absolute `PRAHO_NATIVE_TLS_CERTIFICATE` and `PRAHO_NATIVE_TLS_KEY` paths on each host; Caddy
must be able to read the key, and all clients must trust its issuer. This never disables verification.
`PRAHO_NATIVE_MANAGE_SWAP=false` leaves swap with the surrounding host/container manager; native VPS
deployments retain swap preparation by default. `PRAHO_NATIVE_UV_CACHE_DIRECTORY` optionally selects an
absolute dependency cache directory, without changing `uv sync --frozen`.

## Maintenance and recovery

Before upgrading an existing origin, apply the maintenance-aware edge with `make deploy-caddy ENV=…`.
An existing older edge is refused during coordinated deployment. `/etc/praho-native/hold-platform`,
`hold-portal`, `hold-callbacks`, and `hold-workers` are root-owned persistent gates outside the checkout.
Ordinary edge updates cannot remove them. Ingress returns 503 and `Retry-After: 600`; API maintenance
keeps the `error: maintenance`, `detail`, and `retry_after` JSON contract. No unprocessed callback is
acknowledged with a fabricated success.

The controller validates both hosts, enables maintenance, drains Portal and Platform web writers,
disables qcluster and backup scheduling, waits for active backups, and takes a fresh database/media
pair. Platform migrations precede Portal deployment. Web services restart while workers and public
write ingress remain held. Verified TLS health, ownership and matching SHAs precede authenticated
non-business probes: good/bad Portal localisation signatures must yield 200/401; a signed empty payment
callback must yield precisely `{"error":"order_id required"}` with status 400. Portal callbacks open
before provider ingress, and customer traffic opens last.

A failure returns nonzero. Keep the reported phase, prior and observed SHAs, backup paths and host
identities in the incident record. Retry the coordinated command after fixing the underlying problem.
If SSH is unavailable, use the enrolled console to inspect the root-owned gates and disabled units;
do not assume an unreachable host completed a recovery command. Do not clear a gate to make a probe
pass. Reboots must retain maintenance and worker holds until a coherent pair is verified.

`make rollback-native ENV=prod VERSION=<prior full SHA>` uses the same downtime and verification
sequence. An applied business migration missing from the target revision refuses code-only rollback.
The same compatibility guard applies to an ordinary deployment, so selecting an older version with
`make deploy-prod` cannot bypass it.
No reverse migrations run automatically. For data recovery, validate the explicit database/media pair
and its provenance, keep both origins and workers held, and follow the [native restore guide](PLATFORM_RESTORE.md#native-restore).
Use `restore-platform.sh --leave-stopped <dump>` on Platform. This takes its safety backup as the
backup owner without enabling scheduled workers, restores only local services, and keeps all holds
active. Split mode refuses a restore that would reopen services independently. Resume through the
coordinated launcher after verifying the selected database, media and migration compatibility.
Coordinate Portal recovery separately before resuming the launcher; a Portal session-store change may
require every customer to sign in again.

## Terraform adoption

Terraform 1.13+ is required for the mocked adoption tests. Keep `hcloud_server.platform`,
`hcloud_server.portal[0]` and existing RDNS addresses unchanged. The existing `hcloud_firewall.praho`
becomes Platform's firewall; split Portal receives `hcloud_firewall.portal[0]`. The legacy `firewall_id`
output remains, alongside role-specific firewall and IPv6 outputs. Both servers have destruction
protection. A missing `native_topology="split"` on existing two-server staging must fail, rather than
destroying its Portal server. Intentional retirement requires a separate reviewed operation.

Save adoption plans with `terraform plan -out=<private plan>`. Review their JSON and require **no**
`delete` action for any `hcloud_server` (including replacement actions). Confirm server IDs, addresses,
RDNS and SSH handoff inputs are retained, then review only firewall attachment changes and the new
Portal firewall. Saved plans can contain credentials; keep them outside the checkout and private.
Do not apply an unsaved replacement plan. Public ports 80/443 remain available for HTTPS certificates
and provider callbacks; Caddy enforces path-specific caller policy.

Run `make check-native-adoption-plan PLAN=/private/path/adoption.tfplan TOPOLOGY=split` against
the saved plan, selecting the topology recorded before adoption. This reads its JSON privately,
checks prior server identities, and rejects server or RDNS deletion/replacement. Human review of
the firewall attachments and provider-specific settings remains required before a separately
authorized apply. `make test-native-infra` also proves the missed-staging-setting refusal using
mocked prior state, without cloud resources.

Dev and staging retain `DEPLOY_METHOD=rsync` as a transport option. It transfers only a clean
checkout of the same resolved commit, including the minimal Git metadata needed to verify its SHA.
Uncommitted controller changes and ignored operator files are excluded; publish or select the
intended revision before deployment. Production uses Git.

HTTPS callbacks use the configured public Portal origin in combined mode too. Set
`PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS` to include the host's actual IPv4/IPv6 self-connection sources;
the controller refuses an empty list before deployment. The callback probe uses that same origin
without overriding DNS to loopback.

## Guided cutover

1. Record the current full release SHA, both domains' A/AAAA records, TTLs and certificate expiry.
   Record the existing server IDs and topology. Lower TTLs in advance and wait out the previous TTL.
   Select a qualified release that contains the native orchestration and authenticated callback
   contract. First qualify that release in combined mode when upgrading an older installation;
   retain a qualified prior release as the code rollback target. Historical releases that fail
   the deployment probes cannot be reopened by bypassing those probes.
2. Record and validate a complete Platform database/media backup pair and its provenance. Preserve
   Platform's database, media and encryption keys. Confirm staff/VPN and monitoring access over both
   families, console recovery, stable peer egress, provider delivery logs and the maintenance window.
3. Select a clean Portal host. Enroll its SSH identity independently. Prepare direct Portal DNS and
   certificates, and explicitly select split topology in the controller environment and Terraform.
   Validate the saved infrastructure adoption plan before a separately authorized apply.
4. Install the maintenance-aware edge on the existing host before deploying. Keep the old Portal
   origin serving genuine 503 maintenance responses through DNS expiry; never redirect queued POSTs
   or acknowledge callbacks that were not processed. Preserve its gate even after the new Portal opens.
5. Run the coordinated deployment using the qualified target release. Verify both address families, issuer
   trust, equal SHAs, OS identity, good/bad HMAC probes and the empty signed callback. Verify the real
   customer login flow through Caddy using an operator-approved test account.
6. Reopen in the launcher's order. Observe application errors, task backlog, mail delivery and provider
   event IDs. Retain the old origin until the longest prior TTL and observed DNS cache expiry pass.
   Announce that moving the private Portal session store may require a new sign-in.
7. Reconcile the maintenance window against provider event logs and PRAHO payment/email/audit records.
   Retain the prior release, backup pair and old origin until the observation period is accepted.

## Provider redelivery and reconciliation

Maintenance creates real temporary webhook failures. This release adds no webhook broker and makes
no universal zero-loss delivery claim. Record the start/end timestamps and provider event identifiers.

| Provider | Operator recovery |
| --- | --- |
| Stripe | Inspect failed endpoint deliveries in Workbench. Use the [supported resend operation](https://docs.stripe.com/webhooks#manual-retries), then reconcile payment/invoice state and deduplication records by event ID. |
| PayPal | Inspect event delivery status and use [Resend in the events dashboard](https://developer.paypal.com/api/rest/webhooks/events-dashboard/), then reconcile the original transaction and PRAHO payment. |
| SES/SNS | Inspect subscription delivery failures and the configured retry policy. Recover retained notifications from the subscription's [dead-letter queue](https://docs.aws.amazon.com/sns/latest/dg/sns-dead-letter-queues.html); without one, exhausted deliveries can be discarded. Investigate subscription confirmation separately. |
| Mailgun | Inspect event delivery logs against the [webhook retry policy](https://documentation.mailgun.com/docs/mailgun/user-manual/webhooks/webhook-retries), which excludes delivery notifications from its general retry rule. Reconcile bounces, complaints and suppression state; use replay/export only where the account supports it. |
| SendGrid / other Anymail providers | Inspect failed deliveries against the provider's policy. [SendGrid retries unsuccessful event posts for a bounded period](https://www.twilio.com/docs/sendgrid/for-developers/tracking-events/twilio-sendgrid-event-webhook-overview); it does not follow redirects. Reconcile missing and duplicate event IDs individually. Anymail follows its upstream provider. |
| Virtualmin / managed nodes | Check the sending node's event/retry log and PRAHO provisioning state. Reissue only the original authenticated event through its supported sender path; reconcile partial operations before retrying. |

Check each provider's current delivery policy before scheduling cutover. A provider having retries
does not establish that every event was delivered or that its retention window is still open.

## Acceptance gate

`make test-deploy` runs offline contracts. `make test-deploy-docker` runs real Caddy routing.
`make test-native-infra` formats, validates and runs mocked Terraform plans without cloud credentials.
`make test-native-deploy` runs the dedicated Ubuntu 26.04/systemd lab with SSH, Ansible, PostgreSQL 16,
Python 3.13, frozen dependencies, real Django/Gunicorn processes, DNS and a trusted fixture CA. It fails
on unavailable prerequisites, empty collection, skips, failures and errors. Integration CI and nightly
invoke it explicitly; generic integration collection excludes it. Container tests use host-managed
swap and do not establish a production VPS's kernel, external routing or console behavior.
