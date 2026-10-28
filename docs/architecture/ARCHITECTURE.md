# PRAHO Platform Architecture

**Source snapshot:** 2026-10-27, including the ADR-0061 Phase 3 and Phase 4 implementation branches.
This describes repository behavior, not deployment status. [ADR-0061](../ADRs/ADR-0061-account-hostnames-follow-the-account.md)
remains Proposed; the [execution plan](account-hostnames-dns-mail-plan.md) records phase verification and remaining work.

## Service boundaries

PRAHO is a Django modular monolith with two HTTP services and a background worker. Platform owns business
models and external integrations. Portal renders customer pages and calls Platform through a signed API.
The worker runs Platform code against the same database; it is not a separate business-data service.

| Component | Responsibility | Storage and outbound access |
|---|---|---|
| Platform, port 8700 | Staff UI, authenticated APIs, business services and authorization | PostgreSQL, database cache, provider adapters |
| Portal, port 8701 | Customer HTML/HTMX pages, forms and signed Platform client | Local SQLite sessions and infrastructure counters; disposable local-memory cache; Platform HTTP API |
| Django-Q2 worker | Provisioning, DNS checks, provider operations, notifications and scheduled work | Platform PostgreSQL ORM broker and business models; bounded external transports |

Portal has no Platform business-model imports or PostgreSQL connection. Its local database is still required:
it stores login sessions and shared rate-limit, replay and idempotency claims. Losing it forces re-login and
loses those coordination records, while business records remain on Platform. Portal is not a stateless process.

## Repository structure

```text
services/
  platform/
    apps/                # 17 installed local Django apps
    config/              # Platform settings and root routes
    templates/           # Staff pages
    tests/               # Platform unit, integration and provider-wire tests
  portal/
    apps/                # 10 installed local Django apps; API clients and browser views
    config/              # Portal settings and root routes
    templates/           # Customer pages
    tests/               # Customer views and signed-client tests
shared/ui/               # Shared component templates and JavaScript
assets/css/              # Shared tokens and service-specific Tailwind entry points
deploy/                  # Docker, Caddy and native systemd/Ansible deployment
tests/integration/       # Cross-service and deployment-boundary checks
docs/ADRs/               # Architecture decisions
```

Platform's installed local apps are `common`, `users`, `customers`, `billing`, `tickets`, `provisioning`,
`infrastructure`, `products`, `orders`, `domains`, `notifications`, `integrations`, `audit`, `ui`,
`promotions`, `settings` and `api`. Portal installs `common`, `users`, `dashboard`, `billing`, `tickets`,
`services`, `dns`, `customers`, `ui` and `api_client`; its URL configuration also mounts the `orders` package.
The authoritative lists are the services' `config/settings/base.py` files.

Platform apps share one database. Domain services coordinate transactions and invariants; infrastructure
gateways encapsulate external protocols. This is not a strict dependency DAG: hosting publication and customer
DNS intentionally collaborate. [ADR-0007](../ADRs/ADR-0007-function-level-cross-app-imports.md) defines deferred
cross-app model imports and exempts API composition roots. `make lint-imports` checks new import dependencies.

## Storage, sessions and authentication

Platform base settings use PostgreSQL and Django `DatabaseCache` in `django_cache_table`. Django-Q2 uses
the same database's ORM broker with asynchronous execution. Platform sessions use `apps.users.session_backend`,
which coordinates persisted sessions with their revocation index.
Development and fast unit-test settings may substitute SQLite; PostgreSQL concurrency checks are required to
exercise the real row locks and deferred foreign-key behavior.

Portal uses SQLite in every environment, with WAL mode and a configurable `SESSION_DB_PATH`.
`apps.common.session_store` merges concurrent session writes. The `common_counters` infrastructure model
supports rate limits, expiring token-owned claims and webhook replay protection across Portal workers.
`LocMemCache` holds disposable, per-process data; it is not the shared replay or checkout-claim store.
See [ADR-0050](../ADRs/ADR-0050-portal-infrastructure-tables.md) and
[ADR-0055](../ADRs/ADR-0055-portal-sessions-merge-concurrent-writes.md).

Customer credentials are checked by Platform. Portal validates browser form input, forwards credentials to
`/api/users/login/`, then stores the returned identity, membership and session-authentication information in
its own server-side session. The Portal session cookie is `portal_session`.

Portal-to-Platform business API requests carry `X-Portal-Id`, `X-Nonce`, `X-Timestamp`, `X-Body-Hash` and `X-Signature`.
The HMAC-SHA256 canonical string binds the method, normalized path/query, content type, body hash, portal ID,
nonce and timestamp. User/customer context is bound in the signed JSON payload. Platform verifies the service
signature and replay controls before API decorators establish the active customer membership and role.
DNS status and zone reads permit active customer members; DNS mutation intents require owner or technical roles.
Secrets use `PORTAL_HMAC_SECRET` and Platform's `PORTAL_HMAC_CREDENTIALS` registry when configured; legacy
mode uses `PLATFORM_API_SECRET`. Production configuration applies the required isolation checks.

Platform-to-Portal payment webhooks use a separate `PLATFORM_TO_PORTAL_WEBHOOK_SECRET`, signing `ts.body`
with `X-Platform-Timestamp` and `X-Platform-Signature`; accepted signatures reserve shared SQLite counter claims.

## HTTP routes

Portal serves browser pages, not a versioned `/api/v1` customer API. Current entry points include:

| Browser route | Purpose |
|---|---|
| `/login/`, `/logout/`, `/profile/` | Customer session and profile |
| `/dashboard/`, `/billing/`, `/tickets/`, `/services/` | Customer business pages |
| `/company/`, `/order/` | Team/company management and checkout |
| `/dns/`, `/dns/import/<service_id>/`, `/dns/zones/<zone_uuid>/` | DNS list, hosting-scoped import and zone management |

Platform mounts the signed service API under `/api/`, with domain subroutes such as `/api/users/`,
`/api/customers/`, `/api/billing/`, `/api/services/` and `/api/dns/`. DNS reads use signed JSON POSTs as well
as mutations; do not infer an endpoint's HTTP method from its name.

| Platform endpoint | Method and behavior |
|---|---|
| `/api/users/login/` | POST; validate customer credentials |
| `/api/services/<service_id>/dns-status/` | POST; read saved public DNS status |
| `/api/services/<service_id>/dns-status/recheck/` | POST; persist a bounded recheck request |
| `/api/dns/zones/`, `/api/dns/zones/<zone_uuid>/` | POST; tenant-scoped paginated reads |
| `/api/dns/zones/import/` | POST; parse a complete zone-file upload and save a proposed revision |
| `/api/dns/zones/<zone_uuid>/crosscheck/`, `confirm/`, `switch/`, `delete/` | POST; validate current intent and persist background work |
| `/api/dns/zones/<zone_uuid>/records/` and `records/<record_uuid>/` | POST; request a typed customer record change |

The authoritative route definitions are `services/portal/config/urls.py` and
`services/platform/apps/api/urls.py` with their included domain URL modules. Liveness routes are Portal
`GET /status/` and Platform `GET /api/users/health/`; these shallow responses do not prove database,
provider, DNS or authentication health.

## Hosting names, DNS monitoring and customer zones

### Account identity and publication

`VirtualminAccount.server` identifies the actual hosting node; `Service.server` is a separate service-level
association and is not used as authoritative customer routing advice. Each eligible account has an
`AccountHostname`, with stable identity and direct A/AAAA records through the account-name DNS gateway.
Certificates and node installation evidence gate publication. Account-name customer-content previews remain
disabled in this rollout. Public Suffix List inclusion is a prerequisite for any future enablement, not an
instruction to enable them.

Planned cutover coordinates source write barriers, held target restore, activation, forwarding and authoritative
DNS convergence. Ownership commits once under a live operation lease and publication lock. Before commit,
compensation restores recorded source state; after commit, work proceeds toward the committed target.
Recovery from an unavailable source requires explicit source fencing. A durable `MigrationBridge` retains
the old route separately from migration completion; fresh frontend agreement, cache age and cleanup proofs
gate source removal. These are Phase 2 implementation contracts, not a claim that every deployment enables them.

### Phase 3: saved DNS observations

`provisioning/hosted_domain_dns_service.py` owns saved status and incident state; its dispatcher and worker
in `hosted_domain_dns_tasks.py` call `infrastructure/dns_probes.py`. Probes share a 90-second/96-query budget
and report apex, `www`, CAA, DNSSEC and mail components independently. DNSSEC checks DS/DNSKEY consistency;
they do not claim full cryptographic validation. External or null MX is valid when hosted mail is not enabled.

Reads and manual recheck requests perform no DNS or provider network I/O. Saved results are invalidated against
current tenant, routing generation, maintenance and freshness. Background workers commit fenced observations;
verified deterioration from a healthy baseline may open one notification incident. Unknown observations do not
manufacture a healthy baseline or an outage. See the [ADR-0061 implementation plan](account-hostnames-dns-mail-plan.md#phase-3-watching-customer-dns).

### Phase 4: independently owned customer DNS

The `domains/dns_zone_*` modules own `HostedZone`, immutable import revisions, stable record slots and durable
operations. Enrollment starts from an existing hosting service's primary domain. The first import requires a
complete uploaded zone file; DNS probes cross-check it rather than trying to discover arbitrary record names.
The preview includes original SOA/NS infrastructure, proposed managed-record replacements and unsupported-record
refusals before any provider write or nameserver instructions. The customer confirms the exact revision and digest.

`domains/dns_zone_tasks.py` advances leased provider/checkpoint operations through the typed
`infrastructure/dns_zone_gateway.py` interface and Cloudflare adapter. It verifies complete provider inventories,
record ownership and immutable zone binding, and preserves ambiguous outcomes for reconciliation. Nameserver
instructions require current published/read-back and DNS handover evidence. A supported registrar change is a
separate durable operation; other owners change their registrar manually. Customer edits support A, AAAA,
CNAME, MX, TXT, SRV and CAA; PRAHO-managed records are protected.

`provisioning/managed_dns_service.py` publishes hosting-managed customer records under the same
`AccountHostname` publication fence as the owned name. Migration/recovery share per-record original TTL,
provider confirmation, convergence and restoration evidence. Account and name locks serialize hosting
ownership transfers with publication; `HostedZone.customer` remains the independent DNS data owner.
Hosting termination withdraws managed web records while unrelated DNS remains. Whole-zone deletion requires
a current export and verified move-away/cache-age proof. See the [ADR-0061 implementation plan](account-hostnames-dns-mail-plan.md#phase-4-our-nameservers-on-cloudflare).

Portal's `apps/dns` contains forms, view orchestration and a bounded signed API client; staff diagnostics show
saved private evidence on Platform. Neither interface runs customer DNS probes or provider calls inline.

### Phase 5: withdrawn

Mail on the Virtualmin web nodes is withdrawn. Customer mail moves to a dedicated mail node (#790, #791).
Mailboxes already on the web nodes stay where they are, mail-enabled moves and recoveries stay refused, and
customer-zone import preserves external mail routing.

## Deployment and isolation

`deploy/docker-compose.single-server.yml` defines:

| Service | Role | Networks |
|---|---|---|
| `caddy` | HTTPS edge and hostname routing | `web` |
| `platform` | Staff HTTP app and API | `web`, `internal` |
| `qcluster` | Platform background worker, no HTTP listener | `web`, `internal` |
| `portal` | Customer HTTP app with local SQLite | `web` |
| `db` | PostgreSQL | `internal` |

Portal shares no network with PostgreSQL. Both Platform and its worker need the business database and external
integration access. Other production Compose variants split these roles across hosts or a container service.
Native Ansible installs `praho-platform`, `praho-portal` and `praho-qcluster` systemd services behind Caddy.

On the Platform hostname, Caddy permits the configured public API, webhook and unsubscribe paths; staff pages
and staff static files require `PLATFORM_ALLOWED_CIDRS`. Stored media is served through authorized Django views,
not a public media route. See [deployment instructions](../deployment/DEPLOYMENT.md) and
[ADR-0057](../ADRs/ADR-0057-media-storage-filesystem-or-private-bucket.md) for the private-file contract.

## Verification and diagrams

Use `make test-platform`, `make test-portal`, `make test-integration`, `make lint` and `make check-types` for
application checks. Provider-wire fixtures test complete inventories and uncertain outcomes without real provider
writes. PostgreSQL concurrency tests cover ownership/publication and cutover locking. Native node behavior is
verified separately in the Virtualmin lab; passing unit tests does not establish a production rollout.

The [diagram index](README.md) links the system, request/worker flow, deployment and selected dependency views.
The [ER diagram](diagrams/entity-relationships.mmd) is a selected subset with actual model PK/FK types.
The [table taxonomy](diagrams/database-tables.mmd) is the 2026-10-27 snapshot of 166 concrete local Platform model
tables; it excludes framework tables and automatically created many-to-many tables. Neither diagram replaces
the model definitions or migrations. No latency or availability benchmark is asserted by this guide.
