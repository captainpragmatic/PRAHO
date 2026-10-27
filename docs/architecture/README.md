# PRAHO architecture diagrams

**Source snapshot: 2026-10-27.** These Mermaid sources describe the current repository, including ADR-0061
Phase 3/4 implementation branches. They do not assert deployment or Phase 5 completion. Read the
[architecture guide](ARCHITECTURE.md) and [execution plan](account-hostnames-dns-mail-plan.md) for scope.

| Diagram | Scope |
|---|---|
| [System overview](diagrams/system-overview.mmd) | Portal, Platform, background worker, storage and provider boundaries |
| [Data flow](diagrams/data-flow.mmd) | Browser login, signed requests, saved DNS reads and durable background DNS work |
| [Deployment](diagrams/deployment.mmd) | Production single-host Compose networks, including the Django-Q2 worker |
| [App dependencies](diagrams/app-dependencies.mmd) | All 17 installed Platform apps, with selected verified dependency edges; not a strict layer DAG |
| [Entity relationships](diagrams/entity-relationships.mmd) | Selected business/hosting/DNS entities and actual PK/FK types |
| [Database tables](diagrams/database-tables.mmd) | 166 concrete local Platform model tables as of the snapshot; excludes framework and automatic M2M tables |
| [Rate limiting](diagrams/rate-limiting.mmd) | Portal middleware, Platform global throttles and endpoint-specific throttles |

Portal has its own SQLite sessions and infrastructure counters/claims plus disposable `LocMemCache`.
It has no Platform business models or PostgreSQL connection. Platform and `qcluster` share business storage;
DNS/provider network work belongs to bounded background jobs, while customer/staff requests read saved state
or persist intent. Cloudflare customer zones and owned account-name records use separate gateway contracts.

## Viewing locally

Use a local Mermaid preview extension or an already installed Mermaid CLI. For example, from the repository root:

```bash
mmdc -i docs/architecture/diagrams/system-overview.mmd -o /tmp/praho-system-overview.svg
```

GitHub renders Mermaid when its source is embedded in a Markdown `mermaid` fenced block. The `.mmd` files
remain the editable sources. Rendering locally avoids uploading internal architecture to a third-party renderer.

## Maintenance

Update the relevant sources when a service, provider adapter, model relationship, request protocol or deployment
boundary changes. Keep diagrams explicit about selected subsets and the date of table snapshots. Derive table
names and PK/FK types from installed Django model metadata without querying business rows; use globally unique
node IDs in the table taxonomy. Keep Proposed ADRs and uncompleted phases separate from implemented source paths.

Validate local links, Markdown fences and Mermaid parsing/rendering before publishing changes. Include screenshots
only when they help explain a changed product interface; generated diagram images need not be committed.

## Related documentation

- [Architecture guide](ARCHITECTURE.md)
- [Deployment guide](../deployment/DEPLOYMENT.md)
- [Architecture decisions](../ADRs/)
- [ADR-0061 execution plan](account-hostnames-dns-mail-plan.md)
- [Phase 3 implementation record](account-hostnames-phase3-execution.md)
- [Phase 4 implementation record](account-hostnames-phase4-execution.md)
