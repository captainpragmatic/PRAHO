# ADR-0054: Two Supported Deployment Paths, Native Ansible and Docker Compose

- Status: Accepted
- Date: 2026-10-07
- Authors: PRAHO maintainers
- Related: ADR-0027 (Hetzner provisioning), ADR-0032 (dual HMAC inter-service authentication)

## Context

PRAHO had three ways to deploy itself:

1. **Native Ansible** (`deploy/ansible/roles/praho-native`, `playbooks/native-single-server.yml`):
   systemd services and a host Caddy on one server. `make deploy-prod`, `make deploy-staging` and
   `make deploy-dev-native` use it, configured by the operator's `.env.prod` / `.env.staging` (and
   `.env.dev` for the remote dev box).
2. **Docker Compose** (`deploy/docker-compose.*.yml`, `deploy/scripts/deploy.sh`): containers on any
   Docker host, configured by the same files since #627.
3. **The Ansible Docker role** (`roles/praho`, `playbooks/single-server.yml`, `playbooks/two-servers.yml`):
   it templated its own compose file, Caddyfile and backup, restore and rollback scripts from a separate
   set of Ansible variables (`secret_key`, `db_password`, …). `make deploy-dev` and
   `make ansible-two-servers` used it.

The third was a copy of the second behind a second configuration vocabulary. On 2026-10-07 the same five
defects had to be fixed twice, once for the Compose files (#625) and once for the role's templates
(#626): missing production encryption keys, `sslmode` against the bundled PostgreSQL, the portal's
trusted proxy CIDRs, the healthcheck start period, and health waits on ports nobody published. No
production or staging environment ran on the role.

Four options were weighed:

- **Keep all three.** The double fixes continue.
- **Feed the role the shared env file, keep its templates.** That removes the second vocabulary but not
  the second copy of the stack, so the drift continues.
- **Make the role a thin wrapper around `deploy.sh`.** One stack definition and automated remote Docker
  deploys, at the cost of a wrapper layer and a split-host recovery story that does not exist yet.
- **Retire the role.** Chosen. Production already runs native, and Docker hosts are served by
  `deploy.sh`. If automated multi-host deploys become a requirement, they belong on the native role,
  which is the production path, rather than in a parallel Docker one.

Terraform (ADR-0027) provisions staging and production as two servers, platform and portal, while the
native role deploys one. The decision below records how that layout is deployed meanwhile.

## Decision

### Supported paths

| Path | Where it runs | Entry points | Configuration |
|------|---------------|--------------|---------------|
| Native Ansible | Servers: production, staging, a remote dev box | `make deploy-prod`, `make deploy-staging`, `make deploy-dev-native` | `.env.prod` / `.env.staging`; `.env.dev` for the remote dev box (`env_file_path` follows `praho_env`) |
| Docker Compose | Any Docker host; image builds for managed container platforms | `deploy/scripts/deploy.sh <type>`, `make deploy-*` | `.env.prod` / `.env.staging` (`--env`, `--env-file`) |
| Local development | A developer machine | `make dev`, `make docker-dev` | `make dev`: the repo-root `.env` (development only; `deploy.sh` refuses it). `make docker-dev`: the settings in `deploy/docker-compose.dev.yml` |

The Ansible Docker role, its two playbooks, `playbooks/rollback.yml`, `inventory/two-servers.yml`, the
Docker variant of `make deploy-dev` and `make ansible-two-servers` are retired.

### One configuration source

Both deploy paths read the operator's `.env.prod` / `.env.staging`. A new setting is added to
`.env.example.prod` and `.env.example.staging` and read by both paths; neither gets a vocabulary of its
own.

### Native host topology (amended for #769)

The existing native role owns shared, Platform, Portal and edge responsibilities. The controller
(`deploy/scripts/native_env.py`) validates one normalized topology for deployment, SSH preparation,
Caddy updates, backup and coordinated code rollback. Production defaults to separate hosts; new
staging/dev default to combined. Combined production is explicit. Existing two-server staging must
retain `split` in both native configuration and Terraform during adoption.

`praho_platform` and `praho_portal` inventory groups select responsibilities. Portal-only hosts receive
filtered configuration on transfer, an isolated OS identity and private session state. They receive
no business database, full environment, passfile, worker/Platform units or installed node tooling.
Contaminated Portal targets are refused without removing contents. Both hosts deploy one controller-
resolved immutable SHA, with persistent root-owned ingress and worker holds around migrations and
recovery. Public HTTPS carries the existing two independent HMAC schemes, with certificate verification
and connection-peer CIDRs at native Caddy. Staff and monitoring lists are independent. Provider callbacks
and unsubscribe links retain their public application-verified routes. Origins must be direct; CDN-aware
ingress remains separate work. Optional paired address-check origins serve only the observed peer.

Terraform retains existing server/RDNS addresses and the original Platform firewall, adds a Portal
firewall and protects servers from destruction. Adoption uses saved plans with no server deletions or
replacements. Live cutover and Terraform apply remain separate operator operations.

See [native deployment and recovery](../deployment/NATIVE_TOPOLOGY.md) for configuration, maintenance,
rollback, acceptance and the guided cutover. An old local Portal origin remains a maintenance-only
site through DNS expiry. Session moves may require a new sign-in. Webhook failures during maintenance
require provider-specific redelivery and reconciliation; this decision adds no webhook broker or
universal zero-loss guarantee.

Compose remains a supported independent path. On separate Docker hosts use `platform-only` and
`portal-only --with-caddy`, with `portal-env.sh` filtering on the machine holding the full environment.
Compose's existing API routing behavior is unchanged by the native peer policy.

### Pairs to change together

Native and Compose run the same applications on different runtimes, so a few pieces exist once per
runtime. A change to one side is checked against the other:

| Concern | Native | Compose |
|---------|--------|---------|
| Edge (TLS, HSTS, routing, staff allowlist) | `roles/praho-native/templates/Caddyfile.native.j2` | `deploy/caddy/Caddyfile`, `Caddyfile.platform`, `Caddyfile.portal` |
| Backup, restore, health | `roles/praho-native/templates/{backup-native,restore-platform-native,health-check}.sh.j2` | `deploy/scripts/{backup,restore-platform,health-check}.sh` |
| Required production variables | `deploy/scripts/native_env.py` controller preflight | `deploy/scripts/lib/compose.sh` and the compose files' `${VAR:?}` |

## Consequences

- One copy of each runtime's stack. A fix like #625/#626 lands once per runtime instead of twice for
  the same one.
- Ansible no longer installs Docker or schedules backups on a Docker host. `deploy.sh` expects a host
  with Docker Compose v2, and an operator schedules `deploy/scripts/backup.sh` there.
- `make deploy-dev-native` replaces `make deploy-dev` for the remote dev box; it uses the same inventory.
- Native split-host deployment and code rollback coordinate both hosts. Data recovery remains an
  explicit validated database/media restore; reverse migrations never run automatically. The controller
  refuses code rollback when the target revision omits an applied business migration.
