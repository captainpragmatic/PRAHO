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

### A separate portal host

Until the native role deploys two hosts, the two-server layout is deployed by hand with Compose:

- **Platform server:** `deploy.sh platform-only --full`.
- **Portal server:** `deploy.sh portal-only --with-caddy`, with an env file written by
  `deploy/scripts/portal-env.sh` on the machine that holds the full one.

A portal host holds only the variables the portal-only stack uses, plus its own
`PORTAL_DJANGO_SECRET_KEY`; `deploy.sh portal-only` refuses a file with anything else (#630). The split
stacks publish their application port on loopback only (#631). The portal reaches the platform at
`https://<platform domain>/api` through the platform's Caddy, where `/api/*` is public and Django's HMAC
check guards it.

### Pairs to change together

Native and Compose run the same applications on different runtimes, so a few pieces exist once per
runtime. A change to one side is checked against the other:

| Concern | Native | Compose |
|---------|--------|---------|
| Edge (TLS, HSTS, routing, staff allowlist) | `roles/praho-native/templates/Caddyfile.native.j2` | `deploy/caddy/Caddyfile`, `Caddyfile.platform`, `Caddyfile.portal` |
| Backup, restore, health | `roles/praho-native/templates/{backup-native,restore-native,health-check}.sh.j2` | `deploy/scripts/{backup,restore,health-check}.sh` |
| Required production variables | `playbooks/native-single-server.yml` preflight | `deploy/scripts/lib/compose.sh` and the compose files' `${VAR:?}` |

## Consequences

- One copy of each runtime's stack. A fix like #625/#626 lands once per runtime instead of twice for
  the same one.
- Ansible no longer installs Docker or schedules backups on a Docker host. `deploy.sh` expects a host
  with Docker Compose v2, and an operator schedules `deploy/scripts/backup.sh` there.
- `make deploy-dev-native` replaces `make deploy-dev` for the remote dev box; it uses the same inventory.
- The two-server staging and production layout has no automated deploy, and `rollback.sh` and
  `restore.sh` handle only the single-server stack. Before a split portal host goes live, the native role
  gains two-host support or the recovery scripts become topology-aware.
