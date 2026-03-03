# ADR-0027: Infrastructure Provisioning via hcloud Python SDK

**Status:** Accepted
**Date:** 2026-03-03
**Authors:** PRAHO Development Team
**Supersedes:** None

## Context

PRAHO Platform used Terraform to provision Hetzner Cloud servers. This added significant complexity:

- **State file management** - Terraform state files needed to be stored, versioned, and backed up
- **Subprocess calls** - Terraform was invoked via subprocess from Django, adding error handling complexity
- **HCL template generation** - Python code generated HCL configuration files before each Terraform run
- **Redundant state tracking** - Our `NodeDeployment` model already tracks server IDs and IPs; the database IS the state

Additionally, our provisioning pattern is simple: we provision individual servers, not multi-resource stacks. Terraform's strength in managing complex dependency graphs across resources provides no benefit for our use case.

## Decision Drivers

1. **Operational simplicity** - fewer moving parts in the provisioning pipeline
2. **Development velocity** - typed Python API vs subprocess + HCL generation
3. **State consistency** - single source of truth (database) instead of database + Terraform state
4. **Error handling** - Python exceptions vs parsing Terraform CLI output
5. **Live catalog data** - ability to sync server types, regions, and pricing from Hetzner API

## Options Considered

### Option 1: Keep Terraform

**Pros:**
- Already implemented and working
- Provider-agnostic (supports DigitalOcean, Vultr, Linode)
- Industry standard for infrastructure-as-code

**Cons:**
- State file management overhead (storage, backup, locking)
- Subprocess execution complexity and fragile output parsing
- HCL template generation adds a code generation layer
- Redundant state: database + Terraform state must stay in sync
- Slow feedback loop: init + plan + apply pipeline for single server creation
- No typed Python API; errors discovered at runtime

### Option 2: hcloud Python SDK

**Pros:**
- **No state files** - database is the single source of truth
- **Typed Python API** - IDE support, type checking, no HCL generation
- **Faster deploys** - single API call vs 4-stage Terraform pipeline (config gen, init, plan, apply)
- **Live catalog data** - sync server types, regions, and pricing directly from Hetzner API
- **Simpler error handling** - Python exceptions with structured error data
- **Native Django integration** - fits naturally into services/repos/gateways pattern

**Cons:**
- Hetzner-specific; other providers would need their own SDK wrappers
- Less ecosystem tooling compared to Terraform

## Decision

**We will replace Terraform with the hcloud Python SDK for Hetzner Cloud provisioning.** Terraform will be kept as a deprecated fallback for potential future providers (DigitalOcean, Vultr, Linode).

### Key Decisions

1. **`hcloud>=2.0.0` Python SDK** for all Hetzner API operations (server create, delete, status)
2. **`max_domains` field on NodeDeployment** with size-based defaults (25 for small, up to 500 for large)
3. **Provider catalog synced from Hetzner API** via `sync_providers` management command:
   - Daily automatic sync at 4:00 AM via Django-Q2 scheduled task
   - Manual sync via "Sync Providers" button on Cloud Providers page
   - First-boot sync on initial migration when no providers exist
4. **Terraform fields removed from NodeDeployment** - `terraform_state_path` and `terraform_state_backend` dropped
5. **`terraform_service.py` kept but deprecated** - available as fallback, not used in default pipeline

### Implementation Plan

1. Add `hcloud>=2.0.0` to platform dependencies
2. Create `hcloud_gateway.py` in provisioning app following the gateways pattern
3. Add `sync_providers` management command for catalog sync
4. Add `max_domains` field to `NodeDeployment` with size-based defaults
5. Remove Terraform-specific fields from `NodeDeployment` model
6. Replace 4-stage Terraform pipeline with single hcloud SDK call in deployment service
7. Add "Sync Providers" button to Cloud Providers admin page
8. Register daily sync task in Django-Q2 scheduler

## Consequences

### Positive
- **No state files** to manage, backup, or reconcile with the database
- **Typed Python API** with IDE support and MyPy integration
- **Faster deploys** - eliminates Terraform init/plan/apply overhead
- **Live catalog data** - server types, regions, and pricing always current
- **Simpler error handling** - native Python exceptions instead of subprocess output parsing
- **Reduced dependencies** - no Terraform binary required on deployment servers

### Negative
- **Hetzner-specific** - other cloud providers would need their own SDK wrapper implementations
- **No infrastructure-as-code** audit trail from Terraform plan output

### Neutral
- **Ansible unchanged** - server configuration (post-provisioning) still uses Ansible
- **Provider abstraction** - the gateways pattern allows swapping hcloud for other SDKs per provider

## References

- [hcloud Python SDK](https://github.com/hetznercloud/hcloud-python)
- [Hetzner Cloud API Documentation](https://docs.hetzner.cloud/)
- [ADR-0020: Async Task Processing](ADR-0020-async-task-processing-architecture.md) (Django-Q2 for scheduled sync)
