# Terraform state durability and recovery

The management-server Terraform configuration keeps its existing backend. The Makefile selects an
environment workspace before plan/apply; local non-default workspaces store state beneath
`deploy/terraform/terraform.tfstate.d/<environment>/`, with default state in `terraform.tfstate`.
Inventory the actual workspace/backend before changing anything. These instructions do not select
an organizational backend or migrate live state. Hosting-node Terraform fallback remains supported
under ADR-0027; keep its independently configured state as well.

## Backups

- Treat state, its `.backup` files, saved plans and operator tfvars as private configuration. Keep
  them out of Git and source deployment. Native rsync excludes controller Terraform/lab state,
  saved plans and private tfvars, while retaining existing destination state.
- Before each infrastructure change, save a verified snapshot of each affected workspace's state
  to mode-0600 files in a mode-0700 directory outside the checkout. Record workspace, backend identity,
  state lineage/serial, provider-lock revision and the corresponding configuration revision.
- For an initialized backend, an operator can use `terraform state pull` in the selected workspace.
  Write to a private temporary file, require success/nonempty valid JSON, then rename it atomically.
  Do not print state into terminal logs. Retain multiple versions and an encrypted off-machine copy;
  one local `.backup` file does not protect against loss of the controller disk.
- Verify retrieval and restoration with a disposable state copy. Database/media backups do not back
  up Terraform state, and a state snapshot does not back up server data.

## Recovery

1. Stop infrastructure changes. Preserve the current state/cache/configuration privately before
   attempting recovery; identify the exact environment, workspace, backend and resource ownership.
2. Retrieve the accepted snapshot and matching configuration/provider lock. Validate JSON, lineage
   and serial, then compare resource addresses/IDs with the recorded infrastructure inventory.
3. For a local backend, restore the snapshot to that workspace's exact state path while Terraform is
   idle. For an existing remote backend, use its documented recovery/version procedure or a reviewed
   `terraform state push`; retain normal lineage/serial safeguards rather than forcing an overwrite.
4. Only after the correct state is restored should an operator review a refresh/plan and drift.
   Do not apply, import or recreate resources merely because state appears empty. Resource/data
   reconciliation and any subsequent apply are separate reviewed actions.

An organization may later choose a remote backend with access controls, encryption, locking and
versioned recovery. That choice, credentials and `terraform init -migrate-state` require an explicit
operator plan, backed-up source/destination state and environment-by-environment verification.
They are not performed by this repository change.

`make infra-validate` uses `-backend=false -lockfile=readonly` and a disposable `TF_DATA_DIR`.
It checks source/provider schema without reading or migrating live state and without a cloud plan
or apply. The committed lockfile is retained; validation does not upgrade provider versions.
