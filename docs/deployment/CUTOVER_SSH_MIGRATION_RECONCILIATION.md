# Cutover and SSH migration reconciliation

The SSH release is independent of draft PR #749. It adds provisioning migration
`0015_ssh_transport_state`, based on `0012_bind_server_hostname`. Numbers 0013 and
0014 remain reserved for the cutover branch. Do not renumber applied migrations.

After bringing the released master into the cutover branch, apply the accompanying
patch from the repository root:

```bash
git apply --check docs/deployment/CUTOVER_SSH_MIGRATION_RECONCILIATION.patch
git apply docs/deployment/CUTOVER_SSH_MIGRATION_RECONCILIATION.patch
make check-migrations
```

The patch adds an empty `0016_merge_ssh_cutover` migration and its checksum. Its
parents are `0014_migrationbridge` and `0015_ssh_transport_state`. It changes no
existing migration or data and must stay unapplied until both parents are present.
If either branch adds further migrations first, regenerate the merge dependency
against the actual leaves and update the new checksum before committing.

Verification on 2026-10-26: the patch applied to a temporary combined tree containing
both draft migrations. Django's migration loader reported no conflicts, a single
provisioning leaf at 0016, and retained the SSH port, cutover fields and MigrationBridge
model in the resulting project state. The active cutover checkout was not changed.
A full combined application test and migration execution remain the cutover PR's
responsibility after its rebase.
