# PostgreSQL 16 deployment and upgrade

Fresh native and bundled Docker deployments use PostgreSQL 16. Deployment does not perform a major
upgrade: Docker preflight reads an existing named volume through a disposable, read-only container;
native preflight rejects registered clusters from another major before installing packages. An empty
or absent Docker volume can initialize normally. Unknown data and Docker inspection failures abort.

PostgreSQL major versions can change their storage format. Use a logical dump/restore or a planned
`pg_upgrade` procedure rather than starting a new image on an old data directory. PostgreSQL recommends
using the newer dump client when migrating between majors. See the [PostgreSQL 16 upgrade guide](https://www.postgresql.org/docs/16/upgrading.html)
and [SQL dump guidance](https://www.postgresql.org/docs/16/backup-dump.html).

## Existing PostgreSQL 15 installations

1. Inventory the actual server version, volume/cluster paths, roles, extensions, collation and database
   sizes. Record application image IDs, configuration and the database/media pair. Rehearse on disposable
   copies and reserve space for the old cluster, private logical dumps and a separate new cluster.
2. Schedule maintenance and stop all application writers, including qcluster. Take and verify a final
   private backup of database, media, roles and configuration. `pg_dump` covers one database; capture
   required cluster roles separately. Verify recovery with matching clients before proceeding.
3. Create a separate PostgreSQL 16 volume/cluster and restore the logical data with errors fatal
   (`psql -X --set=ON_ERROR_STOP=1` for SQL, `pg_restore --exit-on-error` for custom dumps). Install the
   required extensions and validate permissions, counts, representative records and application flows.
   Keep the original PostgreSQL 15 data intact and offline. Do not mount it under the 16 server.
4. Cut over deliberately. For Docker, use a reviewed local Compose override that maps `postgres_data`
   (or development's `postgres_dev_data`) to the new 16 volume; use that override consistently for
   deployment and recovery. The stock filenames continue to use their original volume names. Do not
   silently substitute an empty volume when an old one exists. For native hosts, promote the verified
   16 cluster to the configured local port 5432. Archive and deregister the retired 15 cluster only
   after acceptance, so future `pg_lsclusters` preflight lists only the supported target major.
5. Verify Platform, Portal, actual queued work, backups and recovery on 16. Record the accepted target
   image and backup metadata. Retain the old cluster privately through the agreed recovery window.
   Data written after cutover is not present in the old cluster; rollback needs an explicit data plan.

The Docker guard only reads the resolved bundled data volume. Portal-only and external-database
stacks do not operate a remote database. The native recipe provisions local PostgreSQL 16 on port
5432; custom cluster/major layouts require a separately reviewed operator configuration. Normal
minor updates within major 16 retain the volume. Full rollback rejects a backup's different major;
standalone restore remains available for an operator-planned logical migration.

No production migration, old-volume deletion or cluster retirement is performed by this change.
