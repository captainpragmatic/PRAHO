# Virtualmin incremental (differential) backup contract

Evidence for #498. `scripts/virtualmin_incremental_probe.py` (`make virtualmin-probe`) generated it against the
Docker lab in `deploy/virtualmin-lab/`. Re-run the probe to refresh it; do not edit it by hand.

Each assertion is a predicate checked against the node. `FAIL` means the predicate is false, and for
an observation ("the scheduled backup ran") a false predicate can be the finding itself. The verdict
line under each question states what the evidence establishes.

## Environment

- Probe run: 2026-10-13 16:27 UTC
- Node: vm-a.praho.test (container vmlab-a), image praho-virtualmin-lab:8.3.0
- theme version: 26.70
- virtualmin version: 8.3.0
- webmin version: 2.670
- version: 6.12.76-linuxkit
- package virtualmin-config 8.3.0-1
- package webmin 2.670
- package webmin-virtual-server 8.3.0-1-gpl
- tar: tar (GNU tar) 1.34
- os: Debian GNU/Linux 12 (bookworm)
- API user: root (master administrator), through PRAHO's VirtualminGateway

## Verdicts

| Question | Verdict | Reason |
|---|---|---|
| Q1: Remote-API parameter names for differential / no-differential backups | **PROVEN** | `differential=` (bare) makes a differential backup, `no-differential=` a standalone full; `incremental`/`no-incremental` are accepted aliases; any value on the flag is rejected |
| Q2: Where per-domain differential state lives, and what a reset does to it | **PROVEN** | one GNU tar --listed-incremental snapshot per domain at /var/webmin/modules/virtual-server/incremental/<domain id>; every full backup deletes and rewrites it (the new base); a differential restores it after tar |
| Q3: Does a full backup leave the differential base untouched? | **PROVEN** | `no-differential` leaves the base untouched for the full, config-only and migration parameter sets; without it these reset the base today: PRAHO full, PRAHO config-only, PRAHO safety, migration params |
| Q5: Restore order: base full, then the latest differential, with data assertions | **DISPROVEN** | rows and every S2 file match, but the restore is not exact: files deleted after the base come back (['public_html/probe/delete-me.txt']) |
| Q6: Do files deleted after the base come back after base + differential restore? | **PROVEN** | deleted files are resurrected: Virtualmin extracts the differential over the base without replaying deletions |
| Q5b: Hazard: a default (base-resetting) full between base and differential | **PROVEN** | an intervening full that resets the base makes base+differential restore silently lose changes |
| Q7: Restoring a differential alone onto a deleted domain | **PROVEN** | a differential alone recreates the domain and its database but only the files changed since the base; unchanged files are missing, so it must never be restored without its base |
| Q8: A differential after a restore: is there still a base? | **PROVEN** | a restore deletes the domain's base; the next `differential` then silently runs as a full and becomes the new base |
| Q4: Schedule discovery after applying the production virtualmin_backup.yml | **PROVEN** | Virtualmin never reads the playbook's `sched` file (it reads /etc/webmin/virtual-server/backups/ and the legacy backup_* config keys). The config's backup_dest line surfaces as legacy schedule 1: enabled=False, domains=None, differential=No (from backup_increment). Cron runs backup.pl: False. A manual `backup.pl --id 1` backed up a domain: False; it changed the differential base: False. So the scheduled nightly node backup never runs. |

## Q1: Remote-API parameter names for differential / no-differential backups

**PROVEN**: `differential=` (bare) makes a differential backup, `no-differential=` a standalone full; `incremental`/`no-incremental` are accepted aliases; any value on the flag is rejected

### Assertions

| Check | Result | Detail |
|---|---|---|
| full backup (no flag) succeeds | pass |  |
| `differential` accepted over remote.cgi | pass |  |
| differential archive holds only the changed file | pass | ['./public_html/probe/change.txt'] |
| differential dir archive carries the ./.incremental marker | pass |  |
| `no-differential` accepted and produces a complete archive | pass | ['./public_html/probe/change.txt', './public_html/probe/delete-me.txt', './public_html/probe/keep.txt'] |
| legacy aliases `incremental` / `no-incremental` still accepted | pass |  |
| a value on the bare flag is rejected (`differential=1` → `--differential 1`) | pass |  |
| pre-fix full backup is rejected with 'Unknown parameter' | pass |  |
| pre-fix config-only backup is rejected with 'Unknown parameter' | pass |  |
| pre-fix restore is rejected with 'Unknown parameter' | pass |  |
| the rejected pre-fix calls left the differential base untouched | pass |  |

### Steps and output

1. `virtualmin backup-domain --help` (differential lines):

```text
[--differential | --no-differential |
                          --differential-of backup-id]
```

2. Argument parser in backup-domain.pl:

```text
250:	elsif ($a eq "--incremental" || $a eq "--differential") {
254:	elsif ($a eq "--no-incremental" || $a eq "--no-differential") {
257:	elsif ($a eq "--incremental-of" || $a eq "--differential-of") {
```

3. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q1_base.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 1 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 234.95 KiB
```

4. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q1_diff.tar.gz", "all-features": "", "differential": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 0 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 35.42 KiB
```

5. Dir members, base: ['./public_html/probe/change.txt', './public_html/probe/delete-me.txt', './public_html/probe/keep.txt']; differential: ['./public_html/probe/change.txt']

6. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q1_nodiff.tar.gz", "all-features": "", "no-differential": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 0 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 235.54 KiB
```

7. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q1_legacy.tar.gz", "all-features": "", "incremental": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 0 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 35.41 KiB
```

8. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q1_legacy_no.tar.gz", "all-features": "", "no-incremental": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 1 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 235.55 KiB
```

9. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q1_x.tar.gz", "all-features": "", "differential": "1"} → **failure**

```text
…
                         [--kill-running | --wait-running]
                         [--compression gzip|bzip2|tar|zip|zstd]
Multiple domains may be specified with multiple --domain parameters.
Features must be specified using their short names, like web and dns.
The destination can be one of :
 - A local file, like /backup/yourdomain.com.tgz
 - A local directory can be given while passing --newformat option, like /backup/
 - An FTP destination, like ftp://login:pass@server/backup/yourdomain.com.tgz
 - An SSH destination, like ssh://login:pass@server/backup/yourdomain.com.tgz
 - An S3 bucket, like s3://accesskey:secretkey@bucket
 - A Rackspace container, like rs://user:apikey@container
 - A Google Cloud Storage bucket, like gcs://bucket
 - A Dropbox folder, like dropbox://folder
Multiple destinations can be given by repeating this flag.
```

10. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q1_prefix_full.tar.gz", "all-features": true, "all-virtualservers": false, "newformat": true} → **failure**

```text
…
                         [--kill-running | --wait-running]
                         [--compression gzip|bzip2|tar|zip|zstd]
Multiple domains may be specified with multiple --domain parameters.
Features must be specified using their short names, like web and dns.
The destination can be one of :
 - A local file, like /backup/yourdomain.com.tgz
 - A local directory can be given while passing --newformat option, like /backup/
 - An FTP destination, like ftp://login:pass@server/backup/yourdomain.com.tgz
 - An SSH destination, like ssh://login:pass@server/backup/yourdomain.com.tgz
 - An S3 bucket, like s3://accesskey:secretkey@bucket
 - A Rackspace container, like rs://user:apikey@container
 - A Google Cloud Storage bucket, like gcs://bucket
 - A Dropbox folder, like dropbox://folder
Multiple destinations can be given by repeating this flag.
```

11. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q1_prefix_cfg.tar.gz", "only-features": "virtualmin,dir", "newformat": true} → **failure**

```text
…
                         [--kill-running | --wait-running]
                         [--compression gzip|bzip2|tar|zip|zstd]
Multiple domains may be specified with multiple --domain parameters.
Features must be specified using their short names, like web and dns.
The destination can be one of :
 - A local file, like /backup/yourdomain.com.tgz
 - A local directory can be given while passing --newformat option, like /backup/
 - An FTP destination, like ftp://login:pass@server/backup/yourdomain.com.tgz
 - An SSH destination, like ssh://login:pass@server/backup/yourdomain.com.tgz
 - An S3 bucket, like s3://accesskey:secretkey@bucket
 - A Rackspace container, like rs://user:apikey@container
 - A Google Cloud Storage bucket, like gcs://bucket
 - A Dropbox folder, like dropbox://folder
Multiple destinations can be given by repeating this flag.
```

12. remote.cgi `restore-domain` {"domain": "roundtrip.praho.test", "source": "/tmp/probe_q1_nodiff.tar.gz", "all-features": true} → **failure**

```text
…
                         [--skip-warnings]
                         [--continue-on-error]
                         [--delete-existing]
                         [--replication]
Multiple domains may be specified with multiple --domain parameters.
Features must be specified using their short names, like web and dns.
The source can be one of :
 - A local file, like /backup/yourdomain.com.tgz
 - An FTP destination, like ftp://login:pass@server/backup/yourdomain.com.tgz
 - An SSH destination, like ssh://login:pass@server/backup/yourdomain.com.tgz
 - An S3 bucket, like s3://accesskey:secretkey@bucket
 - A Rackspace container, like rs://user:apikey@container
 - A Google Cloud Storage bucket, like gcs://bucket
 - A Dropbox folder, like dropbox://folder
```


## Q2: Where per-domain differential state lives, and what a reset does to it

**PROVEN**: one GNU tar --listed-incremental snapshot per domain at /var/webmin/modules/virtual-server/incremental/<domain id>; every full backup deletes and rewrites it (the new base); a differential restores it after tar

### Assertions

| Check | Result | Detail |
|---|---|---|
| full backup | pass |  |
| state file created at incremental/<domain id> (17919089057386) | pass | /var/webmin/modules/virtual-server/incremental/17919089057386 |
| second full backup | pass |  |
| a full backup rewrites the state (new hash and mtime) | pass |  |
| differential backup | pass |  |
| a differential leaves the state as it was (restored after tar) | pass | 0e587ea48d4be749 7645 16:28:44.535201003 |

### Steps and output

1. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q2_full1.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 0 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 235.09 KiB
```

2. Files created by the first full backup under /etc/webmin/virtual-server, /var/webmin/modules/virtual-server:

```text
/var/webmin/modules/virtual-server/backuplogs/1791908920-8128-1
/var/webmin/modules/virtual-server/backuplogs/1791908920-8128-1.out
/var/webmin/modules/virtual-server/incremental/17919089057386
```

Files changed:

```text
/etc/webmin/virtual-server/domains/17919089057386
/var/webmin/modules/virtual-server/backupsrunning
```

3. `file /var/webmin/modules/virtual-server/incremental/17919089057386`: GNU tar incremental snapshot data version 1.34-2

4. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q2_full2.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 0 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 234.89 KiB
```

5. State after full #1: `fbb91268c974e328 7645 16:28:40.501201001`

State after full #2: `0e587ea48d4be749 7645 16:28:44.535201003`

6. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q2_diff.tar.gz", "all-features": "", "differential": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 1 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 35.36 KiB
```

7. State after a differential: `0e587ea48d4be749 7645 16:28:44.535201003`


## Q3: Does a full backup leave the differential base untouched?

**PROVEN**: `no-differential` leaves the base untouched for the full, config-only and migration parameter sets; without it these reset the base today: PRAHO full, PRAHO config-only, PRAHO safety, migration params

### Assertions

| Check | Result | Detail |
|---|---|---|
| establish base (plain full) | pass |  |
| PRAHO full: a base exists before (non-vacuous) | pass | 44ba7814039b9c67 7645 16:29:08.580275000 |
| PRAHO full: backup ran | pass |  |
| PRAHO full: base RESET | pass | (observed reset) |
| PRAHO config-only: a base exists before (non-vacuous) | pass | 432ddb70830c730a 7643 16:29:15.044275003 |
| PRAHO config-only: backup ran | pass |  |
| PRAHO config-only: base RESET | pass | (observed reset) |
| PRAHO safety: base RESET | pass | (observed) |
| a restore clears the differential base | pass | (observed) |
| re-establish base (plain full) | pass |  |
| migration params (virtualmin_migration_service.py _backup): a base exists before (non-vacuous) | pass | d4fc71bdb7239ea4 7597 16:29:44.619609003 |
| migration params (virtualmin_migration_service.py _backup): backup ran | pass |  |
| migration params (virtualmin_migration_service.py _backup): base RESET | pass | (observed reset) |
| full + no-differential: a base exists before (non-vacuous) | pass | 28ffda1eeb71059b 7597 16:29:48.226609005 |
| full + no-differential: backup ran | pass |  |
| full + no-differential: base UNTOUCHED | pass | (observed untouched) |
| config-only params + no-differential: a base exists before (non-vacuous) | pass | 28ffda1eeb71059b 7597 16:29:48.226609005 |
| config-only params + no-differential: backup ran | pass |  |
| config-only params + no-differential: base UNTOUCHED | pass | (observed untouched) |
| migration params + no-differential: a base exists before (non-vacuous) | pass | 28ffda1eeb71059b 7597 16:29:48.226609005 |
| migration params + no-differential: backup ran | pass |  |
| migration params + no-differential: base UNTOUCHED | pass | (observed untouched) |

### Steps and output

1. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q3_base.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 0 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 234.94 KiB
```

2. PRAHO full (`backup_domain`, include_email=False): Ok

3. PRAHO full: state before `44ba7814039b9c67 7645 16:29:08.580275000` → after `432ddb70830c730a 7643 16:29:15.044275003`

4. PRAHO config-only (`backup_domain`, config_only): Ok

5. PRAHO config-only: state before `432ddb70830c730a 7643 16:29:15.044275003` → after `507c7f11ad883cc6 7643 16:29:23.042275007`

6. PRAHO forced restore of roundtrip.praho.test_20261013_162924_e8af367f_8c3cdfa3d188 (runs the safety backup first): Ok

state before safety+restore `56c879b405163ed0 7645 16:29:27.625275009` → after `absent`

7. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q3_rebase.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 0 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 234.91 KiB
```

8. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q3_migration.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 0 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 235.12 KiB
```

9. migration params (virtualmin_migration_service.py _backup): state before `d4fc71bdb7239ea4 7597 16:29:44.619609003` → after `28ffda1eeb71059b 7597 16:29:48.226609005`

10. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q3_nd_full.tar.gz", "all-features": "", "no-differential": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 1 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 235.56 KiB
```

11. full + no-differential: state before `28ffda1eeb71059b 7597 16:29:48.226609005` → after `28ffda1eeb71059b 7597 16:29:48.226609005`

12. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q3_nd_cfg.tar.gz", "feature": ["virtualmin", "dir"], "no-differential": ""} → **success**

```text
Starting backup..
Testing backup destination local file /tmp/probe_q3_nd_cfg.tar.gz ..
.. done
Creating backup for virtual server roundtrip.praho.test ..
    Copying virtual server configuration ..
    .. done
    Creating TAR file of home directory ..
    .. done
.. completed in 0 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 209.48 KiB
```

13. config-only params + no-differential: state before `28ffda1eeb71059b 7597 16:29:48.226609005` → after `28ffda1eeb71059b 7597 16:29:48.226609005`

14. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q3_nd_mig.tar.gz", "all-features": "", "no-differential": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 1 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 235.58 KiB
```

15. migration params + no-differential: state before `28ffda1eeb71059b 7597 16:29:48.226609005` → after `28ffda1eeb71059b 7597 16:29:48.226609005`

16. Summary: PRAHO full: RESET, PRAHO config-only: RESET, PRAHO safety: RESET, migration params: RESET, full + no-differential: untouched, config-only + no-differential: untouched, migration + no-differential: untouched


## Q5: Restore order: base full, then the latest differential, with data assertions

**DISPROVEN**: rows and every S2 file match, but the restore is not exact: files deleted after the base come back (['public_html/probe/delete-me.txt'])

### Assertions

| Check | Result | Detail |
|---|---|---|
| F0: base full | pass |  |
| D1: differential | pass |  |
| N1: intervening standalone full (no-differential) | pass |  |
| D2: differential | pass |  |
| D2 is relative to F0 (holds every file changed since F0, not since N1) | pass | ['./public_html/probe/added-s1.txt', './public_html/probe/added-s2.txt', './public_html/probe/change.txt'] |
| restore F0 | pass |  |
| restore D2 | pass |  |
| database rows equal S2 | pass |  |
| every S2 file is back with the S2 checksum | pass |  |
| no file beyond S2 (exact equality) | FAIL | ['public_html/probe/delete-me.txt'] |

### Steps and output

1. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q5_f0.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 1 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 234.94 KiB
```

2. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q5_d1.tar.gz", "all-features": "", "differential": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 1 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 35.49 KiB
```

3. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q5_n1.tar.gz", "all-features": "", "no-differential": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 1 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 235.54 KiB
```

4. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q5_d2.tar.gz", "all-features": "", "differential": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 1 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 35.5 KiB
```

5. State S0 (at F0):

```text
{
  "files": "3c2bf2755e36d970435fdf3f0b114d2397f2e850787adb132892dc36eda9a69e  public_html/probe/change.txt\n585f3408cbe87e8590b41c9a03b494f0a0a8ee879d76038cc7e0d34cdfba350e  public_html/probe/delete-me.txt\nde3492e92f0801e915417e6bbf955f1c7d1315455933c2c324ea9e0ddb1993b5  public_html/probe/keep.txt",
  "rows": "1\tone s0\n2\ttwo s0"
}
```

State S2 (at D2):

```text
{
  "files": "d176ce5fbe6ae21fa86c73abe6af1ba491ff4c248580ed035464f2a7f6052c01  public_html/probe/added-s1.txt\n8eea654138d0531c2a69bf2618dbd156c55029e844b086ca798d524dd93579d2  public_html/probe/added-s2.txt\n4a6596661382b2385df08f22aa82167e5d91f0fc4698d7dda39c5d3245cf5123  public_html/probe/change.txt\nde3492e92f0801e915417e6bbf955f1c7d1315455933c2c324ea9e0ddb1993b5  public_html/probe/keep.txt",
  "rows": "1\tone s2\n3\tthree s1"
}
```

6. D2 dir members: ['./public_html/probe/added-s1.txt', './public_html/probe/added-s2.txt', './public_html/probe/change.txt']

7. remote.cgi `delete-domain` {"domain": "roundtrip.praho.test"} → **success**

```text
…
    .. done
    Deleting administration group ..
    .. done
    Deleting server details for roundtrip.praho.test ..
    .. done
    Updating Webmin user ..
    .. done
    Re-loading Webmin ..
    .. done
    Applying webserver configuration ..
    .. done
    Restarting PHP-FPM 8.2 server ..
    .. done
.. deleted
```

8. remote.cgi `restore-domain` {"domain": "roundtrip.praho.test", "source": "/tmp/probe_q5_f0.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Restoring AWStats configuration file ..
    .. done
    Updating Webmin user ..
    .. done
Enabling PHP modules for restored web apps ..
.. no PHP modules needed to be installed
Applying webserver configuration ..
.. done
Reloading PHP-FPM 8.2 server ..
.. done
Re-loading Webmin ..
.. done
Restore completed successfully.
```

9. remote.cgi `restore-domain` {"domain": "roundtrip.praho.test", "source": "/tmp/probe_q5_d2.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Restoring Webmin ACL files ..
    .. done
    Restoring AWStats configuration file ..
    .. done
    Updating Webmin user ..
    .. done
Applying webserver configuration ..
.. done
Reloading PHP-FPM 8.2 server ..
.. done
Re-loading Webmin ..
.. done
Restore completed successfully.
```

10. State after F0 + D2:

```text
{
  "files": "d176ce5fbe6ae21fa86c73abe6af1ba491ff4c248580ed035464f2a7f6052c01  public_html/probe/added-s1.txt\n8eea654138d0531c2a69bf2618dbd156c55029e844b086ca798d524dd93579d2  public_html/probe/added-s2.txt\n4a6596661382b2385df08f22aa82167e5d91f0fc4698d7dda39c5d3245cf5123  public_html/probe/change.txt\n585f3408cbe87e8590b41c9a03b494f0a0a8ee879d76038cc7e0d34cdfba350e  public_html/probe/delete-me.txt\nde3492e92f0801e915417e6bbf955f1c7d1315455933c2c324ea9e0ddb1993b5  public_html/probe/keep.txt",
  "rows": "1\tone s2\n3\tthree s1"
}
```


## Q6: Do files deleted after the base come back after base + differential restore?

**PROVEN**: deleted files are resurrected: Virtualmin extracts the differential over the base without replaying deletions

### Assertions

| Check | Result | Detail |
|---|---|---|
| deleted file present after restore | pass |  |

### Steps and output

1. `probe/delete-me.txt` existed at F0 and was deleted before D2. Present after F0 + D2: **True** (checksum 585f3408cbe87e8590b41c9a03b494f0a0a8ee879d76038cc7e0d34cdfba350e)


## Q5b: Hazard: a default (base-resetting) full between base and differential

**PROVEN**: an intervening full that resets the base makes base+differential restore silently lose changes

### Assertions

| Check | Result | Detail |
|---|---|---|
| F0: base full | pass |  |
| X: intervening default full (as PRAHO/migration/safety send today) | pass |  |
| D: differential | pass |  |
| restore F0 | pass |  |
| restore D | pass |  |
| F0 + D misses the change made before X (silent data loss) | pass |  |

### Steps and output

1. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q5b_f0.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 0 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 234.93 KiB
```

2. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q5b_x.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 0 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 234.93 KiB
```

3. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q5b_d.tar.gz", "all-features": "", "differential": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 1 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 35.44 KiB
```

4. D dir members: ['./public_html/probe/added-h2.txt']

5. remote.cgi `delete-domain` {"domain": "roundtrip.praho.test"} → **success**

```text
…
    .. done
    Deleting administration group ..
    .. done
    Deleting server details for roundtrip.praho.test ..
    .. done
    Updating Webmin user ..
    .. done
    Re-loading Webmin ..
    .. done
    Applying webserver configuration ..
    .. done
    Restarting PHP-FPM 8.2 server ..
    .. done
.. deleted
```

6. remote.cgi `restore-domain` {"domain": "roundtrip.praho.test", "source": "/tmp/probe_q5b_f0.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Restoring AWStats configuration file ..
    .. done
    Updating Webmin user ..
    .. done
Enabling PHP modules for restored web apps ..
.. no PHP modules needed to be installed
Applying webserver configuration ..
.. done
Reloading PHP-FPM 8.2 server ..
.. done
Re-loading Webmin ..
.. done
Restore completed successfully.
```

7. remote.cgi `restore-domain` {"domain": "roundtrip.praho.test", "source": "/tmp/probe_q5b_d.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Restoring Webmin ACL files ..
    .. done
    Restoring AWStats configuration file ..
    .. done
    Updating Webmin user ..
    .. done
Applying webserver configuration ..
.. done
Reloading PHP-FPM 8.2 server ..
.. done
Re-loading Webmin ..
.. done
Restore completed successfully.
```

8. Expected files:

```text
1e2ba5c7c2b12368c550cd5d1bbf8265e4643b78f9d0c07008b1b7e95aeafa42  public_html/probe/added-h2.txt
bca117e409063f4c18bda5113cba607ffba3b412328a606c453142304acf54fb  public_html/probe/change.txt
d3b01f66e8485ab16a2fca0557979af944cdea331c107cbf633dd1c81d7c8aaf  public_html/probe/delete-me.txt
a6c0b7b5bab12fbce9a1449ae3263b8d88cf3e84200b4b5044a72a71e7d28413  public_html/probe/keep.txt
```

After F0 + D:

```text
1e2ba5c7c2b12368c550cd5d1bbf8265e4643b78f9d0c07008b1b7e95aeafa42  public_html/probe/added-h2.txt
9f263027fa5d3d6edaf5239e8637889d423011b90504847ef2b92805dc4554a7  public_html/probe/change.txt
d3b01f66e8485ab16a2fca0557979af944cdea331c107cbf633dd1c81d7c8aaf  public_html/probe/delete-me.txt
a6c0b7b5bab12fbce9a1449ae3263b8d88cf3e84200b4b5044a72a71e7d28413  public_html/probe/keep.txt
```


## Q7: Restoring a differential alone onto a deleted domain

**PROVEN**: a differential alone recreates the domain and its database but only the files changed since the base; unchanged files are missing, so it must never be restored without its base

### Assertions

| Check | Result | Detail |
|---|---|---|
| base full | pass |  |
| differential | pass |  |
| restore-domain reports success | pass |  |
| domain exists afterwards | pass |  |
| files complete | FAIL |  |
| database rows complete (dumps are always full) | pass |  |

### Steps and output

1. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q7_f0.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 0 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 235.08 KiB
```

2. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q7_d.tar.gz", "all-features": "", "differential": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 1 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 35.42 KiB
```

3. remote.cgi `delete-domain` {"domain": "roundtrip.praho.test"} → **success**

```text
…
    .. done
    Deleting administration group ..
    .. done
    Deleting server details for roundtrip.praho.test ..
    .. done
    Updating Webmin user ..
    .. done
    Re-loading Webmin ..
    .. done
    Applying webserver configuration ..
    .. done
    Restarting PHP-FPM 8.2 server ..
    .. done
.. deleted
```

4. remote.cgi `restore-domain` {"domain": "roundtrip.praho.test", "source": "/tmp/probe_q7_d.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Restoring AWStats configuration file ..
    .. done
    Updating Webmin user ..
    .. done
Enabling PHP modules for restored web apps ..
.. no PHP modules needed to be installed
Applying webserver configuration ..
.. done
Reloading PHP-FPM 8.2 server ..
.. done
Re-loading Webmin ..
.. done
Restore completed successfully.
```

5. Expected (state at the differential):

```text
5f274665d9acf8273e061f6e4d4d04beba8a20dd9a7b4ca838049cedda7d4343  public_html/probe/change.txt
f1064b297854e705ed383afa12de1b8129b4ef76ca01cdeec83b2b1fa289a766  public_html/probe/delete-me.txt
c3250e9ef4f3f208b8409867c3d71e4b1f3973cd1fae1730627a7d37bc4aa1f6  public_html/probe/keep.txt
```

After restoring the differential alone:

```text
5f274665d9acf8273e061f6e4d4d04beba8a20dd9a7b4ca838049cedda7d4343  public_html/probe/change.txt
```


## Q8: A differential after a restore: is there still a base?

**PROVEN**: a restore deletes the domain's base; the next `differential` then silently runs as a full and becomes the new base

### Assertions

| Check | Result | Detail |
|---|---|---|
| F0: full | pass |  |
| base exists after F0 | pass |  |
| restore F0 over the live domain | pass |  |
| the restore deleted the base | pass |  |
| D: differential | pass |  |
| D silently contains every file (a full) | pass | ['./public_html/probe/change.txt', './public_html/probe/delete-me.txt', './public_html/probe/keep.txt'] |
| D created a new base | pass |  |

### Steps and output

1. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q8_f0.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 1 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 234.94 KiB
```

2. remote.cgi `restore-domain` {"domain": "roundtrip.praho.test", "source": "/tmp/probe_q8_f0.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Restoring Webmin ACL files ..
    .. done
    Restoring AWStats configuration file ..
    .. done
    Updating Webmin user ..
    .. done
Applying webserver configuration ..
.. done
Reloading PHP-FPM 8.2 server ..
.. done
Re-loading Webmin ..
.. done
Restore completed successfully.
```

3. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q8_d.tar.gz", "all-features": "", "differential": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 0 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 234.89 KiB
```

4. D dir members: ['./public_html/probe/change.txt', './public_html/probe/delete-me.txt', './public_html/probe/keep.txt']


## Q4: Schedule discovery after applying the production virtualmin_backup.yml

**PROVEN**: Virtualmin never reads the playbook's `sched` file (it reads /etc/webmin/virtual-server/backups/ and the legacy backup_* config keys). The config's backup_dest line surfaces as legacy schedule 1: enabled=False, domains=None, differential=No (from backup_increment). Cron runs backup.pl: False. A manual `backup.pl --id 1` backed up a domain: False; it changed the differential base: False. So the scheduled nightly node backup never runs.

### Assertions

| Check | Result | Detail |
|---|---|---|
| base full before the schedule | pass |  |
| production playbook applied | pass |  |
| Virtualmin lists a scheduled backup | pass |  |
| the scheduled backup ran | FAIL |  |
| it reset the differential base | FAIL | (observed) |
| the listed schedule is enabled | FAIL |  |
| a cron job runs backup.pl | FAIL |  |

### Steps and output

1. remote.cgi `backup-domain` {"domain": "roundtrip.praho.test", "dest": "/tmp/probe_q4_base.tar.gz", "all-features": ""} → **success**

```text
…
    .. done
    Copying MariaDB user details ..
    .. done
    Dumping MariaDB database roundtrip ..
    .. done
    Backing up Webmin ACL files ..
    .. done
    Backing up AWStats configuration file ..
    .. done
.. completed in 0 seconds
Creating final backup archive ..
.. done
1 virtual servers backed up successfully
Backup completed successfully. Final size was 234.91 KiB
```

2. `virtualmin list-scheduled-backups --multiline` before:

```text
(empty)
```

3. `AnsibleService.run_playbook(virtualmin_backup.yml)` → **success**

```text
…
Tuesday 13 October 2026  19:33:29 +0300 (0:00:00.040)       0:00:03.825 *******
TASK [Create backup configuration marker] **************************************
changed: [dev-sha-lab-ro-vmla-001]
Tuesday 13 October 2026  19:33:30 +0300 (0:00:00.441)       0:00:04.267 *******
RUNNING HANDLER [Restart virtualmin] *******************************************
changed: [dev-sha-lab-ro-vmla-001]
PLAY RECAP *********************************************************************
dev-sha-lab-ro-vmla-001    : ok=12   changed=9    unreachable=0    failed=0    skipped=5    rescued=0    ignored=0
PLAYBOOK RECAP *****************************************************************
Playbook run took 0 days, 0 hours, 0 minutes, 7 seconds
TASKS RECAP ********************************************************************
Tuesday 13 October 2026  19:33:33 +0300 (0:00:03.282)       0:00:07.549 *******
===============================================================================
Restart virtualmin ------------------------------------------------------ 3.28s
Gathering Facts --------------------------------------------------------- 0.92s
Configure backup features ----------------------------------------------- 0.58s
Create Virtualmin backup schedule --------------------------------------- 0.57s
Create backup configuration marker -------------------------------------- 0.44s
Create backup cleanup script -------------------------------------------- 0.38s
Create backup directory ------------------------------------------------- 0.28s
Test backup configuration ----------------------------------------------- 0.27s
Schedule backup cleanup cron job ---------------------------------------- 0.27s
Configure backup retention ---------------------------------------------- 0.25s
Set backup destination -------------------------------------------------- 0.15s
Display backup destinations --------------------------------------------- 0.04s
Schedule S3 backup sync cron job ---------------------------------------- 0.02s
Create S3 backup sync script -------------------------------------------- 0.02s
Install AWS CLI for S3 backups ------------------------------------------ 0.02s
Set S3 backup destination in Virtualmin --------------------------------- 0.02s
Create AWS credentials directory ---------------------------------------- 0.01s
```

4. /etc/webmin/virtual-server/sched as written:

```text
# Virtualmin backup schedule configuration
# Managed by PRAHO - do not edit manually
#
# Schedule: 0 2 * * * (X X * * *)
# Storage: local
# Retention: 7 days

# Field format: name=value
id=1
enabled=1
sched=0 2 * * *
dest=/var/backups/virtualmin
strftime=%Y%m%d_%H%M%S
mkdir=1
all_doms=1
feature_web=1
feature_mail=1
feature_mysql=1
feature_dns=1
feature_ssl=1
feature_dir=1
feature_unix=1
feature_webmin=1
onebyone=1
compression=gzip
email_err=root
```

backup_* keys in config:

```text
backup_onebyone=1
backup_strftime=%Y%m%d_%H%M%S
backup_dest=/var/backups/virtualmin
backup_virtualmin=1
backup_compression=1
backup_increment=0
```

5. `virtualmin list-scheduled-backups --multiline` after:

```text
1
    Domains: None
    Include sub-servers: No
    Virtualmin configs: 1
    Destination: /var/backups/virtualmin
    Delete old backups after: Never
    Features: All
    Format: One file per server
    Differential: No
    Enabled: No
    Send email: Always
    Notify domain owners: No
    Running: No
```

6. How Virtualmin finds scheduled backups (backups-lib.pl):

```text
5:sub list_scheduled_backups
6-{
7-my @rv;
8-
9-# Add old single schedule, from config file
10-if ($config{'backup_dest'}) {
11-	my %backup = ( 'id' => 1,
12-			  'dest' => $config{'backup_dest'},
13-			  'fmt' => $config{'backup_fmt'},
14-			  'mkdir' => $config{'backup_mkdir'},
15-			  'errors' => $config{'backup_errors'},
16-			  'increment' => $config{'backup_increment'},
17-			  'compression' => $config{'backup_compression'},
18-			  'strftime' => $config{'backup_strftime'},
19-			  'onebyone' => $config{'backup_onebyone'},
```

7. Cron entries for backups:

```text
#Ansible: PRAHO backup cleanup
30 4 * * * /usr/local/bin/praho-backup-cleanup.sh >> /var/log/praho-backup-cleanup.log 2>&1
```

8. `backup.pl --id 1` with the cron wrapper's environment (what cron would run):

```text
exit 0
```

Archives in /var/backups/virtualmin afterwards:

```text
virtualmin.tar.gz 20 bytes, members: 0
```

state `eacc7dc57b18465c 7645 16:33:24.424387008` → `eacc7dc57b18465c 7645 16:33:24.424387008`
