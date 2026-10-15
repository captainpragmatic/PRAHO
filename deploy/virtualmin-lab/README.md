# Virtualmin lab

A local, opt-in lab for testing PRAHO against real Virtualmin. It runs:
- two Virtualmin GPL nodes (`vm-a`, `vm-b`), so migration and drain can be tested between them;
- MinIO with SSE-S3, as the backup store.

It is not part of `make test`.

```bash
make virtualmin-lab-up      # build images if missing, start, register in the lab DB, inject credentials
make test-virtualmin-lab    # production-path backup + restore round trip, then the vm-b checks
make test-virtualmin-contract # every allowlisted Virtualmin program against the real node (also run by test-virtualmin-lab)
make virtualmin-probe       # incremental-backup contract probe -> docs/domain/virtualmin-incremental-contract.md
make virtualmin-lab-down    # stop and remove containers and MinIO data
make virtualmin-lab-build   # rebuild both images
```

Requirements:
- Docker with cgroup v2. This was built on Docker Desktop on Apple Silicon (linux/arm64).
- Ansible on the host (`ansible-playbook`).
- About 3 GB of RAM for the two nodes.

If a pull hangs on the `docker-credential-desktop` helper, point `LAB_DOCKER_CONFIG` at a directory holding an empty `{}` `config.json`. If you need buildx in that directory, symlink `cli-plugins` into it as well.

## What runs where

| Service | Container | Published on 127.0.0.1 | Hostname |
|---|---|---|---|
| Virtualmin node A | `vmlab-a` | SSH `2522`, Webmin/API `10101` | `vm-a.praho.test` |
| Virtualmin node B | `vmlab-b` | SSH `2622`, Webmin/API `10102` | `vm-b.praho.test` |
| MinIO API / console | `vmlab-minio` | `19000` / `19001` | – |
| Bare Debian node (profile `debian-node`, `lab.sh node-up`) | `vmlab-debian-node` | SSH `2722` | `node-c.praho.test` |

The ports can be overridden with `LAB_A_SSH_PORT`, `LAB_A_WEBMIN_PORT`, and so on (see `compose.yml`). If you change one, change the matching `LabNode` in `virtualmin_lab_bootstrap.py` too.

The nodes run with `privileged`, `cgroup: host`, the host's `/sys/fs/cgroup` mounted rw, and tmpfs on `/run` and `/run/lock`. That is what systemd needs as PID 1 under Docker Desktop.

## Images

| Image | Dockerfile | Contents |
|---|---|---|
| `praho-virtualmin-lab:8.3.0` | `virtualmin/Dockerfile` | `debian:12-slim` (pinned by digest), systemd, OpenSSH, Virtualmin GPL |
| `praho-debian-node:12` | `debian-node/Dockerfile` | `debian:12-slim` (same digest), systemd, OpenSSH, nothing else |

Both use `deploy/virtualmin-lab/` as the build context. Both are multi-arch clean: no architecture-specific URLs.

Each image carries OCI labels for:
- source and revision (`VCS_REF` build arg);
- version and licence.

The Virtualmin image also labels every pinned package version.

### How Virtualmin is installed

The official `virtualmin-install.sh --minimal --bundle LAMP` runs in four phases. The image reproduces phases 2 to 4 without the script, because the script expects systemd to be running.

1. **Repository (build time).**
   - The two signing keys are fetched from `keyserve.virtualmin.com`.
   - The build fails unless the primary fingerprints are exactly:
     - `F103C1A32EA75BF911C33707ECEDBFD252CAC4B4` (Virtualmin Developers);
     - `A37DB2F5499365669717F15173FE86789906C8C9` (Sentinel).
   - The repository is then written with `signed-by`, the same line the installer's `--setup` writes.
2. **Packages (build time).**
   - The installer's own commands, with recommends: first `webmin`, then `virtualmin-core` and `virtualmin-lamp-stack-minimal`.
   - Pinned versions:
     - `webmin=2.670`;
     - `webmin-virtual-server=8.3.0-1-gpl`;
     - `virtualmin-core=8.2.0-1`;
     - `virtualmin-config=8.3.0-1`;
     - `virtualmin-lamp-stack-minimal=8.2.0-1`.
   - The pinned packages are held with `apt-mark hold`.
   - A temporary `policy-rc.d` stops services from starting during the build.
3. **Configuration (first boot).** `virtualmin-lab-firstboot.service` runs the installer's phase-4 command, `virtualmin-config-system --bundle MiniLAMP`. It then writes the files the installer writes on success:
   - `/etc/virtualmin-license`;
   - `virtual-server/installed` and `virtual-server/installed-auto`.

   It takes about 30 seconds. The container is healthy once this has finished and Webmin answers on port 10000.

Everything a node needs at runtime is already in the image. `python3` and `cron` arrive through Virtualmin's own recommends, so nothing is added for Ansible.

### Nothing secret or per-node in a layer

- **Identity (at boot).** `lab-node-identity.service` generates:
  - `/etc/machine-id`;
  - the SSH host keys;
  - Webmin's TLS key pair.

  The build deletes all of these, so two nodes never share a host key or certificate.
- **Credentials (at boot).** `lab-node-credentials.service` reads two files from the read-only volume `/etc/lab-node/inject`:
  - `root_password`, applied with `chpasswd`. Webmin's root user authenticates against it, so it is also the API password;
  - `authorized_keys`, for root.

  The image's root account is locked (`*`). `lab.sh apply-credentials` re-runs this service's script on running nodes.

- **Where the credentials come from.** `manage.py virtualmin_lab_bootstrap` writes the inject files. It generates:
  - a random API password per node;
  - a managed ed25519 key per `NodeDeployment`, stored in the credential vault.

## The PRAHO side

- **Settings.**
  - `config.settings.lab` is the development settings with their own database, `services/platform/db-virtualmin-lab.sqlite3`. Your dev database is never touched.
  - Its keys come from `.state/django.env`, which `lab.sh up` generates once.
  - All lab state lives in `deploy/virtualmin-lab/.state/`, which is git-ignored.
- **`virtualmin_lab_bootstrap`.** It refuses to run unless the settings module is `config.settings.lab` and DEBUG is on. For each node it creates or refreshes:
  - a `VirtualminServer`, TLS-pinned to the node's live certificate (`ssl_cert_fingerprint`) with CA verification off;
  - a `NodeDeployment`, with a fresh managed SSH key.

  It also:
  - writes the port-keyed `known_hosts`;
  - sets `backup.s3_endpoint_url`, `backup.s3_bucket_name`, `backup.aws_*` and `provisioning.migration_spool_dir` for the lab;
  - sets `infrastructure.node_admin_allowed_cidrs` to the compose network gateway (`<gateway>/32`). Platform reaches every node through Docker's port publishing, so the nodes see all of its API and SSH traffic from that address; the nodes' own addresses stay outside the list;
  - creates the customer, service and `VirtualminAccount` for `roundtrip.praho.test`.

  Re-running it rotates the node passwords and keys, so run `lab.sh apply-credentials` afterwards. `make virtualmin-lab-up` does both.
- **`virtualmin_lab_roundtrip`** is the gate.
  - It seeds files and database rows, then runs the ordinary `manage.py virtualmin_backup backup <domain>` with the default components. That command goes through the job layer inline, which covers:
    - the remote.cgi `backup-domain` call;
    - the Ansible fetch into the spool;
    - checksum and member verification;
    - the SSE-S3 upload.
  - It checks that both S3 objects are AES256-encrypted, then mutates the data and deletes the domain.
  - It then runs `manage.py virtualmin_backup restore`, which covers:
    - the S3 download;
    - the Ansible push;
    - the `restore-domain` call;
    - verification.
  - It then requires the file checksums and the table rows to equal the pre-backup state.
  - Leg 2 changes the data again and runs `restore --force-restore` over the live domain. That covers the pre-restore safety backup and the ownership re-gate.
    - Every backed-up file and row must come back.
    - Files created after the backup survive, because Virtualmin extracts over the live tree. The gate reports them.

- **`virtualmin_lab_checks`** runs after the round trip, on vm-b, with its own domain `labcheck.praho.test`:
  1. create-domain through `VirtualminProvisioningService`: an absent domain probes as absent, the server gets the "Default Settings" template, the default features and the recovery seed as its description, and a create retry after the server vanished re-creates it;
  2. a base made by a plain full backup stays byte-identical through the ordinary full backup, the config-only backup and the migration backup parameters;
  3. the staging directory `/var/lib/praho-transfer` is root 0700, an unprivileged user cannot read a `.dom` sidecar, a verified fetch leaves nothing behind, and a world-readable staging directory makes the fetch refuse;
  4. `virtualmin_backup.yml`, applied twice, leaves one enabled, non-differential schedule that Webmin cron runs, and running it archives the domain and keeps the base;
  5. `virtualmin.yml` on the installed node succeeds, and its API user authenticates, can disable and enable a domain, lists the templates, and runs PRAHO's backup (with `mkdir`, master-only) and restore parameters.
  6. the access lock (ADR-0060), with vm-a standing in for any host outside the allowlist:
     - the API user works from Platform; from vm-a, remote.cgi answers 403 and a login-form session gets 403 on every page; with vm-a added to the user's allow list the same calls succeed, so the refusal is the lock;
     - with UFW off, vm-a reaches vm-b:10000; after `virtualmin_harden.yml` (run twice, over SSH from Platform) it cannot, port 80 stays open, and Platform still reaches the API.

### The contract suite

`make test-virtualmin-contract` runs `tests/virtualmin_lab/contract/` against vm-b through PRAHO's own `VirtualminGateway`. There is one test per program on `VIRTUALMIN_ALLOWED_PROGRAMS` (`@covers("<program>")`). Each sends PRAHO's parameters (built by the same functions production uses) and asserts `has_explicit_success`, `explicit_rejection`, the read-only replay classification and the retriability of a refusal on the real answer: a success case and, where the lab can produce one, a refusal. The lab has no mail, BIND or public DNS, so aliases, DNS and certificate issuance are pinned by their refusals. The allowlist holds only programs that exist on Virtualmin 8.3; PRAHO calls nothing else, and the gateway refuses any other program before sending it. The suite uses its own `contract*.praho.test` domains on vm-b and removes them.

### Node deploy from scratch (`praho-debian-node`)

`virtualmin.yml` was run end to end against a fresh `praho-debian-node` container (SSH on 127.0.0.1:2722): the Virtualmin 8 installer installed Virtualmin 8.3.0 / Webmin 2.670, the play finished with `failed=0`, and the API user it created could create and delete a domain over remote.cgi. That run is not part of `make test-virtualmin-lab`. Three things a cloud image has and the bare image lacks had to be added first:
- `python3`, for Ansible;
- `iproute2`, or the installer cannot find the primary interface;
- the removal of `/etc/apt/apt.conf.d/docker-clean`, which deletes downloaded packages before dpkg installs them.

The Ansible fact cache (`/tmp/ansible_facts_cache`, `gathering = smart`) is keyed by inventory hostname: a node rebuilt under the same name reuses the old facts for an hour. Clear it between rebuilds.

### Transport adaptations (lab only)

Both nodes publish on 127.0.0.1, which breaks four assumptions in PRAHO's production transport. `lab_transport()` in `apps/provisioning/management/commands/_virtualmin_lab.py` adapts them, and only inside the lab commands: it refuses to run at all unless the settings module is `config.settings.lab` with DEBUG on, so no other process can loosen them. `tests/provisioning/test_virtualmin_transport_guard.py` pins the production side. They are also findings about what production assumes:

1. **API hosts must resolve to global addresses.** The SSRF guard refuses private and loopback targets. The exact lab names resolve to 127.0.0.1. Every other name still goes through the real resolver and the guard.
2. **Ansible always uses port 22.** The generated inventory has no port. Each lab deployment gets its published port as `ansible_port`.
3. **`_wait_for_ssh` probes port 22.** On a Mac that is the host's own sshd. The lab version probes the lab ports instead.
4. **The known_hosts lookup is keyed by bare IP.** It never matches port-keyed entries, so it would fall back to `ssh-keyscan` on port 22 and pin the host's key. The lab known_hosts is used instead, with `StrictHostKeyChecking=yes` kept.

## Limits

The lab is not a production node. It does not provide:
- **Mail.** The minimal LAMP bundle has no mail feature (`virtualmin list-features`: mail `No`), and neither does a node built by PRAHO's own `virtualmin.yml`, which also installs with `--minimal`.
  - The gate's default backup (email included) therefore also proves that verification expects only the components the domain has, which the manifest records as `domain_features`.
  - Mail data itself is never exercised.
- **Quotas.** There are no filesystem quotas in containers.
- **DNS.** BIND is not installed, and `*.praho.test` resolves only inside PRAHO's lab transport.
- **Realistic timing, disk pressure or failure modes of real hardware.**
- **Let's Encrypt, nftables and fail2ban.** These are installed by recommends but have no effect.
- **A clean first boot.** It reports one failed unit, `fcgiwrap-vm-*-praho-test.service`, that config-system references for the host's own name. It is harmless.

Stale jobs: a failed run can park a backup or restore job for attention, and that blocks the account. The next `test-virtualmin-lab` run closes those jobs before it starts.
