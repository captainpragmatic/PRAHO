# Disposable mail-node capability contract

This suite creates its own UUID-labeled Docker container and bridge, with no published ports. It never uses
`vmlab-a`, `vmlab-b`, their MTA/PAM/trust stores, the lab database, MinIO, or private controller scripts.
It is separate from `make test-virtualmin-contract`, ordinary tests, and the existing P2 native contract.

Choose the profile explicitly:

```sh
make test-virtualmin-mail-node MAIL_LAB_PROFILE=debian12
make test-virtualmin-mail-node MAIL_LAB_PROFILE=ubuntu2604
make test-virtualmin-mail-node MAIL_LAB_PROFILE=all
```

Docker must support privileged systemd containers and the existing `/sys/fs/cgroup` mount, as the ordinary lab does.
The active virtualenv must include Ansible and its `community.docker.docker` connection plugin. Set the standard
`ANSIBLE_COLLECTIONS_PATH` if the collection lives in a private cache; this test never silently installs collections.

The default clean images are `praho-virtualmin-lab:8.3.0` (Debian12/Dovecot2.3 after setup) and
`praho-adr61-ubuntu26-virtualmin:8.3.0` (Ubuntu26.04/Dovecot2.4 after setup). Optional overrides are
`MAIL_LAB_DEBIAN_IMAGE` and `MAIL_LAB_UBUNTU_IMAGE`. Each reference is inspected and pinned to its immutable image ID.
The clone must prove exact OS release and Virtualmin package `8.3.0-1-gpl` before fixture/MTA changes; Dovecot may be
absent before setup. No image is pulled, committed, or built by this test.

The tracked image recipe is `deploy/virtualmin-lab/virtualmin/Dockerfile`, with build context
`deploy/virtualmin-lab/`. Its base override is **DEBIAN_IMAGE**, also for Ubuntu:

```sh
docker build -f deploy/virtualmin-lab/virtualmin/Dockerfile -t praho-virtualmin-lab:8.3.0 deploy/virtualmin-lab
docker build -f deploy/virtualmin-lab/virtualmin/Dockerfile --build-arg DEBIAN_IMAGE=ubuntu:26.04 -t praho-adr61-ubuntu26-virtualmin:8.3.0 deploy/virtualmin-lab
```

Prefer a verified base-image digest when rebuilding. Building/downloading packages and the clean image's first
boot can take many minutes. First boot has a bounded1800-second wait; production setup has a bounded1050-second
controller timeout. There is no hidden dependency on a preconfigured private baseline image.

If Docker's embedded DNS cannot reach package repositories in your environment, explicitly pass a working resolver
for **this test's new containers only**:

```sh
make test-virtualmin-mail-node MAIL_LAB_PROFILE=ubuntu2604 MAIL_LAB_DNS=192.0.2.53
```

That documentation address is an example; supply your own reachable resolver. The harness passes `--dns` to Docker.
It never guesses a Docker Desktop host address or rewrites `/etc/resolv.conf`, and production helpers stay unchanged.

The lifecycle calls the actual `virtualmin_mail.yml` through the Docker connection for setup, ready replay,
submitter reconciliation, and fresh post-reboot inspection. It verifies unchanged global PAM/SSH files, existing
credential/aging fingerprints, provider configuration and per-domain mail flags; a new default-feature account
stays mail-off. Real TLS clients must reject the valid, unexpired, unenrolled Unix credentials on993/995/465 before
and after an actual container restart. A fresh runtime marker and Docker start time prove the restart occurred.
There are no enrollment, mailbox-move, DKIM, queue-forwarding or teardown-readiness claims.

The routine certificate extension stages a trusted-but-wrong-name renewal and requires the previous service
copy/journal to remain exact. It then installs two validated replacement leaves, checks every actual TLS frontend,
and replays the first completed UUID against the later generation without replacing it. Both fake renewal CAs stay
trusted only inside that disposable clone. The ordinary preservation/default-off/reboot checks still follow.
These cases cover live-service reload; they do not reset a review/applying journal.

`test_certificate_expiry.py` covers expired-certificate recovery after the boot guard has stopped the services, on the
same owned-clone harness (one clone per case, run them with `-x` so a failure retains at most one clone):

```sh
make test-virtualmin-mail-expiry MAIL_LAB_PROFILE=debian12
make test-virtualmin-mail-expiry MAIL_LAB_PROFILE=ubuntu2604
```

Its in-clone helper `expiry_checks.py` forges a trusted, correctly named leaf that expired a day ago, with matching
manifest digests (production cannot install one: setup and rotation refuse a candidate within seven days of expiry),
and proves a real `systemctl restart` is refused by the guard before stopping mail. The first case asserts the pinned
unit topology, then recovers through `reconcile_node_certificate`, checks all four frontends and bounds each start's
cost under a permit. It then kills the worker right after the guard admitted its first unit (later starts are refused,
the admitted daemon stays fenced, the same UUID resumes). It also kills the worker and restarts the container
mid-sequence (the tmpfs lock and the live fence are gone; Docker keeps the boot ID, so boot binding stays a unit
test), and the same UUID resumes. A completed UUID replays as verification only. The second case sets a clone up
from the previous commit's extracted playbook, expires it, upgrades the helper bundle in place with `upgrade_bundle`,
and then recovers.

An ephemeral strict CA/leaf and random fake passwords live only in clone/private memory or private test state.
Secrets travel over stdin, never into host argv or saved console logs. The fixed in-clone dispatcher suppresses
native command/timeout tracebacks. Public output and private host facts contain only identity/status evidence.

Successful runs remove only their exact recorded container/network IDs after fresh label, image, hostname, port
and endpoint checks. Failed runs retain their clone and journal by default; the captured output names the private
0700 artifact directory and its ownership manifest. To remove an owned failure from the same run, explicitly set
`MAIL_LAB_CLEANUP_FAILURE=1` (pytest option `--cleanup-owned-failures`). Foreign or replaced resources are always refused.
No prune or shared-resource cleanup runs. Retained resources require deliberate operator cleanup using the manifest.

The cheap ownership/error-redaction tests need no Docker daemon or image:

```sh
make test-virtualmin-mail-node-unit
```
