# Container CI and native acceptance

Routine container coverage and native acceptance are separate gates. A green
container job does not qualify Ubuntu filesystem quotas, reboot persistence,
fresh provider deployment, owned DNS or native hosting activation.

`make test-virtualmin-lab-containers` runs the existing lab suites (including
components), fault injection, browser smoke tests and maintenance Portal
acceptance. All legs run and failures are named at the end. The scheduled
`nightly-containers` job and default `suite=containers` dispatch use this target.
The existing merge-queue `pull-request` check and its selection remain unchanged.

`make test-virtualmin-lab-full` retains its native deployment leg. It never skips
that leg because authority is absent. An explicit `suite=full` dispatch uses
`native-full` on the fixed isolated labels `self-hosted`, `linux`,
`native-acceptance`, in the `native-acceptance` environment. No full dispatch,
runner registration, provider resource or credential configuration is authorized
merely by adding this workflow. The owner must approve and configure that
execution environment separately; until then native acceptance remains pending.

The hosted `native-admission` job fails an unconfigured full dispatch before it
queues a private runner. The repository variable `NATIVE_ACCEPTANCE_RUNNER_READY`
must be exactly `true`. This is a configuration declaration, not proof: it can
become stale and cannot prove runner availability or private authority. A
configured but unavailable runner remains an external prerequisite. Admission
success never qualifies the release verifier without actual native execution.
No extra token privileges or automatic billable daily bootstrap are used.

The runner must already have the approved original private VM manifest/key,
completed public deployment and current native qualification, isolated
`praho_native_` PostgreSQL database, provider/DNS authority and exact owned storage
fixture. Keep authority and storage credentials outside the checkout and outside
uploaded artifacts. Configure `NATIVE_VM_MANIFEST`, `NATIVE_DNS_ZONE`,
`NATIVE_S3_MANIFEST`, native database connection variables, and the private
`PRAHO_NATIVE_S3_*` environment supplied by the owned storage fixture. Use the
existing native README's explicit preparation commands first. Retain the original
key and database; no test-key compatibility, automatic rekey or replacement VM
is inferred from an interrupted run.

The named workflow step **Verify fresh Ubuntu native hosting capability** runs
the actual `make test-virtualmin-native-fresh-deployment` before the full suite.
The node-deploy script also requires this proof before any migration or deployment
rerun. An intent-only or raw-provider manifest therefore cannot make `full`
provision a new VM. After admission it serially runs migration, the completed
public deployment rerun, registration, native quota/reboot checks, fresh proof,
owned storage verification and public lifecycle acceptance. Raw registration-resume
remains a separate run/database and supplies no fresh provider-create proof.
The standalone operator preparation command `native-vm-fresh-deploy` remains the
explicit public creation operation.

Container Virtualmin/API behavior and unsupported-baseline refusal controls stay
useful. The old Debian container activation result is not supported managed
Ubuntu activation; Ubuntu installation/API-user/access-lock/firewall/lifecycle
evidence belongs to the native gate. Native notification/commercial acceptance
retains its separate documented controls. This full job does not claim those
additional scenarios merely because its foundation capability check passed.

Native acceptance is optional and does not gate a release. No self-hosted runner
exists, so release-candidate verification requires the latest full Virtualmin lab
on `master` to have passed: the container job (`nightly-containers`, nightly or a
`containers` dispatch) or, when one has run, a native `full` dispatch. A failed or
cancelled latest full lab refuses; drift runs, quiet nights and `full` dispatches
refused at admission are passed over. Kernel, filesystem and cloud-image behaviour
(quotas, image defaults) and node deploy are proven on staging by deploying a test
node after the promote, until a disposable-VM native check runs on hosted runners.
The lab evidence is master's latest full lab, not a run on the candidate itself.
A previously approved staging rollback keeps the release-candidate requirements it
was qualified under and is not requalified retroactively.

Always preserve failed or uncertain native state and private logs for the existing
exact-resource reconciliation and teardown procedures. Container cleanup runs
after failure; it does not delete a native VM, overwrite its identity or upload
private recovery material. Routine CI can be green while this native gate remains
unqualified. The hosting changes must remain unmerged until their required native
acceptance is actually complete.

## Docker kernel prerequisites

An Ubuntu container image supplies userspace; its kernel is the Docker daemon's
kernel. For ext4 user/group quota experiments, that kernel needs both
`CONFIG_QUOTA` and `CONFIG_QFMT_V2`. The [Linux ext4 mount check](https://github.com/torvalds/linux/blob/v7.0/fs/ext4/super.c#L3451)
refuses a writable filesystem with native quota inodes when either is absent.
Additional container capabilities or installing the `quota` package cannot add a
quota format compiled out of the kernel.

On 2026-11-05, a bounded ARM64 Docker Desktop probe reached the real ext4 mount
with a newly created 2 GiB image and one atomically claimed unused loop device.
The running `7.0.14-linuxkit` kernel exposed `CONFIG_QUOTA=y` but
`# CONFIG_QFMT_V2 is not set` in `/proc/config.gz`, and the mount failed before any
UID/GID, PHP or MariaDB quota assertion ran. The probe verified normal owned
cleanup, including the closed loop descriptor, absent loop association, removed
private device node and backing image; the container was then removed without
force. This is an unsupported-kernel result, not a quota acceptance pass.

A Docker daemon with the required kernel support can exercise kernel denial and
adapter behavior within the supported filesystem layout. Ubuntu boot/update
persistence still requires an independently booted Ubuntu guest. A local guest
can supply that kernel and root filesystem; cloud provider and DNS provenance
are additional requirements of the existing full deployment harness. Keep those
evidence scopes distinct, and preserve the production root-filesystem checks.
