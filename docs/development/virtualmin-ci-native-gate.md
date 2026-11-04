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

Release-candidate verification requires the native-inclusive job, successful real
capability step and successful workflow on the exact candidate SHA from `master`.
The native job checks out that immutable event SHA. Container-only, missing or
skipped capability, canceled native attempts and historical pre-native full jobs
cannot qualify it. Genuine drift/quiet/container runs may be passed over to find
actual matching native proof; they cannot turn an older pre-native success into
native evidence. Previously approved staging rollback keeps its existing
successful-release-candidate requirements and is not requalified retroactively.

Always preserve failed or uncertain native state and private logs for the existing
exact-resource reconciliation and teardown procedures. Container cleanup runs
after failure; it does not delete a native VM, overwrite its identity or upload
private recovery material. Routine CI can be green while this native gate remains
unqualified. The hosting changes must remain unmerged until their required native
acceptance is actually complete.
