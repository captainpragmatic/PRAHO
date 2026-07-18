# Issue #299: Deterministic DigitalOcean delete test

**Status:** Implemented; platform verification complete

**Issue:** [#299](https://github.com/captainpragmatic/PRAHO/issues/299)

**Scope:** Test-only correction; no production polling behavior changes

## Objective

Make `TestDigitalOceanServiceDeleteServer.test_delete_server_success` model the
DigitalOcean API's post-delete lifecycle accurately and fail immediately if the
unit test ever attempts a real polling sleep.

The corrected test must prove that PRAHO:

1. sends the delete request with the integer droplet ID;
2. performs a confirmation lookup;
3. treats DigitalOcean's not-found response as successful deletion; and
4. never calls `time.sleep` on this immediate-success path.

## Evidence and root cause

- `DigitalOceanService.delete_server()` in
  `services/platform/apps/infrastructure/digitalocean_service.py` intentionally
  polls `get_server()` until the provider reports the droplet gone.
- The current success test configures `droplets.destroy()` but leaves
  `droplets.get()` as an unconstrained `MagicMock`.
- `get_server()` therefore converts the generic mock into a present
  `ServerInfo`, and the delete loop uses the real
  `infrastructure.do_action_timeout_seconds` default of 300 seconds.
- On fresh `origin/master`, the focused test remained running until manually
  interrupted. This reproduces the reported stall without identifying a
  production defect.

## Approaches considered

### A. Model the provider lifecycle and add a sleep bomb (selected)

Configure `droplets.get()` to raise the same not-found-shaped exception already
covered by `get_server()`, and patch `digitalocean_service.time.sleep` to raise
an assertion if called.

- Preserves production behavior.
- Exercises the real `delete_server()` -> `get_server()` boundary.
- Fails quickly if the fixture regresses.
- Requires a change only in the existing DigitalOcean service test module.

### B. Override the timeout or poll interval in the test

Setting the timeout to zero or reducing the interval would make the test finish,
but it would validate the timeout path instead of successful deletion. It could
also hide an inaccurate provider mock.

### C. Add injectable timing dependencies to production code

Injecting a clock or sleeper could improve general polling testability, but it
would expand a test-fixture defect into a production API refactor. Existing
patch boundaries are sufficient for this issue.

## Implementation plan

### Task 1: Establish the RED regression guard

**File:** `services/platform/tests/infrastructure/test_digitalocean_service.py`

**Test:** `TestDigitalOceanServiceDeleteServer.test_delete_server_success`

1. Patch `apps.infrastructure.digitalocean_service.time.sleep` with a side
   effect that raises `AssertionError` immediately.
2. Run the focused test before changing the provider response fixture.
3. Confirm it fails because `delete_server()` reaches the polling sleep, proving
   that the guard detects the reported defect rather than passing
   tautologically.

Command:

```bash
make test-file FILE=tests.infrastructure.test_digitalocean_service.TestDigitalOceanServiceDeleteServer.test_delete_server_success
```

Expected RED evidence: the sleep guard raises from the delete polling loop.

### Task 2: Make the success fixture reflect deletion

**File:** `services/platform/tests/infrastructure/test_digitalocean_service.py`

**Test:** `TestDigitalOceanServiceDeleteServer.test_delete_server_success`

1. Configure `client.droplets.get()` to raise `RuntimeError("404 not found")`
   after `droplets.destroy()` succeeds. This uses the existing public behavior
   of `DigitalOceanService.get_server()`, which maps not-found responses to
   `Ok(None)`.
2. Keep the sleep bomb installed so any future polling regression fails
   immediately rather than waiting for the configured timeout.
3. Assert all externally relevant interactions:
   - the result is `Ok(True)`;
   - `droplets.destroy(droplet_id=12345)` is called once;
   - `droplets.get(droplet_id=12345)` is called once; and
   - `time.sleep` is not called.
4. Run the focused test and confirm GREEN.

No change is planned for
`services/platform/apps/infrastructure/digitalocean_service.py`; its polling is
required for real asynchronous provider deletion.

### Task 3: Prove regression safety and runner completion

Run checks through the repository Makefile, in this order:

```bash
make test-file FILE=tests.infrastructure.test_digitalocean_service.TestDigitalOceanServiceDeleteServer
make test-file FILE=tests.infrastructure.test_digitalocean_service
make lint
make test-file FILE=tests
make test-platform
```

The first two commands isolate the changed behavior and its surrounding module.
`make test-file FILE=tests` exercises the complete platform suite serially;
`make test-platform` exercises it in the normal parallel configuration. Record
the final summary from both full-suite runs so completion—not merely worker
silence—is verified.

## Invariants and non-goals

- Do not skip, xfail, or delete any test.
- Do not reduce production delete timeouts or polling intervals.
- Do not replace the confirmation lookup with an assertion on mocks alone.
- Do not change other cloud-provider implementations.
- Do not update `CHANGELOG.md`; this is test reliability, not user-facing
  behavior.

## Completion criteria

- The RED run fails immediately at the sleep guard for the expected reason.
- The GREEN focused and module runs pass without calling sleep.
- `make lint` passes.
- Both serial and parallel full platform runs terminate normally and print final
  success summaries.
- The final diff remains test-only and retains DCO sign-off.

## Verification record

Verified on 2026-07-18:

- RED: the focused regression test failed in 0.004s at
  `digitalocean_service.py:152` when the old fixture reached `time.sleep`.
- GREEN: the focused test passed in 0.002s.
- The delete test class passed 2 tests; the full DigitalOcean module passed 23
  tests.
- The full serial platform suite passed 6,852 tests in 47.794s
  (`OK (skipped=4)`).
- The full parallel platform suite passed 6,852 tests in 14.226s
  (`OK (skipped=4)`) and printed its final success marker.
- Python syntax and every Platform lint phase passed. The full `make lint`
  command remains blocked in the Portal phase by the pre-existing editable
  Platform `.pth` entry in the shared virtualenv; no isolation bypass was used.
