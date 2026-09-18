# Manual E2E workflow and coverage audit

The browser suite is a local/manual check. It is not added to PR, scheduled, or nightly CI. Ordinary Django/API/security tests remain in CI. The unused `run_e2e` workflow input was removed because it never enabled a browser job.

## Running the complete suite

Use the repository's platform-specific virtual environment (`make install`), Node dependencies and the Playwright Chromium installation. From the repository root:

```sh
# Terminal 1: migrate, seed, verify, and serve both isolated applications.
make dev-e2e

# Terminal 2: require a healthy owned stack, then run every E2E test.
make test-e2e
make test-e2e  # repeat against the same stack to detect state leakage
```

`make dev-e2e-bg`, `make check-e2e`, and `make stop-e2e` offer the same lifecycle in the background. `make test-e2e-file FILE=tests/e2e/portal/test_customer_users.py` is a focused diagnostic. `test-with-e2e` is an alias; `test-e2e-platform`, `test-e2e-portal`, and `test-e2e-orm` select subsets. A subset is not evidence that the complete suite passed.

The servers listen only on loopback: Platform `localhost:8700`, Portal `localhost:8701`. The runner starts no workers and inherits an explicit environment allowlist. It does not read `.env`, inherit payment/cloud credentials, or contact live payment/provisioning providers. Local HMAC authentication and CSRF stay enabled. Email uses the memory backend. Uploads stay under ignored `output/e2e-media/`.

The server databases are `services/platform/e2e-platform-<sys.platform>.sqlite3` and `services/portal/e2e-portal-<sys.platform>.sqlite3`. ORM tests use a separate test database. Do not point these settings at development/customer data. The management commands reject non-E2E settings and the wrong database path. Stopping verifies the recorded supervisor's command and instance nonce; occupied ports are reported, never cleared by killing an unknown process.

Setup fails on migration/seed errors. Before testing, the runner checks log availability, fixture ownership, both independent customer memberships, real logins, persisted sessions, and a signed Portal-to-Platform company read. A missing prerequisite fails the run. Under the runner, any skip or xfail makes the session fail; no smaller passing declaration of coverage is accepted.

## Fixtures and isolation

Baseline records are owned by `praho-e2e-v1`. They include a staff administrator, two unrelated customer accounts, a known purchasable hosting product, service plan, and enough invoices/proformas/services/tickets to exceed the first page. Customer one has 25 of each document/service/ticket; customer two has two. Paid invoices have real succeeded payments; issued documents use the actual fiscal/FSM services.

The validated manifest is `logs/e2e-fixtures.json`. Tests that change data create private `account`, `billing`, or `pricing` scenarios through `seed_e2e --scenario ... --key ...`; they do not write the live server database through pytest's ORM connection. Shared baseline records are read-only. The existing localisation test deliberately restores all profile preferences in `finally`; the private-account language test independently verifies persistence.

A restarted stack keeps its database. This makes a second run useful: baseline corruption must surface instead of being hidden by a reset. To discard a disposable stack, stop it first, archive only the two dedicated E2E databases and their SQLite sidecars, then start it again. Do not delete ordinary service databases. Uploaded test files and run artifacts may be removed after stopping the owned stack when no longer needed.

## What the audit changed

[e2e-audit.json](e2e-audit.json) accounts for all 317 original collected tests at `b26e427b8b4dafdf51823cce75203f739c1b0e9d`. Each row records original intent/assertions, disposition, replacement nodes and review notes. Audit disposition describes coverage; passing status comes from actual run artifacts.

| Disposition | Original cases |
| --- | ---: |
| Retained meaningful checks | 28 |
| Strengthened checks/prerequisites | 266 |
| Renamed to the behavior actually provided | 13 |
| Consolidated duplicate coverage | 7 |
| Moved deterministic checks to the appropriate layer | 2 |
| Removed accidental collection of an imported helper | 1 |

Mutating tests now verify saved outcomes instead of accepting navigation, arbitrary HTTP errors, a missing control, or an early return. Examples include paid invoice conversion and immutable amounts, public/internal ticket visibility, real attachment bytes and authorization, actual search results beyond page one, independent customer isolation, selected order terms/payment method, password changes, and one-use recovery codes.

Production fixes include sample-data integrity and real-model audit fields; eligibility/authorization of manual proforma payments; customer identity/phone and order metadata; full billing synchronization; service search/pagination/date/usage contracts; user-scoped MFA/password/customer-switch endpoints; nullable company identity; HTMX product toggle responses; bounded ticket uploads and signed download proxying; and mobile ticket/service layout. Existing monetary calculation policy is preserved. The D390 export form has a distinct hidden month ID.

## Evidence and acceptance

Each run writes `output/playwright/runs/<timestamp>/` containing `pytest.log`, JUnit, failure traces/screenshots, copied server logs, fixture manifest and `run.json`. Metadata records the Git head, staged/unstaged/untracked source fingerprint, dirty status, stack identity, command, exit status, and whether source changed during the run. Treat an exploratory run with changing source as diagnostic only.

Acceptance requires two complete successful runs on the same unchanged stack and source, no unexpected skip/xfail, and no new unexpected browser/HTML/server errors. Expected errors are scoped to specific negative tests (for example, a missing Stripe key); a successful browser result does not mean a live card charge occurred.

Keep the host awake during verification. On macOS, `caffeinate -is make test-e2e` prevents idle sleep only while the command runs, without changing power settings. Sleep can interrupt browser deadlines and expire staff sessions; preserve a disrupted run as failed evidence and repeat it. Saved-session fixtures validate a 200 response from the actual protected dashboard, rejecting missing pages and login redirects before falling back to real login.

Run `make test`, `make lint`, `make check-types-platform`, `make check-types-portal`, and `make check-migrations`. The template component scan has pre-existing findings and its Make target is advisory: compare against baseline and compile all changed templates rather than interpreting its zero exit as a clean strict scan. `make lint` also prints advisory legacy results; inspect the actual no-new-Ruff-debt gate and typing output. A working-tree Ruff check must pass explicit changed paths until commits exist, since the default gate compares committed heads.

The Platform API and query-performance directories are Python packages so Django discovers their tests in the default suite. A discovery regression check rejects test directories that lack `__init__.py`; previously these directories could pass focused runs while being silently omitted from `make test`.

SQLite cannot prove row-lock behavior. Financial/authorization concurrency checks must also run with `config.settings.ci` against an isolated PostgreSQL database. The manual-payment race submits twice from separate connections and requires one succeeded payment, one locked paid invoice, and the same invoice returned to both callers. Existing recurring collection, order confirmation, promotion redemption and API-token concurrency tests are included.

## Remaining feature boundaries

These are explicit follow-ups, not tests silently marked as passing:

| Feature | What is verified now | Work needed / when |
| --- | --- | --- |
| Customer password-reset delivery | Accessible request form and uniform response | Implement and test the complete Portal-to-Platform reset/token/email flow before advertising working recovery. The Portal request handler is still a stub. |
| Service requests and historical usage | Current recorded usage, domain field, action choices/required reason/cancel | Implement authorized request submission/lifecycle and real history endpoints before claiming these actions or charts work. A missing endpoint is not mocked into an E2E success. |
| Customer order history | Catalog, cart, real checkout/confirmation, isolation | Build an explicit history route/view if required; `/order/` currently serves the catalog. |
| Registrar, bundle expansion and remote provisioning | Retained input/configuration, real local order FSM and service controls | Provider contract and operator validation belong to their domain work; these local tests do not register a domain, split a bundle, or create a remote server. |
| GDPR export completion and email | Authenticated private export request and its pending state | Verify worker completion, archive contents and delivery with an owned mail/worker environment before claiming end-to-end delivery. |
| Card payments and panel certificates | Controlled missing-provider behavior and existing offline contracts | Run explicit provider/operator drills with authorized credentials. #436 remains a separate live panel-certificate rollout; this E2E repair does not close it. |

Browser success proves the supported local workflow, not ANAF acceptance, certificate issuance, email delivery or live payment settlement. No production deployment or live-provider mutation is part of this task.
