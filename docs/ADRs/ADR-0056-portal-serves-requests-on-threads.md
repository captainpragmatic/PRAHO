# ADR-0056: The Portal Serves Requests on Threads

- Status: Accepted
- Date: 2026-10-10
- Authors: PRAHO maintainers
- Related: ADR-0030 (rate limiting, per-principal amendment), ADR-0032 (dual HMAC), ADR-0055 (portal sessions merge concurrent writes)

## Context

The portal ran gunicorn **sync** workers: one request per process at a time.
- **Native installs ran one portal process,** so a single slow request blocked every customer. Slow requests include:
  - a Platform call (up to 30 s per attempt, with 503 retries);
  - a proxied invoice PDF;
  - the login timing floor (at least 1 s per login).
- **Docker ran two processes,** which barely helped.

Requests are I/O-bound: almost all of a request's time is spent waiting on Platform. That is what threads are for.

## Decision

The portal runs gunicorn's built-in **`gthread`** worker, **2 processes × 4 threads**, on every deploy path.
- **One setting.** `services/portal/gunicorn.conf.py` owns it (`PORTAL_GUNICORN_WORKER_CLASS`, `_WORKERS`, `_THREADS`).
- **Rollback.** Setting `PORTAL_GUNICORN_WORKER_CLASS=sync` restores one request per process. It always means one thread: gunicorn otherwise silently keeps `gthread` whenever threads > 1.

### Why not the alternatives

| Option | Why not |
|---|---|
| Python 3.14 free-threaded | Removes the GIL for CPU-bound work; our requests wait on I/O. A sync view still holds its thread or process for its whole duration. Free-threading stays opt-in (PEP 779), and C extensions can re-enable the GIL. |
| Django 6.0 / 6.1 | No change to WSGI concurrency. Async views would still need an async HTTP client. |
| gunicorn's `asgi` worker | Our views and `requests` calls are synchronous, so Django runs each one in a thread anyway. A real gain needs httpx (a new library) plus rewriting views and middleware. |
| gevent | A new library, plus monkey-patching of sockets, `sleep`, `threading.local` and sqlite3. |
| uvicorn / granian | A server swap with no gain for sync views. |
| More sync processes only | Safe, but every concurrent request costs a whole process. This remains the rollback. |

### Settings that make threads safe

- **`worker_connections = threads`.** A worker whose threads are all busy stops accepting connections, so the next request goes to an idle sibling instead of queueing behind held requests. With gunicorn's default (1000), the acceptance test with 7 of 8 threads held fails.
- **`keepalive = 0`.**
  - Each connection closes after its response, as sync workers always did.
  - Caddy keeps upstream connections for two minutes. It answers 502 to a non-idempotent request on a connection the worker has already closed, so closing every connection avoids that trap.
- **`timeout` is only a liveness check under `gthread`.** The worker checks in while its requests run, so gunicorn never ends a slow request. Two other limits bound one:
  - **Platform calls:** each has a total budget, retries included (at most 45 s, `PLATFORM_API_TOTAL_BUDGET_SECONDS`).
  - **Slow clients:** Caddy buffers the request (6 MB, above the 5 MB body cap) and up to 10 MiB of the response, and a body must arrive within 60 s (`read_body`). A slow client therefore holds Caddy, not a portal thread. Only a response larger than 10 MiB streams through a thread.
- **`graceful_timeout = 50`,** with Docker's stop grace at 55 s, so a restart drains requests in flight.

## What threads share, and why it is safe

| Shared object | Verdict | Evidence |
|---|---|---|
| Outbound `requests.Session` (cookie jar, connection pool) | Fixed | One Session per thread, whose cookie policy blocks every cookie. `requests` merges a Session's cookies into every request, so a shared jar could carry one customer's Platform cookie into another's call. |
| Caddy ↔ gunicorn connection reuse | Avoided | `keepalive = 0`, as above. |
| HMAC nonce, signature, body | Safe | Built per call. |
| Singletons `api_client`, `tickets_api`, `services_api` | Safe | No `self.` writes after `__init__`. |
| Request-ID thread-local | Safe | Cleared in `finally`. |
| Middleware instances, translation, timezone, caches | Safe | No per-request instance state; `translation.override` is paired; caches are keyed by language. |
| Validation single-flight | Safe | Held under a lock and keyed by session. |
| SQLite counters and claims | Safe | Single-statement upserts on one connection per thread. Claims stay atomic under concurrency. |
| Whole-session saves for one user | Fixed by ADR-0055 | Concurrent requests on one session merge their changes instead of the last save undoing the others. |
| Platform's per-portal rate limits | Fixed by the ADR-0030 amendment | Limits are per customer, so one busy customer cannot use up every customer's budget. |
| Log files across processes | Fixed | `WatchedFileHandler` plus logrotate replaces in-process rotation, which raced across processes. |

## Sizing

Measured on 2026-10-10:
- **Setup.** The production image ran with `--memory 512m`, equal to the native unit's `MemoryMax=512M`. Each thread served a concurrent login answered with a 5 MiB body, for 3 rounds, followed by a graceful reload.
- **Platform.** Docker Desktop, linux/aarch64. Production is x86_64, so absolute numbers will differ somewhat.

| Config | Idle | Peak | Share of 512 MiB |
|---|---|---|---|
| sync 1×1 (native before) | 72 MiB | 88 MiB | 17% |
| sync 2×1 (Docker before) | 113 MiB | 152 MiB | 30% |
| **gthread 2×4 (chosen)** | 114 MiB | 195 MiB | 38% |
| gthread 1×8 | 74 MiB | 148 MiB | 29% |

- **Cost model.** Threads share their process's Django, so the cost is per process, plus roughly 10 MiB per concurrent large response.
- **Why 2×4 over 1×8.** Two processes keep the portal serving if one worker dies or is recycled. They also halve the GIL contention of any CPU-bound moments, such as JSON parsing and template rendering.

## Verification

`make test-portal-server` runs in its own CI job, `portal-server`. It starts real gunicorn with the shipped config and production settings, against a stub Platform whose logins can be held open:

1. **gthread 1×4.** With three logins held, `/status/` still answers immediately, and the log says `Using worker: gthread`.
2. **gthread 2×4.** With seven of eight threads held, ten probes in a row all answer immediately. This fails with gunicorn's default `worker_connections`.
3. **sync 1×1.** One held login makes `/status/` wait. This shows the rollback really is one request at a time, and it fails if sync stops forcing one thread.
4. **Release.** Held requests finish, and every response carries `Connection: close`.

## Consequences

- **What this fixes.** One customer waiting on Platform no longer makes the others wait for the portal. Examples are a slow invoice PDF, a login held by its timing floor, or a Platform retry.
- **Residual risk: Platform still runs sync workers** (2 native, 4 Docker).
  - Portal threads can now queue *at Platform*. Two slow PDFs can therefore still stall other customers' Platform-backed pages on a native install.
  - The staging check measures this with a Platform-backed probe while slow requests are held. Platform under threads is a separate decision.
- **Residual risk: buffering.** Caddy's buffers cost memory per connection. `read_body` bounds how long a body may take, so holding that memory needs real bandwidth, not a trickle.
- **Rollback.** `PORTAL_GUNICORN_WORKER_CLASS=sync` (optionally with more workers) on any deploy path, then confirm `Using worker: sync` in the startup log. `docs/deployment/DEPLOYMENT.md` has the runbook.
