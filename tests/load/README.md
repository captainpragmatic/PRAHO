# Load Testing for PRAHO Platform

A [Locust](https://locust.io/) load test for the staff Platform. Staff users log in once, then browse
the main listing pages by weight.

| File | What it is |
|---|---|
| `locustfile.py` | One `StaffUser` class. It validates its login, then every response |
| `scenarios.py` | The pages and their weights, with no Locust import |

`services/platform/tests/common/test_load_test_scenarios.py` checks that every page in `scenarios.py`
exists, sits behind the staff login, and renders for staff. A renamed route therefore fails a unit
test instead of quietly turning a load run into 404s.

## Setup

Locust is not a project dependency, and the script imports nothing from PRAHO. Run it in an isolated
environment with [`uvx`](https://docs.astral.sh/uv/), so it never touches the project virtualenv.

The account must be **staff with no second factor enrolled**. A staff login with 2FA stops at the code
page, and the script records that as a failed login and stops the user.

**Against the isolated E2E stack (recommended).** This leaves your dev database alone, and its
fixtures already include a suitable staff account:

```bash
make dev-e2e-bg
LOCUST_EMAIL=e2e-admin@test.local LOCUST_PASSWORD=test123 \
  uvx locust -f tests/load/locustfile.py --host=http://localhost:8700 --headless -u 3 -r 1 -t 45s
make stop-e2e
```

**Against `make dev`.** Create a dedicated staff account first. The user model is email-based and has
no `username` field.

```bash
VENV=.venv-$(uname -s | tr '[:upper:]' '[:lower:]')
cd services/platform
PYTHONPATH=$PWD ../../$VENV/bin/python manage.py shell --settings=config.settings.dev -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(email='loadtest_staff@test.ro').exists():
    User.objects.create_user(email='loadtest_staff@test.ro', password='LoadTest123!', is_staff=True, staff_role='admin')
"
```

`LOCUST_EMAIL` and `LOCUST_PASSWORD` default to that account.

## Running Load Tests

```bash
# Web UI at http://localhost:8089
uvx locust -f tests/load/locustfile.py --host=http://localhost:8700

# Headless, 100 users spawning 10 per second for 5 minutes, with an HTML report
uvx locust -f tests/load/locustfile.py --host=http://localhost:8700 --headless -u 100 -r 10 -t 5m --html=load_report.html
```

| Scenario | Command flags |
|---|---|
| Smoke | `--headless -u 5 -r 1 -t 1m` |
| Load | `--headless -u 100 -r 10 -t 10m` |
| Stress | `--headless -u 500 -r 50 -t 15m` |
| Spike | `--headless -u 200 -r 100 -t 5m` |

No CI workflow runs these tests. The development and E2E servers are single-process and use SQLite.
Their numbers show regressions between two runs on the same machine, not production capacity.

## What is not covered

- **The Platform API.** It only accepts HMAC-signed requests from the portal, with specific methods and
  payloads, so API load needs a signed scenario. The old unauthenticated API user class measured
  nothing but 401s and was removed.
- **The customer portal.** Its pages proxy to the platform; a portal scenario would need customer
  accounts and the portal's own login.

## Performance Targets

| Metric | Target |
|--------|--------|
| Response Time (p50) | < 200ms |
| Response Time (p95) | < 1000ms |
| Response Time (p99) | < 2000ms |
| Error Rate | < 1% |
| Requests/second | > 100 |

## Common Issues

1. **`login` failures**: wrong credentials, or the account has 2FA enrolled. The failure message names
   the page the login ended on.
2. **"redirected to the login page" failures**: the session was lost mid-run. Check the session
   settings and the server log.
3. **Connection refused**: nothing is serving `:8700`. Start `make dev` or `make dev-e2e-bg`.
4. **Slow pages**: check database performance and N+1 queries for the named page.
