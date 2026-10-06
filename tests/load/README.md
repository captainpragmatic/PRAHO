# Load Testing for PRAHO Platform

This directory holds a [Locust](https://locust.io/) load-test script for the staff Platform
(`locustfile.py`).

## Current state: the script needs rework before it measures anything

The scenarios predate the platform's current URLs and login form. Run as it stands, the script only
measures failures:

- **Login.** It posts a `username` field, but the platform's login form takes `email`, so every login
  fails.
- **Routes.** It requests `/app/<section>/` URLs. Only `/app/` survives, as an alias of the dashboard.
  The sections now live at the top level: `/customers/`, `/orders/`, `/billing/`, `/products/`,
  `/tickets/`, `/provisioning/`, `/domains/`, `/audit/` and `/settings/`.
- **API.** `PRAHOAPIUser` sends no credentials, so the platform refuses its `/api/...` requests.

Treat any numbers it produces as meaningless until the script is updated. The rest of this page
describes how to run it once that is done.

## Setup

Locust is not a project dependency, and the script imports nothing from PRAHO. Run it in an isolated
environment with [`uvx`](https://docs.astral.sh/uv/), so it never touches the project virtualenv.

1. Start the platform with `make dev`. It serves on `http://localhost:8700`.
2. Create the two test users. The user model is email-based and has no `username` field. Staff
   accounts without an enrolled second factor log in with the password alone.

```bash
VENV=.venv-$(uname -s | tr '[:upper:]' '[:lower:]')
cd services/platform
PYTHONPATH=$PWD ../../$VENV/bin/python manage.py shell --settings=config.settings.dev -c "
from django.contrib.auth import get_user_model
User = get_user_model()
for email, extra in (
    ('loadtest@test.ro', {}),
    ('loadtest_staff@test.ro', {'is_staff': True, 'staff_role': 'support'}),
):
    if not User.objects.filter(email=email).exists():
        User.objects.create_user(email=email, password='LoadTest123!', **extra)
"
```

## Running Load Tests

### Web UI mode (for development)
```bash
uvx locust -f tests/load/locustfile.py --host=http://localhost:8700
```
Then open http://localhost:8089 in your browser.

### Headless mode
```bash
# 100 users, spawning 10 per second, for 5 minutes
uvx locust -f tests/load/locustfile.py --host=http://localhost:8700 --headless -u 100 -r 10 -t 5m

# With an HTML report
uvx locust -f tests/load/locustfile.py --host=http://localhost:8700 --headless -u 100 -r 10 -t 5m --html=load_report.html
```

No CI workflow runs these tests.

### Specific user types
```bash
# Choose user classes in the web UI
uvx locust -f tests/load/locustfile.py --host=http://localhost:8700 --class-picker

# Filter by tags
uvx locust -f tests/load/locustfile.py --host=http://localhost:8700 --tags dashboard customers
```

## User Types

| User Type | Description | Wait Time |
|-----------|-------------|-----------|
| PRAHOWebUser | Regular web users | 1-5s |
| PRAHOAPIUser | API clients | 0.5-2s |
| PRAHOHeavyUser | Heavy operations (reports, exports) | 5-15s |
| PRAHOStaffUser | Administrative tasks | 2-8s |
| PRAHOMixedUser | Realistic mixed usage | 1-10s |

## Test Scenarios

```bash
# Smoke
uvx locust -f tests/load/locustfile.py --host=http://localhost:8700 --headless -u 5 -r 1 -t 1m
# Load
uvx locust -f tests/load/locustfile.py --host=http://localhost:8700 --headless -u 100 -r 10 -t 10m
# Stress
uvx locust -f tests/load/locustfile.py --host=http://localhost:8700 --headless -u 500 -r 50 -t 15m
# Spike: rapid increase to high load
uvx locust -f tests/load/locustfile.py --host=http://localhost:8700 --headless -u 200 -r 100 -t 5m
```

The development server is single-process and uses SQLite. Its numbers show regressions between two
runs on the same machine, not production capacity.

## Performance Targets

| Metric | Target |
|--------|--------|
| Response Time (p50) | < 200ms |
| Response Time (p95) | < 1000ms |
| Response Time (p99) | < 2000ms |
| Error Rate | < 1% |
| Requests/second | > 100 |

## Interpreting Results

- **RPS (requests per second)**: higher is better
- **Response time**: lower is better
- **Failure rate**: should be near 0%. Today it is not; see "Current state" above
- **Percentiles**: p95 and p99 show worst-case performance

## Common Issues

1. **Every login fails**: the script posts `username`; see "Current state"
2. **CSRF errors**: check that the CSRF token is read from the login page before posting
3. **Connection refused**: the platform is not running on `:8700`; start it with `make dev`
4. **Slow response times**: check database performance and N+1 queries
