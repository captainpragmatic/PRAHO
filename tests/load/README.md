# Load Testing for PRAHO Platform

This directory contains load testing scripts using [Locust](https://locust.io/).

## Setup

1. Install dependencies:
```bash
pip install -r ../../services/platform/requirements/testing.txt
```

2. Create test users in the database:
```bash
cd services/platform
python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()

# Create regular test user
User.objects.get_or_create(
    username='loadtest_user',
    defaults={
        'email': 'loadtest@test.ro',
        'is_staff': False,
    }
)
User.objects.filter(username='loadtest_user').first().set_password('LoadTest123!')

# Create staff test user
User.objects.get_or_create(
    username='loadtest_staff',
    defaults={
        'email': 'loadtest_staff@test.ro',
        'is_staff': True,
        'staff_role': 'support',
    }
)
User.objects.filter(username='loadtest_staff').first().set_password('LoadTest123!')
"
```

## Running Load Tests

### Web UI Mode (Recommended for development)
```bash
locust -f tests/load/locustfile.py --host=http://localhost:8000
```
Then open http://localhost:8089 in your browser.

### Headless Mode (For CI/CD)
```bash
# 100 users, spawn 10 per second, run for 5 minutes
locust -f tests/load/locustfile.py --host=http://localhost:8000 --headless -u 100 -r 10 -t 5m

# With HTML report
locust -f tests/load/locustfile.py --host=http://localhost:8000 --headless -u 100 -r 10 -t 5m --html=load_report.html
```

### Specific User Types
```bash
# Only API users
locust -f tests/load/locustfile.py --host=http://localhost:8000 --class-picker

# Filter by tags
locust -f tests/load/locustfile.py --host=http://localhost:8000 --tags dashboard customers
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

### Smoke Test
```bash
locust -f tests/load/locustfile.py --host=http://localhost:8000 --headless -u 5 -r 1 -t 1m
```

### Load Test
```bash
locust -f tests/load/locustfile.py --host=http://localhost:8000 --headless -u 100 -r 10 -t 10m
```

### Stress Test
```bash
locust -f tests/load/locustfile.py --host=http://localhost:8000 --headless -u 500 -r 50 -t 15m
```

### Spike Test
```bash
# Rapid increase to high load
locust -f tests/load/locustfile.py --host=http://localhost:8000 --headless -u 200 -r 100 -t 5m
```

## Performance Targets

| Metric | Target |
|--------|--------|
| Response Time (p50) | < 200ms |
| Response Time (p95) | < 1000ms |
| Response Time (p99) | < 2000ms |
| Error Rate | < 1% |
| Requests/second | > 100 |

## Interpreting Results

- **RPS (Requests per second)**: Higher is better
- **Response Time**: Lower is better
- **Failure Rate**: Should be near 0%
- **Percentiles**: p95 and p99 show worst-case performance

## Common Issues

1. **High failure rate on login**: Check test user credentials
2. **CSRF errors**: Ensure CSRF token extraction is working
3. **Connection refused**: Ensure Django server is running
4. **Slow response times**: Check database performance, N+1 queries
