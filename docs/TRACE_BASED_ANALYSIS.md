# Trace-Based Dynamic Analysis

This document describes the trace-based dynamic analysis infrastructure added to PRAHO Platform for runtime debugging, performance monitoring, and N+1 query detection.

## Overview

Instead of relying solely on static code analysis, this infrastructure allows stepping through code execution to see how the system actually behaves at runtime. This is particularly effective for:

- **Diagnosing potential bugs** that only manifest at runtime
- **Catching side effects** that static analysis misses
- **Detecting performance problems** like N+1 queries
- **Correlating logs** across request lifecycles

## Components

### 1. RequestIDFilter (`apps/common/logging.py`)

Adds request correlation IDs to all log messages for end-to-end tracing.

```python
# Settings configuration
LOGGING = {
    "filters": {
        "add_request_id": {
            "()": "apps.common.logging.RequestIDFilter",
        },
    },
    "handlers": {
        "console": {
            "filters": ["add_request_id"],
            ...
        },
    },
}
```

Log output example:
```
[a1b2c3d4-5678-90ab-cdef-123456789abc] INFO 2025-01-15 10:30:00 views: User login successful
```

### 2. QueryTracer

Monitors database queries with N+1 detection.

```python
from apps.common.logging import QueryTracer, QueryBudget

# Basic usage
with QueryTracer() as tracer:
    users = list(User.objects.all())
    for user in users:
        print(user.profile.bio)  # N+1 detected!

summary = tracer.get_summary()
print(f"Queries: {summary['total_queries']}")
print(f"Duplicates (N+1): {summary['duplicate_count']}")

# With budget enforcement
budget = QueryBudget(max_queries=10, max_duplicates=2, raise_on_exceed=True)
with QueryTracer(budget=budget) as tracer:
    # Will raise QueryBudgetExceeded if limits exceeded
    pass
```

### 3. MethodTracer

Traces method execution timing and call graphs.

```python
from apps.common.logging import MethodTracer

# As decorator
@MethodTracer.trace
def my_function(arg1, arg2):
    return expensive_operation()

# As context manager
with MethodTracer.context("database_sync") as trace:
    sync_all_records()
print(f"Duration: {trace.duration_ms}ms")

# Get report
report = MethodTracer.get_trace_report()
```

### 4. RuntimeAnalyzer

Combines all tracing tools for comprehensive analysis.

```python
from apps.common.logging import RuntimeAnalyzer

analyzer = RuntimeAnalyzer()

with analyzer.analyze("user_registration"):
    user = User.objects.create(...)
    Profile.objects.create(user=user, ...)
    send_welcome_email(user)

analysis = analyzer.get_analysis("user_registration")
print(analyzer.generate_report())
```

### 5. SideEffectDetector

Tracks unintended mutations during code execution.

```python
from apps.common.logging import SideEffectDetector

with SideEffectDetector() as detector:
    # Code that should only read
    process_data(data)

if detector.has_side_effects:
    print(f"Unexpected writes: {detector.get_report()}")
```

## Middleware

### TraceMiddleware

Automatic request tracing middleware.

```python
# settings.py
MIDDLEWARE = [
    ...
    "apps.common.trace_middleware.TraceMiddleware",
]

# Configuration
TRACE_MIDDLEWARE_ENABLED = True
TRACE_MIDDLEWARE_QUERY_BUDGET = 50
TRACE_MIDDLEWARE_LOG_SLOW_REQUESTS = True
TRACE_MIDDLEWARE_SLOW_REQUEST_THRESHOLD_MS = 500
```

Response headers added:
- `X-Trace-Duration-Ms`: Request duration
- `X-Trace-Query-Count`: Number of database queries
- `X-Trace-Duplicate-Queries`: Detected N+1 patterns

### View Decorator

Target specific views for tracing:

```python
from apps.common.trace_middleware import trace_view

@trace_view(max_queries=10, warn_on_n_plus_one=True)
def my_view(request):
    return render(request, "template.html")
```

## Django Silk Integration

For detailed SQL profiling, enable Django Silk:

```bash
export ENABLE_SILK_PROFILER=true
python manage.py runserver
```

Access Silk dashboard at `/silk/`.

## Testing

### Query Budget Tests

```python
from apps.common.logging import assert_max_queries

def test_user_list_efficiency():
    with assert_max_queries(max_count=5, max_duplicates=0):
        users = list(User.objects.select_related('profile').all())
        for user in users:
            _ = user.profile.bio  # Should not cause extra query
```

### Running Trace Tests

```bash
# Run all trace tests
make test-platform  # or
cd services/platform && python manage.py test tests.tracing

# Run specific test
python manage.py test tests.tracing.test_trace_analysis.TestQueryTracer
```

## Best Practices

### 1. Use Query Budgets in Views

```python
class CustomerListView(ListView):
    def get_queryset(self):
        with assert_max_queries(max_count=3):
            return Customer.objects.select_related(
                'billing_profile',
                'tax_profile',
            ).prefetch_related(
                'addresses',
            )
```

### 2. Trace Critical Paths

```python
@MethodTracer.trace
def process_payment(invoice):
    with QueryTracer() as tracer:
        result = stripe.charge(invoice.total)
        invoice.mark_paid()

    if tracer.get_summary()['duplicate_count'] > 0:
        logger.warning("Payment processing has N+1 queries")

    return result
```

### 3. Monitor in Development

Enable trace middleware in development:

```python
# settings/dev.py
TRACE_MIDDLEWARE_ENABLED = True
TRACE_MIDDLEWARE_INJECT_HTML = True  # Visual debugging
```

### 4. Analyze Performance Regressions

```python
def test_no_performance_regression():
    with PerformanceProfiler() as profiler:
        # Perform operation
        pass

    report = profiler.get_report()
    assert report['duration_ms'] < 100  # Under 100ms
```

## Troubleshooting

### Common N+1 Patterns

1. **Accessing ForeignKey without select_related**
   ```python
   # Bad
   for order in Order.objects.all():
       print(order.customer.name)  # N+1!

   # Good
   for order in Order.objects.select_related('customer'):
       print(order.customer.name)  # Single query
   ```

2. **Accessing reverse relations without prefetch_related**
   ```python
   # Bad
   for customer in Customer.objects.all():
       for order in customer.orders.all():  # N+1!
           print(order.total)

   # Good
   for customer in Customer.objects.prefetch_related('orders'):
       for order in customer.orders.all():  # Single query
           print(order.total)
   ```

### Debugging Request IDs

If request IDs aren't appearing in logs:

1. Ensure `RequestIDMiddleware` is in MIDDLEWARE
2. Verify `RequestIDFilter` is configured in LOGGING
3. Check that middleware order has RequestIDMiddleware early

## Configuration Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `TRACE_MIDDLEWARE_ENABLED` | `False` | Enable trace middleware globally |
| `TRACE_MIDDLEWARE_QUERY_BUDGET` | `100` | Max queries per request |
| `TRACE_MIDDLEWARE_LOG_SLOW_REQUESTS` | `True` | Log requests exceeding threshold |
| `TRACE_MIDDLEWARE_SLOW_REQUEST_THRESHOLD_MS` | `500` | Slow request threshold |
| `TRACE_MIDDLEWARE_DETECT_SIDE_EFFECTS` | `False` | Track DB writes |
| `ENABLE_SILK_PROFILER` | `False` | Enable Django Silk (env var) |
