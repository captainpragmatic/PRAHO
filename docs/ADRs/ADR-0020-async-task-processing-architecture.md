# ADR-003: Async Task Processing Architecture

**Status:** Accepted
**Date:** 2025-09-02
**Authors:** PRAHO Development Team
**Supersedes:** None

## Context

PRAHO Platform requires asynchronous task processing for hosting operations that cannot block the web interface, including:

- **Virtualmin provisioning operations** (create, suspend, delete hosting accounts)
- **Billing automation** (invoice generation, payment processing)
- **System maintenance** (health checks, statistics updates)
- **Customer notifications** (emails, SMS, webhooks)

Currently, we use Django-Q2 for asynchronous task processing as decided in the previous architecture review.

## Decision Drivers

1. **Romanian hosting market scale** - moderate volume (~50-100 provisioning operations/day)
2. **Team expertise** - Django-focused team, minimal distributed systems experience
3. **Operational simplicity** - single PostgreSQL database preferred for compliance
4. **Romanian business compliance** - GDPR audit trails, all data in controlled environment
5. **Development velocity** - focus on hosting domain features, not infrastructure
6. **Reliability requirements** - provisioning failures = customer support tickets

## Options Considered

### Option 1: Celery + Redis

**Pros:**
- Industry standard with extensive features
- Sophisticated retry logic with exponential backoff and jitter
- Built-in periodic task scheduling (Celery Beat)
- Horizontal scaling capabilities
- Workflow orchestration (chains, groups, chords)

**Cons:**
- **Additional infrastructure complexity** - Redis dependency
- **Two failure modes** - both PostgreSQL AND Redis must be operational
- **Operational overhead** - Redis monitoring, backup, persistence configuration
- **Team expertise gap** - distributed systems knowledge required
- **Memory management** - Redis keeps all data in RAM
- **Cost increase** - ~60% infrastructure cost increase (Redis hosting, monitoring)
- **GDPR compliance complexity** - customer data in volatile Redis storage
- **Audit trail gaps** - job data separate from business database

### Option 2: Custom Database Queue + Workers

**Pros:**
- **Single database dependency** - uses existing PostgreSQL
- **Full control** over queue logic and retry policies
- **ACID transactions** - job creation + business logic atomicity
- **Natural Django integration** - ORM queries, admin interface
- **Built-in persistence** - jobs survive all system failures

**Cons:**
- **Significant development overhead** - 2-3 months to build production-ready system
- **Missing enterprise features** - monitoring, admin interface, job result storage
- **Performance polling** - database polling vs pub/sub notifications
- **Concurrency complexity** - row locking, dead letter handling, worker coordination
- **Maintenance burden** - ongoing feature development and bug fixes
- **Team velocity impact** - engineering resources diverted from business features

### Option 3: Django-Q2 + Database Backend

**Pros:**
- **Zero additional infrastructure** - uses existing PostgreSQL
- **Battle-tested framework** - production-ready with extensive features
- **Rich admin interface** - job monitoring, scheduling, result inspection
- **Multiple broker support** - database, Redis, AWS SQS options
- **Django ecosystem integration** - familiar patterns, ORM usage
- **Built-in scheduling** - cron-like recurring tasks
- **Hook system** - job completion callbacks for audit integration
- **Development velocity** - implement async features in weeks, not months
- **Database flexibility** - SQLite in development, PostgreSQL in production

**Cons:**
- **External dependency** - relies on third-party package maintenance
- **Less sophisticated** than Celery for complex workflow orchestration
- **Polling-based** when using database backend (vs Redis pub/sub)

## Security Considerations

All async task solutions face common security challenges:

- **Unvalidated job payloads** - always validate input data
- **Resource exhaustion** - set memory/time limits
- **Information leakage in error messages** - sanitize before storing
- **No built-in rate limiting** - implement at application level

Django-Q2 addresses some through Django's built-in security (ORM protection, input validation), but application-level controls remain necessary.

## Industry Analysis

Research of major hosting billing platforms reveals:

- **WHMCS** (market leader): Simple cron-based system, single `cron.php` every 5 minutes, database-driven scheduling
- **Blesta**: Similar 5-minute cron approach with time-based vs interval-based tasks
- **HostBill**: Background queue system with worker processes, but still cron-triggered
- **Modern Laravel alternatives**: Use Laravel Queues but fall back to cron-based processing on shared hosting

**Key insight**: Even billion-dollar hosting platforms use simple cron + database patterns for reliability and operational simplicity.

## Decision

**We will use Django-Q2 with database backend** for async task processing.

### Implementation Plan

1. **Installation**: Add `django-q2>=1.7.0` to requirements
2. **Configuration**: Database backend with 2-4 workers initially
3. **Migration**: Replace existing Celery task placeholders
4. **Monitoring**: Leverage built-in admin interface and Django logging
5. **Scaling**: Start with database backend, option to add Redis later if needed

### Configuration

```python
# Development (SQLite)
Q_CLUSTER = {
    'sync': True,  # Synchronous execution for debugging
    'workers': 1,
    'save_limit': 50,
}

# Production (PostgreSQL)
Q_CLUSTER = {
    'name': 'praho-cluster',
    'workers': 4,
    'timeout': 300,
    'queue_limit': 500,
    'bulk': 10,
    'orm': 'default',
    'save_limit': 10000,
}
```

## Consequences

### Positive
- **Faster time-to-market** - provisioning features delivered in weeks
- **Operational simplicity** - single PostgreSQL database to monitor/backup
- **Team productivity** - familiar Django patterns and admin tools
- **Romanian compliance** - all audit data in controlled database environment
- **Cost efficiency** - no additional infrastructure costs
- **Flexible scaling** - can migrate to Redis backend if volume increases

### Negative
- **External dependency** - relies on django-q2 package maintenance
- **Polling overhead** - database queries every few seconds vs pub/sub notifications
- **Limited workflow orchestration** compared to Celery's advanced features

### Risks & Mitigations
- **Package abandonment**: Django-Q2 is actively maintained fork of django-q with strong community
- **Performance bottlenecks**: Monitor queue performance, ready to migrate to Redis backend
- **Feature limitations**: Django-Q2 provides sufficient features for our current needs

## Future Considerations

- **Volume scaling**: Monitor queue performance; migrate to Redis backend if >1000 jobs/minute
- **Complex workflows**: Django-Q2 handles our current workflow requirements well
- **Multi-tenant**: Django-Q2 supports multiple brokers for tenant isolation

## References

- [Django-Q2 Documentation](https://django-q2.readthedocs.io/)
- [PRAHO Architecture Overview](./ARCHITECTURE.md)
- Industry analysis of WHMCS, Blesta, HostBill task processing patterns
