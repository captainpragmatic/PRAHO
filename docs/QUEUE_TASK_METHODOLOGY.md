# PRAHO Queue & Task Management Methodology

**Status:** Active  
**Version:** 1.0  
**Last Updated:** 2025-09-02  
**Related ADR:** [ADR-003: Async Task Processing Architecture](./ADR-003-async-task-processing-architecture.md)

## Overview

PRAHO Platform uses **Django-Q2** for asynchronous task processing, providing reliable background job execution for hosting operations, billing automation, and system maintenance without blocking the web interface.

## Architecture Decision Summary

- **Queue Backend**: PostgreSQL database (same as main application)
- **Worker Framework**: Django-Q2 with database persistence
- **Scheduling**: Built-in cron-like scheduling with database storage
- **Monitoring**: Django Admin interface + structured logging
- **Development**: Integrated with `make dev` for seamless development experience

## Core Principles

### 1. **Database-First Approach** 🗄️
- All jobs, schedules, and results stored in PostgreSQL
- No external dependencies (Redis, RabbitMQ, etc.)
- ACID compliance for job creation + business logic transactions
- Full audit trail for Romanian GDPR compliance

### 2. **App-Specific Task Organization** 📁
```
apps/
├── provisioning/
│   ├── virtualmin_tasks.py      # Virtualmin operations
│   └── management/commands/setup_virtualmin_tasks.py
├── billing/
│   ├── tasks.py                 # Invoice generation, payments
│   └── management/commands/setup_billing_tasks.py
├── domains/
│   ├── tasks.py                 # Expiration checks, renewals
│   └── management/commands/setup_domain_tasks.py
└── customers/
    ├── tasks.py                 # Account cleanup, notifications
    └── management/commands/setup_customer_tasks.py
```

### 3. **Explicit Task Setup** ⚙️
- Scheduled tasks are **database records**, not code
- Development requires setup on each database reset
- Production sets up once during deployment
- Each app provides its own setup management command

## Task Types

### 1. **Immediate Tasks** ⚡
User-triggered operations that run as soon as workers are available:

```python
# Provision hosting account immediately
task_id = provision_virtualmin_account_async(
    service_id="123",
    domain="example.com"
)
```

### 2. **Scheduled Tasks** ⏰
Recurring operations managed by Django-Q2's scheduler:

```python
# Health check every hour
schedule(
    'apps.provisioning.virtualmin_tasks.health_check_virtualmin_servers',
    schedule_type=Schedule.HOURLY,
    name='virtualmin-health-check'
)
```

### 3. **Retry Tasks** 🔄
Failed operations that can be automatically retried:

```python
# Retry failed provisioning jobs every 15 minutes
schedule(
    'apps.provisioning.virtualmin_tasks.process_failed_virtualmin_jobs',
    schedule_type=Schedule.MINUTES,
    minutes=15,
    name='virtualmin-retry-failed-jobs'
)
```

## Task Implementation Pattern

### Standard Task Structure

```python
# apps/myapp/tasks.py
from django_q.tasks import async_task, schedule
from django_q.models import Schedule

# Sync function - actual work
def my_business_operation(param1: str, param2: int) -> dict[str, Any]:
    """
    Synchronous task function that does the actual work.
    
    Args:
        param1: Description
        param2: Description
        
    Returns:
        Dictionary with operation result
        
    Raises:
        Exception: On operation failure (triggers retry)
    """
    logger.info(f"🔄 [MyApp] Starting operation {param1}")
    
    try:
        # Do the work
        result = do_business_logic(param1, param2)
        
        if result.is_ok():
            logger.info(f"✅ [MyApp] Operation {param1} successful")
            return {"success": True, "data": result.unwrap()}
        else:
            error_msg = result.unwrap_err()
            logger.error(f"❌ [MyApp] Operation {param1} failed: {error_msg}")
            
            # Check if retryable
            if _is_retryable_error(error_msg):
                raise Exception(error_msg)  # Trigger retry
                
            return {"success": False, "error": error_msg}
            
    except Exception as e:
        logger.exception(f"💥 [MyApp] Unexpected error in {param1}: {e}")
        raise  # Re-raise to trigger retry

# Async wrapper - queuing function
def my_business_operation_async(param1: str, param2: int) -> str:
    """Queue business operation for async execution."""
    return async_task(
        'apps.myapp.tasks.my_business_operation',
        param1, param2,
        timeout=300
    )

# Setup function for scheduled tasks
def setup_myapp_scheduled_tasks() -> dict[str, str]:
    """Set up all MyApp scheduled tasks."""
    tasks_created = {}
    
    # Daily cleanup
    cleanup_schedule = schedule(
        'apps.myapp.tasks.daily_cleanup',
        schedule_type=Schedule.DAILY,
        schedule_time='02:00',
        name='myapp-daily-cleanup'
    )
    tasks_created['cleanup'] = str(cleanup_schedule) if cleanup_schedule else 'already_exists'
    
    return tasks_created
```

### Management Command Template

```python
# apps/myapp/management/commands/setup_myapp_tasks.py
from django.core.management.base import BaseCommand, CommandError
from apps.myapp.tasks import setup_myapp_scheduled_tasks

class Command(BaseCommand):
    help = 'Set up MyApp scheduled tasks'

    def add_arguments(self, parser):
        parser.add_argument(
            '--check-existing',
            action='store_true',
            help='Skip if schedules already exist',
        )

    def handle(self, *args, **options):
        if options['check_existing']:
            from django_q.models import Schedule
            existing = Schedule.objects.filter(name__startswith='myapp-').count()
            if existing > 0:
                self.stdout.write("✅ Scheduled tasks already exist, skipping...")
                return
        
        self.stdout.write('🚀 Setting up MyApp scheduled tasks...')
        
        try:
            results = setup_myapp_scheduled_tasks()
            
            self.stdout.write(self.style.SUCCESS('✅ MyApp scheduled tasks configured:'))
            
            for task_name, result in results.items():
                if result == 'already_exists':
                    self.stdout.write(
                        self.style.WARNING(f'  - {task_name}: Already exists')
                    )
                else:
                    self.stdout.write(
                        self.style.SUCCESS(f'  - {task_name}: Created')
                    )
            
        except Exception as e:
            raise CommandError(f'❌ Failed to set up scheduled tasks: {e}')
```

## Development Workflow

### Local Development Setup
```bash
# Single command starts everything
make dev
```

**What happens:**
1. 🗄️ Database migrations
2. 🔧 Test data setup  
3. ⚙️ **Scheduled task creation** (runs setup commands)
4. 🚀 Django-Q2 workers start in background
5. 🌐 Development server starts on port 8001
6. 🛑 Clean shutdown when you Ctrl+C

### Manual Task Management
```bash
# Set up specific app tasks
python manage.py setup_virtualmin_tasks
python manage.py setup_billing_tasks

# Start workers only
python manage.py qcluster

# Monitor in admin
# Visit: /admin/django_q/
```

### Development Database Resets
Since development databases get reset frequently, scheduled tasks need to be recreated:

- ✅ **Automatic**: `make dev` recreates schedules
- ✅ **Manual**: Run `setup_*_tasks` commands after migrations
- ✅ **Conditional**: Use `--check-existing` flag to avoid duplicates

## Production Deployment

### Initial Deployment
```bash
# One-time setup during deployment
python manage.py migrate
python manage.py setup_virtualmin_tasks
python manage.py setup_billing_tasks
python manage.py setup_domain_tasks
# ... other app task setups

# Start workers (systemd service)
systemctl start praho-workers
systemctl enable praho-workers
```

### Service Configuration
```ini
# /etc/systemd/system/praho-workers.service
[Unit]
Description=PRAHO Django-Q2 Workers
After=network.target postgresql.service

[Service]
Type=exec
User=praho
WorkingDirectory=/opt/praho
Environment=DJANGO_SETTINGS_MODULE=config.settings.production
ExecStart=/opt/praho/.venv/bin/python manage.py qcluster --workers=4
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Restarts & Updates
```bash
# Application restart - schedules persist ✅
systemctl restart praho-workers

# Database migrations - may need task recreation
python manage.py migrate
# Check if new tasks needed
python manage.py setup_virtualmin_tasks --check-existing
```

## Configuration

### Django Settings

```python
# config/settings/base.py
Q_CLUSTER = {
    'name': 'praho-cluster',
    'workers': 2,               # Adjust based on server capacity
    'timeout': 300,             # 5 minutes
    'retry': 600,               # 10 minutes retry delay
    'save_limit': 1000,         # Keep last 1000 task results
    'queue_limit': 100,         # Max 100 jobs in queue
    'orm': 'default',           # Use PostgreSQL database
    'bulk': 10,                 # Process 10 jobs at once
    'catch_up': False,          # Don't run missed scheduled tasks
}
```

### Environment-Specific Overrides

```python
# config/settings/development.py
Q_CLUSTER = {
    **Q_CLUSTER_BASE,
    'sync': False,              # Async execution
    'workers': 1,               # Single worker for development
    'save_limit': 50,           # Keep fewer records
}

# config/settings/production.py
Q_CLUSTER = {
    **Q_CLUSTER_BASE,
    'workers': 4,               # Multiple workers
    'recycle': 500,             # Restart workers after 500 tasks
    'save_limit': 10000,        # Keep more history
}
```

## Monitoring & Debugging

### Admin Interface
- **URL**: `/admin/django_q/`
- **Features**: View tasks, schedules, success/failure rates, worker stats
- **Task Results**: Full result data and error messages
- **Schedules**: Manage recurring tasks

### Logging
```python
# All tasks use structured logging
logger.info("🔄 [AppName] Starting operation X")
logger.info("✅ [AppName] Operation X successful")  
logger.error("❌ [AppName] Operation X failed: reason")
logger.exception("💥 [AppName] Unexpected error: details")
```

### Log Files
- **Development**: `django_q.log` (created by `make dev`)
- **Production**: Configure via systemd logging or Django LOGGING setting

### Health Monitoring
```python
# Built-in health check task (every hour)
def health_check_virtualmin_servers():
    # Returns health status for all servers
    return {"healthy_servers": 3, "unhealthy_servers": 0}
```

## Task Patterns & Best Practices

### 1. **Error Handling Pattern**
```python
def _is_retryable_error(error_message: str) -> bool:
    """Determine if error should trigger retry."""
    retryable_patterns = [
        "connection timeout", "server error", "rate limit",
        "temporarily unavailable", "network error"
    ]
    return any(pattern in error_message.lower() for pattern in retryable_patterns)
```

### 2. **Distributed Locking Pattern**
```python
def periodic_task_with_lock():
    """Prevent concurrent execution of periodic tasks."""
    lock_key = "my_task_lock"
    if cache.get(lock_key):
        return {"success": True, "message": "Already running"}
        
    cache.set(lock_key, True, 3600)  # 1 hour lock
    try:
        # Do work
        pass
    finally:
        cache.delete(lock_key)  # Always release lock
```

### 3. **Audit Integration Pattern**
```python
def business_task(entity_id: str):
    """Task with automatic audit logging."""
    try:
        result = do_business_operation(entity_id)
        
        # Audit successful operation
        AuditService.log_event(
            event_type='task.completed',
            resource_id=entity_id,
            details={'result': result}
        )
        
        return result
    except Exception as e:
        # Audit failed operation
        AuditService.log_event(
            event_type='task.failed',
            resource_id=entity_id,
            details={'error': str(e)}
        )
        raise
```

## Security Considerations

### Input Validation
```python
def secure_task(user_input: str):
    """Always validate task parameters."""
    # Validate input before processing
    if not user_input or len(user_input) > 255:
        raise ValueError("Invalid input parameter")
    
    # Sanitize if needed
    clean_input = bleach.clean(user_input)
    
    # Process with validated input
    return process_business_logic(clean_input)
```

### Resource Limits
- **Timeout**: Set appropriate timeouts for all tasks
- **Memory**: Monitor worker memory usage
- **Rate Limiting**: Implement at application level for external APIs
- **Payload Size**: Validate job payload sizes

### Information Leakage
```python
def secure_error_handling():
    """Sanitize error messages before storing."""
    try:
        # Business operation
        pass
    except Exception as e:
        # Log full details internally
        logger.exception("Full error details for debugging")
        
        # Return sanitized error to client
        return {"success": False, "error": "Operation failed"}
```

## Migration & Scaling

### Adding New Task Types
1. Create task function in appropriate app
2. Add async wrapper function
3. Update app's setup function
4. Create/update management command
5. Update production deployment scripts

### Scaling Workers
```bash
# Increase worker count in production
Q_CLUSTER['workers'] = 8

# Or run multiple clusters
python manage.py qcluster --cluster=provisioning --workers=4
python manage.py qcluster --cluster=billing --workers=2
```

### Database Maintenance
```python
# Periodic cleanup of old task results
def cleanup_old_tasks():
    """Remove task results older than 30 days."""
    cutoff = timezone.now() - timedelta(days=30)
    deleted = Task.objects.filter(stopped__lt=cutoff).delete()
    return {"deleted_tasks": deleted[0]}
```

## Troubleshooting

### Common Issues

**Tasks not executing:**
- ✅ Check workers are running: `ps aux | grep qcluster`
- ✅ Check schedules exist: Django Admin → Django Q → Scheduled tasks
- ✅ Check task queue: Django Admin → Django Q → Tasks

**Failed tasks:**
- ✅ Review error messages in Django Admin
- ✅ Check logs: `tail -f django_q.log`
- ✅ Verify function import paths are correct

**Schedule not running:**
- ✅ Verify `catch_up: False` in settings (prevents running missed tasks)
- ✅ Check schedule time zones match Django TIME_ZONE
- ✅ Ensure workers are running when schedule should execute

### Debug Commands
```bash
# Test task execution manually
python manage.py shell
>>> from apps.provisioning.virtualmin_tasks import health_check_virtualmin_servers
>>> result = health_check_virtualmin_servers()

# View queue status
python manage.py qmonitor

# Clear failed tasks
python manage.py shell
>>> from django_q.models import Task
>>> Task.objects.filter(success=False).delete()
```

## Future Enhancements

### Planned Improvements
- **Universal Setup Command**: Single command to setup all app tasks
- **Health Check Dashboard**: Web interface for task monitoring
- **Task Metrics**: Performance monitoring and alerting
- **Queue Prioritization**: High/low priority queues
- **Multi-tenant Isolation**: Customer-specific task queues

### Migration Considerations
- **To Redis**: Change `orm` to `redis` in Q_CLUSTER settings
- **Advanced Features**: Django-Q2 provides all needed functionality
- **Horizontal Scaling**: Multiple worker instances with load balancing

---

## Quick Reference

### Essential Commands
```bash
# Development
make dev                                    # Start everything

# Task Management  
python manage.py setup_virtualmin_tasks    # Setup Virtualmin schedules
python manage.py qcluster                   # Start workers only

# Monitoring
/admin/django_q/                           # Web interface
tail -f django_q.log                       # Worker logs
```

### Key Files
- `apps/*/tasks.py` - App-specific task functions
- `apps/*/management/commands/setup_*_tasks.py` - Schedule setup
- `config/settings/base.py` - Q_CLUSTER configuration
- `docs/ADR-003-async-task-processing-architecture.md` - Architecture decision

This methodology ensures reliable, maintainable, and scalable async task processing for PRAHO's Romanian hosting operations. 🚀