"""
PRAHO PLATFORM - Beat Scheduler
===============================================================================
Periodic task scheduler for Romanian hosting provider operations
"""

import argparse
import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import django
from redis import Redis
from rq import Queue

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.dev')
django.setup()

from django.conf import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/scheduler.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class ScheduledTask:
    """Represents a scheduled task"""
    name: str
    func_path: str
    schedule_type: str  # 'daily', 'hourly', 'weekly', 'monthly'
    time: str = ''  # Time in HH:MM format for daily tasks
    interval: int = 0  # Interval in minutes for recurring tasks
    queue: str = 'default'
    description: str = ''
    last_run: datetime | None = None
    next_run: datetime | None = None


class PragmaticHostScheduler:
    """
    Romanian hosting provider periodic task scheduler
    
    Schedules:
    - Daily invoice generation and sending
    - Server backup automation  
    - Customer reminder emails
    - System health checks
    - Database maintenance
    - Report generation
    """

    def __init__(self) -> None:
        """Initialize scheduler with Redis connection"""
        self.redis_conn = Redis.from_url(
            settings.REDIS_URL if hasattr(settings, 'REDIS_URL')
            else 'redis://localhost:6379/0'
        )

        self.queues = {
            'high': Queue('high', connection=self.redis_conn),
            'default': Queue('default', connection=self.redis_conn),
            'low': Queue('low', connection=self.redis_conn),
            'email': Queue('email', connection=self.redis_conn),
            'reports': Queue('reports', connection=self.redis_conn),
        }

        self.tasks = []
        self.running = False
        self._setup_tasks()
        logger.info("Initialized PragmaticHost beat scheduler")

    def _setup_tasks(self) -> None:
        """Setup all periodic tasks for Romanian hosting operations"""

        # Daily tasks
        self.tasks.extend([
            ScheduledTask(
                name='generate_daily_invoices',
                func_path='apps.billing.tasks.generate_daily_invoices',
                schedule_type='daily',
                time='08:00',
                queue='default',
                description='Generate daily invoices'
            ),
            ScheduledTask(
                name='send_payment_reminders',
                func_path='apps.billing.tasks.send_payment_reminders',
                schedule_type='daily',
                time='10:00',
                queue='email',
                description='Send payment reminders'
            ),
            ScheduledTask(
                name='backup_servers',
                func_path='apps.provisioning.tasks.backup_servers',
                schedule_type='daily',
                time='02:00',
                queue='low',
                description='Backup all servers'
            ),
            ScheduledTask(
                name='cleanup_database',
                func_path='apps.common.tasks.cleanup_database',
                schedule_type='daily',
                time='03:00',
                queue='low',
                description='Database maintenance'
            ),
            ScheduledTask(
                name='generate_daily_reports',
                func_path='apps.common.tasks.generate_daily_reports',
                schedule_type='daily',
                time='18:00',
                queue='reports',
                description='Generate daily business reports'
            ),
        ])

        # Hourly/interval tasks
        self.tasks.extend([
            ScheduledTask(
                name='monitor_server_health',
                func_path='apps.provisioning.tasks.monitor_server_health',
                schedule_type='hourly',
                interval=60,
                queue='high',
                description='Monitor server health'
            ),
            ScheduledTask(
                name='process_pending_payments',
                func_path='apps.billing.tasks.process_pending_payments',
                schedule_type='hourly',
                interval=30,
                queue='high',
                description='Process pending payments'
            ),
            ScheduledTask(
                name='process_email_queue',
                func_path='apps.common.tasks.process_email_queue',
                schedule_type='hourly',
                interval=15,
                queue='email',
                description='Process email queue'
            ),
            ScheduledTask(
                name='check_system_alerts',
                func_path='apps.common.tasks.check_system_alerts',
                schedule_type='hourly',
                interval=5,
                queue='high',
                description='Check for system alerts'
            ),
        ])

        # Calculate initial run times
        self._calculate_next_runs()
        logger.info(f"Setup {len(self.tasks)} periodic tasks")

    def _calculate_next_runs(self) -> None:
        """Calculate next run times for all tasks"""
        now = datetime.now()

        for task in self.tasks:
            if task.schedule_type == 'daily':
                # Parse time and set for today or tomorrow
                hour, minute = map(int, task.time.split(':'))
                today_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)

                if today_run <= now:
                    task.next_run = today_run + timedelta(days=1)
                else:
                    task.next_run = today_run

            elif task.schedule_type == 'hourly':
                # Set next run based on interval
                task.next_run = now + timedelta(minutes=task.interval)

    def _enqueue_task(self, task: ScheduledTask) -> None:
        """Enqueue a task for execution"""
        try:
            # Import the function dynamically
            module_path, func_name = task.func_path.rsplit('.', 1)

            # For now, just log the task (actual implementation would import and execute)
            logger.info(f"Would execute task: {task.description} ({task.func_path})")

            # Update run times
            task.last_run = datetime.now()

            if task.schedule_type == 'daily' and task.next_run:
                task.next_run = task.next_run + timedelta(days=1)
            elif task.schedule_type == 'hourly' and task.next_run:
                task.next_run = task.next_run + timedelta(minutes=task.interval)

        except Exception as e:
            logger.error(f"Failed to execute task {task.name}: {e}")

    def start(self) -> None:
        """Start the beat scheduler"""
        try:
            logger.info("Starting PragmaticHost beat scheduler...")
            self.running = True

            while self.running:
                now = datetime.now()

                # Check each task
                for task in self.tasks:
                    if task.next_run and now >= task.next_run:
                        logger.info(f"Executing scheduled task: {task.description}")
                        self._enqueue_task(task)

                # Sleep for 30 seconds before next check
                time.sleep(30)

        except KeyboardInterrupt:
            logger.info("Scheduler shutdown requested by user")
            self.running = False
        except Exception as e:
            logger.error(f"Scheduler failed: {e}")
            raise

    def stop(self) -> None:
        """Stop the scheduler"""
        self.running = False
        logger.info("Scheduler stopped")

    def get_scheduled_tasks(self) -> dict[str, Any]:
        """Get information about scheduled tasks"""
        # ⚡ PERFORMANCE: Use list comprehension instead of append loop
        task_info = [
            {
                'name': task.name,
                'description': task.description,
                'schedule_type': task.schedule_type,
                'time': task.time if task.schedule_type == 'daily' else f"Every {task.interval} minutes",
                'queue': task.queue,
                'last_run': task.last_run.isoformat() if task.last_run else None,
                'next_run': task.next_run.isoformat() if task.next_run else None,
            }
            for task in self.tasks
        ]

        return {
            'total_tasks': len(self.tasks),
            'tasks': task_info
        }


def main() -> None:
    """Main scheduler entry point"""
    parser = argparse.ArgumentParser(description='PragmaticHost Beat Scheduler')
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    parser.add_argument(
        '--list-tasks',
        action='store_true',
        help='List scheduled tasks and exit'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    scheduler = PragmaticHostScheduler()

    if args.list_tasks:
        tasks_info = scheduler.get_scheduled_tasks()
        print(f"\nPragmaticHost Scheduled Tasks ({tasks_info['total_tasks']} total):")
        print("=" * 70)
        for task in tasks_info['tasks']:
            print(f"\nTask: {task['name']}")
            print(f"Description: {task['description']}")
            print(f"Schedule: {task['time']} ({task['schedule_type']})")
            print(f"Queue: {task['queue']}")
            print(f"Last run: {task['last_run'] or 'Never'}")
            print(f"Next run: {task['next_run'] or 'Not scheduled'}")
        return

    # Start the scheduler
    scheduler.start()


if __name__ == '__main__':
    main()
