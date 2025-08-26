"""
PRAHO PLATFORM - Background Worker System
===============================================================================
Redis Queue (RQ) worker for background job processing in Romanian hosting provider
"""

import argparse
import logging
import os
import sys

import django
from redis import Redis
from rq import Connection, Queue, Worker

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.dev')
django.setup()

from django.conf import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/worker.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class PragmaticHostWorker:
    """
    Romanian hosting provider background worker
    
    Handles:
    - Invoice generation and email sending
    - Server provisioning automation
    - Backup and maintenance tasks
    - Email notifications and reminders
    - Payment processing webhooks
    - System monitoring and alerts
    """

    def __init__(self, queues: list[str] | None = None):
        """
        Initialize worker with Redis connection and queues
        
        Args:
            queues: List of queue names to process (defaults to all)
        """
        self.redis_conn = Redis.from_url(
            settings.REDIS_URL if hasattr(settings, 'REDIS_URL')
            else 'redis://localhost:6379/0'
        )

        # Default queue configuration for Romanian hosting operations
        self.default_queues = [
            'high',      # Critical: payment processing, security alerts
            'default',   # Standard: invoice generation, provisioning
            'low',       # Background: backups, cleanup, monitoring
            'email',     # Email notifications and marketing
            'reports',   # Analytics and business intelligence
        ]

        self.queue_names = queues or self.default_queues
        self.queues = [Queue(name, connection=self.redis_conn) for name in self.queue_names]

        logger.info(f"Initialized PragmaticHost worker for queues: {self.queue_names}")

    def start(self) -> None:
        """Start the worker process"""
        try:
            logger.info("Starting PragmaticHost background worker...")

            with Connection(self.redis_conn):
                worker = Worker(
                    self.queues,
                    name=f'pragmatichost-worker-{os.getpid()}',
                    exception_handlers=[self._handle_job_exception]
                )

                # Register shutdown handlers
                worker.push_exc_handler(self._handle_job_exception)

                logger.info(f"Worker {worker.name} started successfully")
                worker.work(with_scheduler=True)

        except KeyboardInterrupt:
            logger.info("Worker shutdown requested by user")
        except Exception as e:
            logger.error(f"Worker failed to start: {e}")
            raise

    def _handle_job_exception(self, job, exc_type, exc_value, traceback) -> None:
        """
        Handle job exceptions with Romanian business context
        
        Args:
            job: Failed RQ job
            exc_type: Exception type
            exc_value: Exception value
            traceback: Exception traceback
        """
        logger.error(
            f"Job {job.id} failed: {exc_type.__name__}: {exc_value}",
            extra={
                'job_id': job.id,
                'job_func': job.func_name,
                'job_args': job.args,
                'job_kwargs': job.kwargs,
                'queue': job.origin,
            }
        )

        # Send alert to admin for critical failures
        if job.origin == 'high':
            try:
                # TODO: Implement send_admin_alert in apps.common.utils
                logger.critical(f"ADMIN ALERT: Critical job failed - {job.func_name}")
            except Exception as e:
                logger.error(f"Failed to send admin alert: {e}")

    def get_queue_stats(self) -> dict:
        """Get statistics for all queues"""
        stats = {}
        for queue in self.queues:
            stats[queue.name] = {
                'pending': len(queue),
                'failed': queue.failed_job_registry.count,
                'finished': queue.finished_job_registry.count,
                'started': queue.started_job_registry.count,
            }
        return stats

    def clear_failed_jobs(self, queue_name: str | None = None) -> None:
        """Clear failed jobs from queue(s)"""
        if queue_name:
            queue = Queue(queue_name, connection=self.redis_conn)
            failed_jobs = queue.failed_job_registry.get_job_ids()
            for job_id in failed_jobs:
                queue.failed_job_registry.requeue(job_id)
            logger.info(f"Cleared {len(failed_jobs)} failed jobs from queue: {queue_name}")
        else:
            total_cleared = 0
            for queue in self.queues:
                failed_jobs = queue.failed_job_registry.get_job_ids()
                for job_id in failed_jobs:
                    queue.failed_job_registry.requeue(job_id)
                total_cleared += len(failed_jobs)
                logger.info(f"Cleared {len(failed_jobs)} failed jobs from queue: {queue.name}")
            logger.info(f"Total failed jobs cleared: {total_cleared}")


def main() -> None:
    """Main worker entry point"""
    parser = argparse.ArgumentParser(description='PragmaticHost Background Worker')
    parser.add_argument(
        '--queues',
        nargs='+',
        help='Specific queues to process',
        default=None
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show queue statistics and exit'
    )
    parser.add_argument(
        '--clear-failed',
        action='store_true',
        help='Clear failed jobs and exit'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    worker = PragmaticHostWorker(queues=args.queues)

    if args.stats:
        stats = worker.get_queue_stats()
        print("\nPragmaticHost Queue Statistics:")
        print("=" * 50)
        for queue_name, queue_stats in stats.items():
            print(f"\n{queue_name.upper()} Queue:")
            for stat_name, count in queue_stats.items():
                print(f"  {stat_name.capitalize()}: {count}")
        return

    if args.clear_failed:
        worker.clear_failed_jobs()
        print("Failed jobs cleared successfully")
        return

    # Start the worker
    worker.start()


if __name__ == '__main__':
    main()
