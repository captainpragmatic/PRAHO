import logging

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.common.constants import SECONDS_PER_HOUR, SECONDS_PER_MINUTE
from apps.integrations.models import WebhookEvent
from apps.integrations.webhooks.base import (
    process_pending_webhooks,
    retry_failed_webhooks,
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    🔄 Process webhook queue and retry failed webhooks
    
    Usage:
    python manage.py process_webhooks --pending --retry --source stripe --limit 50
    
    Options:
    --pending: Process pending webhooks
    --retry: Retry failed webhooks
    --source: Filter by specific source (stripe, virtualmin, etc.)
    --limit: Limit number of webhooks to process (default: 100)
    --cleanup: Clean up old processed webhooks (>30 days)
    """

    help = '🔄 Process webhook queue and retry failed webhooks'

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            '--pending',
            action='store_true',
            help='Process pending webhooks'
        )
        parser.add_argument(
            '--retry',
            action='store_true',
            help='Retry failed webhooks'
        )
        parser.add_argument(
            '--source',
            type=str,
            help='Filter by webhook source (stripe, virtualmin, etc.)'
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=100,
            help='Limit number of webhooks to process (default: 100)'
        )
        parser.add_argument(
            '--cleanup',
            action='store_true',
            help='Clean up old processed webhooks (>30 days)'
        )
        parser.add_argument(
            '--stats',
            action='store_true',
            help='Show webhook processing statistics'
        )

    def handle(self, *args, **options) -> None:
        """🎯 Main command handler"""
        self.stdout.write(
            self.style.SUCCESS('🔄 Starting webhook processing...')
        )

        source = options.get('source')
        limit = options.get('limit', 100)

        if options['stats']:
            self.show_stats()

        if options['pending']:
            self.process_pending(source, limit)

        if options['retry']:
            self.retry_failed(source)

        if options['cleanup']:
            self.cleanup_old_webhooks()

        if not any([options['pending'], options['retry'], options['cleanup'], options['stats']]):
            # Default: process pending and retry failed
            self.process_pending(source, limit)
            self.retry_failed(source)

        self.stdout.write(
            self.style.SUCCESS('✅ Webhook processing completed!')
        )

    def process_pending(self, source: str = None, limit: int = 100) -> None:
        """📋 Process pending webhooks"""
        self.stdout.write(f"📋 Processing pending webhooks (source: {source or 'all'}, limit: {limit})")

        stats = process_pending_webhooks(source=source, limit=limit)

        self.stdout.write(
            f"  ✅ Processed: {stats['processed']}"
        )
        self.stdout.write(
            f"  ❌ Failed: {stats['failed']}"
        )
        self.stdout.write(
            f"  ⏭️ Skipped: {stats['skipped']}"
        )

        if stats['failed'] > 0:
            self.stdout.write(
                self.style.WARNING(f"⚠️ {stats['failed']} webhooks failed - they will be retried later")
            )

    def retry_failed(self, source=None) -> None:
        """🔄 Retry failed webhooks"""
        self.stdout.write(f"🔄 Retrying failed webhooks (source: {source or 'all'})")

        stats = retry_failed_webhooks(source=source)

        self.stdout.write(
            f"  ✅ Retried successfully: {stats['retried']}"
        )
        self.stdout.write(
            f"  ❌ Failed again: {stats['failed']}"
        )
        self.stdout.write(
            f"  🗑️ Abandoned (too old/max retries): {stats['abandoned']}"
        )

    def cleanup_old_webhooks(self) -> None:
        """🗑️ Clean up old processed webhooks"""
        self.stdout.write("🗑️ Cleaning up old processed webhooks (>30 days)")

        cutoff_date = timezone.now() - timezone.timedelta(days=30)

        # Only delete processed/skipped webhooks, keep failed ones for analysis
        old_webhooks = WebhookEvent.objects.filter(
            status__in=['processed', 'skipped'],
            processed_at__lt=cutoff_date
        )

        count = old_webhooks.count()
        if count > 0:
            old_webhooks.delete()
            self.stdout.write(f"  🗑️ Deleted {count} old webhook records")
        else:
            self.stdout.write("  ℹ️ No old webhooks to clean up")

    def show_stats(self) -> None:
        """📊 Show webhook statistics"""
        self.stdout.write("📊 Webhook Processing Statistics")
        self.stdout.write("=" * 50)

        # Overall stats
        total = WebhookEvent.objects.count()
        pending = WebhookEvent.objects.filter(status='pending').count()
        processed = WebhookEvent.objects.filter(status='processed').count()
        failed = WebhookEvent.objects.filter(status='failed').count()
        skipped = WebhookEvent.objects.filter(status='skipped').count()

        self.stdout.write(f"📈 Total webhooks: {total}")
        self.stdout.write(f"⏳ Pending: {pending}")
        self.stdout.write(f"✅ Processed: {processed}")
        self.stdout.write(f"❌ Failed: {failed}")
        self.stdout.write(f"⏭️ Skipped: {skipped}")

        # Stats by source
        self.stdout.write("\n📊 By Source:")
        for source, _ in WebhookEvent.SOURCE_CHOICES:
            source_count = WebhookEvent.objects.filter(source=source).count()
            if source_count > 0:
                source_pending = WebhookEvent.objects.filter(source=source, status='pending').count()
                source_failed = WebhookEvent.objects.filter(source=source, status='failed').count()

                status_indicator = ""
                if source_pending > 0:
                    status_indicator += f" (⏳ {source_pending} pending)"
                if source_failed > 0:
                    status_indicator += f" (❌ {source_failed} failed)"

                self.stdout.write(f"  {source}: {source_count}{status_indicator}")

        # Recent activity
        recent_webhooks = WebhookEvent.objects.order_by('-received_at')[:5]
        if recent_webhooks:
            self.stdout.write("\n🕒 Recent Activity:")
            for webhook in recent_webhooks:
                age = timezone.now() - webhook.received_at
                if age.days > 0:
                    age_str = f"{age.days}d ago"
                elif age.seconds > SECONDS_PER_HOUR:
                    age_str = f"{age.seconds // SECONDS_PER_HOUR}h ago"
                elif age.seconds > SECONDS_PER_MINUTE:
                    age_str = f"{age.seconds // SECONDS_PER_MINUTE}m ago"
                else:
                    age_str = "just now"

                status_icon = {
                    'pending': '⏳',
                    'processed': '✅',
                    'failed': '❌',
                    'skipped': '⏭️'
                }.get(webhook.status, '❓')

                self.stdout.write(
                    f"  {status_icon} {webhook.source} | {webhook.event_type} | {age_str}"
                )

        # Failed webhooks requiring attention
        failed_ready_for_retry = WebhookEvent.objects.filter(
            status='failed',
            next_retry_at__lte=timezone.now()
        ).count()

        if failed_ready_for_retry > 0:
            self.stdout.write(
                self.style.WARNING(f"\n⚠️ {failed_ready_for_retry} failed webhooks ready for retry")
            )

        # Old webhooks that can be cleaned up
        cutoff_date = timezone.now() - timezone.timedelta(days=30)
        old_webhooks = WebhookEvent.objects.filter(
            status__in=['processed', 'skipped'],
            processed_at__lt=cutoff_date
        ).count()

        if old_webhooks > 0:
            self.stdout.write(
                f"\n🗑️ {old_webhooks} old webhook records can be cleaned up (>30 days)"
            )
