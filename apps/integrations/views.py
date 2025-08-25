import json
import logging

from django.http import HttpResponseBadRequest, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import WebhookEvent
from .webhooks.base import get_webhook_processor

logger = logging.getLogger(__name__)


# ===============================================================================
# WEBHOOK ENDPOINT VIEWS
# ===============================================================================

@method_decorator(csrf_exempt, name='dispatch')
class WebhookView(View):
    """
    🔄 Generic webhook endpoint with deduplication
    
    Handles webhooks from all external services:
    - POST /webhooks/stripe/ → Stripe events
    - POST /webhooks/virtualmin/ → Server management events
    - POST /webhooks/paypal/ → PayPal payments
    - POST /webhooks/registrar/ → Domain events
    """

    source_name = None  # Override in subclasses

    def post(self, request):
        """📨 Process incoming webhook"""
        if not self.source_name:
            return HttpResponseBadRequest("Webhook source not configured")

        try:
            # Parse JSON payload
            if request.content_type == 'application/json':
                payload = json.loads(request.body)
            else:
                return HttpResponseBadRequest("Content-Type must be application/json")

            # Extract metadata
            signature = self.extract_signature(request)
            ip_address = self.get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            headers = dict(request.headers)

            # Get processor for this source
            processor = get_webhook_processor(self.source_name)
            if not processor:
                return HttpResponseBadRequest(f"No processor found for source: {self.source_name}")

            # Process webhook
            success, message, webhook_event = processor.process_webhook(
                payload=payload,
                signature=signature,
                headers=headers,
                ip_address=ip_address,
                user_agent=user_agent
            )

            if success:
                logger.info(f"✅ {self.source_name} webhook processed: {message}")
                return JsonResponse({
                    'status': 'success',
                    'message': message,
                    'webhook_id': str(webhook_event.id) if webhook_event else None
                })
            else:
                logger.error(f"❌ {self.source_name} webhook failed: {message}")
                return JsonResponse({
                    'status': 'error',
                    'message': message,
                    'webhook_id': str(webhook_event.id) if webhook_event else None
                }, status=400)

        except json.JSONDecodeError:
            return HttpResponseBadRequest("Invalid JSON payload")

        except Exception as e:
            logger.exception(f"💥 Critical error processing {self.source_name} webhook")
            return JsonResponse({
                'status': 'error',
                'message': f"Internal error: {str(e)}"
            }, status=500)

    def extract_signature(self, request):
        """🔐 Extract webhook signature from headers - override in subclasses"""
        return request.META.get('HTTP_X_SIGNATURE', '')

    def get_client_ip(self, request):
        """🌐 Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class StripeWebhookView(WebhookView):
    """💳 Stripe webhook endpoint"""
    source_name = 'stripe'

    def extract_signature(self, request):
        """🔐 Extract Stripe signature"""
        return request.META.get('HTTP_STRIPE_SIGNATURE', '')


class VirtualminWebhookView(WebhookView):
    """🖥️ Virtualmin webhook endpoint"""
    source_name = 'virtualmin'


class PayPalWebhookView(WebhookView):
    """🟡 PayPal webhook endpoint"""
    source_name = 'paypal'


# ===============================================================================
# WEBHOOK MANAGEMENT API
# ===============================================================================

def webhook_status(request):
    """📊 Webhook processing status and statistics"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    # Get webhook statistics
    stats = {
        'total_webhooks': WebhookEvent.objects.count(),
        'pending': WebhookEvent.objects.filter(status='pending').count(),
        'processed': WebhookEvent.objects.filter(status='processed').count(),
        'failed': WebhookEvent.objects.filter(status='failed').count(),
        'skipped': WebhookEvent.objects.filter(status='skipped').count(),
    }

    # Get stats by source
    by_source = {}
    for source, _ in WebhookEvent.SOURCE_CHOICES:
        source_count = WebhookEvent.objects.filter(source=source).count()
        if source_count > 0:
            by_source[source] = {
                'total': source_count,
                'pending': WebhookEvent.objects.filter(source=source, status='pending').count(),
                'processed': WebhookEvent.objects.filter(source=source, status='processed').count(),
                'failed': WebhookEvent.objects.filter(source=source, status='failed').count(),
            }

    # Recent activity
    recent_webhooks = WebhookEvent.objects.order_by('-received_at')[:10]
    recent_data = []
    for webhook in recent_webhooks:
        recent_data.append({
            'id': str(webhook.id),
            'source': webhook.source,
            'event_type': webhook.event_type,
            'status': webhook.status,
            'received_at': webhook.received_at.isoformat(),
            'processed_at': webhook.processed_at.isoformat() if webhook.processed_at else None,
        })

    return JsonResponse({
        'stats': stats,
        'by_source': by_source,
        'recent_webhooks': recent_data,
    })


@require_http_methods(["POST"])
def retry_webhook(request, webhook_id):
    """🔄 Manually retry a failed webhook"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    try:
        webhook_event = WebhookEvent.objects.get(id=webhook_id)

        # Only retry failed webhooks
        if webhook_event.status != 'failed':
            return JsonResponse({
                'error': f'Cannot retry webhook with status: {webhook_event.status}'
            }, status=400)

        # Get processor
        processor = get_webhook_processor(webhook_event.source)
        if not processor:
            return JsonResponse({
                'error': f'No processor found for source: {webhook_event.source}'
            }, status=400)

        # Process the webhook
        success, message = processor.handle_event(webhook_event)

        if success:
            webhook_event.mark_processed()
            return JsonResponse({
                'status': 'success',
                'message': f'Webhook retried successfully: {message}'
            })
        else:
            webhook_event.mark_failed(message)
            return JsonResponse({
                'status': 'error',
                'message': f'Webhook retry failed: {message}'
            }, status=400)

    except WebhookEvent.DoesNotExist:
        return JsonResponse({'error': 'Webhook not found'}, status=404)

    except Exception as e:
        logger.exception(f"Error retrying webhook {webhook_id}")
        return JsonResponse({
            'error': f'Internal error: {str(e)}'
        }, status=500)
