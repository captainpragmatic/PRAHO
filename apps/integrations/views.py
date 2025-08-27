import json
import logging
from typing import Any

from django.http import HttpRequest, HttpResponseBadRequest, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from apps.common.types import Err, Ok, Result

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

    def post(self, request: Any) -> Any:
        """📨 Process incoming webhook using result pipeline"""
        if not self.source_name:
            return HttpResponseBadRequest("Webhook source not configured")

        try:
            result = (self._parse_request(request)
                     .and_then(lambda payload: self._extract_metadata(request, payload))
                     .and_then(lambda context: self._get_processor(context))
                     .and_then(lambda context: self._process_webhook(context)))
            
            if result.is_ok():
                return result.value
            else:
                return self._create_error_response(result.error)

        except Exception as e:
            logger.exception(f"💥 Critical error processing {self.source_name} webhook")
            return JsonResponse({
                'status': 'error',
                'message': f"Internal error: {e!s}"
            }, status=500)

    def _parse_request(self, request: Any) -> Result[dict[str, Any], str]:
        """Parse and validate the incoming request payload."""
        if request.content_type != 'application/json':
            return Err("Content-Type must be application/json")

        try:
            payload = json.loads(request.body)
            return Ok(payload)
        except json.JSONDecodeError:
            return Err("Invalid JSON payload")

    def _extract_metadata(self, request: Any, payload: dict[str, Any]) -> Result[dict[str, Any], str]:
        """Extract webhook metadata from the request."""
        return Ok({
            'payload': payload,
            'signature': self.extract_signature(request),
            'ip_address': self.get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'headers': dict(request.headers)
        })

    def _get_processor(self, context: dict[str, Any]) -> Result[dict[str, Any], str]:
        """Get the appropriate webhook processor for this source."""
        processor = get_webhook_processor(self.source_name)
        if not processor:
            return Err(f"No processor found for source: {self.source_name}")
        
        context['processor'] = processor
        return Ok(context)

    def _process_webhook(self, context: dict[str, Any]) -> Result[JsonResponse, str]:
        """Process the webhook and create the appropriate response."""
        processor = context['processor']
        success, message, webhook_event = processor.process_webhook(
            payload=context['payload'],
            signature=context['signature'],
            headers=context['headers'],
            ip_address=context['ip_address'],
            user_agent=context['user_agent']
        )

        webhook_id = str(webhook_event.id) if webhook_event else None

        if success:
            logger.info(f"✅ {self.source_name} webhook processed: {message}")
            return Ok(JsonResponse({
                'status': 'success',
                'message': message,
                'webhook_id': webhook_id
            }))
        else:
            logger.error(f"❌ {self.source_name} webhook failed: {message}")
            return Ok(JsonResponse({
                'status': 'error',
                'message': message,
                'webhook_id': webhook_id
            }, status=400))

    def _create_error_response(self, error_message: str) -> JsonResponse:
        """Create a standardized error response."""
        if error_message in {"Content-Type must be application/json", "Invalid JSON payload"} or error_message.startswith("No processor found"):
            return HttpResponseBadRequest(error_message)
        else:
            return JsonResponse({
                'status': 'error',
                'message': error_message
            }, status=400)

    def extract_signature(self, request: Any) -> str:
        """🔐 Extract webhook signature from headers - override in subclasses"""
        return request.META.get('HTTP_X_SIGNATURE', '')

    def get_client_ip(self, request: Any) -> str:
        """🌐 Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        ip = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')
        return ip


class StripeWebhookView(WebhookView):
    """💳 Stripe webhook endpoint"""
    source_name = 'stripe'

    def extract_signature(self, request: Any) -> str:
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

def webhook_status(request: HttpRequest) -> JsonResponse:
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
    # ⚡ PERFORMANCE: Use list comprehension for better performance
    recent_data = [
        {
            'id': str(webhook.id),
            'source': webhook.source,
            'event_type': webhook.event_type,
            'status': webhook.status,
            'received_at': webhook.received_at.isoformat(),
            'processed_at': webhook.processed_at.isoformat() if webhook.processed_at else None,
        }
        for webhook in recent_webhooks
    ]

    return JsonResponse({
        'stats': stats,
        'by_source': by_source,
        'recent_webhooks': recent_data,
    })


@require_http_methods(["POST"])
def retry_webhook(request: HttpRequest, webhook_id: int) -> JsonResponse:
    """🔄 Manually retry a failed webhook using result pipeline"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    try:
        result = (_get_webhook_event(webhook_id)
                 .and_then(_validate_webhook_status)
                 .and_then(_get_webhook_processor)
                 .and_then(_process_webhook_retry))
        
        if result.is_ok():
            return result.value
        else:
            return _create_retry_error_response(result.error)

    except Exception as e:
        logger.exception(f"Error retrying webhook {webhook_id}")
        return JsonResponse({
            'error': f'Internal error: {e!s}'
        }, status=500)


def _get_webhook_event(webhook_id: int) -> Result[WebhookEvent, str]:
    """Get the webhook event by ID."""
    try:
        webhook_event = WebhookEvent.objects.get(id=webhook_id)
        return Ok(webhook_event)
    except WebhookEvent.DoesNotExist:
        return Err("Webhook not found")


def _validate_webhook_status(webhook_event: WebhookEvent) -> Result[WebhookEvent, str]:
    """Validate that the webhook can be retried."""
    if webhook_event.status != 'failed':
        return Err(f'Cannot retry webhook with status: {webhook_event.status}')
    return Ok(webhook_event)


def _get_webhook_processor(webhook_event: WebhookEvent) -> Result[tuple[WebhookEvent, Any], str]:
    """Get the processor for the webhook event."""
    processor = get_webhook_processor(webhook_event.source)
    if not processor:
        return Err(f'No processor found for source: {webhook_event.source}')
    
    return Ok((webhook_event, processor))


def _process_webhook_retry(context: tuple[WebhookEvent, Any]) -> Result[JsonResponse, str]:
    """Process the webhook retry and update status."""
    webhook_event, processor = context
    
    success, message = processor.handle_event(webhook_event)

    if success:
        webhook_event.mark_processed()
        return Ok(JsonResponse({
            'status': 'success',
            'message': f'Webhook retried successfully: {message}'
        }))
    else:
        webhook_event.mark_failed(message)
        return Ok(JsonResponse({
            'status': 'error',
            'message': f'Webhook retry failed: {message}'
        }, status=400))


def _create_retry_error_response(error_message: str) -> JsonResponse:
    """Create appropriate error response for webhook retry failures."""
    if error_message == "Webhook not found":
        return JsonResponse({'error': error_message}, status=404)
    elif error_message.startswith(("Cannot retry webhook", "No processor found")):
        return JsonResponse({'error': error_message}, status=400)
    else:
        return JsonResponse({'error': error_message}, status=400)
