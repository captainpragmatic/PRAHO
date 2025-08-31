import json
import logging
import uuid
from typing import Any

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit  # type: ignore[import-untyped]

from apps.audit.services import RateLimitEventData, SecurityAuditService
from apps.common.types import Err, Ok, Result

from .models import WebhookEvent
from .webhooks.base import get_webhook_processor

logger = logging.getLogger(__name__)


# ===============================================================================
# WEBHOOK ENDPOINT VIEWS
# ===============================================================================

@method_decorator([
    csrf_exempt,
    ratelimit(key='ip', rate='60/m', method='POST', block=False),    # 60 webhooks per minute per IP
    ratelimit(key='ip', rate='1000/h', method='POST', block=False),  # 1000 webhooks per hour per IP
], name='dispatch')
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
            return JsonResponse({'error': 'Webhook source not configured'}, status=400)

        # Handle rate limiting with custom response
        if getattr(request, 'limited', False):
            ip_address = self.get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            
            logger.warning(f"🚨 [Security] Rate limit exceeded for {self.source_name} webhook from IP: {ip_address}")
            
            # Log to SecurityAuditService for comprehensive audit trail
            rate_limit_data = RateLimitEventData(
                endpoint=f'integrations:webhook_{self.source_name}',
                ip_address=ip_address,
                user_agent=user_agent,
                rate_limit_key='ip',
                rate_limit_rate='60/m,1000/h'
            )
            SecurityAuditService.log_rate_limit_event(
                event_data=rate_limit_data,
                user=None  # Webhooks are unauthenticated
            )
            
            # Also log rate limit event to WebhookEvent for webhook-specific monitoring
            WebhookEvent.objects.create(
                source=self.source_name,
                event_type='rate_limited',
                event_id=f"rate_limit_{uuid.uuid4().hex[:8]}",
                payload={'error': 'Rate limit exceeded', 'ip': ip_address},
                status='skipped',
                ip_address=ip_address,
                user_agent=user_agent,
                error_message='Rate limit exceeded'
            )
            return JsonResponse({
                'status': 'rate_limited',
                'message': 'Too many webhook requests. Please slow down.'
            }, status=429)

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
        # Type guard: ensure source_name is not None before calling get_webhook_processor
        if self.source_name is None:
            return Err("Webhook source not configured")
        
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

    def _create_error_response(self, error_message: str) -> HttpResponse:
        """Create a standardized error response."""
        if error_message in {"Content-Type must be application/json", "Invalid JSON payload"} or error_message.startswith("No processor found"):
            return JsonResponse({'error': error_message}, status=400)
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

@ratelimit(key='user', rate='30/m', method='GET', block=False)  # type: ignore[misc]
def webhook_status(request: HttpRequest) -> JsonResponse:
    """📊 Webhook processing status and statistics"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    # Handle rate limiting for authenticated users
    if getattr(request, 'limited', False):
        logger.warning(f"🚨 [Security] Rate limit exceeded for webhook status API by user: {request.user.email}")
        rate_limit_data = RateLimitEventData(
            endpoint='integrations:webhook_status',
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            rate_limit_key='user',
            rate_limit_rate='30/m'
        )
        SecurityAuditService.log_rate_limit_event(
            event_data=rate_limit_data,
            user=request.user if request.user.is_authenticated else None
        )
        return JsonResponse({
            'error': 'Too many requests. Please wait before requesting status again.'
        }, status=429)

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
@ratelimit(key='user', rate='10/m', method='POST', block=False)  # type: ignore[misc]
def retry_webhook(request: HttpRequest, webhook_id: str | int) -> JsonResponse:
    """🔄 Manually retry a failed webhook using result pipeline"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    # Handle rate limiting for webhook retries
    if getattr(request, 'limited', False):
        logger.warning(f"🚨 [Security] Rate limit exceeded for webhook retry by user: {request.user.email}")
        rate_limit_data = RateLimitEventData(
            endpoint='integrations:retry_webhook',
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            rate_limit_key='user',
            rate_limit_rate='10/m'
        )
        SecurityAuditService.log_rate_limit_event(
            event_data=rate_limit_data,
            user=request.user if request.user.is_authenticated else None
        )
        return JsonResponse({
            'error': 'Too many retry requests. Please wait before retrying webhooks.'
        }, status=429)

    try:
        result = (_get_webhook_event(webhook_id)
                 .and_then(_validate_webhook_status)
                 .and_then(_get_webhook_processor)
                 .and_then(_process_webhook_retry))
        
        # Proper type narrowing for Result handling
        match result:
            case Ok(value):
                # result is Ok type - safe to access .value
                return value
            case Err(error):
                # result is Err type - safe to access .error  
                return _create_retry_error_response(error)
            case _:
                # Fallback for any unexpected cases
                return JsonResponse({'error': 'Unknown result type'}, status=500)

    except Exception as e:
        logger.exception(f"Error retrying webhook {webhook_id}")
        return JsonResponse({
            'error': f'Internal error: {e!s}'
        }, status=500)


def _get_webhook_event(webhook_id: str | int) -> Result[WebhookEvent, str]:
    """Get the webhook event by ID."""
    try:
        # Handle both string UUID and integer input
        # Convert to UUID if string, validate if already UUID-like
        if isinstance(webhook_id, str):
            try:
                parsed_uuid = uuid.UUID(webhook_id)
            except ValueError:
                return Err("Invalid webhook ID format")
        else:
            # If it's an integer, it's likely from a URL param - convert to string first
            try:
                parsed_uuid = uuid.UUID(str(webhook_id))
            except ValueError:
                return Err("Invalid webhook ID format")
        
        webhook_event = WebhookEvent.objects.get(id=parsed_uuid)
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
