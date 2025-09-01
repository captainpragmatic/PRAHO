"""
Provisioning Webhook Handlers - PRAHO Platform
Secure webhook processing for server management integrations.
"""

import json
import logging
from datetime import datetime
from typing import Any

from django.http import HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from apps.audit.services import AuditContext, ProvisioningAuditService
from apps.common.request_ip import get_safe_client_ip
from apps.common.validators import log_security_event

from .models import ProvisioningTask, Server, Service
from .secure_gateway import SecureServerGateway, ResourceAllocationWorkflow

logger = logging.getLogger(__name__)


@method_decorator(csrf_exempt, name='dispatch')
class ServerWebhookView(View):
    """
    🔐 Secure server webhook handler with signature verification
    
    Handles webhooks from server management systems for:
    - Service provisioning completion
    - Resource usage updates
    - Server status changes
    - Service suspension/activation
    - Resource allocation alerts
    """
    
    def post(self, request: HttpRequest, server_id: str) -> JsonResponse:
        """Process incoming webhook from server management system"""
        # Get server and validate
        server = get_object_or_404(Server, id=server_id, is_active=True)
        
        # Get client IP for security logging
        client_ip = get_safe_client_ip(request)
        
        try:
            # Get webhook payload
            payload_body = request.body.decode('utf-8')
            
            # Verify webhook signature
            signature = request.headers.get('X-Hub-Signature-256') or request.headers.get('X-Signature')
            
            if not self._verify_webhook_signature(server, payload_body, signature):
                # Log security event for invalid webhook
                log_security_event(
                    "server_webhook_invalid_signature",
                    {
                        "server_id": str(server.id),
                        "server_name": server.name,
                        "client_ip": client_ip,
                        "signature_provided": bool(signature),
                        "payload_size": len(payload_body),
                    },
                    client_ip
                )
                
                logger.warning(f"🚨 [Server Webhook] Invalid signature from {server.name} at {client_ip}")
                return JsonResponse({"error": "Invalid signature"}, status=403)
            
            # Parse webhook payload
            try:
                webhook_data = json.loads(payload_body)
            except json.JSONDecodeError as e:
                logger.error(f"🔥 [Server Webhook] Invalid JSON from {server.name}: {e}")
                return JsonResponse({"error": "Invalid JSON payload"}, status=400)
            
            # Process webhook event
            event_type = webhook_data.get('event_type', 'unknown')
            
            # Log successful webhook receipt
            logger.info(f"📩 [Server Webhook] Received {event_type} from {server.name}")
            
            # Process the webhook based on event type
            success, message = self._process_webhook_event(server, event_type, webhook_data, client_ip)
            
            if success:
                return JsonResponse({
                    "status": "success",
                    "message": message,
                    "event_type": event_type,
                    "server": server.name,
                })
            else:
                logger.error(f"🔥 [Server Webhook] Processing failed: {message}")
                return JsonResponse({
                    "status": "error", 
                    "message": message,
                    "event_type": event_type,
                }, status=400)
                
        except Exception as e:
            # Log unexpected webhook error
            log_security_event(
                "server_webhook_processing_error",
                {
                    "server_id": str(server.id),
                    "server_name": server.name,
                    "client_ip": client_ip,
                    "error": str(e)[:200],
                },
                client_ip
            )
            
            logger.exception(f"🔥 [Server Webhook] Unexpected error processing webhook from {server.name}")
            return JsonResponse({"error": "Internal processing error"}, status=500)
    
    def _verify_webhook_signature(self, server: Server, payload: str, signature: str | None) -> bool:
        """🔐 Verify webhook signature using server's webhook secret"""
        if not signature:
            logger.warning(f"⚠️ [Server Webhook] No signature provided by {server.name}")
            return False
        
        return SecureServerGateway.verify_webhook_signature(server, payload, signature)
    
    def _process_webhook_event(
        self, server: Server, event_type: str, webhook_data: dict[str, Any], client_ip: str
    ) -> tuple[bool, str]:  # noqa: PLR0911, PLR0912
        """📋 Process specific webhook event types"""
        
        # Process based on event type
        if event_type == 'service.provisioned':
            return self._handle_service_provisioned(server, webhook_data, client_ip)
        elif event_type == 'service.suspended':
            return self._handle_service_suspended(server, webhook_data, client_ip)
        elif event_type == 'service.activated':
            return self._handle_service_activated(server, webhook_data, client_ip)
        elif event_type == 'server.resources_updated':
            return self._handle_server_resources_updated(server, webhook_data, client_ip)
        elif event_type == 'server.status_changed':
            return self._handle_server_status_changed(server, webhook_data, client_ip)
        elif event_type == 'resource.allocation_alert':
            return self._handle_resource_allocation_alert(server, webhook_data, client_ip)
        elif event_type == 'provisioning.task_completed':
            return self._handle_provisioning_task_completed(server, webhook_data, client_ip)
        elif event_type == 'provisioning.task_failed':
            return self._handle_provisioning_task_failed(server, webhook_data, client_ip)
        else:
            logger.warning(f"⚠️ [Server Webhook] Unknown event type: {event_type}")
            return True, f"Event {event_type} acknowledged (no handler)"
    
    def _handle_service_provisioned(
        self, server: Server, webhook_data: dict[str, Any], client_ip: str
    ) -> tuple[bool, str]:
        """✅ Handle service provisioning completion"""
        try:
            service_username = webhook_data.get('service_username')
            if not service_username:
                return False, "Missing service_username in webhook data"
            
            # Find service by username
            try:
                service = Service.objects.get(username=service_username, server=server)
            except Service.DoesNotExist:
                logger.warning(f"⚠️ [Server Webhook] Service {service_username} not found on {server.name}")
                return False, f"Service {service_username} not found"
            
            # Update service status
            service.status = 'active'
            service.activated_at = datetime.now()
            
            # Update provisioning data if provided
            if 'provisioning_result' in webhook_data:
                service.provisioning_data = webhook_data['provisioning_result']
            
            service.save()
            
            # Complete any pending provisioning tasks
            ProvisioningTask.objects.filter(
                service=service,
                task_type='create_service',
                status__in=['pending', 'running']
            ).update(
                status='completed',
                completed_at=datetime.now(),
                result=webhook_data.get('provisioning_result', {})
            )
            
            # Log audit event
            ProvisioningAuditService.log_service_event(
                event_type="service_provisioned_webhook",
                service=service,
                user=None,
                context=AuditContext(actor_type="system", source_ip=client_ip),
                description=f"Service provisioned via webhook from {server.name}",
            )
            
            logger.info(f"✅ [Server Webhook] Service provisioned: {service.service_name} on {server.name}")
            return True, "Service provisioning completed successfully"
            
        except Exception as e:
            logger.error(f"🔥 [Server Webhook] Failed to process service provisioning: {e}")
            return False, str(e)
    
    def _handle_service_suspended(
        self, server: Server, webhook_data: dict[str, Any], client_ip: str
    ) -> tuple[bool, str]:
        """⏸️ Handle service suspension"""
        try:
            service_username = webhook_data.get('service_username')
            suspension_reason = webhook_data.get('reason', 'Server-initiated suspension')
            
            if not service_username:
                return False, "Missing service_username in webhook data"
            
            # Find and suspend service
            try:
                service = Service.objects.get(username=service_username, server=server)
            except Service.DoesNotExist:
                return False, f"Service {service_username} not found"
            
            service.suspend(reason=suspension_reason)
            
            # Log security event
            log_security_event(
                "service_suspended_by_server",
                {
                    "service_id": str(service.id),
                    "service_name": service.service_name,
                    "server_id": str(server.id),
                    "server_name": server.name,
                    "reason": suspension_reason,
                    "client_ip": client_ip,
                },
                client_ip
            )
            
            logger.warning(f"⏸️ [Server Webhook] Service suspended: {service.service_name}")
            return True, "Service suspension processed successfully"
            
        except Exception as e:
            logger.error(f"🔥 [Server Webhook] Failed to process service suspension: {e}")
            return False, str(e)
    
    def _handle_service_activated(
        self, server: Server, webhook_data: dict[str, Any], client_ip: str
    ) -> tuple[bool, str]:
        """▶️ Handle service activation"""
        try:
            service_username = webhook_data.get('service_username')
            
            if not service_username:
                return False, "Missing service_username in webhook data"
            
            # Find and activate service
            try:
                service = Service.objects.get(username=service_username, server=server)
            except Service.DoesNotExist:
                return False, f"Service {service_username} not found"
            
            service.activate()
            
            logger.info(f"▶️ [Server Webhook] Service activated: {service.service_name}")
            return True, "Service activation processed successfully"
            
        except Exception as e:
            logger.error(f"🔥 [Server Webhook] Failed to process service activation: {e}")
            return False, str(e)
    
    def _handle_server_resources_updated(
        self, server: Server, webhook_data: dict[str, Any], client_ip: str
    ) -> tuple[bool, str]:
        """📊 Handle server resource updates"""
        try:
            resources = webhook_data.get('resources', {})
            
            # Update server resource metrics
            if 'cpu_usage_percent' in resources:
                server.cpu_usage_percent = resources['cpu_usage_percent']
            if 'ram_usage_percent' in resources:
                server.ram_usage_percent = resources['ram_usage_percent']
            if 'disk_usage_percent' in resources:
                server.disk_usage_percent = resources['disk_usage_percent']
            
            server.save(update_fields=['cpu_usage_percent', 'ram_usage_percent', 'disk_usage_percent', 'updated_at'])
            
            logger.info(f"📊 [Server Webhook] Resources updated for {server.name}")
            return True, "Server resource metrics updated successfully"
            
        except Exception as e:
            logger.error(f"🔥 [Server Webhook] Failed to update server resources: {e}")
            return False, str(e)
    
    def _handle_server_status_changed(
        self, server: Server, webhook_data: dict[str, Any], client_ip: str
    ) -> tuple[bool, str]:
        """🖥️ Handle server status changes"""
        try:
            new_status = webhook_data.get('new_status')
            old_status = webhook_data.get('old_status', server.status)
            
            if not new_status:
                return False, "Missing new_status in webhook data"
            
            # Validate status
            valid_statuses = ['active', 'maintenance', 'offline', 'decommissioned']
            if new_status not in valid_statuses:
                return False, f"Invalid server status: {new_status}"
            
            server.status = new_status
            server.save(update_fields=['status', 'updated_at'])
            
            # Log security event for critical status changes
            if new_status in ['offline', 'decommissioned']:
                log_security_event(
                    "server_critical_status_change_webhook",
                    {
                        "server_id": str(server.id),
                        "server_name": server.name,
                        "old_status": old_status,
                        "new_status": new_status,
                        "active_services": server.active_services_count,
                        "client_ip": client_ip,
                    },
                    client_ip
                )
            
            logger.info(f"🖥️ [Server Webhook] Status changed: {server.name} {old_status} → {new_status}")
            return True, "Server status updated successfully"
            
        except Exception as e:
            logger.error(f"🔥 [Server Webhook] Failed to update server status: {e}")
            return False, str(e)
    
    def _handle_resource_allocation_alert(
        self, server: Server, webhook_data: dict[str, Any], client_ip: str
    ) -> tuple[bool, str]:
        """⚠️ Handle resource allocation alerts"""
        try:
            alert_type = webhook_data.get('alert_type', 'resource_threshold')
            resource_type = webhook_data.get('resource_type', 'unknown')
            current_usage = webhook_data.get('current_usage', 0)
            threshold = webhook_data.get('threshold', 0)
            
            # Log resource alert
            log_security_event(
                "server_resource_allocation_alert",
                {
                    "server_id": str(server.id),
                    "server_name": server.name,
                    "alert_type": alert_type,
                    "resource_type": resource_type,
                    "current_usage": current_usage,
                    "threshold": threshold,
                    "client_ip": client_ip,
                },
                client_ip
            )
            
            logger.warning(
                f"⚠️ [Server Webhook] Resource alert: {server.name} {resource_type} at {current_usage}% (threshold: {threshold}%)"
            )
            
            return True, "Resource allocation alert processed successfully"
            
        except Exception as e:
            logger.error(f"🔥 [Server Webhook] Failed to process resource alert: {e}")
            return False, str(e)
    
    def _handle_provisioning_task_completed(
        self, server: Server, webhook_data: dict[str, Any], client_ip: str
    ) -> tuple[bool, str]:
        """✅ Handle provisioning task completion"""
        try:
            task_id = webhook_data.get('task_id')
            task_result = webhook_data.get('result', {})
            
            if not task_id:
                return False, "Missing task_id in webhook data"
            
            # Find and update provisioning task
            try:
                task = ProvisioningTask.objects.get(id=task_id)
                task.status = 'completed'
                task.completed_at = datetime.now()
                task.result = task_result
                task.save()
                
                logger.info(f"✅ [Server Webhook] Provisioning task completed: {task.get_task_type_display()}")
                return True, "Provisioning task completion processed successfully"
                
            except ProvisioningTask.DoesNotExist:
                logger.warning(f"⚠️ [Server Webhook] Provisioning task {task_id} not found")
                return False, f"Provisioning task {task_id} not found"
            
        except Exception as e:
            logger.error(f"🔥 [Server Webhook] Failed to process task completion: {e}")
            return False, str(e)
    
    def _handle_provisioning_task_failed(
        self, server: Server, webhook_data: dict[str, Any], client_ip: str
    ) -> tuple[bool, str]:
        """❌ Handle provisioning task failure"""
        try:
            task_id = webhook_data.get('task_id')
            error_message = webhook_data.get('error_message', 'Task failed on server')
            
            if not task_id:
                return False, "Missing task_id in webhook data"
            
            # Find and update provisioning task
            try:
                task = ProvisioningTask.objects.get(id=task_id)
                task.status = 'failed'
                task.error_message = error_message
                task.save()
                
                logger.error(f"❌ [Server Webhook] Provisioning task failed: {task.get_task_type_display()} - {error_message}")
                return True, "Provisioning task failure processed successfully"
                
            except ProvisioningTask.DoesNotExist:
                logger.warning(f"⚠️ [Server Webhook] Provisioning task {task_id} not found")
                return False, f"Provisioning task {task_id} not found"
            
        except Exception as e:
            logger.error(f"🔥 [Server Webhook] Failed to process task failure: {e}")
            return False, str(e)


@require_http_methods(["GET"])
def server_webhook_health_check(request: HttpRequest, server_id: str) -> JsonResponse:
    """🏥 Health check endpoint for server webhooks"""
    try:
        server = get_object_or_404(Server, id=server_id, is_active=True)
        return JsonResponse({
            "status": "healthy",
            "server": server.name,
            "api_endpoint_configured": bool(server.management_api_url),
            "webhook_secret_configured": bool(server.management_webhook_secret),
            "has_valid_api_config": server.has_valid_api_config,
        })
    except Exception as e:
        logger.error(f"🔥 [Server Webhook] Health check failed for {server_id}: {e}")
        return JsonResponse({"status": "unhealthy", "error": str(e)}, status=500)


@require_http_methods(["POST"])  
@csrf_exempt
def resource_allocation_webhook(request: HttpRequest) -> JsonResponse:
    """🎯 Handle resource allocation confirmation webhooks"""
    try:
        # Get webhook payload
        payload_body = request.body.decode('utf-8')
        webhook_data = json.loads(payload_body)
        
        allocation_id = webhook_data.get('allocation_id')
        action = webhook_data.get('action', 'unknown')
        
        if not allocation_id:
            return JsonResponse({"error": "Missing allocation_id"}, status=400)
        
        # Get client IP for security logging
        client_ip = get_safe_client_ip(request)
        
        if action == 'confirm':
            
            confirmed_by = webhook_data.get('confirmed_by', 'system')
            success, message = ResourceAllocationWorkflow.confirm_resource_allocation(
                allocation_id, confirmed_by
            )
            
            # Log security event
            log_security_event(
                "resource_allocation_confirmed",
                {
                    "allocation_id": allocation_id,
                    "confirmed_by": confirmed_by,
                    "client_ip": client_ip,
                    "success": success,
                },
                client_ip
            )
            
            status_code = 200 if success else 400
            return JsonResponse({"status": "success" if success else "error", "message": message}, status=status_code)
        
        else:
            return JsonResponse({"error": f"Unknown action: {action}"}, status=400)
            
    except json.JSONDecodeError as e:
        logger.error(f"🔥 [Resource Allocation Webhook] Invalid JSON: {e}")
        return JsonResponse({"error": "Invalid JSON payload"}, status=400)
    except Exception as e:
        logger.exception(f"🔥 [Resource Allocation Webhook] Processing error: {e}")
        return JsonResponse({"error": "Internal processing error"}, status=500)
