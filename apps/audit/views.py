"""
Audit and GDPR compliance views for PRAHO Platform
Comprehensive data subject rights implementation with industry-standard UI/UX.
"""

import csv
import datetime
import json
import logging
import uuid
from datetime import timedelta
from functools import wraps
from io import StringIO
from typing import TYPE_CHECKING, Any, cast

from django.contrib import messages
from django.contrib.auth import get_user_model, logout  # For GDPR deletion logout
from django.contrib.auth.decorators import login_required
from django.contrib.contenttypes.models import ContentType
from django.core.files.storage import default_storage
from django.core.paginator import Paginator
from django.db import models
from django.db.models import Q
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from apps.common.types import Err, Ok

from .models import (
    AuditAlert,
    AuditEvent,
    AuditIntegrityCheck,
    AuditRetentionPolicy,
    AuditSearchQuery,
    ComplianceLog,
    DataExport,
)
from .services import (
    AuditService,
    ComplianceEventRequest,
    audit_integrity_service,
    audit_retention_service,
    audit_search_service,
    audit_service,
    gdpr_consent_service,
    gdpr_deletion_service,
    gdpr_export_service,
)

if TYPE_CHECKING:
    from apps.users.models import User
else:
    User = get_user_model()

logger = logging.getLogger(__name__)


# ===============================================================================
# CUSTOM DECORATORS
# ===============================================================================

def staff_required(view_func: Any) -> Any:
    """
    Custom decorator to check if user is staff (instead of Django admin staff_member_required).
    This prevents NoReverseMatch errors since we don't use Django admin.
    """
    @wraps(view_func)
    @login_required
    def _wrapped_view(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not request.user.is_staff:
            messages.error(request, _("You don't have permission to access this page."))
            return redirect('dashboard')
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def _get_client_ip(request: HttpRequest) -> str | None:
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


def _parse_date_filters(filters: dict) -> dict:
    """Parse date strings to timezone-aware datetime objects to prevent naive datetime warnings."""
    parsed_filters = filters.copy()
    
    for key in ['start_date', 'end_date']:
        if parsed_filters.get(key):
            date_str = parsed_filters[key]
            if isinstance(date_str, str):
                # Try to parse as date string (YYYY-MM-DD format)
                parsed_date = parse_date(date_str)
                if parsed_date:
                    if key == 'start_date':
                        # Convert to timezone-aware datetime at start of day
                        parsed_filters[key] = timezone.make_aware(
                            datetime.datetime.combine(parsed_date, datetime.time.min)
                        )
                    else:  # end_date
                        # Convert to timezone-aware datetime at end of day
                        parsed_filters[key] = timezone.make_aware(
                            datetime.datetime.combine(parsed_date, datetime.time.max)
                        )
    
    return parsed_filters


# ===============================================================================
# GDPR DATA EXPORT VIEWS
# ===============================================================================

@login_required
def gdpr_dashboard(request: HttpRequest) -> HttpResponse:
    """GDPR privacy dashboard - main entry point for data subject rights"""
    user = cast(User, request.user)  # Safe due to @login_required
    
    # Get user's consent history
    consent_history = gdpr_consent_service.get_consent_history(user)

    # Get recent export requests
    recent_exports = DataExport.objects.filter(
        requested_by=user
    ).order_by('-requested_at')[:5]

    # Get recent deletion requests
    recent_deletions = ComplianceLog.objects.filter(
        compliance_type='gdpr_deletion',
        user=user
    ).order_by('-timestamp')[:5]

    # Calculate current consent status
    consent_status = {
        'data_processing': bool(user.gdpr_consent_date),
        'marketing': user.accepts_marketing,
        'last_updated': user.gdpr_consent_date.isoformat() if user.gdpr_consent_date else None
    }

    context = {
        'consent_history': consent_history,
        'recent_exports': recent_exports,
        'recent_deletions': recent_deletions,
        'consent_status': consent_status,
        'user': user
    }

    return render(request, 'audit/gdpr_dashboard.html', context)


@login_required
@require_POST
@csrf_protect
def request_data_export(request: HttpRequest) -> HttpResponse:
    """Create a new GDPR data export request"""
    user = cast(User, request.user)  # Safe due to @login_required
    
    # Add debugging info
    logger.info(f"🔍 [GDPR Export] Export request from {user.email}")
    logger.info(f"🔍 [GDPR Export] POST data: {dict(request.POST)}")
    
    try:
        # Get export scope from form
        export_scope = {
            'include_profile': request.POST.get('include_profile') == 'on',
            'include_customers': request.POST.get('include_customers') == 'on',
            'include_billing': request.POST.get('include_billing') == 'on',
            'include_tickets': request.POST.get('include_tickets') == 'on',
            'include_audit_logs': request.POST.get('include_audit_logs') == 'on',
            'format': 'json'
        }
        
        logger.info(f"🔍 [GDPR Export] Export scope: {export_scope}")

        # Create export request
        logger.info("🔍 [GDPR Export] Creating export request...")
        result = gdpr_export_service.create_data_export_request(
            user=user,
            request_ip=_get_client_ip(request),
            export_scope=export_scope
        )
        logger.info(f"🔍 [GDPR Export] Export request creation result type: {type(result)}")

        match result:
            case Ok(export_request):
                logger.info(f"✅ [GDPR Export] Export request created: {export_request.id}")
                messages.success(
                    request,
                    _('Your data export request has been created. You will receive an email '
                      'when it is ready for download. Request ID: {}').format(
                        str(export_request.id)[:8]
                    )
                )

                # Process export asynchronously (in a real app, use Celery)
                # For now, process immediately for demo
                logger.info("🔍 [GDPR Export] Processing export immediately...")
                processing_result = gdpr_export_service.process_data_export(export_request)
                logger.info(f"🔍 [GDPR Export] Processing result type: {type(processing_result)}")
                
                match processing_result:
                    case Ok(_):
                        logger.info("✅ [GDPR Export] Export processed successfully")
                        
                        # For HTMX requests, offer immediate download
                        if request.headers.get('HX-Request'):
                            logger.info("🔍 [GDPR Export] HTMX request detected, offering immediate download")
                            # Get the completed export
                            export_request.refresh_from_db()
                            
                            if export_request.status == 'completed' and export_request.file_path:
                                try:
                                    # Read the file content
                                    file_content = default_storage.open(export_request.file_path).read()
                                    
                                    # Create HTTP response with file download
                                    response = HttpResponse(
                                        file_content,
                                        content_type='application/json'
                                    )
                                    response['Content-Disposition'] = f'attachment; filename="gdpr-export-{export_request.id}.json"'
                                    
                                    # Log the download
                                    export_request.download_count += 1
                                    export_request.save(update_fields=['download_count'])
                                    
                                    # Log audit event for download
                                    compliance_request = ComplianceEventRequest(
                                        compliance_type='gdpr_data_portability',
                                        reference_id=f"data_export_download_{export_request.id}",
                                        description="GDPR data export downloaded (immediate)",
                                        user=user,
                                        status='success',
                                        evidence={
                                            'export_id': str(export_request.id),
                                            'file_size_bytes': len(file_content),
                                            'download_count': export_request.download_count,
                                            'immediate_download': True
                                        },
                                        metadata={
                                            'ip_address': _get_client_ip(request),
                                            'user_agent': request.META.get('HTTP_USER_AGENT', 'Unknown')
                                        }
                                    )
                                    AuditService.log_compliance_event(compliance_request)
                                    
                                    logger.info(f"✅ [GDPR Export] Immediate download served for export {export_request.id}")
                                    return response
                                    
                                except Exception as e:
                                    logger.error(f"🔥 [GDPR Export] Failed to serve immediate download: {e}", exc_info=True)
                                    messages.error(request, _('Failed to download export file. Please try again.'))
                            else:
                                logger.warning("⚠️ [GDPR Export] Export not ready for immediate download")
                                messages.warning(request, _('Export is still being processed. Please check back in a few minutes.'))
                        else:
                            messages.success(request, _('Your data export is ready for download!'))
                            
                    case Err(error_msg):
                        logger.warning(f"⚠️ [GDPR Export] Processing failed: {error_msg}")
                        messages.warning(request, _('Export is being processed. Please check back in a few minutes.'))

            case Err(error_msg):
                logger.error(f"🔥 [GDPR Export] Request creation failed: {error_msg}")
                messages.error(
                    request,
                    _('Failed to create data export request: {}').format(error_msg)
                )

    except Exception as e:
        logger.error(f"🔥 [GDPR Export] Request creation failed for {user.email}: {e}", exc_info=True)
        messages.error(request, _('An error occurred while creating your export request. Please try again.'))

    # For HTMX requests, return the updated dashboard HTML
    if request.headers.get('HX-Request'):
        logger.info("🔍 [GDPR Export] HTMX request detected, returning updated dashboard HTML")
        return gdpr_dashboard(request)
    
    return redirect('audit:gdpr_dashboard')


@login_required
def download_data_export(request: HttpRequest, export_id: uuid.UUID) -> HttpResponse:
    """Download completed GDPR data export"""
    user = cast(User, request.user)  # Safe due to @login_required
    
    try:
        # Get export request (ensure it belongs to the user)
        export_request = get_object_or_404(
            DataExport,
            id=export_id,
            requested_by=user,
            status='completed'
        )

        # Check if expired
        if timezone.now() > export_request.expires_at:
            messages.error(request, _('This export has expired and is no longer available for download.'))
            return redirect('audit:gdpr_dashboard')

        # Check if file exists
        if not export_request.file_path or not default_storage.exists(export_request.file_path):
            messages.error(request, _('Export file not found. Please contact support.'))
            return redirect('audit:gdpr_dashboard')

        # Increment download count
        export_request.download_count += 1
        export_request.save(update_fields=['download_count'])

        # Log download
        audit_service.log_compliance_event(
            compliance_type='gdpr_consent',
            reference_id=f"export_download_{export_request.id}",
            description=f"GDPR export downloaded by {user.email}",
            user=user,
            status='success',
            evidence={
                'export_id': str(export_request.id),
                'download_count': export_request.download_count,
                'file_size': export_request.file_size
            },
            metadata={'ip_address': _get_client_ip(request)}
        )

        # Serve file
        file_content = default_storage.open(export_request.file_path).read()
        response = HttpResponse(file_content, content_type='application/json')
        response['Content-Disposition'] = f'attachment; filename="gdpr_export_{user.id}.json"'
        response['Content-Length'] = len(file_content)

        return response

    except Http404:
        # Re-raise 404 errors to get proper 404 response
        raise
    except Exception as e:
        logger.error(f"🔥 [GDPR Export] Download failed for {user.email}: {e}")
        messages.error(request, _('Failed to download export file. Please try again.'))
        return redirect('audit:gdpr_dashboard')


# ===============================================================================
# GDPR DATA DELETION VIEWS
# ===============================================================================

@login_required
@require_POST
@csrf_protect
def request_data_deletion(request: HttpRequest) -> HttpResponse:
    """Create a GDPR data deletion/anonymization request"""
    user = cast(User, request.user)  # Safe due to @login_required
    
    try:
        deletion_type = request.POST.get('deletion_type', 'anonymize')
        reason = request.POST.get('reason', '').strip()

        if not reason:
            messages.error(request, _('Please provide a reason for your deletion request.'))
            return redirect('audit:gdpr_dashboard')

        # Create deletion request
        result = gdpr_deletion_service.create_deletion_request(
            user=user,
            deletion_type=deletion_type,
            request_ip=_get_client_ip(request),
            reason=reason
        )

        match result:
            case Ok(deletion_request):
                messages.warning(
                    request,
                    _('Your data deletion request has been submitted. '
                      'This action cannot be undone. Request ID: {}').format(
                        deletion_request.reference_id[:16]
                    )
                )

                # For demo purposes, process immediately
                # In production, this would be handled by staff or automated process
                if request.POST.get('confirm_immediate') == 'yes':
                    processing_result = gdpr_deletion_service.process_deletion_request(deletion_request)
                    match processing_result:
                        case Ok(_):
                            messages.success(
                                request,
                                _('Your account data has been processed according to your request.')
                            )
                            # If full deletion, user would be logged out
                            if deletion_type == 'delete':
                                logout(request)
                                return redirect('users:login')
                        case Err(error_msg):
                            messages.error(request, _('Processing failed: {}').format(error_msg))

            case Err(error_msg):
                messages.error(
                    request,
                    _('Failed to create deletion request: {}').format(error_msg)
                )

    except Exception as e:
        logger.error(f"🔥 [GDPR Deletion] Request creation failed for {user.email}: {e}")
        messages.error(request, _('An error occurred while creating your deletion request. Please try again.'))

    return redirect('audit:gdpr_dashboard')


# ===============================================================================
# GDPR CONSENT MANAGEMENT VIEWS
# ===============================================================================

@login_required
@require_POST
@csrf_protect
def withdraw_consent(request: HttpRequest) -> HttpResponse:
    """Withdraw specific GDPR consents"""
    user = cast(User, request.user)  # Safe due to @login_required
    
    try:
        consent_types = request.POST.getlist('consent_types')

        if not consent_types:
            messages.error(request, _('Please select at least one consent type to withdraw.'))
            return redirect('audit:gdpr_dashboard')

        # Process consent withdrawal
        result = gdpr_consent_service.withdraw_consent(
            user=user,
            consent_types=consent_types,
            request_ip=_get_client_ip(request)
        )

        match result:
            case Ok(success_msg):
                messages.success(
                    request,
                    _('Your consent has been withdrawn for: {}').format(success_msg)
                )

                # If data processing consent withdrawn, warn about anonymization
                if 'data_processing' in consent_types:
                    messages.warning(
                        request,
                        _('Data processing consent withdrawal will trigger account anonymization. '
                          'This cannot be undone.')
                    )
            case Err(error_msg):
                messages.error(
                    request,
                    _('Failed to withdraw consent: {}').format(error_msg)
                )

    except Exception as e:
        logger.error(f"🔥 [GDPR Consent] Withdrawal failed for {user.email}: {e}")
        messages.error(request, _('An error occurred while processing your consent withdrawal. Please try again.'))

    return redirect('audit:gdpr_dashboard')


@login_required
@require_POST
@csrf_protect
def update_consent(request: HttpRequest) -> HttpResponse:
    """Update specific GDPR consents"""
    user = cast(User, request.user)  # Safe due to @login_required
    
    # Add debugging info
    logger.info(f"🔍 [GDPR Consent] Update request from {user.email}")
    logger.info(f"🔍 [GDPR Consent] POST data: {dict(request.POST)}")
    
    try:
        # Get current values for comparison
        old_values = {
            'accepts_marketing': user.accepts_marketing,
            'gdpr_consent_date': user.gdpr_consent_date.isoformat() if user.gdpr_consent_date else None
        }
        
        logger.info(f"🔍 [GDPR Consent] Current values: {old_values}")
        
        changes_made = []
        
        # Handle marketing consent
        marketing_consent = request.POST.get('accepts_marketing') == 'on'
        logger.info(f"🔍 [GDPR Consent] Marketing consent checkbox: {request.POST.get('accepts_marketing')} -> {marketing_consent}")
        
        if marketing_consent != user.accepts_marketing:
            user.accepts_marketing = marketing_consent
            changes_made.append(f'marketing_consent_{"granted" if marketing_consent else "withdrawn"}')
            logger.info(f"✅ [GDPR Consent] Marketing consent changed: {user.accepts_marketing} -> {marketing_consent}")
        
        # Handle data processing consent (only if granting, withdrawal is handled differently)
        data_processing_consent = request.POST.get('gdpr_consent') == 'on'
        logger.info(f"🔍 [GDPR Consent] Data processing consent checkbox: {request.POST.get('gdpr_consent')} -> {data_processing_consent}")
        
        if data_processing_consent and not user.gdpr_consent_date:
            user.gdpr_consent_date = timezone.now()
            changes_made.append('gdpr_consent_granted')
            logger.info("✅ [GDPR Consent] Data processing consent granted")
        
        logger.info(f"🔍 [GDPR Consent] Changes to make: {changes_made}")
        
        if changes_made:
            user.save(update_fields=['accepts_marketing', 'gdpr_consent_date'])
            logger.info(f"✅ [GDPR Consent] User saved with changes: {changes_made}")
            
            new_values = {
                'accepts_marketing': user.accepts_marketing,
                'gdpr_consent_date': user.gdpr_consent_date.isoformat() if user.gdpr_consent_date else None
            }
            
            # Log consent update
            compliance_request = ComplianceEventRequest(
                compliance_type='gdpr_consent',
                reference_id=f"consent_update_{user.id}_{uuid.uuid4().hex[:8]}",
                description=f"Consent updated: {', '.join(changes_made)}",
                user=user,
                status='success',
                evidence={
                    'changes': changes_made,
                    'old_values': old_values,
                    'new_values': new_values,
                    'update_date': timezone.now().isoformat()
                },
                metadata={'ip_address': _get_client_ip(request)}
            )
            AuditService.log_compliance_event(compliance_request)
            logger.info("✅ [GDPR Consent] Compliance event logged")
            
            messages.success(
                request,
                _('Your privacy preferences have been updated successfully.')
            )
        else:
            logger.info("[GDPR Consent] No changes detected")
            messages.info(request, _('No changes were made to your privacy preferences.'))
            
    except Exception as e:
        logger.error(f"🔥 [GDPR Consent] Update failed for {user.email}: {e}", exc_info=True)
        messages.error(request, _('An error occurred while updating your privacy preferences. Please try again.'))
    
    # For HTMX requests, return the updated dashboard HTML
    if request.headers.get('HX-Request'):
        logger.info("🔍 [GDPR Consent] HTMX request detected, returning updated dashboard HTML")
        return gdpr_dashboard(request)
    
    return redirect('audit:gdpr_dashboard')




# ===============================================================================
# ENTERPRISE AUDIT MANAGEMENT DASHBOARD
# ===============================================================================

@staff_required
def audit_management_dashboard(request: HttpRequest) -> HttpResponse:
    """Enterprise audit management dashboard with real-time metrics and alerts."""
    
    # Log staff access
    logger.info(f"🔒 [Audit Management] Dashboard accessed by {getattr(request.user, 'email', 'anonymous')} from {_get_client_ip(request)}")
    
    # Get dashboard metrics
    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=7)
    
    # Audit event statistics
    audit_stats = {
        'total_events': AuditEvent.objects.count(),
        'today_events': AuditEvent.objects.filter(timestamp__gte=today_start).count(),
        'week_events': AuditEvent.objects.filter(timestamp__gte=week_start).count(),
        'critical_events': AuditEvent.objects.filter(
            severity='critical',
            timestamp__gte=week_start
        ).count(),
        'sensitive_events': AuditEvent.objects.filter(
            is_sensitive=True,
            timestamp__gte=today_start
        ).count(),
        'review_required': AuditEvent.objects.filter(
            requires_review=True,
            timestamp__gte=week_start
        ).count(),
    }
    
    # Active alerts
    active_alerts = AuditAlert.objects.filter(
        status__in=['active', 'acknowledged', 'investigating']
    ).order_by('-created_at')[:10]
    
    # Recent integrity checks
    recent_integrity_checks = AuditIntegrityCheck.objects.order_by('-checked_at')[:5]
    
    # Retention policy summary
    retention_policies = AuditRetentionPolicy.objects.filter(is_active=True).count()
    
    # Popular saved searches
    popular_searches = AuditSearchQuery.objects.filter(
        is_shared=True
    ).order_by('-usage_count')[:5]
    
    context = {
        'audit_stats': audit_stats,
        'active_alerts': active_alerts,
        'recent_integrity_checks': recent_integrity_checks,
        'retention_policies_count': retention_policies,
        'popular_searches': popular_searches,
        'dashboard_refresh_interval': 30,  # seconds
    }
    
    return render(request, 'audit/management_dashboard.html', context)


@staff_required
def audit_log(request: HttpRequest) -> HttpResponse:
    """Enhanced audit logs view with advanced search capabilities."""
    
    # Get available filter options
    context = {
        'action_choices': AuditEvent.ACTION_CHOICES,
        'category_choices': AuditEvent.CATEGORY_CHOICES,
        'severity_choices': AuditEvent.SEVERITY_CHOICES,
        'content_types': ContentType.objects.all().order_by('app_label', 'model'),
        'users': User.objects.filter(is_active=True).order_by('email'),
        'saved_searches': AuditSearchQuery.objects.filter(
            Q(created_by=request.user) | Q(is_shared=True)
        ).order_by('-last_used_at', 'name'),
    }
    return render(request, 'audit/logs.html', context)


@staff_required
def logs_list(request: HttpRequest) -> HttpResponse:
    """Enhanced HTMX endpoint for filtered audit logs with advanced search."""
    
    # Build advanced search filters
    filters = {
        'user_ids': [uid for uid in request.GET.getlist('user') if uid.strip() and uid.strip().isdigit()] or None,
        'actions': [action for action in request.GET.getlist('action') if action.strip()] or None,
        'categories': [cat for cat in request.GET.getlist('category') if cat.strip()] or None,
        'severities': [sev for sev in request.GET.getlist('severity') if sev.strip()] or None,
        'content_types': [ct_id for ct_id in request.GET.getlist('content_type') if ct_id.strip() and ct_id.strip().isdigit()] or None,
        'start_date': request.GET.get('start_date') or None,
        'end_date': request.GET.get('end_date') or None,
        'ip_addresses': request.GET.get('ip_address') or None,
        'request_ids': request.GET.get('request_id') or None,
        'session_keys': request.GET.get('session_key') or None,
        'search_text': request.GET.get('search') or None,
        'is_sensitive': request.GET.get('is_sensitive') == 'true' if request.GET.get('is_sensitive') else None,
        'requires_review': request.GET.get('requires_review') == 'true' if request.GET.get('requires_review') else None,
        'has_old_values': request.GET.get('has_old_values') == 'true' if request.GET.get('has_old_values') else None,
        'has_new_values': request.GET.get('has_new_values') == 'true' if request.GET.get('has_new_values') else None,
    }
    
    # Remove None values and empty strings
    filters = {k: v for k, v in filters.items() if v is not None and v != ''}
    
    # Use advanced search service
    # Ensure user is authenticated before passing to service
    if not request.user.is_authenticated:
        return HttpResponseForbidden()
    
    # Parse date filters to prevent naive datetime warnings
    parsed_filters = _parse_date_filters(filters)
    queryset, query_info = audit_search_service.build_advanced_query(parsed_filters, request.user)
    
    # Pagination
    page = request.GET.get('page', 1)
    page_size = min(int(request.GET.get('page_size', 50)), 200)  # Max 200 per page
    paginator = Paginator(queryset, page_size)
    audit_events = paginator.get_page(page)
    
    
    context = {
        'audit_events': audit_events,
        'query_info': query_info,
        'total_results': paginator.count,
        'page_size': page_size,
    }

    # Check if HTMX request
    if request.headers.get('HX-Request'):
        return render(request, 'audit/partials/logs_list.html', context)

    return render(request, 'audit/partials/logs_list.html', context)




@staff_required
def export_logs(request: HttpRequest) -> HttpResponse:
    """Export filtered audit logs in multiple formats (CSV, JSON)."""
    
    export_format = request.GET.get('format', 'csv')
    
    # Build same filters as logs_list
    filters = {
        'user_ids': [uid for uid in request.GET.getlist('user') if uid.strip() and uid.strip().isdigit()] or None,
        'actions': [action for action in request.GET.getlist('action') if action.strip()] or None,
        'categories': [cat for cat in request.GET.getlist('category') if cat.strip()] or None,
        'severities': [sev for sev in request.GET.getlist('severity') if sev.strip()] or None,
        'content_types': [ct_id for ct_id in request.GET.getlist('content_type') if ct_id.strip() and ct_id.strip().isdigit()] or None,
        'start_date': request.GET.get('start_date'),
        'end_date': request.GET.get('end_date'),
        'ip_addresses': request.GET.get('ip_address'),
        'request_ids': request.GET.get('request_id'),
        'session_keys': request.GET.get('session_key'),
        'search_text': request.GET.get('search'),
        'is_sensitive': request.GET.get('is_sensitive') == 'true' if request.GET.get('is_sensitive') else None,
        'requires_review': request.GET.get('requires_review') == 'true' if request.GET.get('requires_review') else None,
    }
    
    # Remove None values and empty strings (same as logs_list)
    filters = {k: v for k, v in filters.items() if v is not None and v != ''}
    
    # Use advanced search service
    # Ensure user is authenticated before passing to service
    if not request.user.is_authenticated:
        return HttpResponseForbidden()
    
    # Parse date filters to prevent naive datetime warnings
    parsed_filters = _parse_date_filters(filters)
    queryset, _ = audit_search_service.build_advanced_query(parsed_filters, request.user)
    
    # Limit export size for performance
    max_export_size = 10000
    if queryset.count() > max_export_size:
        messages.warning(
            request,
            f'Export limited to {max_export_size} most recent records. Use date filters to reduce dataset size.'
        )
        queryset = queryset[:max_export_size]
    
    # Log the export
    audit_service.log_event(
        event_type='export',
        user=request.user,
        description=f'Audit logs exported in {export_format} format ({queryset.count()} records)',
        ip_address=_get_client_ip(request),
        metadata={'export_format': export_format, 'record_count': queryset.count()}
    )
    
    timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
    
    if export_format == 'json':
        return _export_logs_json(queryset, timestamp)
    else:
        return _export_logs_csv(queryset, timestamp)


def _export_logs_csv(queryset: models.QuerySet[AuditEvent], timestamp: str) -> HttpResponse:
    """Export audit logs as CSV."""
    output = StringIO()
    writer = csv.writer(output)
    
    # Enhanced CSV header
    writer.writerow([
        'Timestamp',
        'User',
        'Action',
        'Category',
        'Severity',
        'Content Type',
        'Object ID',
        'IP Address',
        'User Agent',
        'Description',
        'Is Sensitive',
        'Requires Review',
        'Request ID',
        'Session Key',
        'Old Values',
        'New Values',
        'Metadata',
    ])

    # Write data
    for event in queryset:
        writer.writerow([
            event.timestamp.isoformat(),
            event.user.email if event.user else 'System',
            event.get_action_display(),
            event.get_category_display(),
            event.get_severity_display(),
            str(event.content_type) if event.content_type else '',
            event.object_id,
            event.ip_address or '',
            event.user_agent or '',
            event.description or '',
            event.is_sensitive,
            event.requires_review,
            event.request_id or '',
            event.session_key or '',
            json.dumps(event.old_values) if event.old_values else '',
            json.dumps(event.new_values) if event.new_values else '',
            json.dumps(event.metadata) if event.metadata else '',
        ])

    response = HttpResponse(output.getvalue(), content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="audit_logs_{timestamp}.csv"'
    return response


def _export_logs_json(queryset: models.QuerySet[AuditEvent], timestamp: str) -> HttpResponse:
    """Export audit logs as JSON."""
    
    data = {
        'export_metadata': {
            'generated_at': timezone.now().isoformat(),
            'record_count': queryset.count(),
            'export_format': 'json',
            'praho_platform': 'Enterprise Audit Export'
        },
        'audit_events': []
    }
    
    for event in queryset:
        event_data = {
            'id': str(event.id),
            'timestamp': event.timestamp.isoformat(),
            'user': {
                'id': str(event.user.id) if event.user else None,
                'email': event.user.email if event.user else None,
            },
            'actor_type': event.actor_type,
            'action': event.action,
            'action_display': event.get_action_display(),
            'category': event.category,
            'category_display': event.get_category_display(),
            'severity': event.severity,
            'severity_display': event.get_severity_display(),
            'is_sensitive': event.is_sensitive,
            'requires_review': event.requires_review,
            'content_type': {
                'app_label': event.content_type.app_label if event.content_type else None,
                'model': event.content_type.model if event.content_type else None,
            },
            'object_id': event.object_id,
            'description': event.description,
            'ip_address': event.ip_address,
            'user_agent': event.user_agent,
            'request_id': event.request_id,
            'session_key': event.session_key,
            'old_values': event.old_values,
            'new_values': event.new_values,
            'metadata': event.metadata,
        }
        data['audit_events'].append(event_data)
    
    response = HttpResponse(
        json.dumps(data, indent=2, default=str, ensure_ascii=False),
        content_type='application/json'
    )
    response['Content-Disposition'] = f'attachment; filename="audit_logs_{timestamp}.json"'
    return response


# ===============================================================================
# STAFF GDPR MANAGEMENT VIEWS  
# ===============================================================================

@staff_required
def gdpr_management_dashboard(request: HttpRequest) -> HttpResponse:
    """Staff-only GDPR management dashboard for processing all user requests"""
    
    # Log staff access for security audit
    logger.info(f"🔒 [Staff GDPR] Dashboard accessed by {getattr(request.user, 'email', 'anonymous')} from {_get_client_ip(request)}")
    
    # Get summary statistics
    export_stats = {
        'pending': DataExport.objects.filter(status='pending').count(),
        'processing': DataExport.objects.filter(status='processing').count(),
        'completed': DataExport.objects.filter(status='completed').count(),
        'failed': DataExport.objects.filter(status='failed').count(),
        'expired': DataExport.objects.filter(
            status='completed', 
            expires_at__lt=timezone.now()
        ).count()
    }
    
    # Get recent export requests for dashboard overview
    recent_exports = DataExport.objects.select_related('requested_by').order_by('-requested_at')[:10]
    
    context = {
        'export_stats': export_stats,
        'recent_exports': recent_exports,
        'total_requests': sum(export_stats.values()) - export_stats['expired']
    }
    
    return render(request, 'audit/gdpr_management_dashboard.html', context)


@staff_required 
def gdpr_export_requests_list(request: HttpRequest) -> HttpResponse:
    """HTMX endpoint for filtered GDPR export requests list"""
    
    # Get query parameters for filtering
    status = request.GET.get('status')
    user_email = request.GET.get('user_email', '').strip()
    export_type = request.GET.get('export_type')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    expired_filter = request.GET.get('expired')
    page = request.GET.get('page', 1)
    
    # Build query
    queryset = DataExport.objects.select_related('requested_by')
    
    # Apply filters
    if status and status != 'all':
        queryset = queryset.filter(status=status)
    if user_email:
        queryset = queryset.filter(requested_by__email__icontains=user_email)
    if export_type:
        queryset = queryset.filter(export_type=export_type)
    if start_date:
        queryset = queryset.filter(requested_at__gte=start_date)
    if end_date:
        queryset = queryset.filter(requested_at__lte=end_date)
    if expired_filter == 'expired':
        queryset = queryset.filter(status='completed', expires_at__lt=timezone.now())
    elif expired_filter == 'active':
        queryset = queryset.exclude(status='completed', expires_at__lt=timezone.now())
    
    # Order by most recent first
    queryset = queryset.order_by('-requested_at')
    
    # Pagination
    paginator = Paginator(queryset, 25)
    export_requests = paginator.get_page(page)
    
    context = {
        'export_requests': export_requests,
        'current_time': timezone.now()
    }
    
    # Check if HTMX request
    if request.headers.get('HX-Request'):
        return render(request, 'audit/partials/gdpr_export_requests_list.html', context)
    
    return render(request, 'audit/partials/gdpr_export_requests_list.html', context)


@staff_required
@require_POST
@csrf_protect
def process_export_request(request: HttpRequest, export_id: uuid.UUID) -> HttpResponse:
    """Process a GDPR export request (approve, reject, or mark as processed)"""
    
    try:
        export_request = get_object_or_404(DataExport, id=export_id)
        action = request.POST.get('action')
        
        if action == 'process_now':
            # Process the export immediately
            result = gdpr_export_service.process_data_export(export_request)
            match result:
                case Ok(_):
                    # Log the staff action
                    audit_service.log_event(
                        event_type='export',
                        user=request.user,
                        content_object=export_request,
                        description=f'Staff processed GDPR export request for {export_request.requested_by.email}',
                        ip_address=_get_client_ip(request)
                    )
                    messages.success(request, _('Export request processed successfully.'))
                case Err(error_msg):
                    messages.error(request, _('Failed to process export: {}').format(error_msg))
        
        elif action == 'mark_failed':
            error_message = request.POST.get('error_message', '').strip()
            if not error_message:
                messages.error(request, _('Please provide an error message.'))
            else:
                export_request.status = 'failed'
                export_request.error_message = error_message
                export_request.save(update_fields=['status', 'error_message'])
                
                # Log the staff action
                audit_service.log_event(
                    event_type='update',
                    user=request.user,
                    content_object=export_request,
                    description=f'Staff marked GDPR export as failed for {export_request.requested_by.email}: {error_message}',
                    ip_address=_get_client_ip(request)
                )
                messages.warning(request, _('Export request marked as failed.'))
        
        elif action == 'delete_expired':
            if export_request.status == 'completed' and timezone.now() > export_request.expires_at:
                # Delete the file if it exists
                if export_request.file_path and default_storage.exists(export_request.file_path):
                    default_storage.delete(export_request.file_path)
                
                # Log the staff action before deletion
                audit_service.log_event(
                    event_type='delete',
                    user=request.user,
                    content_object=export_request,
                    description=f'Staff deleted expired GDPR export for {export_request.requested_by.email}',
                    ip_address=_get_client_ip(request)
                )
                
                export_request.delete()
                messages.success(request, _('Expired export deleted successfully.'))
            else:
                messages.error(request, _('Can only delete expired completed exports.'))
        
        else:
            messages.error(request, _('Invalid action specified.'))
    
    except Exception as e:
        logger.error(f"🔥 [Staff GDPR] Processing failed for request {export_id}: {e}")
        messages.error(request, _('An error occurred while processing the request.'))
    
    # Return to management dashboard
    return redirect('audit:gdpr_management_dashboard')


@staff_required
def gdpr_export_detail(request: HttpRequest, export_id: uuid.UUID) -> HttpResponse:
    """HTMX endpoint for detailed export request view"""
    export_request = get_object_or_404(DataExport, id=export_id)
    
    # Check if file exists and get file info
    file_exists = False
    if export_request.file_path:
        file_exists = default_storage.exists(export_request.file_path)
    
    context = {
        'export_request': export_request,
        'file_exists': file_exists,
        'current_time': timezone.now(),
        'is_expired': (
            export_request.status == 'completed' and 
            timezone.now() > export_request.expires_at
        )
    }
    
    return render(request, 'audit/partials/gdpr_export_detail.html', context)


@staff_required
def download_user_export(request: HttpRequest, export_id: uuid.UUID) -> HttpResponse:
    """Staff download of user's GDPR export for review/compliance purposes"""
    
    try:
        export_request = get_object_or_404(DataExport, id=export_id)
        
        # Check if file exists
        if not export_request.file_path or not default_storage.exists(export_request.file_path):
            messages.error(request, _('Export file not found.'))
            return redirect('audit:gdpr_management_dashboard')
        
        # Log the staff download
        audit_service.log_event(
            event_type='access',
            user=request.user,
            content_object=export_request,
            description=f'Staff downloaded GDPR export for compliance review (user: {export_request.requested_by.email})',
            ip_address=_get_client_ip(request)
        )
        
        # Serve file
        file_content = default_storage.open(export_request.file_path).read()
        response = HttpResponse(file_content, content_type='application/json')
        response['Content-Disposition'] = f'attachment; filename="gdpr_export_{export_request.requested_by.id}_{export_request.id}.json"'
        response['Content-Length'] = len(file_content)
        
        return response
    
    except Exception as e:
        logger.error(f"🔥 [Staff GDPR] Download failed for request {export_id}: {e}")
        messages.error(request, _('Failed to download export file.'))
        return redirect('audit:gdpr_management_dashboard')


# ===============================================================================
# ENTERPRISE AUDIT MANAGEMENT VIEWS
# ===============================================================================

@staff_required
def audit_search_suggestions(request: HttpRequest) -> HttpResponse:
    """HTMX endpoint for search auto-completion suggestions."""
    
    query = request.GET.get('q', '').strip()
    # Ensure user is authenticated
    if not request.user.is_authenticated:
        return JsonResponse({'suggestions': {}})
    suggestions = audit_search_service.get_search_suggestions(query, request.user)
    
    context = {
        'suggestions': suggestions,
        'query': query
    }
    
    return render(request, 'audit/partials/search_suggestions.html', context)


@staff_required
@require_POST
@csrf_protect
def save_search_query(request: HttpRequest) -> HttpResponse:
    """Save a search query for reuse."""
    
    try:
        name = request.POST.get('name', '').strip()
        description = request.POST.get('description', '').strip()
        is_shared = request.POST.get('is_shared') == 'on'
        
        # Get current search parameters from session or form
        query_params = {}
        for key in request.POST:
            if key.startswith('filter_'):
                param_name = key.replace('filter_', '')
                query_params[param_name] = request.POST.get(key)
        
        if not name:
            messages.error(request, _('Search query name is required.'))
            return redirect('audit:logs')
        
        # Ensure user is authenticated for saving searches
        if not request.user.is_authenticated:
            messages.error(request, _('You must be logged in to save search queries.'))
            return redirect('audit:logs')
            
        result = audit_search_service.save_search_query(
            name=name,
            query_params=query_params,
            user=request.user,
            description=description,
            is_shared=is_shared
        )
        
        match result:
            case Ok(_):
                messages.success(
                    request,
                    _('Search query "{}" saved successfully.').format(name)
                )
            case Err(error_msg):
                messages.error(
                    request,
                    _('Failed to save search query: {}').format(error_msg)
                )
    
    except Exception as e:
        logger.error(f"🔥 [Audit Search] Failed to save query: {e}")
        messages.error(request, _('An error occurred while saving the search query.'))
    
    return redirect('audit:logs')


@staff_required
def load_saved_search(request: HttpRequest, query_id: uuid.UUID) -> HttpResponse:
    """Load a saved search query."""
    
    try:
        search_query = get_object_or_404(
            AuditSearchQuery,
            id=query_id
        )
        
        # Check permissions
        if not (search_query.created_by == request.user or search_query.is_shared):
            messages.error(request, _('You do not have permission to access this search query.'))
            return redirect('audit:logs')
        
        # Update usage statistics
        search_query.last_used_at = timezone.now()
        search_query.usage_count += 1
        search_query.save(update_fields=['last_used_at', 'usage_count'])
        
        # Build URL with query parameters
        base_url = '/audit/logs/'
        query_string = '&'.join([f"{k}={v}" for k, v in search_query.query_params.items() if v])
        redirect_url = f"{base_url}?{query_string}" if query_string else base_url
        
        messages.info(
            request,
            _('Loaded saved search: "{}"').format(search_query.name)
        )
        
        return redirect(redirect_url)
    
    except Exception as e:
        logger.error(f"🔥 [Audit Search] Failed to load saved query: {e}")
        messages.error(request, _('Failed to load saved search query.'))
        return redirect('audit:logs')


@staff_required
def integrity_dashboard(request: HttpRequest) -> HttpResponse:
    """Audit data integrity monitoring dashboard."""
    
    # Get recent integrity checks
    recent_checks = AuditIntegrityCheck.objects.order_by('-checked_at')[:20]
    
    # Get integrity statistics
    total_checks = AuditIntegrityCheck.objects.count()
    healthy_checks = AuditIntegrityCheck.objects.filter(status='healthy').count()
    warning_checks = AuditIntegrityCheck.objects.filter(status='warning').count()
    compromised_checks = AuditIntegrityCheck.objects.filter(status='compromised').count()
    
    # Recent issues
    recent_issues = AuditIntegrityCheck.objects.filter(
        status__in=['warning', 'compromised'],
        checked_at__gte=timezone.now() - timedelta(days=7)
    ).order_by('-checked_at')[:10]
    
    context = {
        'recent_checks': recent_checks,
        'stats': {
            'total_checks': total_checks,
            'healthy_checks': healthy_checks,
            'warning_checks': warning_checks,
            'compromised_checks': compromised_checks,
            'health_percentage': (healthy_checks / total_checks * 100) if total_checks > 0 else 0
        },
        'recent_issues': recent_issues
    }
    
    return render(request, 'audit/integrity_dashboard.html', context)


@staff_required
@require_POST
@csrf_protect
def run_integrity_check(request: HttpRequest) -> HttpResponse:
    """Manually trigger an audit integrity check."""
    
    try:
        check_type = request.POST.get('check_type', 'hash_verification')
        
        # Default to last 24 hours
        end_time = timezone.now()
        start_time = end_time - timedelta(days=1)
        
        # Allow custom time range
        start_date = request.POST.get('start_date')
        if start_date:
            start_time = timezone.datetime.fromisoformat(start_date)
        end_date = request.POST.get('end_date')
        if end_date:
            end_time = timezone.datetime.fromisoformat(end_date)
        
        # Run integrity check
        result = audit_integrity_service.verify_audit_integrity(
            period_start=start_time,
            period_end=end_time,
            check_type=check_type
        )
        
        match result:
            case Ok(integrity_check):
                messages.success(
                    request,
                    _('Integrity check completed: {} ({} issues found)').format(
                        integrity_check.get_status_display(),
                        integrity_check.issues_found
                    )
                )
            case Err(error_msg):
                messages.error(
                    request,
                    _('Integrity check failed: {}').format(error_msg)
                )
        
    except Exception as e:
        logger.error(f"🔥 [Integrity Check] Manual check failed: {e}")
        messages.error(request, _('Failed to run integrity check.'))
    
    return redirect('audit:integrity_dashboard')


@staff_required
def retention_dashboard(request: HttpRequest) -> HttpResponse:
    """Audit retention policy management dashboard."""
    
    # Get all retention policies
    policies = AuditRetentionPolicy.objects.all().order_by('category', 'name')
    
    # Get statistics about data eligible for retention processing
    retention_stats = {}
    for policy in policies.filter(is_active=True):
        cutoff_date = timezone.now() - timedelta(days=policy.retention_days)
        
        queryset = AuditEvent.objects.filter(
            timestamp__lt=cutoff_date,
            category=policy.category
        )
        
        if policy.severity:
            queryset = queryset.filter(severity=policy.severity)
        
        retention_stats[str(policy.id)] = {
            'policy_name': policy.name,
            'eligible_events': queryset.count(),
            'action': policy.get_action_display(),
            'cutoff_date': cutoff_date
        }
    
    context = {
        'policies': policies,
        'retention_stats': retention_stats,
        'category_choices': AuditEvent.CATEGORY_CHOICES,
        'severity_choices': AuditEvent.SEVERITY_CHOICES,
        'action_choices': AuditRetentionPolicy.RETENTION_ACTION_CHOICES,
    }
    
    return render(request, 'audit/retention_dashboard.html', context)


@staff_required
@require_POST
@csrf_protect
def apply_retention_policies(request: HttpRequest) -> HttpResponse:
    """Apply retention policies to audit data."""
    
    try:
        # Confirm before applying (dangerous operation)
        if request.POST.get('confirm') != 'yes':
            messages.warning(
                request,
                _('Retention policy application requires confirmation. This action cannot be undone.')
            )
            return redirect('audit:retention_dashboard')
        
        # Apply retention policies
        result = audit_retention_service.apply_retention_policies()
        
        match result:
            case Ok(results):
                messages.success(
                    request,
                    _('Retention policies applied: {} policies processed, {} events affected').format(
                        results['policies_applied'],
                        results['events_processed']
                    )
                )
                
                if results['errors']:
                    for error in results['errors']:
                        messages.warning(request, error)
                        
            case Err(error_msg):
                messages.error(
                    request,
                    _('Failed to apply retention policies: {}').format(error_msg)
                )
        
    except Exception as e:
        logger.error(f"🔥 [Retention] Policy application failed: {e}")
        messages.error(request, _('Failed to apply retention policies.'))
    
    return redirect('audit:retention_dashboard')


@staff_required
def alerts_dashboard(request: HttpRequest) -> HttpResponse:
    """Security and compliance alerts dashboard."""
    
    # Get filter parameters
    status_filter = request.GET.get('status', 'active')
    alert_type_filter = request.GET.get('alert_type')
    severity_filter = request.GET.get('severity')
    
    # Build query
    queryset = AuditAlert.objects.all()
    
    if status_filter and status_filter != 'all':
        if status_filter == 'open':
            queryset = queryset.filter(status__in=['active', 'acknowledged', 'investigating'])
        else:
            queryset = queryset.filter(status=status_filter)
    
    if alert_type_filter:
        queryset = queryset.filter(alert_type=alert_type_filter)
    
    if severity_filter:
        queryset = queryset.filter(severity=severity_filter)
    
    alerts = queryset.order_by('-created_at')
    
    # Pagination
    paginator = Paginator(alerts, 25)
    page = request.GET.get('page', 1)
    alerts_page = paginator.get_page(page)
    
    # Statistics
    alert_stats = {
        'total_alerts': AuditAlert.objects.count(),
        'active_alerts': AuditAlert.objects.filter(status='active').count(),
        'critical_alerts': AuditAlert.objects.filter(
            severity='critical',
            status__in=['active', 'acknowledged', 'investigating']
        ).count(),
        'my_assigned': AuditAlert.objects.filter(
            assigned_to=request.user if request.user.is_authenticated else None,
            status__in=['active', 'acknowledged', 'investigating']
        ).count() if request.user.is_authenticated else 0,
    }
    
    context = {
        'alerts': alerts_page,
        'alert_stats': alert_stats,
        'status_filter': status_filter,
        'alert_type_filter': alert_type_filter,
        'severity_filter': severity_filter,
        'alert_type_choices': AuditAlert.ALERT_TYPE_CHOICES,
        'severity_choices': AuditAlert.SEVERITY_CHOICES,
        'status_choices': AuditAlert.STATUS_CHOICES,
    }
    
    return render(request, 'audit/alerts_dashboard.html', context)


@staff_required
@require_POST
@csrf_protect
def update_alert_status(request: HttpRequest, alert_id: uuid.UUID) -> HttpResponse:
    """Update alert status and assignment."""
    
    try:
        alert = get_object_or_404(AuditAlert, id=alert_id)
        action = request.POST.get('action')
        
        if action == 'acknowledge':
            alert.status = 'acknowledged'
            alert.acknowledged_by = request.user
            alert.acknowledged_at = timezone.now()
            messages.success(request, _('Alert acknowledged.'))
            
        elif action == 'assign_to_me':
            alert.assigned_to = request.user
            if alert.status == 'active':
                alert.status = 'investigating'
            messages.success(request, _('Alert assigned to you.'))
            
        elif action == 'resolve':
            alert.status = 'resolved'
            alert.resolved_at = timezone.now()
            alert.resolution_notes = request.POST.get('resolution_notes', '')
            messages.success(request, _('Alert resolved.'))
            
        elif action == 'false_positive':
            alert.status = 'false_positive'
            alert.resolved_at = timezone.now()
            alert.resolution_notes = request.POST.get('resolution_notes', '')
            messages.success(request, _('Alert marked as false positive.'))
        
        alert.save()
        
        # Log the action
        audit_service.log_event(
            event_type='update',
            user=request.user,
            content_object=alert,
            description=f'Alert status updated: {action}',
            ip_address=_get_client_ip(request)
        )
        
    except Exception as e:
        logger.error(f"🔥 [Alerts] Status update failed: {e}")
        messages.error(request, _('Failed to update alert status.'))
    
    return redirect('audit:alerts_dashboard')


@staff_required
def event_detail(request: HttpRequest, event_id: uuid.UUID) -> HttpResponse:
    """Enhanced HTMX endpoint for detailed event view with correlation analysis."""
    
    event = get_object_or_404(AuditEvent, id=event_id)
    
    # Find related events for forensic analysis
    related_events: list[AuditEvent] = []
    
    # Same user, within 1 hour
    if event.user:
        time_window = timedelta(hours=1)
        related_by_user = AuditEvent.objects.filter(
            user=event.user,
            timestamp__gte=event.timestamp - time_window,
            timestamp__lte=event.timestamp + time_window
        ).exclude(id=event.id).order_by('timestamp')[:10]
        related_events.extend(related_by_user)
    
    # Same session
    if event.session_key:
        related_by_session = AuditEvent.objects.filter(
            session_key=event.session_key,
            timestamp__gte=event.timestamp - timedelta(minutes=30),
            timestamp__lte=event.timestamp + timedelta(minutes=30)
        ).exclude(id=event.id).order_by('timestamp')[:5]
        related_events.extend(related_by_session)
    
    # Same request ID
    if event.request_id:
        related_by_request = AuditEvent.objects.filter(
            request_id=event.request_id
        ).exclude(id=event.id).order_by('timestamp')
        related_events.extend(related_by_request)
    
    # Remove duplicates and limit
    seen_ids = set()
    unique_related = []
    for rel_event in related_events:
        if rel_event.id not in seen_ids:
            unique_related.append(rel_event)
            seen_ids.add(rel_event.id)
    
    related_events = unique_related[:15]  # Limit to 15 related events
    
    # Check if this event is part of any alerts
    related_alerts = AuditAlert.objects.filter(
        related_events=event
    ).order_by('-created_at')[:5]
    
    context = {
        'event': event,
        'related_events': related_events,
        'related_alerts': related_alerts,
        'event_metadata_json': json.dumps(event.metadata, indent=2) if event.metadata else None,
        'old_values_json': json.dumps(event.old_values, indent=2) if event.old_values else None,
        'new_values_json': json.dumps(event.new_values, indent=2) if event.new_values else None,
    }
    
    return render(request, 'audit/partials/event_detail.html', context)


# ===============================================================================
# LEGACY/ADMIN VIEWS
# ===============================================================================

# Legacy export endpoint - redirect to new GDPR system
@login_required
def export_data(request: HttpRequest) -> HttpResponse:
    """Legacy data export endpoint - redirect to GDPR dashboard"""
    messages.info(request, _('Data export has moved to the GDPR Privacy Dashboard.'))
    return redirect('audit:gdpr_dashboard')
