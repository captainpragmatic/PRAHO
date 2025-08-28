"""
Audit and GDPR compliance views for PRAHO Platform
Comprehensive data subject rights implementation with industry-standard UI/UX.
"""

import csv
import logging
import uuid
from io import StringIO
from typing import TYPE_CHECKING, cast

from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import get_user_model, logout  # For GDPR deletion logout
from django.contrib.auth.decorators import login_required
from django.contrib.contenttypes.models import ContentType
from django.core.files.storage import default_storage
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from apps.common.types import Err, Ok

from .models import AuditEvent, ComplianceLog, DataExport
from .services import (
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


def _get_client_ip(request: HttpRequest) -> str | None:
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


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

        # Create export request
        result = gdpr_export_service.create_data_export_request(
            user=user,
            request_ip=_get_client_ip(request),
            export_scope=export_scope
        )

        match result:
            case Ok(export_request):
                messages.success(
                    request,
                    _('Your data export request has been created. You will receive an email '
                      'when it is ready for download. Request ID: {}').format(
                        str(export_request.id)[:8]
                    )
                )

                # Process export asynchronously (in a real app, use Celery)
                # For now, process immediately for demo
                processing_result = gdpr_export_service.process_data_export(export_request)
                match processing_result:
                    case Ok(_):
                        messages.success(request, _('Your data export is ready for download!'))
                    case Err(_):
                        messages.warning(request, _('Export is being processed. Please check back in a few minutes.'))

            case Err(error_msg):
                messages.error(
                    request,
                    _('Failed to create data export request: {}').format(error_msg)
                )

    except Exception as e:
        logger.error(f"🔥 [GDPR Export] Request creation failed for {user.email}: {e}")
        messages.error(request, _('An error occurred while creating your export request. Please try again.'))

    return redirect('audit:gdpr_dashboard')


@login_required
def download_data_export(request: HttpRequest, export_id: int) -> HttpResponse:
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
def consent_history(request: HttpRequest) -> HttpResponse:
    """Display detailed consent history"""
    user = cast(User, request.user)  # Safe due to @login_required
    
    history = gdpr_consent_service.get_consent_history(user)

    context = {
        'consent_history': history,
        'user': user
    }

    return render(request, 'audit/consent_history.html', context)


# ===============================================================================
# AUDIT LOGS VIEWS (STAFF/ADMIN)
# ===============================================================================

@staff_member_required
def audit_log(request: HttpRequest) -> HttpResponse:
    """Main audit logs dashboard for staff/admin users."""
    
    context = {
        'action_choices': AuditEvent.ACTION_CHOICES,
        'content_types': ContentType.objects.all().order_by('app_label', 'model'),
        'users': User.objects.filter(is_active=True).order_by('email'),
    }
    return render(request, 'audit/logs.html', context)


@staff_member_required
def logs_list(request: HttpRequest) -> HttpResponse:
    """HTMX endpoint for filtered audit logs."""
    
    # Get query parameters
    user_id = request.GET.get('user')
    action = request.GET.get('action')
    content_type_id = request.GET.get('content_type')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    ip_address = request.GET.get('ip_address')
    search = request.GET.get('search')
    page = request.GET.get('page', 1)

    # Build query
    queryset = AuditEvent.objects.select_related('user', 'content_type')
    
    # Apply filters
    if user_id:
        queryset = queryset.filter(user_id=user_id)
    if action:
        queryset = queryset.filter(action=action)
    if content_type_id:
        try:
            queryset = queryset.filter(content_type_id=content_type_id)
        except ValueError:
            pass
    if start_date:
        queryset = queryset.filter(timestamp__gte=start_date)
    if end_date:
        queryset = queryset.filter(timestamp__lte=end_date)
    if ip_address:
        queryset = queryset.filter(ip_address__icontains=ip_address)
    if search:
        queryset = queryset.filter(
            Q(description__icontains=search) |
            Q(old_values__icontains=search) |
            Q(new_values__icontains=search) |
            Q(action__icontains=search)
        )

    # Order by most recent first
    queryset = queryset.order_by('-timestamp')

    # Pagination
    paginator = Paginator(queryset, 50)
    audit_events = paginator.get_page(page)

    context = {
        'audit_events': audit_events,
    }

    # Check if HTMX request
    if request.headers.get('HX-Request'):
        return render(request, 'audit/partials/logs_list.html', context)

    return render(request, 'audit/partials/logs_list.html', context)


@staff_member_required
def event_detail(request: HttpRequest, event_id: uuid.UUID) -> HttpResponse:
    """HTMX endpoint for detailed event view."""
    event = get_object_or_404(AuditEvent, id=event_id)
    return render(request, 'audit/partials/event_detail.html', {'event': event})


@staff_member_required
def export_logs_csv(request: HttpRequest) -> HttpResponse:
    """Export filtered audit logs as CSV."""

    # Get same filters as logs_list
    queryset = AuditEvent.objects.select_related('user', 'content_type')
    
    # Apply same filtering logic
    user_id = request.GET.get('user')
    action = request.GET.get('action')
    content_type_id = request.GET.get('content_type')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    ip_address = request.GET.get('ip_address')
    search = request.GET.get('search')

    if user_id:
        queryset = queryset.filter(user_id=user_id)
    if action:
        queryset = queryset.filter(action=action)
    if content_type_id:
        try:
            queryset = queryset.filter(content_type_id=content_type_id)
        except ValueError:
            pass
    if start_date:
        queryset = queryset.filter(timestamp__gte=start_date)
    if end_date:
        queryset = queryset.filter(timestamp__lte=end_date)
    if ip_address:
        queryset = queryset.filter(ip_address__icontains=ip_address)
    if search:
        queryset = queryset.filter(
            Q(description__icontains=search) |
            Q(old_values__icontains=search) |
            Q(new_values__icontains=search) |
            Q(action__icontains=search)
        )

    queryset = queryset.order_by('-timestamp')

    # Create CSV
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Timestamp',
        'User',
        'Action',
        'Content Type',
        'Object ID',
        'IP Address',
        'User Agent',
        'Description',
        'Old Values',
        'New Values',
    ])

    # Write data
    for event in queryset:
        writer.writerow([
            event.timestamp.isoformat(),
            event.user.email if event.user else 'System',
            event.get_action_display(),
            str(event.content_type) if event.content_type else '',
            event.object_id,
            event.ip_address or '',
            event.user_agent or '',
            event.description or '',
            str(event.old_values) if event.old_values else '',
            str(event.new_values) if event.new_values else '',
        ])

    # Create response
    response = HttpResponse(output.getvalue(), content_type='text/csv')
    timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
    response['Content-Disposition'] = f'attachment; filename="audit_logs_{timestamp}.csv"'
    return response


# ===============================================================================
# STAFF GDPR MANAGEMENT VIEWS  
# ===============================================================================

@staff_member_required
def gdpr_management_dashboard(request: HttpRequest) -> HttpResponse:
    """Staff-only GDPR management dashboard for processing all user requests"""
    
    # Log staff access for security audit
    logger.info(f"🔒 [Staff GDPR] Dashboard accessed by {request.user.email} from {_get_client_ip(request)}")
    
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


@staff_member_required 
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


@staff_member_required
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
                        user=request.user,
                        action='export',
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
                    user=request.user,
                    action='update',
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
                    user=request.user,
                    action='delete',
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


@staff_member_required
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


@staff_member_required
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
            user=request.user,
            action='access',
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
# LEGACY/ADMIN VIEWS
# ===============================================================================


# Legacy export endpoint - redirect to new GDPR system
@login_required
def export_data(request: HttpRequest) -> HttpResponse:
    """Legacy data export endpoint - redirect to GDPR dashboard"""
    messages.info(request, _('Data export has moved to the GDPR Privacy Dashboard.'))
    return redirect('audit:gdpr_dashboard')
