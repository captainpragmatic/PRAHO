"""
Audit and GDPR compliance views for PRAHO Platform
Comprehensive data subject rights implementation with industry-standard UI/UX.
"""

import logging
from typing import Optional

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.files.storage import default_storage
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from .models import ComplianceLog, DataExport
from .services import (
    audit_service,
    gdpr_consent_service,
    gdpr_deletion_service,
    gdpr_export_service,
)

logger = logging.getLogger(__name__)


def _get_client_ip(request: HttpRequest) -> Optional[str]:
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
    # Get user's consent history
    consent_history = gdpr_consent_service.get_consent_history(request.user)

    # Get recent export requests
    recent_exports = DataExport.objects.filter(
        requested_by=request.user
    ).order_by('-requested_at')[:5]

    # Get recent deletion requests
    recent_deletions = ComplianceLog.objects.filter(
        compliance_type='gdpr_deletion',
        user=request.user
    ).order_by('-timestamp')[:5]

    # Calculate current consent status
    consent_status = {
        'data_processing': bool(request.user.gdpr_consent_date),
        'marketing': request.user.accepts_marketing,
        'last_updated': request.user.gdpr_consent_date.isoformat() if request.user.gdpr_consent_date else None
    }

    context = {
        'consent_history': consent_history,
        'recent_exports': recent_exports,
        'recent_deletions': recent_deletions,
        'consent_status': consent_status,
        'user': request.user
    }

    return render(request, 'audit/gdpr_dashboard.html', context)


@login_required
@require_POST
@csrf_protect
def request_data_export(request: HttpRequest) -> HttpResponse:
    """Create a new GDPR data export request"""
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
            user=request.user,
            request_ip=_get_client_ip(request),
            export_scope=export_scope
        )

        if result.is_ok():
            export_request = result.value
            messages.success(
                request,
                _('Your data export request has been created. You will receive an email when it is ready for download. Request ID: {}').format(
                    str(export_request.id)[:8]
                )
            )

            # Process export asynchronously (in a real app, use Celery)
            # For now, process immediately for demo
            processing_result = gdpr_export_service.process_data_export(export_request)
            if processing_result.is_ok():
                messages.success(request, _('Your data export is ready for download!'))
            else:
                messages.warning(request, _('Export is being processed. Please check back in a few minutes.'))

        else:
            messages.error(
                request,
                _('Failed to create data export request: {}').format(result.error)
            )

    except Exception as e:
        logger.error(f"🔥 [GDPR Export] Request creation failed for {request.user.email}: {e}")
        messages.error(request, _('An error occurred while creating your export request. Please try again.'))

    return redirect('audit:gdpr_dashboard')


@login_required
def download_data_export(request: HttpRequest, export_id: int) -> HttpResponse:
    """Download completed GDPR data export"""

    try:
        # Get export request (ensure it belongs to the user)
        export_request = get_object_or_404(
            DataExport,
            id=export_id,
            requested_by=request.user,
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
            description=f"GDPR export downloaded by {request.user.email}",
            user=request.user,
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
        response['Content-Disposition'] = f'attachment; filename="gdpr_export_{request.user.id}.json"'
        response['Content-Length'] = len(file_content)

        return response

    except Http404:
        # Re-raise 404 errors to get proper 404 response
        raise
    except Exception as e:
        logger.error(f"🔥 [GDPR Export] Download failed for {request.user.email}: {e}")
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
    try:
        deletion_type = request.POST.get('deletion_type', 'anonymize')
        reason = request.POST.get('reason', '').strip()

        if not reason:
            messages.error(request, _('Please provide a reason for your deletion request.'))
            return redirect('audit:gdpr_dashboard')

        # Create deletion request
        result = gdpr_deletion_service.create_deletion_request(
            user=request.user,
            deletion_type=deletion_type,
            request_ip=_get_client_ip(request),
            reason=reason
        )

        if result.is_ok():
            deletion_request = result.value
            messages.warning(
                request,
                _('Your data deletion request has been submitted. This action cannot be undone. Request ID: {}').format(
                    deletion_request.reference_id[:16]
                )
            )

            # For demo purposes, process immediately
            # In production, this would be handled by staff or automated process
            if request.POST.get('confirm_immediate') == 'yes':
                processing_result = gdpr_deletion_service.process_deletion_request(deletion_request)
                if processing_result.is_ok():
                    messages.success(request, _('Your account data has been processed according to your request.'))
                    # If full deletion, user would be logged out
                    if deletion_type == 'delete':
                        from django.contrib.auth import logout
                        logout(request)
                        return redirect('users:login')
                else:
                    messages.error(request, _('Processing failed: {}').format(processing_result.error))

        else:
            messages.error(
                request,
                _('Failed to create deletion request: {}').format(result.error)
            )

    except Exception as e:
        logger.error(f"🔥 [GDPR Deletion] Request creation failed for {request.user.email}: {e}")
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
    try:
        consent_types = request.POST.getlist('consent_types')

        if not consent_types:
            messages.error(request, _('Please select at least one consent type to withdraw.'))
            return redirect('audit:gdpr_dashboard')

        # Process consent withdrawal
        result = gdpr_consent_service.withdraw_consent(
            user=request.user,
            consent_types=consent_types,
            request_ip=_get_client_ip(request)
        )

        if result.is_ok():
            messages.success(
                request,
                _('Your consent has been withdrawn for: {}').format(result.value)
            )

            # If data processing consent withdrawn, warn about anonymization
            if 'data_processing' in consent_types:
                messages.warning(
                    request,
                    _('Data processing consent withdrawal will trigger account anonymization. This cannot be undone.')
                )
        else:
            messages.error(
                request,
                _('Failed to withdraw consent: {}').format(result.error)
            )

    except Exception as e:
        logger.error(f"🔥 [GDPR Consent] Withdrawal failed for {request.user.email}: {e}")
        messages.error(request, _('An error occurred while processing your consent withdrawal. Please try again.'))

    return redirect('audit:gdpr_dashboard')


@login_required
def consent_history(request: HttpRequest) -> HttpResponse:
    """Display detailed consent history"""
    history = gdpr_consent_service.get_consent_history(request.user)

    context = {
        'consent_history': history,
        'user': request.user
    }

    return render(request, 'audit/consent_history.html', context)


# ===============================================================================
# LEGACY/ADMIN VIEWS
# ===============================================================================

@login_required
def audit_log(request: HttpRequest) -> HttpResponse:
    """Display audit log for authorized users."""
    # TODO: Implement audit log view for staff
    return render(request, 'audit/log.html')


# Legacy export endpoint - redirect to new GDPR system
@login_required
def export_data(request: HttpRequest) -> HttpResponse:
    """Legacy data export endpoint - redirect to GDPR dashboard"""
    messages.info(request, _('Data export has moved to the GDPR Privacy Dashboard.'))
    return redirect('audit:gdpr_dashboard')
