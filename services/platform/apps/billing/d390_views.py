"""Billing-role monthly D390 preview and audited draft downloads."""

from __future__ import annotations

import hashlib

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.utils.translation import gettext as _
from django.views.decorators.http import require_http_methods

from apps.audit.services import AuditService
from apps.common.decorators import billing_staff_required

from .d390 import D390ExportError, Declarant, render_d390_xml, render_reconciliation_csv, validate_supplier
from .ec_sales_service import ReportingPeriod, aggregate_ec_services
from .efactura.xml_builder import get_supplier_info
from .forms import D390ExportForm, D390PeriodForm


@billing_staff_required
@require_http_methods(["GET", "POST"])
def d390_report(request: HttpRequest) -> HttpResponse:
    """Recompute the report on every export; the browser cannot authorize a partial XML."""
    data = request.POST if request.method == "POST" else request.GET
    period_form = D390PeriodForm(data if data else {"month": ReportingPeriod.previous().label})
    report = None
    export_form = D390ExportForm(request.POST or None)
    status = 200
    supplier_error = ""
    try:
        validate_supplier(get_supplier_info())
    except D390ExportError as exc:
        supplier_error = str(exc)
    if period_form.is_valid():
        report = aggregate_ec_services(period_form.cleaned_data["month"])
        if request.method == "GET":
            export_form = D390ExportForm(
                initial={"month": report.period.label, "source_fingerprint": report.source_fingerprint}
            )
        elif export_form.is_valid():
            action = export_form.cleaned_data["action"]
            try:
                if export_form.cleaned_data["source_fingerprint"] != report.source_fingerprint:
                    raise D390ExportError(_("The source invoices changed. Refresh the preview before exporting."))
                if action == "xml":
                    content = render_d390_xml(
                        report,
                        Declarant(
                            export_form.cleaned_data["surname"],
                            export_form.cleaned_data["given_name"],
                            export_form.cleaned_data["role"],
                        ),
                    )
                    content_type = "application/xml"
                else:
                    content = render_reconciliation_csv(report)
                    content_type = "text/csv; charset=utf-8"
                AuditService.log_simple_event(
                    "d390_export",
                    user=request.user,
                    description=f"D390 services-only draft {action.upper()} for {report.period.label}",
                    metadata={
                        "period": report.period.label,
                        "format": action,
                        "source_fingerprint": report.source_fingerprint,
                        "export_sha256": hashlib.sha256(content).hexdigest(),
                        "candidate_count": len(report.candidate_line_ids),
                        "exception_count": len(report.exceptions),
                        "draft": True,
                        "operation": "P",
                    },
                )
                response = HttpResponse(content, content_type=content_type)
                response["Content-Disposition"] = (
                    f'attachment; filename="d390-services-draft-{report.period.label}.{action}"'
                )
                response["Cache-Control"] = "private, no-store"
                return response
            except D390ExportError as exc:
                export_form.add_error(None, str(exc))
                status = 400
        else:
            status = 400
    else:
        status = 400
    response = render(
        request,
        "billing/d390_report.html",
        {
            "period_form": period_form,
            "export_form": export_form,
            "report": report,
            "supplier_error": supplier_error,
        },
        status=status,
    )
    response["Cache-Control"] = "private, no-store"
    return response
