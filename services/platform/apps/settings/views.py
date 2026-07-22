"""
System Settings Views for PRAHO Platform

Provides API endpoints for settings access with proper authentication and caching.
Maintains Romanian business context and follows PRAHO security patterns.
"""

from __future__ import annotations

import json
import logging
from decimal import Decimal
from typing import TYPE_CHECKING, Any, ClassVar

from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import AnonymousUser
from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.decorators.http import require_http_methods
from django_q.models import OrmQ, Schedule, Task

from apps.audit.models import AuditEvent
from apps.common.decorators import admin_required
from apps.common.security_decorators import log_security_event
from apps.common.types import Ok

from .catalog import (
    CATALOG,
    CATALOG_BY_KEY,
    GROUPS_BY_SLUG,
    ZONE_BUSINESS,
    ZONE_INTEGRATIONS,
    ZONE_PLATFORM,
    SettingDef,
    defs_for_group,
    groups_in_zone,
)
from .models import SystemSetting
from .services import SettingsService

if TYPE_CHECKING:
    from django.http import HttpRequest

    from apps.users.models import User

logger = logging.getLogger(__name__)


def is_staff_user(user: User | AnonymousUser) -> bool:
    """Check if user is staff member (delegates to User.is_staff_user property)"""
    return user.is_authenticated and getattr(user, "is_staff_user", False)


# ===============================================================================
# STAFF SETTINGS API
# ===============================================================================


def _api_setting_payload(setting: SystemSetting) -> dict[str, Any]:
    """Serialize one setting for the staff API — sensitive values are never disclosed"""
    return {
        "value": None if setting.is_sensitive else setting.value,
        "configured": setting.value is not None,
        "is_sensitive": setting.is_sensitive,
        "data_type": setting.data_type,
        "description": setting.description,
        "is_required": setting.is_required,
        "requires_restart": setting.requires_restart,
    }


@method_decorator([login_required, user_passes_test(is_staff_user)], name="dispatch")
class SettingsAPIView(View):
    """
    ⚙️ Staff read-only API for system settings

    Writes go exclusively through the change-set endpoint and the admin-only
    credential endpoints — this API never mutates and never discloses
    sensitive values (not even ciphertext).
    """

    http_method_names: ClassVar[list[str]] = ["get"]

    def get(self, request: HttpRequest, key: str | None = None) -> JsonResponse:
        """
        🔍 Get setting value(s)

        GET /api/settings/ - Get all settings grouped by category
        GET /api/settings/billing.proforma_validity_days/ - Get specific setting
        """
        try:
            if key:
                setting = get_object_or_404(SystemSetting, key=key, is_active=True)
                payload = _api_setting_payload(setting)
                payload["key"] = setting.key
                payload["category"] = setting.category
                payload["updated_at"] = setting.updated_at.isoformat()
                return JsonResponse({"success": True, "setting": payload})

            # SystemSetting.category is a plain CharField — group by its value
            result: dict[str, Any] = {}
            for setting in SystemSetting.objects.filter(is_active=True).order_by("category", "key"):
                bucket = result.setdefault(
                    setting.category,
                    {"name": setting.category.replace("_", " ").title(), "settings": {}},
                )
                bucket["settings"][setting.key] = _api_setting_payload(setting)

            return JsonResponse({"success": True, "categories": result})

        except Http404:
            return JsonResponse({"success": False, "error": f'Setting "{key}" not found'}, status=404)
        except Exception as e:
            logger.error(f"💥 Error getting settings: {e}")
            return JsonResponse({"success": False, "error": "Failed to retrieve settings"}, status=500)


# ===============================================================================
# CACHE MANAGEMENT VIEWS
# ===============================================================================


@user_passes_test(is_staff_user)
@login_required
@require_http_methods(["POST"])
def refresh_cache(request: HttpRequest) -> JsonResponse:
    """
    🔄 Refresh settings cache

    POST /api/settings/cache/refresh/
    """
    try:
        SettingsService.clear_all_cache()

        # Log security event
        user_email = (
            request.user.email
            if hasattr(request.user, "email") and not isinstance(request.user, AnonymousUser)
            else "anonymous"
        )
        log_security_event(
            event_type="settings_cache_refresh",
            details={"initiated_by": user_email, "resource_type": "SettingsCache"},
            request_ip=request.META.get("REMOTE_ADDR"),
        )

        return JsonResponse({"success": True, "message": "Settings cache refreshed successfully"})

    except Exception as e:
        logger.error(f"💥 Error refreshing cache: {e}")
        return JsonResponse({"success": False, "error": "Failed to refresh cache"}, status=500)


# ===============================================================================
# HEALTH CHECK VIEW
# ===============================================================================


@require_http_methods(["GET"])
def settings_health_check(request: HttpRequest) -> JsonResponse:
    """
    🏥 Health check for settings system

    GET /api/settings/health/
    """
    try:
        # Test database access
        total_settings = SystemSetting.objects.count()
        active_settings = SystemSetting.objects.filter(is_active=True).count()

        # Test cache access
        cache_test_key = "settings_health_check"
        cache.set(cache_test_key, "ok", 60)
        cache_working = cache.get(cache_test_key) == "ok"
        cache.delete(cache_test_key)

        return JsonResponse(
            {
                "success": True,
                "status": "healthy",
                "checks": {
                    "database": {"status": "ok", "total_settings": total_settings, "active_settings": active_settings},
                    "cache": {"status": "ok" if cache_working else "error", "working": cache_working},
                },
            }
        )

    except Exception as e:
        logger.error(f"💥 Settings health check failed: {e}")
        # SECURITY: Don't expose internal error details
        return JsonResponse({"success": False, "status": "unhealthy", "error": "Health check failed"}, status=500)


# ===============================================================================
# EXPORT/IMPORT VIEWS (Future Enhancement)
# ===============================================================================


@require_http_methods(["GET"])
@login_required
def export_settings(request: HttpRequest) -> HttpResponse:
    """
    📥 Export non-sensitive settings as JSON (for backup/migration)

    GET /api/settings/export/
    """
    try:
        # Get only non-sensitive settings
        settings = SystemSetting.objects.filter(is_active=True, is_sensitive=False)
        sensitive_count = SystemSetting.objects.filter(is_active=True, is_sensitive=True).count()

        user_email = (
            request.user.email
            if hasattr(request.user, "email") and not isinstance(request.user, AnonymousUser)
            else "anonymous"
        )
        export_data: dict[str, Any] = {
            "export_info": {
                "exported_at": timezone.now().isoformat(),
                "exported_by": user_email,
                "total_settings": settings.count(),
                "export_type": "standard",
                "sensitive_settings_excluded": sensitive_count,
                "note": f"Sensitive settings excluded for security ({sensitive_count} settings hidden)",
            },
            "categories": {},
            "settings": [],
        }

        for setting in settings:
            category_key = setting.category if setting.category else "uncategorized"

            if category_key not in export_data["categories"]:
                group = GROUPS_BY_SLUG.get(category_key)
                export_data["categories"][category_key] = {
                    "name": str(group.label) if group else category_key.title(),
                    "description": str(group.description) if group else f"Settings for {category_key}",
                }

            export_data["settings"].append(
                {
                    "key": setting.key,
                    "category": category_key,
                    "name": setting.name,
                    "description": setting.description,
                    "value": setting.value,
                    "default_value": setting.default_value,
                    "data_type": setting.data_type,
                    "is_required": setting.is_required,
                    "requires_restart": setting.requires_restart,
                }
            )

        # Log export event
        log_security_event(
            event_type="settings_export",
            details={"settings_count": len(export_data["settings"]), "resource_type": "SystemSetting"},
            request_ip=request.META.get("REMOTE_ADDR"),
        )

        response = HttpResponse(json.dumps(export_data, indent=2, ensure_ascii=False), content_type="application/json")
        response["Content-Disposition"] = 'attachment; filename="praho_settings_export.json"'

        return response

    except Exception as e:
        logger.error(f"💥 Error exporting settings: {e}")
        return JsonResponse({"success": False, "error": "Failed to export settings"}, status=500)


@admin_required
def export_settings_full(request: HttpRequest) -> HttpResponse:
    """
    📥 Export ALL settings including sensitive ones (Admin-only)

    GET /api/settings/export/full/
    """
    try:
        # Get all settings including sensitive ones
        settings = SystemSetting.objects.filter(is_active=True)
        sensitive_count = settings.filter(is_sensitive=True).count()

        user_email = (
            request.user.email
            if hasattr(request.user, "email") and not isinstance(request.user, AnonymousUser)
            else "anonymous"
        )
        export_data: dict[str, Any] = {
            "export_info": {
                "exported_at": timezone.now().isoformat(),
                "exported_by": user_email,
                "total_settings": settings.count(),
                "export_type": "full",
                "sensitive_settings_included": sensitive_count,
                "security_warning": "This export contains sensitive encrypted data - handle with care",
            },
            "categories": {},
            "settings": [],
        }

        for setting in settings:
            category_key = setting.category if setting.category else "uncategorized"

            if category_key not in export_data["categories"]:
                group = GROUPS_BY_SLUG.get(category_key)
                export_data["categories"][category_key] = {
                    "name": str(group.label) if group else category_key.title(),
                    "description": str(group.description) if group else f"Settings for {category_key}",
                }

            export_data["settings"].append(
                {
                    "key": setting.key,
                    "category": category_key,
                    "name": setting.name,
                    "description": setting.description,
                    "value": setting.value,  # Includes encrypted sensitive values
                    "default_value": setting.default_value,
                    "data_type": setting.data_type,
                    "is_required": setting.is_required,
                    "is_sensitive": setting.is_sensitive,
                    "requires_restart": setting.requires_restart,
                }
            )

        # Log export event
        log_security_event(
            event_type="settings_export_full",
            details={
                "settings_count": len(export_data["settings"]),
                "sensitive_count": sensitive_count,
                "resource_type": "SystemSetting",
            },
            request_ip=request.META.get("REMOTE_ADDR"),
        )

        response = HttpResponse(json.dumps(export_data, indent=2, ensure_ascii=False), content_type="application/json")
        response["Content-Disposition"] = 'attachment; filename="praho_settings_full_export.json"'

        return response

    except Exception as e:
        logger.error(f"💥 Error exporting full settings: {e}")
        return JsonResponse({"success": False, "error": "Failed to export settings"}, status=500)


# ===============================================================================
# SETTINGS IMPORT
# ===============================================================================

MAX_IMPORT_SIZE = 1_048_576  # 1 MB


def _extract_import_payload(request: HttpRequest) -> tuple[bytes | None, str | None]:
    """Extract raw bytes from JSON body or multipart file upload. Returns (data, error)."""
    content_type = request.content_type or ""
    if "multipart/form-data" in content_type:
        uploaded = request.FILES.get("file")
        if not uploaded:
            return None, "No file uploaded"
        return uploaded.read(), None
    return request.body, None


def _build_import_updates(
    settings_list: list[dict[str, Any]],
    include_sensitive: bool,
    user_id: int | None,
) -> tuple[list[Any], list[dict[str, str]]]:
    """Validate setting entries and build SettingUpdate list. Returns (updates, skipped)."""
    from .services import SettingUpdate  # Circular: same-app  # noqa: PLC0415  # Deferred: avoids circular import

    updates: list[SettingUpdate] = []
    skipped: list[dict[str, str]] = []

    for entry in settings_list:
        key = entry.get("key")
        if not key or "value" not in entry:
            skipped.append({"key": key or "(missing)", "reason": "missing key or value"})
            continue

        key_known = key in SettingsService.DEFAULT_SETTINGS or SystemSetting.objects.filter(key=key).exists()
        if not key_known:
            skipped.append({"key": key, "reason": "unknown setting key"})
            continue

        if not include_sensitive and SystemSetting.objects.filter(key=key, is_sensitive=True).exists():
            skipped.append({"key": key, "reason": "sensitive (use ?include_sensitive=true)"})
            continue

        updates.append(SettingUpdate(key=key, value=entry["value"], user_id=user_id, reason="Settings import"))

    return updates, skipped


@admin_required
@require_http_methods(["POST"])
def import_settings(request: HttpRequest) -> JsonResponse:
    """
    📤 Import settings from JSON (backup restore / environment migration)

    POST /api/settings/import/

    Accepts JSON body or multipart file upload. Settings are validated
    against known keys. Sensitive settings are skipped unless
    ?include_sensitive=true is provided.
    """
    try:
        raw_data, extract_error = _extract_import_payload(request)
        if extract_error:
            return JsonResponse({"success": False, "error": extract_error}, status=400)
        assert raw_data is not None  # guaranteed when extract_error is None

        if len(raw_data) > MAX_IMPORT_SIZE:
            return JsonResponse(
                {"success": False, "error": f"Payload too large (max {MAX_IMPORT_SIZE // 1024}KB)"},
                status=400,
            )

        try:
            payload = json.loads(raw_data)
        except json.JSONDecodeError as exc:
            return JsonResponse({"success": False, "error": f"Invalid JSON: {exc}"}, status=400)

        settings_list = payload.get("settings")
        if not isinstance(settings_list, list):
            return JsonResponse(
                {"success": False, "error": "Payload must contain a 'settings' list"},
                status=400,
            )

        include_sensitive = request.GET.get("include_sensitive") == "true"
        user_id = (
            request.user.id if hasattr(request.user, "id") and not isinstance(request.user, AnonymousUser) else None
        )

        updates, skipped = _build_import_updates(settings_list, include_sensitive, user_id)

        imported_count = 0
        errors: list[dict[str, str]] = []
        if updates:
            result = SettingsService.bulk_update_settings(updates, user_id=user_id)
            if isinstance(result, Ok):
                imported_count = len(result.value)
            else:
                errors.extend({"key": err.key, "error": err.message} for err in result.error)

        log_security_event(
            event_type="settings_imported",
            details={
                "imported_count": imported_count,
                "skipped_count": len(skipped),
                "error_count": len(errors),
                "resource_type": "SystemSetting",
            },
            request_ip=request.META.get("REMOTE_ADDR"),
        )

        return JsonResponse(
            {
                "success": True,
                "imported": imported_count,
                "skipped": skipped,
                "errors": errors,
            }
        )

    except Exception as e:
        logger.error(f"💥 Error importing settings: {e}")
        return JsonResponse({"success": False, "error": "Failed to import settings"}, status=500)


# ===============================================================================
# SETTINGS UI (three-surface IA: Business / Integrations / Platform — ADR-0042)
# ===============================================================================

INTEGRATION_GROUPS = ("stripe", "virtualmin", "efactura", "node-deployment", "backup")

SEARCH_MIN_QUERY_LENGTH = 2
SEARCH_MAX_RESULTS = 30

# Integration pages annotate where their configuration really lives
INTEGRATION_SOURCE_NOTES: dict[str, Any] = {
    "virtualmin": _(
        "Server credentials are vault-managed per server (ADR-0033) and are not edited here — "
        "these settings tune connection and provisioning behavior."
    ),
    "efactura": _(
        "Values here are database settings with a deployment fallback: when a key has no row, "
        "the EFACTURA_* Django settings apply."
    ),
}


def _is_admin(user: Any) -> bool:
    return bool(getattr(user, "is_superuser", False) or getattr(user, "staff_role", "") == "admin")


def _requires_admin(definition: SettingDef) -> bool:
    """Business-zone settings are staff-editable; everything else needs admin"""
    return GROUPS_BY_SLUG[definition.group].zone != ZONE_BUSINESS


def _row_context(definition: SettingDef, row: SystemSetting | None) -> dict[str, Any]:
    """Template context for one setting row"""
    current = row.get_typed_value() if row is not None else definition.default
    if definition.data_type == "decimal" and current is not None:
        current = str(current)
    configured = bool(row is not None and row.value not in (None, ""))
    return {
        "definition": definition,
        "key": definition.key,
        "current": current,
        "current_json": json.dumps(current, ensure_ascii=False, default=str),
        "baseline": row.updated_at.isoformat() if row is not None else "",
        "modified": row is not None and row.get_typed_value() != definition.default,
        "configured": configured,
        "updated_at": row.updated_at if row is not None else None,
        "choices": (definition.validation or {}).get("choices", []),
    }


def _group_sections(slug: str) -> list[dict[str, Any]]:
    """Ordered sections with row contexts for one group"""
    definitions = defs_for_group(slug)
    rows = {row.key: row for row in SystemSetting.objects.filter(key__in=[d.key for d in definitions])}
    sections: dict[str, list[dict[str, Any]]] = {}
    for definition in definitions:
        sections.setdefault(str(definition.section), []).append(_row_context(definition, rows.get(definition.key)))
    # Explicit section order first (GroupDef.section_order), then any remainder alphabetically
    preferred = [str(title) for title in GROUPS_BY_SLUG[slug].section_order]
    ordered = [title for title in preferred if title in sections]
    ordered += sorted(title for title in sections if title not in ordered)
    return [{"title": title, "rows": sections[title]} for title in ordered]


def _sidebar_context(active_slug: str | None, user: Any) -> dict[str, Any]:
    show_admin = _is_admin(user)
    zones = []
    for zone, label in (
        (ZONE_BUSINESS, _("Business")),
        (ZONE_INTEGRATIONS, _("Integrations")),
        (ZONE_PLATFORM, _("Platform")),
    ):
        groups = [g for g in groups_in_zone(zone) if show_admin or zone == ZONE_BUSINESS]
        if groups:
            zones.append({"label": label, "groups": groups})
    return {"nav_zones": zones, "active_group": active_slug}


@login_required
@user_passes_test(is_staff_user)
def settings_home(request: HttpRequest) -> HttpResponse:
    """🏠 Settings overview: attention items, recent changes, modified count"""
    definitions = {d.key: d for d in CATALOG}
    rows = {row.key: row for row in SystemSetting.objects.filter(key__in=list(definitions))}

    modified_count = sum(
        1 for key, row in rows.items() if key in definitions and row.get_typed_value() != definitions[key].default
    )

    integration_state = []
    for slug in INTEGRATION_GROUPS:
        secret_defs = [d for d in defs_for_group(slug) if d.sensitive]
        configured = all(rows.get(d.key) is not None and rows[d.key].value not in (None, "") for d in secret_defs)
        integration_state.append(
            {
                "group": GROUPS_BY_SLUG[slug],
                "configured": configured if secret_defs else True,
            }
        )

    setting_ct = ContentType.objects.get_for_model(SystemSetting)
    recent_events = AuditEvent.objects.filter(content_type=setting_ct).select_related("user").order_by("-timestamp")[:8]

    context = {
        **_sidebar_context(None, request.user),
        "modified_count": modified_count,
        "integration_state": integration_state,
        "recent_events": recent_events,
        "maintenance_active": SettingsService.get_boolean_setting("system.maintenance_mode", False),
        "is_admin": _is_admin(request.user),
    }
    return render(request, "settings/home.html", context)


@login_required
@user_passes_test(is_staff_user)
def settings_group(request: HttpRequest, group_slug: str) -> HttpResponse:
    """📂 One settings group page (business, integration, platform, or advanced)"""
    group = GROUPS_BY_SLUG.get(group_slug)
    if group is None:
        raise Http404("Unknown settings group")
    if group.zone != ZONE_BUSINESS and not _is_admin(request.user):
        return HttpResponse(status=403)

    context = {
        **_sidebar_context(group_slug, request.user),
        "group": group,
        "sections": _group_sections(group_slug),
        "is_integration": group_slug in INTEGRATION_GROUPS,
        "source_note": INTEGRATION_SOURCE_NOTES.get(group_slug, ""),
        "is_advanced": group_slug == "advanced",
        "is_admin": _is_admin(request.user),
    }
    return render(request, "settings/group.html", context)


@login_required
@user_passes_test(is_staff_user)
@require_http_methods(["POST"])
def save_change_set(request: HttpRequest) -> JsonResponse:
    """💾 Apply a dirty-only change set atomically (JSON contract with rebaselining)"""
    try:
        payload = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": _("Invalid JSON body")}, status=400)

    changes = payload.get("changes") or {}
    baselines = payload.get("baselines") or {}
    reason = (payload.get("reason") or "").strip() or None
    if not isinstance(changes, dict) or not isinstance(baselines, dict):
        return JsonResponse({"success": False, "error": _("changes and baselines must be objects")}, status=400)

    # Zone gating: non-business keys need admin
    if not _is_admin(request.user):
        for key in changes:
            definition = CATALOG_BY_KEY.get(key)
            if definition is not None and _requires_admin(definition):
                return JsonResponse(
                    {"success": False, "errors": {key: str(_("Administrator role required for this setting"))}},
                    status=403,
                )

    result = SettingsService.apply_change_set(changes, baselines, user_id=request.user.id, reason=reason)
    if isinstance(result, Ok):
        outcome = result.value
        saved = {
            key: {"baseline": setting.updated_at.isoformat(), "value": setting.get_typed_value()}
            for key, setting in outcome.settings.items()
        }
        for entry in saved.values():
            if isinstance(entry["value"], Decimal):
                entry["value"] = str(entry["value"])
        return JsonResponse({"success": True, "change_set_id": outcome.change_set_id, "saved": saved})

    error = result.error
    if error.code == "conflict":
        return JsonResponse(
            {
                "success": False,
                "conflicts": [
                    {"key": conflict.key, "server_updated_at": conflict.server_updated_at}
                    for conflict in error.conflicts
                ],
            },
            status=409,
        )
    return JsonResponse(
        {
            "success": False,
            "errors": {e.key: e.message for e in error.errors} or {"__all__": str(_("Nothing to save"))},
        },
        status=400,
    )


@admin_required
@require_http_methods(["POST"])
def secret_set(request: HttpRequest, key: str) -> JsonResponse:
    """🔐 Set or replace a credential (write-only; empty submissions are rejected)"""
    definition = CATALOG_BY_KEY.get(key)
    if definition is None or not definition.sensitive:
        raise Http404("Unknown credential")
    try:
        payload = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": _("Invalid JSON body")}, status=400)

    value = payload.get("value") or ""
    if not value.strip():
        return JsonResponse({"success": False, "error": _("Credential value is required")}, status=400)
    reason = (payload.get("reason") or "").strip() or "Credential replaced"

    result = SettingsService.update_setting(key, value, user_id=request.user.id, reason=reason)
    if isinstance(result, Ok):
        return JsonResponse({"success": True, "configured": True})
    return JsonResponse({"success": False, "error": result.error.message}, status=400)


@admin_required
@require_http_methods(["POST"])
def secret_clear(request: HttpRequest, key: str) -> JsonResponse:
    """🗑️ Clear a credential (dangerous action; requires a reason)"""
    definition = CATALOG_BY_KEY.get(key)
    if definition is None or not definition.sensitive:
        raise Http404("Unknown credential")
    try:
        payload = json.loads(request.body)
    except json.JSONDecodeError:
        payload = {}
    reason = (payload.get("reason") or "").strip()
    if not reason:
        return JsonResponse({"success": False, "error": _("A reason is required to clear a credential")}, status=400)

    result = SettingsService.update_setting(key, "", user_id=request.user.id, reason=reason)
    if isinstance(result, Ok):
        return JsonResponse({"success": True, "configured": False})
    return JsonResponse({"success": False, "error": result.error.message}, status=400)


@admin_required
@require_http_methods(["POST"])
def integration_test(request: HttpRequest, integration: str) -> JsonResponse:
    """🔌 Test an integration's connectivity using its real gateway"""
    try:
        if integration == "stripe":
            from apps.billing.gateways.stripe_gateway import StripeGateway  # noqa: PLC0415  # ADR-0007

            ok = StripeGateway().validate_configuration()
            message = _("Stripe credentials verified") if ok else _("Stripe validation failed — check the secret key")
        elif integration == "virtualmin":
            from apps.provisioning.virtualmin_auth_manager import (  # noqa: PLC0415  # ADR-0007
                VirtualminAuthenticationManager,
            )
            from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415  # ADR-0007

            server = VirtualminServer.objects.filter(status="active").first() or VirtualminServer.objects.first()
            if server is None:
                ok = False
                message = _("No Virtualmin servers registered")
            else:
                health = VirtualminAuthenticationManager(server).health_check_all_methods()
                ok = any(getattr(result, "success", False) for result in health.values())
                message = (
                    _("Virtualmin authentication healthy") if ok else _("No Virtualmin authentication method succeeded")
                )
        elif integration == "efactura":
            from apps.billing.efactura.settings import efactura_settings  # noqa: PLC0415  # ADR-0007
            from apps.billing.efactura.token_storage import OAuthToken  # noqa: PLC0415  # ADR-0007

            cui = efactura_settings.company_cui
            token = OAuthToken.objects.get_valid_token(cui) if cui else None
            ok = token is not None
            message = _("Active ANAF OAuth token present") if ok else _("No valid ANAF OAuth token — authorize first")
        else:
            raise Http404("Unknown integration")
    except Http404:
        raise
    except Exception as e:
        logger.error("🔥 [Settings] Integration test failed for %s: %s", integration, e)
        return JsonResponse({"success": False, "message": str(_("Connection test failed — see logs"))})

    log_security_event(
        event_type="integration_connection_test",
        details={"integration": integration, "ok": ok, "resource_type": "SystemSetting"},
        request_ip=request.META.get("REMOTE_ADDR"),
    )
    return JsonResponse({"success": ok, "message": str(message)})


@login_required
@user_passes_test(is_staff_user)
def settings_search(request: HttpRequest) -> HttpResponse:
    """⌕ HTMX search across catalog keys, labels, and help text"""
    query = (request.GET.get("q") or "").strip().lower()
    results: list[dict[str, Any]] = []
    if len(query) >= SEARCH_MIN_QUERY_LENGTH:
        show_admin = _is_admin(request.user)
        scored: list[tuple[int, int, int, str, dict[str, Any]]] = []
        for definition in CATALOG:
            group = GROUPS_BY_SLUG[definition.group]
            if group.zone != ZONE_BUSINESS and not show_admin:
                continue
            label = str(definition.label).lower()
            if query in label:
                field_rank = 0
            elif query in definition.key:
                field_rank = 1
            elif query in str(definition.help_text).lower():
                field_rank = 2
            else:
                continue
            # Operator-policy results outrank tuning internals
            zone_rank = 0 if group.zone == ZONE_BUSINESS else 1
            scored.append(
                (
                    zone_rank,
                    int(definition.advanced),
                    field_rank,
                    definition.key,
                    {"definition": definition, "group": group},
                )
            )
        scored.sort(key=lambda item: item[:4])
        results = [entry for *_ranks, entry in scored[:SEARCH_MAX_RESULTS]]
    return render(request, "settings/partials/search_results.html", {"results": results, "query": query})


@login_required
@user_passes_test(is_staff_user)
def setting_history(request: HttpRequest, key: str) -> HttpResponse:
    """🕘 HTMX drawer: audit history for one setting key"""
    definition = CATALOG_BY_KEY.get(key)
    if definition is None:
        raise Http404("Unknown setting")
    setting_ct = ContentType.objects.get_for_model(SystemSetting)
    events = (
        AuditEvent.objects.filter(content_type=setting_ct, metadata__setting_key=key)
        .select_related("user")
        .order_by("-timestamp")[:10]
    )
    return render(request, "settings/partials/history_drawer.html", {"definition": definition, "events": events})


@login_required
@user_passes_test(is_staff_user)
def settings_automation(request: HttpRequest) -> HttpResponse:
    """⏱️ Django-Q2 schedules with their latest run outcome"""
    schedules = Schedule.objects.all().order_by("name")
    latest_by_func: dict[str, Task] = {}
    for task in Task.objects.order_by("-started")[:200]:
        latest_by_func.setdefault(task.func, task)
    entries = [{"schedule": schedule, "last_task": latest_by_func.get(schedule.func)} for schedule in schedules]
    context = {
        **_sidebar_context(None, request.user),
        "entries": entries,
        "queue_depth": OrmQ.objects.count(),
    }
    return render(request, "settings/automation.html", context)
