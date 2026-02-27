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
from django.core.cache import cache
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.cache import cache_page
from django.views.decorators.http import require_http_methods
from django.views.generic import TemplateView

from apps.common.decorators import admin_required
from apps.common.security_decorators import log_security_event
from apps.common.types import Ok

from .models import SettingCategory, SystemSetting
from .services import SettingsService

if TYPE_CHECKING:
    from django.http import HttpRequest

    from apps.users.models import User

logger = logging.getLogger(__name__)


def is_staff_user(user: User | AnonymousUser) -> bool:
    """Check if user is staff member"""
    return user.is_authenticated and hasattr(user, "is_staff") and user.is_staff


# ===============================================================================
# PUBLIC SETTINGS API (CACHED)
# ===============================================================================


@cache_page(60 * 15)  # Cache for 15 minutes
@require_http_methods(["GET"])
def public_settings_api(request: HttpRequest) -> JsonResponse:
    """
    🔓 Get public settings accessible to all users

    Returns settings marked as is_public=True for frontend use.
    Heavily cached to reduce database load.

    Example response:
    {
        "success": true,
        "settings": {
            "domains.registration_enabled": true,
            "users.session_timeout_minutes": 120
        }
    }
    """
    try:
        public_settings = SystemSetting.get_public_settings()

        settings_data = {setting.key: setting.value for setting in public_settings}

        return JsonResponse({"success": True, "settings": settings_data, "count": len(settings_data)})

    except Exception as e:
        logger.error(f"💥 Error getting public settings: {e}")
        return JsonResponse({"success": False, "error": "Failed to load public settings"}, status=500)


# ===============================================================================
# STAFF SETTINGS API
# ===============================================================================


@method_decorator([login_required, user_passes_test(is_staff_user)], name="dispatch")
class SettingsAPIView(View):
    """
    ⚙️ Staff API for system settings management

    Provides CRUD operations for system settings with proper authentication,
    validation, and audit logging.
    """

    http_method_names: ClassVar[list[str]] = ["get", "post", "put", "delete"]

    def get(self, request: HttpRequest, key: str | None = None) -> JsonResponse:
        """
        🔍 Get setting value(s)

        GET /api/settings/ - Get all settings
        GET /api/settings/billing.proforma_validity_days/ - Get specific setting
        """
        try:
            if key:
                # Get specific setting
                setting = get_object_or_404(SystemSetting, key=key, is_active=True)

                return JsonResponse(
                    {
                        "success": True,
                        "setting": {
                            "key": setting.key,
                            "value": setting.value,
                            "data_type": setting.data_type,
                            "description": setting.description,
                            "category": setting.category.name if setting.category else None,
                            "is_required": setting.is_required,
                            "requires_restart": setting.requires_restart,
                            "updated_at": setting.updated_at.isoformat(),
                        },
                    }
                )
            else:
                # Get all settings grouped by category
                categories = SettingCategory.objects.filter(is_active=True).prefetch_related("settings")

                result: dict[str, Any] = {}
                for category in categories:
                    result[category.key] = {"name": category.name, "description": category.description, "settings": {}}

                    for setting in category.settings.filter(is_active=True):
                        result[category.key]["settings"][setting.key] = {
                            "value": setting.value,
                            "data_type": setting.data_type,
                            "description": setting.description,
                            "is_required": setting.is_required,
                            "requires_restart": setting.requires_restart,
                        }

                return JsonResponse({"success": True, "categories": result})

        except Http404:
            return JsonResponse({"success": False, "error": f'Setting "{key}" not found'}, status=404)
        except Exception as e:
            logger.error(f"💥 Error getting settings: {e}")
            return JsonResponse({"success": False, "error": "Failed to retrieve settings"}, status=500)

    def post(self, request: HttpRequest) -> JsonResponse:
        """
        💾 Update setting value

        POST /api/settings/
        Body: {
            "key": "billing.proforma_validity_days",
            "value": 45,
            "reason": "Extended validity for Q4 promotion"
        }
        """
        try:
            data = json.loads(request.body)
            key = data.get("key")
            value = data.get("value")
            reason = data.get("reason", "")

            if not key:
                return JsonResponse({"success": False, "error": "Setting key is required"}, status=400)

            settings_service = SettingsService
            user_id = (
                request.user.id if hasattr(request.user, "id") and not isinstance(request.user, AnonymousUser) else None
            )
            result = settings_service.update_setting(key, value, user_id, reason)

            if isinstance(result, Ok):
                # Log security event
                log_security_event(
                    event_type="setting_updated",
                    details={
                        "key": key,
                        "new_value": value,
                        "reason": reason,
                        "resource_type": "SystemSetting",
                        "resource_id": key,
                        "user": user_id,
                    },
                    request_ip=request.META.get("REMOTE_ADDR"),
                )

                return JsonResponse({"success": True, "message": f'Setting "{key}" updated successfully'})
            else:
                return JsonResponse({"success": False, "error": result.error}, status=400)

        except json.JSONDecodeError:
            return JsonResponse({"success": False, "error": "Invalid JSON in request body"}, status=400)
        except Exception as e:
            logger.error(f"💥 Error updating setting: {e}")
            return JsonResponse({"success": False, "error": "Failed to update setting"}, status=500)


# ===============================================================================
# CATEGORY SETTINGS API
# ===============================================================================


@user_passes_test(is_staff_user)
@login_required
@login_required
@require_http_methods(["GET"])
def category_settings_api(request: HttpRequest, category_key: str) -> JsonResponse:
    """
    📦 Get all settings for a specific category

    GET /api/settings/category/billing/
    """
    try:
        category = get_object_or_404(SettingCategory, key=category_key, is_active=True)
        settings_data = SettingsService.get_settings_by_category(category_key)

        return JsonResponse(
            {
                "success": True,
                "category": {"key": category.key, "name": category.name, "description": category.description},
                "settings": settings_data,
                "count": len(settings_data),
            }
        )

    except Http404:
        return JsonResponse({"success": False, "error": f'Category "{category_key}" not found'}, status=404)
    except Exception as e:
        logger.error(f"💥 Error getting category settings: {e}")
        return JsonResponse({"success": False, "error": "Failed to retrieve category settings"}, status=500)


# ===============================================================================
# SETTINGS DASHBOARD VIEW
# ===============================================================================


@method_decorator([login_required, user_passes_test(is_staff_user)], name="dispatch")
class SettingsDashboardView(TemplateView):
    """
    📊 Staff dashboard for settings overview

    Provides a comprehensive interface for managing system configuration
    with visual indicators and quick access to common settings.
    """

    template_name = "settings/dashboard.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """🎯 Prepare dashboard context"""
        context = super().get_context_data(**kwargs)

        try:
            # Get settings service
            settings_service = SettingsService

            # Get categories
            categories = SettingCategory.objects.filter(is_active=True)

            context.update(
                {
                    "categories": categories,
                    "settings_service": settings_service,
                    "total_settings": SystemSetting.objects.filter(is_active=True).count(),
                    "public_settings_count": SystemSetting.objects.filter(is_active=True, is_public=True).count(),
                    "restart_required_count": SystemSetting.objects.filter(
                        is_active=True, requires_restart=True
                    ).count(),
                    # Quick access to common settings
                    "quick_settings": {
                        "proforma_validity": SettingsService.get_setting("billing.proforma_validity_days", 30),
                        "session_timeout": SettingsService.get_setting("users.session_timeout_minutes", 120),
                        "domain_registration": SettingsService.get_setting("domains.registration_enabled", True),
                        "mfa_required": SettingsService.get_setting("users.mfa_required_for_staff", True),
                    },
                }
            )

        except Exception as e:
            logger.error(f"💥 Error preparing dashboard context: {e}")
            context["error"] = "Failed to load settings dashboard"

        return context


# ===============================================================================
# SETTINGS MANAGEMENT VIEWS
# ===============================================================================


@method_decorator([login_required, user_passes_test(is_staff_user)], name="dispatch")
class SettingsManagementView(TemplateView):
    """
    🎛️ Staff settings management interface with multi-tab dynamic view

    Provides a comprehensive interface for managing system configuration
    with tab-based navigation, HTMX dynamic loading, and form controls.
    """

    template_name = "settings/manage.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """🎯 Prepare management context"""
        context = super().get_context_data(**kwargs)

        try:
            # Get all categories for tab navigation
            categories = SettingCategory.objects.filter(is_active=True).order_by("name")

            # Get default category (first one or from URL parameter)
            active_category = self.request.GET.get("category")
            if not active_category and categories:
                first_category = categories.first()
                active_category = first_category.key if first_category else None

            context.update(
                {
                    "categories": categories,
                    "active_category": active_category,
                    "settings_service": SettingsService,
                }
            )

        except Exception as e:
            logger.error(f"💥 Error preparing management context: {e}")
            context["error"] = "Failed to load settings management"

        return context


def _convert_setting_value(value: str, data_type: str) -> Any:
    """🔄 Convert POST value based on setting data type"""
    if data_type == "boolean":
        return value.lower() in ("true", "1", "on", "yes")
    elif data_type == "integer":
        return int(value)
    elif data_type == "decimal":
        return Decimal(value)
    return value


def _update_category_settings(request: HttpRequest, category_key: str) -> JsonResponse:
    """💾 Handle POST request to update category settings"""
    updated_count = 0
    errors = []

    for key, value in request.POST.items():
        if not key.startswith("setting_"):
            continue

        setting_key = key[8:]  # Remove 'setting_' prefix
        try:
            setting = SystemSetting.objects.get(key=setting_key, category=category_key)
            converted_value = _convert_setting_value(str(value), setting.data_type)
            SettingsService.set_setting(setting_key, converted_value)
            updated_count += 1
        except (SystemSetting.DoesNotExist, ValueError, TypeError):
            # SECURITY: Don't expose internal error details
            errors.append(f"Error updating {setting_key}")

    if errors:
        return JsonResponse({"success": False, "errors": errors}, status=400)
    return JsonResponse({"success": True, "updated": updated_count})


@login_required
@require_http_methods(["GET", "POST"])
def category_management_partial(request: HttpRequest, category_key: str) -> HttpResponse:
    """
    🔄 HTMX partial view for category-specific settings management

    Returns the HTML fragment for managing settings in a specific category.
    Supports both viewing and updating settings via HTMX.
    """

    try:
        # Get category
        try:
            category = SettingCategory.objects.get(key=category_key, is_active=True)
        except SettingCategory.DoesNotExist:
            return JsonResponse({"error": "Category not found"}, status=404)

        if request.method == "POST":
            return _update_category_settings(request, category_key)

        # GET request - return settings form
        settings = SystemSetting.objects.filter(category=category_key, is_active=True).order_by("name")

        context = {
            "category": category,
            "settings": settings,
        }

        return render(request, "settings/partials/category_form.html", context)

    except Exception as e:
        logger.error(f"💥 Error in category management partial: {e}")
        # SECURITY: Don't expose internal error details
        return JsonResponse({"error": "Internal error processing category settings"}, status=500)


# ===============================================================================
# CACHE MANAGEMENT VIEWS
# ===============================================================================


@user_passes_test(is_staff_user)
@login_required
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
                # Try to get the category object if it exists
                try:
                    category_obj = SettingCategory.objects.get(key=category_key)
                    export_data["categories"][category_key] = {
                        "name": category_obj.name,
                        "description": category_obj.description,
                    }
                except SettingCategory.DoesNotExist:
                    export_data["categories"][category_key] = {
                        "name": category_key.title(),
                        "description": f"Settings for {category_key}",
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
                    "validation_rules": setting.validation_rules,
                    "is_required": setting.is_required,
                    "is_public": setting.is_public,
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
                # Try to get the category object if it exists
                try:
                    category_obj = SettingCategory.objects.get(key=category_key)
                    export_data["categories"][category_key] = {
                        "name": category_obj.name,
                        "description": category_obj.description,
                    }
                except SettingCategory.DoesNotExist:
                    export_data["categories"][category_key] = {
                        "name": category_key.title(),
                        "description": f"Settings for {category_key}",
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
                    "validation_rules": setting.validation_rules,
                    "is_required": setting.is_required,
                    "is_public": setting.is_public,
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


def test_export(request: HttpRequest) -> HttpResponse:
    """Test view to debug URL routing issues"""
    return JsonResponse({"message": "Test view works", "user": str(request.user)})
