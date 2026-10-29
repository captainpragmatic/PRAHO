"""
Portal Authentication Middleware
Production-ready two-tier validation with jitter, single-flight locks, and stale-while-revalidate.
Localisation policy is applied by apps.common.localisation_middleware.
"""

import logging
import math
import random
import threading
import uuid
from datetime import datetime, timedelta
from typing import Any, ClassVar, cast
from urllib.parse import quote, urlsplit

from django.conf import settings
from django.core.cache import cache
from django.db import Error as DatabaseError
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone as django_timezone
from django.utils.http import url_has_allowed_host_and_scheme, urlencode

from apps.api_client.services import (
    PlatformAPIError,
    api_client,
    platform_call_budget_seconds,
    platform_call_timeout_seconds,
)
from apps.common import counters, request_context
from apps.common.localisation_services import store_localisation_preferences
from apps.common.store_unavailable import end_session_or_unavailable, wants_json
from apps.users import customer_view_policy

logger = logging.getLogger(__name__)

# Circuit breaker: max consecutive fail-open validations before forced logout (#130/M1)
_MAX_FAIL_OPEN_COUNT = 5
_VALIDATION_LOCK = threading.Lock()


def _message_state(request: HttpRequest) -> tuple[list[Any], bool, bool] | None:
    """The message storage's queue and read state before the view runs."""
    storage = getattr(request, "_messages", None)
    if storage is None:
        return None
    return list(storage._queued_messages), storage.used, storage.added_new


def _restore_messages(request: HttpRequest, state: tuple[list[Any], bool, bool] | None) -> None:
    """Undo what a view that needs confirmation did to the messages.

    Its own messages are dropped, and the ones waiting before it stay unread: rendering a page
    marks every message read, even when that page is then thrown away for the confirm redirect.
    """
    storage = getattr(request, "_messages", None)
    if storage is not None and state is not None:
        storage._queued_messages, storage.used, storage.added_new = list(state[0]), state[1], state[2]


def _same_site_path(request: HttpRequest, url: str) -> str:
    """The path and query of a URL on this site, or "" for any other."""
    if not url or not url_has_allowed_host_and_scheme(
        url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return ""
    parts = urlsplit(url)
    if not parts.path.startswith("/"):
        return ""
    return parts.path + (f"?{parts.query}" if parts.query else "")


def _step_up_return_path(request: HttpRequest) -> str:
    """Where the browser goes back to after confirming: the page the action was made from."""
    if request.headers.get("HX-Request"):
        source = request.headers.get("HX-Current-URL", "")
    elif request.method == "GET" and not request_context.step_up_from_download():
        return request.get_full_path()
    else:
        # A form post or a download link: back to the page that holds them, never the action itself.
        source = request.META.get("HTTP_REFERER", "")
    return _same_site_path(request, source) or "/dashboard/"


class PortalAuthenticationMiddleware:
    """
    Production-ready authentication middleware with sophisticated caching patterns.

    Architecture:
    - Tier 1: Fast session check (zero latency)
    - Tier 2: Jittered periodic validation with single-flight locks
    - Stale-while-revalidate: Soft/hard TTL boundaries
    - Thundering herd protection: one in-flight validation per session at a time (per process)
    - Fail-open windows: Graceful degradation when Platform is unavailable
    """

    # Public URLs that don't require authentication
    PUBLIC_URLS: ClassVar[list[str]] = [
        "/login/",
        "/logout/",
        "/register/",
        "/password-reset/",
        "/static/",
        "/media/",
        "/status/",
        "/favicon.ico",
        "/robots.txt",
        "/cookie-policy/",
        "/legal/",  # Published legal releases, by id
        "/api/cookie-consent/",
    ]

    # Public leaf pages, matched exactly: a later route under them stays private.
    # The slash-less forms are listed too. This middleware answers before routing, and
    # CommonMiddleware adds the slash only for a 404, so they would otherwise get the login redirect.
    PUBLIC_EXACT_URLS: ClassVar[frozenset[str]] = frozenset(
        {
            # Customer view handoff (ADR-0065): arrives with no portal session; checked by exact Origin.
            "/customer-view/redeem/",
            "/terms/",
            "/terms",
            "/privacy-policy/",
            "/privacy-policy",
            "/cookie-policy",
            # The public forms' proof-of-work challenge (apps.common.altcha)
            "/altcha/challenge/",
            "/altcha/challenge",
            # The registration page's company register lookup
            "/company-lookup/",
            "/company-lookup",
        }
    )

    # Validation timing configuration
    REVALIDATE_EVERY = 600  # 10 minutes base interval
    JITTER_MAX = 120  # 0-2 minutes random jitter
    VALIDATION_LEASE_MARGIN_SECONDS = 5  # Single-flight lease: a whole Platform call, plus this
    SOFT_TTL_GRACE = 300  # 5 minutes soft grace period (stale-while-revalidate)
    HARD_TTL_GRACE = 21600  # 6 hours hard grace period (force logout after this)

    def __init__(self, get_response: Any) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # ADR-0017 section 5: bind the Platform session for the whole request, public routes
        # included, so every signed call made for this customer names it.
        with request_context.bound(request.session.get("portal_session_id"), request.session.get("user_id")):
            messages_before = _message_state(request)
            response = self._authenticate(request)
            if request_context.rejected():
                # Platform ended the session during the view; the view may have caught the error.
                logger.warning("🚨 [Auth] Platform ended the portal session during %s", request.path)
                return self._end_session(request)
            if request_context.step_up_required():
                # Platform wants the password again before this action (ADR-0017 section 6).
                _restore_messages(request, messages_before)
                return self._ask_to_confirm(request)
        if request.session.get("customer_view"):
            # A customer view's pages are never kept by the browser or a shared cache (ADR-0065).
            response["Cache-Control"] = "no-store"
        return response

    def _ask_to_confirm(self, request: HttpRequest) -> HttpResponse:
        """Send the browser to confirm its identity, and from there back to where the action began."""
        target = f"{reverse('users:confirm_identity')}?next={quote(_step_up_return_path(request), safe='')}"
        logger.info("🔐 [Auth] Platform asked for a fresh identity check during %s", request.path)
        if request.headers.get("HX-Request"):
            # A 302 would be followed by HTMX and swapped into the page; HX-Redirect navigates.
            response = HttpResponse(status=200)
            response["HX-Redirect"] = target
            return response
        if wants_json(request):
            return JsonResponse({"error": "reauth_required", "redirect": target}, status=403)
        return redirect(target)

    def _end_session(self, request: HttpRequest) -> HttpResponse:
        unavailable_response = end_session_or_unavailable(request)
        if unavailable_response is not None:
            return unavailable_response
        if wants_json(request):
            return JsonResponse({"error": "Session ended", "redirect": "/login/"}, status=401)
        return self.redirect_to_login(request)

    def _customer_view_refusal(self, request: HttpRequest) -> HttpResponse | None:
        if not request.session.get("customer_view"):
            return None
        if not settings.CUSTOMER_VIEW_ENABLED:
            return self._end_session(request)
        if customer_view_policy.allowed(request):
            return None
        logger.info("🔒 [CustomerView] Refused %s %s", request.method, customer_view_policy.route_name(request))
        return customer_view_policy.refused(request)

    def _authenticate(self, request: HttpRequest) -> HttpResponse:  # noqa: C901, PLR0911, PLR0912 -- one branch per session tier
        # Ensure CSRF cookie is available on responses (including redirects).
        get_token(request)

        # ADR-0065: a customer view reads only, public routes included (cookie consent is a write).
        if (refusal := self._customer_view_refusal(request)) is not None:
            return refusal

        # Skip authentication for public URLs
        if self.is_public_url(request.path):
            # Add an anonymous user for Django auth compatibility
            class AnonymousUser:
                id = None
                email = None
                is_authenticated = False
                is_active = False
                is_staff = False
                is_superuser = False

                def __str__(self) -> str:
                    return "AnonymousUser"

            request.user = AnonymousUser()  # type: ignore[assignment]
            return cast(HttpResponse, self.get_response(request))

        # Tier 1: Fast session check with age validation
        # Historically, 'customer_id' in session stored the platform user_id.
        # We normalize here: ensure we have a user_id and derive an active customer_id.
        session_user_id = request.session.get("user_id") or request.session.get("customer_id")
        if not session_user_id:
            logger.debug("🔒 [Auth] No customer_id in session, redirecting to login")
            return self.redirect_to_login(request)

        # A session from before Platform owned sessions names none: it ends once, at its next request.
        if getattr(settings, "PORTAL_SESSION_ID_REQUIRED", True) and not request.session.get("portal_session_id"):
            logger.info("🔒 [Auth] Session of user %s has no Platform session, ending it", session_user_id)
            return self._end_session(request)

        # Check if session has exceeded its intended lifetime
        if not self._is_session_age_valid(request):
            logger.warning(f"⏰ [Auth] Session for user {session_user_id} has exceeded lifetime, forcing logout")
            unavailable_response = end_session_or_unavailable(request)
            return unavailable_response if unavailable_response is not None else self.redirect_to_login(request)

        # Tier 2: Sophisticated validation with timing controls
        validation_result = self.validate_customer_with_timing(request, str(session_user_id))

        if not validation_result:
            logger.warning(f"⚠️ [Auth] User {session_user_id} validation failed, clearing session")
            unavailable_response = end_session_or_unavailable(request)
            return unavailable_response if unavailable_response is not None else self.redirect_to_login(request)

        # Attach customer data to request for views
        # Priority: selected_customer_id (company switcher) > active_customer_id > customer_id (fallback)
        selected_customer_id = request.session.get("selected_customer_id")
        active_customer_id = request.session.get("active_customer_id")

        try:
            user_id_int = int(session_user_id)
        except (TypeError, ValueError):
            user_id_int = None

        # If user has selected a specific customer via company switcher, use that
        if selected_customer_id:
            request.customer_id = int(selected_customer_id)  # type: ignore[attr-defined]
        elif active_customer_id:
            request.customer_id = active_customer_id  # type: ignore[attr-defined]
        # Fallback: resolve active customer context for this user (first accessible)
        elif user_id_int:
            try:
                with request_context.background():
                    customers = api_client.get_user_customers(user_id_int)
                if customers:
                    active_customer_id = customers[0].get("id")
                    request.session["active_customer_id"] = active_customer_id
                    request.customer_id = active_customer_id  # type: ignore[attr-defined]
                else:
                    # No accessible customers for this user; use legacy customer_id
                    request.customer_id = request.session.get("customer_id")  # type: ignore[attr-defined]
            except Exception as e:
                logger.error(f"🔥 [Auth] Failed to fetch accessible customers for user {session_user_id}: {e}")
                request.customer_id = request.session.get("customer_id")  # type: ignore[attr-defined]
        else:
            request.customer_id = request.session.get("customer_id")  # type: ignore[attr-defined]
        request.user_id = session_user_id  # type: ignore[attr-defined]
        request.customer_email = request.session.get("email")  # type: ignore[attr-defined]
        request.is_authenticated = True  # type: ignore[attr-defined]

        # Create a simple user-like object for Django auth compatibility
        class PortalUser:
            def __init__(self, user_id: str, email: str):
                self.id = user_id
                self.email = email
                self.is_authenticated = True
                self.is_active = True
                self.is_staff = False
                self.is_superuser = False

            def __str__(self) -> str:
                return self.email or f"customer_{self.id}"

        request.user = PortalUser(str(session_user_id), request.session.get("email", ""))  # type: ignore[assignment]

        return cast(HttpResponse, self.get_response(request))

    def is_public_url(self, path: str) -> bool:
        """Check if path requires authentication.

        PORTAL_EXTRA_PUBLIC_URLS lets a specific runtime (e.g. the CSP E2E
        settings) whitelist additional prefixes without adding test-only paths
        to the production PUBLIC_URLS list.
        """
        extra_public_urls = getattr(settings, "PORTAL_EXTRA_PUBLIC_URLS", ())
        # Resolve development-only prefixes per request; never mutate the shared class list.
        debug_public_urls = ("/__debug__/",) if settings.DEBUG and "debug_toolbar" in settings.INSTALLED_APPS else ()
        return path in self.PUBLIC_EXACT_URLS or any(
            path.startswith(public_url) for public_url in (*self.PUBLIC_URLS, *extra_public_urls, *debug_public_urls)
        )

    def redirect_to_login(self, request: HttpRequest) -> HttpResponse:
        """Redirect to login preserving the originally requested URL."""
        login_url = "/login/"
        if request.path and request.path != "/":
            # Add the current path as the next parameter
            params = urlencode({"next": request.get_full_path()})
            login_url = f"{login_url}?{params}"
        return redirect(login_url)

    def validate_customer_with_timing(self, request: HttpRequest, user_id: str) -> bool:
        """
        Sophisticated validation with jitter, single-flight locks, and stale-while-revalidate.

        Session validation fields:
        - validated_at: Last successful validation timestamp
        - next_validate_at: When next validation should occur (with jitter)
        - membership_hash: Hash of user's memberships for cache invalidation
        - session_created_at: When session was first created
        """
        now = django_timezone.now()

        # Get or initialize session validation metadata
        validated_at = self._get_session_datetime(request, "validated_at")
        next_validate_at = self._get_session_datetime(request, "next_validate_at")
        session_created_at = self._get_session_datetime(request, "session_created_at", now)

        # Validate immediately when metadata or the credential binding is missing.
        # A customer view holds no credential of the customer: its Platform session is its binding.
        bound = request.session.get("session_auth_hash") or request.session.get("customer_view")
        if not validated_at or not next_validate_at or not bound:
            # Fresh session - validate immediately but set next validation with jitter
            request.session["session_created_at"] = (session_created_at or now).isoformat()
            next_validate_at = self._calculate_next_validation_time(now)
            request.session["next_validate_at"] = next_validate_at.isoformat()
            return self._perform_validation(request, user_id, now)

        # Check if we're within soft TTL (no validation needed)
        if now <= next_validate_at:
            logger.debug(f"✅ [Auth] User {user_id} within soft TTL, skipping validation")
            return True

        # Check if we're within soft grace period (stale-while-revalidate)
        soft_deadline = next_validate_at + timedelta(seconds=self.SOFT_TTL_GRACE)
        if now <= soft_deadline:
            return self._validate_once_per_session(request, user_id, now)

        # Check if we're within hard grace period (force validation)
        hard_deadline = next_validate_at + timedelta(seconds=self.HARD_TTL_GRACE)
        if now <= hard_deadline:
            logger.info(f"⏰ [Auth] User {user_id} past soft TTL, forcing validation")
            return self._perform_validation(request, user_id, now)

        # Past hard deadline - force logout for security
        logger.warning(f"🚨 [Auth] User {user_id} past hard TTL deadline, forcing logout")
        return False

    def _get_session_datetime(self, request: HttpRequest, key: str, default: datetime | None = None) -> datetime | None:
        """Get datetime from session, handling ISO format conversion."""
        value = request.session.get(key)
        if value:
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass
        return default

    def _calculate_next_validation_time(self, now: datetime) -> datetime:
        """Calculate next validation time with jitter to prevent thundering herd."""
        jitter_seconds = random.randint(0, self.JITTER_MAX)  # noqa: S311
        return now + timedelta(seconds=self.REVALIDATE_EVERY + jitter_seconds)

    def _validate_once_per_session(self, request: HttpRequest, user_id: str, now: datetime) -> bool:
        """Revalidate inside the soft grace, coalescing concurrent requests of one session."""
        session_key = request.session.session_key
        if session_key is None:
            # Nothing stored yet, so there is no second request to coalesce with.
            return self._perform_validation(request, user_id, now)
        lease = self._should_revalidate_async(session_key)
        if lease is None:
            # Another request of this session is validating; keep serving the soft grace.
            return True
        lock_key, token = lease
        try:
            return self._perform_validation(request, user_id, now)
        finally:
            with _VALIDATION_LOCK:
                if cache.get(lock_key) == token:
                    cache.delete(lock_key)

    def _validation_lease_seconds(self) -> int:
        """Outlast a validation call, so a slow one does not let a second start beside it.

        Sized to the call's time budget plus one read wait. A call that overruns that (a peer
        trickling bytes) only lets a duplicate validation of the same session start.
        """
        longest_call = platform_call_budget_seconds() + platform_call_timeout_seconds()
        return math.ceil(longest_call) + self.VALIDATION_LEASE_MARGIN_SECONDS

    def _should_revalidate_async(self, session_key: str) -> tuple[str, str] | None:
        """Acquire a per-session validation lease within this process.

        The lease coalesces concurrent revalidations of one session; it is not a
        security guard, so a per-process cache is acceptable. LocMemCache has no
        compare-and-swap, so acquisition here and the ownership-checked release in
        the caller both run under _VALIDATION_LOCK.
        """
        lock_key = f"validating:{session_key}"
        token = uuid.uuid4().hex
        with _VALIDATION_LOCK:
            if not cache.add(lock_key, token, timeout=self._validation_lease_seconds()):
                return None
        return lock_key, token

    def _perform_validation(  # noqa: C901, PLR0911, PLR0912 -- session refresh and explicit error policies
        self, request: HttpRequest, user_id: str, now: datetime
    ) -> bool:
        """

        Perform actual Platform API validation and update session metadata.
        """
        try:
            # Call secure Platform API validation (HMAC-signed, no ID enumeration)
            with request_context.background():  # revalidation is not the customer's activity
                validation_response = api_client.validate_session_secure(
                    user_id, session_auth_hash=request.session.get("session_auth_hash")
                )
            is_valid = validation_response and validation_response.get("active", False)

            if is_valid:
                if "session_auth_hash" in validation_response:
                    request.session["session_auth_hash"] = validation_response["session_auth_hash"]

                if "localisation_preferences" in validation_response:
                    store_localisation_preferences(request, validation_response["localisation_preferences"])
                # Update session with successful validation
                request.session["validated_at"] = now.isoformat()
                request.session["next_validate_at"] = self._calculate_next_validation_time(now).isoformat()

                # Compare membership_hash — if it changed, clear cached memberships
                # so decorators force-refresh roles on next access check.
                new_hash = validation_response.get("membership_hash")
                old_hash = request.session.get("membership_hash")
                if new_hash:
                    if old_hash is None:
                        # First validation — just store the hash, don't invalidate
                        request.session["membership_hash"] = new_hash
                    elif new_hash != old_hash:
                        # Hash changed — memberships were modified, invalidate cache
                        request.session["membership_hash"] = new_hash
                        request.session.pop("user_memberships", None)
                        request.session.pop("user_memberships_fetched_at", None)
                        logger.info(
                            "🔄 [Auth] Membership hash changed for user %s, invalidated cached memberships",
                            user_id,
                        )

                request.session.modified = True

                logger.debug(f"✅ [Auth] User {user_id} validated successfully")
                # Reset fail-open circuit breaker on successful validation (#130/M1).
                # Cleanup carries no authorisation meaning, so a store error here is logged, not enforced.
                try:
                    counters.reset(f"auth:fail_open:{user_id}")
                except DatabaseError:
                    logger.warning("⚠️ [Auth] Could not reset the fail-open counter for user %s", user_id)
                return True
            else:
                logger.warning(f"❌ [Auth] User {user_id} validation failed - account disabled/deleted")
                return False

        except PlatformAPIError as e:
            # ADR-0017: only an explicit credential rejection bypasses the outage breaker.
            if (
                e.status_code in (401, 403)
                and isinstance(e.response_data, dict)
                and e.response_data.get("active") is False
            ):
                logger.warning("🚨 [Auth] Session rejected by Platform for user %s", user_id)
                return False
            if e.is_rate_limited:
                logger.warning("⚠️ [Auth] Platform rate limited validation for user %s: %s", user_id, e)
            elif e.status_code in (401, 403):
                logger.error("🔥 [Auth] Platform authentication fault during validation for user %s: %s", user_id, e)
            else:
                logger.error("🔥 [Auth] Platform API error during validation for user %s: %s", user_id, e)

            # Fail-open with circuit breaker (#130/M1): allow access during API outages
            # but force logout after too many consecutive fail-opens for same user.
            fail_open_key = f"auth:fail_open:{user_id}"
            try:
                fail_count = counters.increment(fail_open_key, 3600)
            except Exception:
                logger.exception("🔥 [Auth] Counter store unavailable; denying access for user %s", user_id)
                return False

            if fail_count >= _MAX_FAIL_OPEN_COUNT:
                logger.warning(
                    "🔥 [Auth] Circuit breaker tripped for user %s — %d consecutive fail-opens, forcing logout",
                    user_id,
                    fail_count,
                )
                return False

            logger.info(
                "🛡️ [Auth] Failing open for user %s (%d/%d) due to API unavailability",
                user_id,
                fail_count,
                _MAX_FAIL_OPEN_COUNT,
            )
            return True

        except Exception as e:
            logger.error(f"🔥 [Auth] Unexpected validation error for {user_id}: {e}")
            # Fail CLOSED for unexpected errors — ADR-0017: programming bugs must not grant access
            return False

    def _is_session_age_valid(self, request: HttpRequest) -> bool:
        """
        Validate that the session hasn't exceeded its intended lifetime based on 'remember_me' setting.

        Returns:
            bool: True if session is within its intended lifetime, False if expired
        """
        authenticated_at_str = request.session.get("authenticated_at")
        remember_me = request.session.get("remember_me", False)

        if not authenticated_at_str:
            # Backward compatibility: older sessions/tests may not have this field.
            # Initialize from known validation timestamps when possible, otherwise "now".
            fallback_timestamp = (
                request.session.get("validated_at")
                or request.session.get("session_created_at")
                or django_timezone.now().isoformat()
            )
            request.session["authenticated_at"] = fallback_timestamp
            request.session.modified = True
            authenticated_at_str = fallback_timestamp
            logger.warning("⚠️ [Auth] Missing authenticated_at; initialized fallback timestamp")

        try:
            authenticated_at = datetime.fromisoformat(authenticated_at_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError) as e:
            logger.error(f"🔥 [Auth] Invalid authenticated_at format in session: {e}")
            return False

        # Calculate intended session lifetime
        if remember_me:
            max_age_seconds = getattr(settings, "SESSION_COOKIE_AGE_REMEMBER_ME", 30 * 24 * 60 * 60)  # 30 days
            session_type = "extended (30 days)"
        else:
            max_age_seconds = getattr(settings, "SESSION_COOKIE_AGE_DEFAULT", 24 * 60 * 60)  # 24 hours
            session_type = "standard (24 hours)"

        # Check if session has exceeded its intended lifetime
        now = django_timezone.now()
        session_age = (now - authenticated_at).total_seconds()

        if session_age > max_age_seconds:
            customer_id = request.session.get("customer_id", "unknown")
            logger.warning(
                f"⏰ [Auth] {session_type} session for customer {customer_id} has exceeded lifetime "
                f"({session_age:.0f}s > {max_age_seconds:.0f}s)"
            )
            return False

        logger.debug(
            f"✅ [Auth] {session_type} session is within valid lifetime ({session_age:.0f}s / {max_age_seconds:.0f}s)"
        )
        return True
