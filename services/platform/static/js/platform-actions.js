/*
 * Platform-only delegated data-action dispatcher (#284).
 *
 * Loaded ONLY by the platform base layout, alongside the shared ui-actions.js.
 * It owns action names the shared registry does NOT define, so both document-level
 * listeners run but each acts only on its own actions (unknown -> no-op). It is
 * deliberately separate from the portal's csp-actions.js: the portal already owns
 * navigate/copy with different data attributes + same-origin validation, and adding
 * those to the SHARED file would double-fire on the portal. This file is never loaded
 * by the portal.
 *
 * Actions:
 *   navigate         (data-href)                      — same-origin navigation
 *   navigate-select  (data-href-base, on <select> change) — same-origin nav to base + value
 *   copy             (data-copy)                      — clipboard write + brief affordance
 *   remove-self      (optional data-remove-closest)   — remove the element (or nearest match)
 *   show / hide      (data-target)                    — toggle `hidden` on #target
 *   stop             — no-op; claims the click so an ancestor navigate/etc. does not fire
 *   filter-tab       (data-select-name, data-select-value) — set a form select + fire change
 *   cookie-prefs     (data-fallback-message)          — open consent panel or alert fallback
 *   reset-form       (data-reset-target)              — reset a target form (or closest)
 */
(function () {
  "use strict";

  // Resolve a URL and refuse anything not same-origin before assigning location.
  function safeNavigate(href) {
    if (!href) {
      return;
    }
    var url;
    try {
      url = new URL(href, window.location.origin);
    } catch (e) {
      console.warn("Blocked malformed navigate:", href);
      return;
    }
    if (url.origin !== window.location.origin) {
      console.warn("Blocked cross-origin navigate:", href);
      return;
    }
    window.location.href = url.href;
  }

  document.addEventListener("click", function (event) {
    var el = event.target.closest("[data-action]");
    if (!el) {
      return;
    }

    switch (el.dataset.action) {
      case "navigate": {
        safeNavigate(el.dataset.href);
        break;
      }
      case "copy": {
        var text = el.dataset.copy;
        if (text && navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
          navigator.clipboard.writeText(text).then(function () {
            el.setAttribute("data-copied", "true");
            window.setTimeout(function () {
              el.removeAttribute("data-copied");
            }, 1200);
          }, function () {
            /* clipboard denied; leave the UI unchanged */
          });
        }
        break;
      }
      case "remove-self": {
        var selector = el.dataset.removeClosest;
        var target = selector ? el.closest(selector) : el;
        if (target) {
          target.remove();
        }
        break;
      }
      case "show": {
        var showEl = document.getElementById(el.dataset.target);
        if (showEl) {
          showEl.classList.remove("hidden");
        }
        break;
      }
      case "hide": {
        var hideEl = document.getElementById(el.dataset.target);
        if (hideEl) {
          hideEl.classList.add("hidden");
        }
        break;
      }
      case "confirm-dangerous": {
        // Open the shared dangerous-action modal. It listens on WINDOW
        // (@confirm-dangerous-action.window) and calls detail.action on confirm, so we
        // dispatch on window (the old inline handlers dispatched on document, which does
        // not reach a window listener) and build a TRUSTED callback from data attributes —
        // never eval a string. The action submits the named form (the only operation these
        // buttons performed).
        var formId = el.dataset.submitForm;
        window.dispatchEvent(
          new CustomEvent("confirm-dangerous-action", {
            detail: {
              title: el.dataset.title || "",
              message: el.dataset.message || "",
              confirmText: el.dataset.confirmText || "I really am sure I want to do this!",
              action: function () {
                var form = formId ? document.getElementById(formId) : null;
                if (form && typeof form.requestSubmit === "function") {
                  form.requestSubmit();
                } else if (form) {
                  form.submit();
                }
              },
            },
          })
        );
        break;
      }
      case "stop": {
        // No-op: exists so a wrapper element claims the click via closest(), keeping an
        // ancestor registry action (e.g. a row's navigate) from firing. It does NOT stop
        // ancestor Alpine/HTMX/native handlers — migrate propagation groups together.
        break;
      }
      case "filter-tab": {
        // Set a form-scoped <select> and fire its change event so an existing
        // hx-trigger="change from:select[name=...]" re-runs the server-side filter.
        var filterForm = el.closest("form");
        if (filterForm) {
          var filterSel = filterForm.querySelector(
            'select[name="' + el.dataset.selectName + '"]'
          );
          if (filterSel) {
            filterSel.value = el.dataset.selectValue || "";
            filterSel.dispatchEvent(new Event("change", { bubbles: true }));
          }
        }
        break;
      }
      case "cookie-prefs": {
        // Open the cookie-preferences panel if the consent script registered one,
        // else surface the fallback message (mirrors the portal's cookie-prefs).
        if (typeof window.showCookiePreferences === "function") {
          window.showCookiePreferences();
        } else if (el.dataset.fallbackMessage) {
          window.alert(el.dataset.fallbackMessage);
        }
        break;
      }
      case "reset-form": {
        // Reset the target form (selector in data-reset-target, else the closest form).
        // Contract mirrors the portal csp-actions.js reset-form.
        var resetTarget = el.dataset.resetTarget;
        var resetForm = resetTarget ? document.querySelector(resetTarget) : el.closest("form");
        if (resetForm && typeof resetForm.reset === "function") {
          resetForm.reset();
        }
        break;
      }
      default:
        break;
    }
  });

  // Submit-level, fail-CLOSED confirm gate for destructive NATIVE forms. Unlike an onclick
  // gate this covers keyboard submit and requestSubmit() (both fire the submit event), and
  // it cancels the submission when the user declines — replacing onsubmit="return confirm()".
  document.addEventListener("submit", function (event) {
    var form = event.target.closest("form[data-confirm]");
    if (form && !window.confirm(form.dataset.confirm)) {
      event.preventDefault();
    }
  });

  document.addEventListener("change", function (event) {
    var sel = event.target.closest('select[data-action="navigate-select"]');
    if (!sel) {
      return;
    }
    var base = sel.dataset.hrefBase || "";
    safeNavigate(base + encodeURIComponent(sel.value));
  });
})();
