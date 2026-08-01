/*
 * Delegated data-action registry (#104 [M7], UNIT 2a).
 *
 * Replaces inline on*= handlers so the portal can drop script-src
 * 'unsafe-inline'. A single document-level listener dispatches on the
 * data-action attribute, so it survives HTMX fragment swaps (no per-element
 * re-binding) and needs no nonce (loaded as an external 'self' script).
 * Plain form submissions with data-confirm are gated by a delegated submit
 * listener before the request is sent.
 *
 * Supported actions:
 *   navigate  — go to data-href (whole-row click targets, HTMX-swapped tables)
 *   dismiss   — hide the element matched by data-dismiss-target (notifications)
 *   copy      — copy a literal value or an element's text to the clipboard
 *   load-usage — load usage data for the period in data-period
 *   remove-file — remove the uploaded file at data-index
 *   submit-form — submit the enclosing form
 *   cookie-prefs — open the guarded global cookie-preferences dialog
 *   modal-open   — show the modal matched by data-modal-target
 *   modal-close  — hide the modal matched by data-modal-target
 *   print-codes — print MFA backup codes via the guarded global helper
 *   regenerate-codes — regenerate MFA backup codes via the guarded global helper
 *   reset-form — reset a form and optionally clear its character counter
 *   toggle-customer-selector — toggle the guarded global customer selector
 *   toggle-mobile-menu — toggle the guarded global mobile menu
 *   switch-customer — switch customer via the guarded global helper
 */
(function () {
  "use strict";

  document.addEventListener("click", function (event) {
    var el = event.target.closest("[data-action]");
    if (!el) {
      return;
    }

    switch (el.dataset.action) {
      case "navigate": {
        var href = el.dataset.href;
        if (href) {
          window.location.href = href;
        }
        break;
      }
      case "dismiss": {
        var target = el.dataset.dismissTarget;
        if (target) {
          var node = document.querySelector(target);
          if (node) {
            node.style.display = "none";
          }
        }
        break;
      }
      case "copy": {
        var value = el.dataset.copyValue;
        var copyTarget = el.dataset.copyTarget;
        if (value === undefined && copyTarget) {
          var copyNode = document.querySelector(copyTarget);
          if (copyNode) {
            value = copyNode.textContent.trim();
          }
        }
        if (value === undefined || !navigator.clipboard) {
          break;
        }

        navigator.clipboard.writeText(value).then(function () {
          var feedback = el.dataset.copyFeedback;
          if (feedback) {
            var originalHtml = el.innerHTML;
            el.textContent = feedback;
            setTimeout(function () {
              el.innerHTML = originalHtml;
            }, 2000);
          }
        }).catch(function (err) {
          console.error("Could not copy text: ", err);
        });
        break;
      }
      case "load-usage": {
        if (window.loadUsageData) {
          window.loadUsageData(el.dataset.period);
        }
        break;
      }
      case "remove-file": {
        if (window.removeFile) {
          window.removeFile(Number(el.dataset.index));
        }
        break;
      }
      case "submit-form": {
        var submitForm = el.closest("form");
        if (submitForm) {
          submitForm.submit();
        }
        break;
      }
      case "cookie-prefs": {
        if (window.showCookiePreferences) {
          window.showCookiePreferences();
        }
        break;
      }
      case "modal-open": {
        var openTarget = el.dataset.modalTarget;
        var openNode = openTarget && document.querySelector(openTarget);
        if (openNode) {
          openNode.classList.remove("hidden");
        }
        break;
      }
      case "modal-close": {
        var closeTarget = el.dataset.modalTarget;
        var closeNode = closeTarget && document.querySelector(closeTarget);
        if (closeNode) {
          closeNode.classList.add("hidden");
        }
        break;
      }
      case "print-codes": {
        if (window.printCodes) {
          window.printCodes();
        }
        break;
      }
      case "regenerate-codes": {
        if (window.regenerateCodes) {
          window.regenerateCodes();
        }
        break;
      }
      case "reset-form": {
        var resetTarget = el.dataset.resetTarget;
        var resetForm = resetTarget ? document.querySelector(resetTarget) : el.closest("form");
        if (resetForm) {
          resetForm.reset();
        }
        var counterTarget = el.dataset.counterTarget;
        var counterNode = counterTarget && document.querySelector(counterTarget);
        if (counterNode) {
          counterNode.textContent = "0";
        }
        break;
      }
      case "toggle-customer-selector": {
        if (window.toggleCustomerSelector) { window.toggleCustomerSelector(); }
        break;
      }
      case "toggle-mobile-menu": {
        if (window.toggleMobileMenu) { window.toggleMobileMenu(); }
        break;
      }
      default:
        break;
    }
  });

  document.addEventListener("submit", function (event) {
    var form = event.target.closest("form[data-confirm]");
    if (form && !window.confirm(form.dataset.confirm)) {
      event.preventDefault();
    }
  });

  document.addEventListener("change", function (event) {
    var el = event.target.closest('[data-action="switch-customer"]');
    if (el && window.switchCustomer) {
      window.switchCustomer(el.value);
    }
  });
})();
