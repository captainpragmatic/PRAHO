/*
 * Shared design-system delegated data-action registry (loaded by both services).
 *
 * Supported actions:
 *   back          — navigate to the previous page in browser history
 *   badge-dismiss — remove the badge containing the action element
 *   reload        — reload the current page
 *   invoke        — call the window global named in data-invoke, passing the element
 *   confirm-submit — gate a submit button's click: call the return-gating global in
 *                    data-invoke, else confirm(data-confirm); preventDefault cancels it
 *   close-modal    — close the modal named in data-modal-id via window.closeModal
 *   toggle-password (data-input-id) — toggle a password field's visibility
 *   clear-input     (data-input-id) — clear + refocus a field
 *   switch-tab      — list_page_filters tab click (click + a delegated keydown
 *                     listener for ArrowLeft/Right/Home/End roving focus)
 */
(function () {
  "use strict";

  // The guard test pins this allow-list to literal data-invoke template usage.
  var INVOKE_ALLOWLIST = Object.freeze({
    checkWebAuthnSupport: true,
    closeEventDetail: true,
    closeModal: true,
    confirmDisable: true,
    confirmRegenerate: true,
    exportCSV: true,
    resetFilters: true,
    showInvoiceRefundModal: true,
    showInvoiceRefundRequestModal: true,
    showOrderRefundRequestModal: true,
    showRefundModal: true,
  });

  document.addEventListener("click", function (event) {
    var el = event.target.closest("[data-action]");
    if (!el) {
      return;
    }

    switch (el.dataset.action) {
      case "back": {
        window.history.back();
        break;
      }
      case "badge-dismiss": {
        if (el.parentElement) {
          el.parentElement.remove();
        }
        break;
      }
      case "reload": {
        window.location.reload();
        break;
      }
      case "invoke": {
        var invokeName = el.dataset.invoke;
        if (
          !Object.prototype.hasOwnProperty.call(INVOKE_ALLOWLIST, invokeName) ||
          typeof window[invokeName] !== "function"
        ) {
          console.warn("Blocked invoke action:", invokeName);
          break;
        }
        window[invokeName](el);
        break;
      }
      case "confirm-submit": {
        var gateName = el.dataset.invoke;
        var proceed = true;
        if (gateName !== undefined) {
          if (
            !Object.prototype.hasOwnProperty.call(INVOKE_ALLOWLIST, gateName) ||
            typeof window[gateName] !== "function"
          ) {
            event.preventDefault();
            console.warn("Blocked confirm-submit gate:", gateName);
            break;
          }
          proceed = window[gateName](el) !== false;
        } else if (el.dataset.confirm) {
          proceed = window.confirm(el.dataset.confirm);
        }
        if (!proceed) {
          event.preventDefault();
        }
        break;
      }
      case "close-modal": {
        var modalId = el.dataset.modalId;
        if (modalId && typeof window.closeModal === "function") {
          window.closeModal(modalId);
        }
        break;
      }
      case "toggle-password": {
        var pwInput = document.getElementById(el.dataset.inputId);
        if (pwInput) {
          var pwType = pwInput.getAttribute("type") === "password" ? "text" : "password";
          pwInput.setAttribute("type", pwType);
        }
        break;
      }
      case "clear-input": {
        var clearInput = document.getElementById(el.dataset.inputId);
        if (clearInput) {
          clearInput.value = "";
          clearInput.focus();
        }
        break;
      }
      case "switch-tab": {
        switchTab(el);
        break;
      }
      default:
        break;
    }
  });

  document.addEventListener("keydown", function (event) {
    var tab = event.target.closest('[data-action="switch-tab"]');
    if (tab) {
      handleTabKeydown(event, tab);
    }
  });

  function switchTab(el) {
    var root = el.closest('.list-filters-sync');
    var borderClass = el.dataset.tabBorder;
    var textClass = el.dataset.tabText;
    var value = el.dataset.tabValue || '';
    var activeInput = root.querySelector('#list-filter-active-tab');
    if (activeInput) {
      activeInput.value = value;
    }
    /* Reset all sibling tabs */
    var tabs = root.querySelectorAll('.list-filter-tab');
    for (var i = 0; i < tabs.length; i++) {
      var t = tabs[i];
      t.setAttribute('aria-selected', 'false');
      t.setAttribute('tabindex', '-1');
      /* Remove any active border/text color classes, restore inactive.
         Guards: classList.remove('') throws for a tab without styling data. */
      if (t.dataset.tabBorder) { t.classList.remove(t.dataset.tabBorder); }
      if (t.dataset.tabText) { t.classList.remove(t.dataset.tabText); }
      t.classList.add('border-transparent', 'text-slate-400');
    }
    /* Activate clicked tab (both desktop and mobile instances share same data attrs) */
    var allMatching = root.querySelectorAll('.list-filter-tab[data-tab-value="' + CSS.escape(value) + '"]');
    for (var j = 0; j < allMatching.length; j++) {
      var m = allMatching[j];
      m.setAttribute('aria-selected', 'true');
      m.setAttribute('tabindex', '0');
      m.classList.remove('border-transparent', 'text-slate-400');
      if (borderClass) { m.classList.add(borderClass); }
      if (textClass) { m.classList.add(textClass); }
    }
    var panel = document.getElementById(el.getAttribute('aria-controls'));
    if (panel) {
      panel.setAttribute('aria-labelledby', el.id);
    }
  }

  function handleTabKeydown(event, el) {
    var key = event.key;
    var supportedKeys = ['ArrowLeft', 'ArrowRight', 'Home', 'End'];
    if (supportedKeys.indexOf(key) === -1) {
      return;
    }

    var tablist = el.closest('[role="tablist"]');
    var tabs = Array.prototype.slice.call(tablist.querySelectorAll('[role="tab"]'));
    var currentIndex = tabs.indexOf(el);
    var targetIndex;

    if (key === 'Home') {
      targetIndex = 0;
    } else if (key === 'End') {
      targetIndex = tabs.length - 1;
    } else if (key === 'ArrowLeft') {
      targetIndex = (currentIndex - 1 + tabs.length) % tabs.length;
    } else {
      targetIndex = (currentIndex + 1) % tabs.length;
    }

    event.preventDefault();
    var target = tabs[targetIndex];
    target.focus();
    target.click();
  }
})();
