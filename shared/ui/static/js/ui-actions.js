/*
 * Shared design-system delegated data-action registry (loaded by both services).
 *
 * Supported actions:
 *   back          — navigate to the previous page in browser history
 *   badge-dismiss — remove the badge containing the action element
 *   reload        — reload the current page
 *   invoke        — call the window global named in data-invoke, passing the element
 *   invoke-change — like invoke but bound to the CHANGE event (for <select> etc.);
 *                   a distinct action so a select's click never double-fires it
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

  // The guard test pins this allow-list to literal data-invoke template usage
  // (services/portal/tests/ui/test_registry_invoke_allowlist.py). Every data-invoke
  // name used in ANY template must appear here exactly once, and vice versa.
  var INVOKE_ALLOWLIST = Object.freeze({
    cancelAddItemForm: true,
    cancelAddItemOrModal: true,
    cancelEditItemOrModal: true,
    cancelExpandableEditAction: true,
    checkWebAuthnSupport: true,
    closeEventDetail: true,
    closeModal: true,
    confirmAccountDeleteAction: true,
    confirmDisable: true,
    confirmProtectionToggleAction: true,
    confirmReactivateAction: true,
    confirmRegenerate: true,
    confirmSuspendAction: true,
    copyAllCodes: true,
    copyCodeAction: true,
    copySecret: true,
    deleteOrderItemAction: true,
    dismissToastAction: true,
    downloadCodes: true,
    exportCSV: true,
    handleReplyActionChange: true,
    hideFailFormAction: true,
    hideInvoiceRefundModal: true,
    hideInvoiceRefundRequestModal: true,
    hideOrderRefundRequestModal: true,
    hideRefundModal: true,
    hideStatusModal: true,
    navigateToDocumentAction: true,
    printCodes: true,
    removeFileAction: true,
    resetFilters: true,
    sendProformaAction: true,
    showBackupCodeInput: true,
    showFailFormAction: true,
    showInvoiceRefundModal: true,
    showInvoiceRefundRequestModal: true,
    showOrderRefundRequestModal: true,
    showRefundModal: true,
    showTabAction: true,
    submitBackupCode: true,
    toggleAddItemForm: true,
    toggleEventDetailAction: true,
    toggleExpandableEditAction: true,
    toggleExportDetailAction: true,
    toggleMobileMenu: true,
    togglePreviewAction: true,
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

  document.addEventListener("change", function (event) {
    var el = event.target.closest('[data-action="invoke-change"]');
    if (!el) {
      return;
    }
    var changeName = el.dataset.invoke;
    if (
      !Object.prototype.hasOwnProperty.call(INVOKE_ALLOWLIST, changeName) ||
      typeof window[changeName] !== "function"
    ) {
      console.warn("Blocked invoke-change action:", changeName);
      return;
    }
    window[changeName](el);
  });

  document.addEventListener("keydown", function (event) {
    var tab = event.target.closest('[data-action="switch-tab"]');
    if (tab) {
      handleTabKeydown(event, tab);
    }
  });

  function switchTab(el) {
    var root = el.closest('.list-filters-sync');
    var value = el.dataset.tabValue || '';
    var activeInput = root.querySelector('#list-filter-active-tab');
    if (activeInput) {
      activeInput.value = value;
    }
    /* Reset all sibling tabs. Styling follows aria-selected via CSS (#368):
       accents are aria-selected:-variant utilities and hover affordance is
       not-aria-selected:-gated, so toggling the ARIA state IS the styling
       change — no classList juggling, which previously left activated tabs
       with inactive hover colors and deactivated tabs hover-dead. */
    var tabs = root.querySelectorAll('.list-filter-tab');
    for (var i = 0; i < tabs.length; i++) {
      var t = tabs[i];
      t.setAttribute('aria-selected', 'false');
      t.setAttribute('tabindex', '-1');
    }
    /* Activate clicked tab (both desktop and mobile instances share same value) */
    var allMatching = root.querySelectorAll('.list-filter-tab[data-tab-value="' + CSS.escape(value) + '"]');
    for (var j = 0; j < allMatching.length; j++) {
      var m = allMatching[j];
      m.setAttribute('aria-selected', 'true');
      m.setAttribute('tabindex', '0');
    }
    var panel = document.getElementById(el.getAttribute('aria-controls'));
    if (panel) {
      /* Reference BOTH tablists' instances of the active tab: the hidden
         breakpoint's tab is outside the accessibility tree, so a single id
         would leave the panel unlabelled on the other breakpoint. */
      var labelIds = [];
      for (var k = 0; k < allMatching.length; k++) {
        if (allMatching[k].id) { labelIds.push(allMatching[k].id); }
      }
      panel.setAttribute('aria-labelledby', labelIds.join(' ') || el.id);
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
