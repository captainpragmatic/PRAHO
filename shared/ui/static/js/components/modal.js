// ===============================================================================
// PRAHO PORTAL — MODAL MODULE 🔳
// ===============================================================================
//
// Centralized modal management. Include ONCE in base.html.
//
// API:
//   openModal(modalId)   — Show modal, trap focus, lock body scroll
//   closeModal(modalId)  — Hide modal, restore focus, unlock body scroll
//
// Features:
//   - Single Escape key listener (closes topmost visible modal)
//   - Focus trap (Tab/Shift+Tab cycle within modal)
//   - Focus restoration on close
//   - HTMX afterSwap auto-open integration
//   - Body scroll lock while modal is open
//
// ===============================================================================

(function () {
  'use strict';

  // =========================================================================
  // FOCUS RESTORATION REGISTRY 🎯
  // =========================================================================
  // O(1) lookup — tracks which element opened each modal for focus return.
  var _previousFocus = {};

  // =========================================================================
  // FOCUSABLE ELEMENT SELECTOR 🔍
  // =========================================================================
  var FOCUSABLE_SELECTOR =
    'button:not([disabled]), [href], input:not([type="hidden"]):not([disabled]),' +
    ' select:not([disabled]), textarea:not([disabled]),' +
    ' [tabindex]:not([tabindex="-1"])';

  // =========================================================================
  // OPEN MODAL 🚪
  // =========================================================================

  /**
   * Open a modal by its DOM id.
   * @param {string} modalId - The id attribute of the modal element
   */
  window.openModal = function (modalId) {
    var modal = document.getElementById(modalId);
    if (!modal) {
      console.warn('⚠️ [Modal] Element not found:', modalId);
      return;
    }

    // Save current focus for restoration on close
    _previousFocus[modalId] = document.activeElement;

    modal.style.display = 'block';
    document.body.style.overflow = 'hidden';

    // Focus first focusable element inside the modal
    requestAnimationFrame(function () {
      var focusable = modal.querySelector(FOCUSABLE_SELECTOR);
      if (focusable) {
        focusable.focus();
      }
    });
  };

  // =========================================================================
  // CLOSE MODAL 🚪
  // =========================================================================

  /**
   * Close a modal by its DOM id.
   * @param {string} modalId - The id attribute of the modal element
   */
  window.closeModal = function (modalId) {
    var modal = document.getElementById(modalId);
    if (!modal) return;

    modal.style.display = 'none';

    // Only restore body scroll if no other modals are open
    var stillOpen = document.querySelectorAll(
      '[role="dialog"][style*="display: block"]'
    );
    if (stillOpen.length === 0) {
      document.body.style.overflow = '';
    }

    // Restore previous focus
    if (_previousFocus[modalId]) {
      _previousFocus[modalId].focus();
      delete _previousFocus[modalId];
    }
  };

  // =========================================================================
  // ESCAPE KEY HANDLER (single global listener) ⌨️
  // =========================================================================
  // Closes the topmost visible modal only — prevents closing all at once.

  document.addEventListener('keydown', function (event) {
    if (event.key !== 'Escape') return;

    var visibleModals = document.querySelectorAll(
      '[role="dialog"][style*="display: block"]'
    );
    if (visibleModals.length === 0) return;

    // Close the last (topmost in DOM order) modal
    var topModal = visibleModals[visibleModals.length - 1];
    if (topModal.id) {
      closeModal(topModal.id);
    }
  });

  // =========================================================================
  // FOCUS TRAP 🔒
  // =========================================================================
  // Tab/Shift+Tab cycles within the topmost visible modal.

  document.addEventListener('keydown', function (event) {
    if (event.key !== 'Tab') return;

    var visibleModals = document.querySelectorAll(
      '[role="dialog"][style*="display: block"]'
    );
    if (visibleModals.length === 0) return;

    var topModal = visibleModals[visibleModals.length - 1];
    var focusableElements = topModal.querySelectorAll(FOCUSABLE_SELECTOR);
    if (focusableElements.length === 0) return;

    var firstFocusable = focusableElements[0];
    var lastFocusable = focusableElements[focusableElements.length - 1];

    if (event.shiftKey) {
      // Shift+Tab at first element → wrap to last
      if (document.activeElement === firstFocusable) {
        event.preventDefault();
        lastFocusable.focus();
      }
    } else {
      // Tab at last element → wrap to first
      if (document.activeElement === lastFocusable) {
        event.preventDefault();
        firstFocusable.focus();
      }
    }
  });

  // =========================================================================
  // HTMX INTEGRATION 🔄
  // =========================================================================

  // Auto-open modals when HTMX swaps content into a [role="dialog"] element
  document.addEventListener('htmx:afterSwap', function (evt) {
    if (evt.detail.target && evt.detail.target.matches('[role="dialog"]')) {
      openModal(evt.detail.target.id);
    }
  });

  // Close modal on successful form submission when marked with data attribute
  document.addEventListener('htmx:afterRequest', function (evt) {
    if (evt.detail.xhr.status >= 200 && evt.detail.xhr.status < 300) {
      var target = evt.detail.target;
      if (target && target.hasAttribute('data-close-modal-on-success')) {
        var modalId = target.getAttribute('data-close-modal-on-success');
        closeModal(modalId);
      }
    }
  });
})();
