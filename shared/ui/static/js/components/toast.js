// ===============================================================================
// PRAHO PORTAL — TOAST NOTIFICATION MODULE 🍞
// ===============================================================================
//
// Programmatic toast API for client-side triggered notifications.
// Server-rendered toasts (Django messages) use the Alpine.js {% toast %}
// component in base.html — this module handles JS-triggered toasts only.
//
// Usage:
//   showToast('success', 'Product added to cart!');
//   showToast('error', 'Something went wrong', { duration: 8000 });
//   showToast('warning', 'Session expiring soon');
//   showToast('info', 'Processing your request...');
//
// Options:
//   duration    — Auto-dismiss delay in ms (default: 5000, 0 = no auto-dismiss)
//   dismissible — Show close button (default: true)
//   maxVisible  — Max toasts visible at once (default: 3, oldest removed first)
//
// ===============================================================================

(function () {
  'use strict';

  // =========================================================================
  // CONFIGURATION ⚙️
  // =========================================================================

  var DEFAULTS = {
    duration: 5000,
    dismissible: true,
    maxVisible: 3,
  };

  // =========================================================================
  // VARIANT STYLING (matches toast.html component) 🎨
  // =========================================================================
  // O(1) lookup via object keys — no branching or iteration needed.

  var VARIANT_CLASSES = {
    success:
      'bg-green-50 border-green-200 text-green-800 dark:bg-green-950 dark:border-green-800 dark:text-green-200',
    error:
      'bg-red-50 border-red-200 text-red-800 dark:bg-red-950 dark:border-red-800 dark:text-red-200',
    warning:
      'bg-yellow-50 border-yellow-200 text-yellow-800 dark:bg-yellow-950 dark:border-yellow-800 dark:text-yellow-200',
    info:
      'bg-blue-50 border-blue-200 text-blue-800 dark:bg-blue-950 dark:border-blue-800 dark:text-blue-200',
  };

  var ICON_COLORS = {
    success: 'text-green-400 dark:text-green-300',
    error: 'text-red-400 dark:text-red-300',
    warning: 'text-yellow-400 dark:text-yellow-300',
    info: 'text-blue-400 dark:text-blue-300',
  };

  // Inline SVG paths for toast icons (Heroicons outline, 24x24 viewBox)
  var ICON_PATHS = {
    success:
      '<path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />',
    error:
      '<path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />',
    warning:
      '<path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />',
    info:
      '<path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" />',
  };

  // =========================================================================
  // CONTAINER MANAGEMENT 📦
  // =========================================================================

  /**
   * Get or create the toast container element.
   * Matches the container in base.html for consistent positioning.
   * @returns {HTMLElement}
   */
  function getOrCreateContainer() {
    var container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      container.className =
        'fixed top-4 lg:top-20 left-1/2 transform -translate-x-1/2 z-50 space-y-2';
      container.setAttribute('aria-live', 'assertive');
      document.body.appendChild(container);
    }
    return container;
  }

  // =========================================================================
  // HTML ESCAPING 🛡️
  // =========================================================================

  /**
   * Escape HTML entities to prevent XSS in dynamically created toasts.
   * @param {string} str - Raw text to escape
   * @returns {string} Escaped HTML-safe string
   */
  function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

  // =========================================================================
  // ICON BUILDER 🎯
  // =========================================================================

  function createIconSvg(variant) {
    var path = ICON_PATHS[variant] || ICON_PATHS.info;
    var colorClass = ICON_COLORS[variant] || ICON_COLORS.info;
    return (
      '<svg class="h-5 w-5 ' +
      colorClass +
      ' mr-2" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">' +
      path +
      '</svg>'
    );
  }

  // =========================================================================
  // OVERFLOW MANAGEMENT 📊
  // =========================================================================

  /**
   * Remove oldest toasts when exceeding maxVisible limit.
   * O(K) where K = number removed (typically 0 or 1).
   */
  function enforceMaxVisible(container, max) {
    while (container.children.length >= max) {
      var oldest = container.children[0];
      if (oldest) {
        oldest.remove();
      }
    }
  }

  // =========================================================================
  // PUBLIC API: showToast() 🍞
  // =========================================================================

  /**
   * Show a toast notification programmatically.
   *
   * @param {string} variant  - 'success' | 'error' | 'warning' | 'info'
   * @param {string} message  - Notification text (auto-escaped for XSS safety)
   * @param {Object} [options] - Optional overrides { duration, dismissible, maxVisible }
   */
  window.showToast = function (variant, message, options) {
    var opts = {};
    var key;
    for (key in DEFAULTS) {
      opts[key] = DEFAULTS[key];
    }
    if (options) {
      for (key in options) {
        opts[key] = options[key];
      }
    }

    var container = getOrCreateContainer();
    enforceMaxVisible(container, opts.maxVisible);

    var variantClass = VARIANT_CLASSES[variant] || VARIANT_CLASSES.info;
    var toast = document.createElement('div');
    toast.className =
      'max-w-sm rounded-lg p-4 shadow-lg border ' +
      variantClass +
      ' transform transition-all duration-300 opacity-0 -translate-y-4';
    toast.setAttribute('role', 'alert');

    var dismissBtn = opts.dismissible
      ? '<button onclick="this.closest(\'[role=alert]\').remove()"' +
      ' class="ml-4 inline-flex rounded-md p-1.5 opacity-60 hover:opacity-100"' +
      ' aria-label="Close notification">' +
      '<svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">' +
      '<path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />' +
      '</svg></button>'
      : '';

    // nosemgrep: insecure-document-method — message is escaped via escapeHtml() above
    toast.innerHTML =
      '<div class="flex items-center justify-between">' +
      '<div class="flex items-center">' +
      createIconSvg(variant) +
      '<span class="text-sm font-medium">' +
      escapeHtml(message) +
      '</span>' +
      '</div>' +
      dismissBtn +
      '</div>';

    container.appendChild(toast);

    // Animate in on next frame
    requestAnimationFrame(function () {
      toast.classList.remove('opacity-0', '-translate-y-4');
      toast.classList.add('opacity-100', 'translate-y-0');
    });

    // Auto-dismiss after duration
    if (opts.duration > 0) {
      setTimeout(function () {
        toast.classList.remove('opacity-100', 'translate-y-0');
        toast.classList.add('opacity-0', '-translate-y-4');
        setTimeout(function () {
          if (toast.parentNode) {
            toast.remove();
          }
        }, 300);
      }, opts.duration);
    }
  };
})();
