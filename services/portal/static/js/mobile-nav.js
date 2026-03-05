// ===============================================================================
// MOBILE MENU FUNCTIONALITY 📱
// ===============================================================================
// Extracted from components/mobile_header.html (Phase A.4)
// Controls hamburger menu toggle, outside-click dismiss, Escape key, and
// HTMX navigation auto-close for the portal mobile header.
// ===============================================================================

// Wait for DOM to be ready before binding events
document.addEventListener('DOMContentLoaded', function () {
  console.log('📱 [Mobile Nav] Initializing mobile navigation');

  // Ensure mobile menu starts closed
  var menu = document.getElementById('mobile-menu');
  if (menu) {
    menu.classList.add('hidden');
  }

  // Initialize menu state
  document.body.classList.remove('mobile-menu-open');
});

/**
 * Toggle mobile navigation menu open/closed.
 * Called by the hamburger button's onclick handler in mobile_header.html.
 */
function toggleMobileMenu() {
  var menu = document.getElementById('mobile-menu');
  var hamburger = document.getElementById('hamburger-icon');
  var close = document.getElementById('close-icon');

  if (menu && hamburger && close) {
    if (menu.classList.contains('hidden')) {
      // Opening menu
      menu.classList.remove('hidden');
      menu.removeAttribute('inert');
      hamburger.classList.add('hidden');
      close.classList.remove('hidden');
      document.body.classList.add('mobile-menu-open');
      console.log('📱 [Mobile Nav] Menu opened');
    } else {
      // Closing menu
      menu.classList.add('hidden');
      menu.setAttribute('inert', '');
      hamburger.classList.remove('hidden');
      close.classList.add('hidden');
      document.body.classList.remove('mobile-menu-open');
      console.log('📱 [Mobile Nav] Menu closed');
    }
  } else {
    console.warn('⚠️ [Mobile Nav] Menu elements not found — layout may not be ready');
  }
}

// Close menu when clicking outside — use event delegation
document.addEventListener('click', function (event) {
  var menu = document.getElementById('mobile-menu');
  var toggle = document.getElementById('mobile-menu-toggle');

  if (
    menu &&
    toggle &&
    !menu.contains(event.target) &&
    !toggle.contains(event.target) &&
    !menu.classList.contains('hidden')
  ) {
    toggleMobileMenu();
  }
});

// Close menu on Escape key
document.addEventListener('keydown', function (event) {
  if (event.key === 'Escape') {
    var menu = document.getElementById('mobile-menu');
    if (menu && !menu.classList.contains('hidden')) {
      toggleMobileMenu();
    }
  }
});

// Close menu when HTMX navigates to a new page
document.addEventListener('htmx:beforeRequest', function () {
  var menu = document.getElementById('mobile-menu');
  if (menu && !menu.classList.contains('hidden')) {
    toggleMobileMenu();
  }
});
