/*
 * Shared design-system delegated data-action registry (loaded by both services).
 *
 * Supported actions:
 *   back          — navigate to the previous page in browser history
 *   badge-dismiss — remove the badge containing the action element
 */
(function () {
  "use strict";

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
      default:
        break;
    }
  });
})();
