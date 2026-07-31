/*
 * Delegated data-action registry (#104 [M7], UNIT 2a).
 *
 * Replaces inline on*= handlers so the portal can drop script-src
 * 'unsafe-inline'. A single document-level listener dispatches on the
 * data-action attribute, so it survives HTMX fragment swaps (no per-element
 * re-binding) and needs no nonce (loaded as an external 'self' script).
 *
 * Supported actions:
 *   navigate  — go to data-href (whole-row click targets, HTMX-swapped tables)
 *   dismiss   — hide the element matched by data-dismiss-target (notifications)
 *   copy      — copy a literal value or an element's text to the clipboard
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
      default:
        break;
    }
  });
})();
