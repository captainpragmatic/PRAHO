/*
 * Audit fragment behaviours (#284), relocated out of HTMX-swapped partials so they
 * survive the enforcing nonce CSP (a swapped fragment's inline <script> carries the
 * fragment request's nonce, which never matches the document's — so it is blocked).
 *
 * Loaded once per audit full page. Pure DOM only — no Django template tags; the
 * localized results-count and the processing auto-refresh stay in the full-page
 * nonce'd script (they need {% trans %}/{% url %} and run once on load).
 */
(function () {
  "use strict";

  // Shared expand/collapse for a detail row: toggle #detailId, rotate the chevron,
  // and mark the enclosing .group expanded.
  function toggleDetail(button, detailId) {
    var detailDiv = document.getElementById(detailId);
    if (!detailDiv) {
      return;
    }
    var chevron = button.querySelector(".chevron-icon");
    var group = button.closest(".group");
    if (detailDiv.classList.contains("hidden")) {
      detailDiv.classList.remove("hidden");
      if (chevron) {
        chevron.style.transform = "rotate(180deg)";
      }
      if (group) {
        group.classList.add("expanded");
      }
    } else {
      detailDiv.classList.add("hidden");
      if (chevron) {
        chevron.style.transform = "rotate(0deg)";
      }
      if (group) {
        group.classList.remove("expanded");
      }
    }
  }

  // Invoke targets — global for the delegated `invoke` dispatcher in ui-actions.js.
  window.toggleEventDetailAction = function (el) {
    toggleDetail(el, "event-detail-" + el.dataset.eventId);
  };

  window.toggleExportDetailAction = function (el) {
    toggleDetail(el, "export-detail-" + el.dataset.requestId);
  };

  window.closeEventDetail = function (el) {
    var container = el.closest(".event-details");
    if (!container) {
      return;
    }
    container.classList.add("hidden");
    var chevron =
      container.parentElement &&
      container.parentElement.querySelector(".expand-btn .chevron-icon");
    if (chevron) {
      chevron.style.transform = "rotate(0deg)";
    }
    var group = container.closest(".group");
    if (group) {
      group.classList.remove("expanded");
    }
  };

  // Search suggestions: one delegated click listener replaces the per-swap
  // DOMContentLoaded binding (which never ran for swapped-in suggestion panels).
  document.addEventListener("click", function (event) {
    var item = event.target.closest(".suggestion-item");
    if (!item) {
      return;
    }
    var searchInput = document.querySelector('input[name="search"]');
    if (!searchInput) {
      return;
    }
    searchInput.value = item.getAttribute("data-value") || "";
    var panel = item.closest(".bg-white");
    if (panel) {
      panel.style.display = "none";
    }
    var form = searchInput.closest("form");
    if (form) {
      form.dispatchEvent(new Event("submit"));
    }
  });
})();
