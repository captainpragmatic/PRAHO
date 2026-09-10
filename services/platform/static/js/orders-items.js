/*
 * Order-items management (#284), relocated out of the order_items_list HTMX/fetch
 * partial so it survives the enforcing nonce CSP. The partial's inline <script> was
 * re-parsed on every fetch()+innerHTML reload (which never executes inserted scripts)
 * and re-registered its document listeners each time. Here the logic loads ONCE per
 * order page; per-request data (order id, i18n, icons) comes from window.PRAHO_ORDER_ITEMS,
 * emitted by a nonce'd config block on the full page. Behaviour (incl. the existing
 * URL shapes) is preserved verbatim.
 */
(function () {
  "use strict";

  function cfg() {
    return window.PRAHO_ORDER_ITEMS || { orderId: "", i18n: {}, icons: {} };
  }
  function t(key) {
    return (cfg().i18n && cfg().i18n[key]) || "";
  }
  function ic(key) {
    return (cfg().icons && cfg().icons[key]) || "";
  }
  function base() {
    return "/app/orders/" + cfg().orderId;
  }

  // Global state for tracking open edit forms
  var activeEditRowId = null;

  function toggleExpandableEdit(itemId) {
    var editRow = document.getElementById("edit-row-" + itemId);
    var editBtn = document.getElementById("edit-btn-" + itemId);
    var formContainer = document.getElementById("inline-edit-form-" + itemId);

    if (!editRow || !editBtn || !formContainer) {
      console.error("Required elements not found for item", itemId);
      return;
    }

    if (activeEditRowId && activeEditRowId !== itemId) {
      cancelExpandableEdit(activeEditRowId);
    }

    if (editRow.classList.contains("hidden")) {
      editRow.classList.remove("hidden");
      editBtn.innerHTML = '<span class="mr-1">' + ic("document") + "</span> " + t("editing");
      editBtn.disabled = true;
      activeEditRowId = itemId;

      fetch(base() + "/items/" + itemId + "/edit/", {
        method: "GET",
        headers: { "HX-Request": "true", "X-Requested-With": "XMLHttpRequest" },
      })
        .then(function (response) { return response.text(); })
        .then(function (html) {
          formContainer.innerHTML = html;
          var firstInput = formContainer.querySelector("input, select, textarea");
          if (firstInput) { firstInput.focus(); }
        })
        .catch(function (error) {
          console.error("Error loading edit form:", error);
          formContainer.innerHTML =
            '<div class="text-center text-red-400 py-4"><span class="mr-2">' +
            ic("x") + "</span>" + t("errLoadEdit") + "</div>";
          editBtn.innerHTML = '<span class="mr-1"></span> ' + t("edit");
          editBtn.disabled = false;
        });
    } else {
      cancelExpandableEdit(itemId);
    }
  }

  function cancelExpandableEdit(itemId) {
    var editRow = document.getElementById("edit-row-" + itemId);
    var editBtn = document.getElementById("edit-btn-" + itemId);
    if (editRow) { editRow.classList.add("hidden"); }
    if (editBtn) {
      editBtn.innerHTML = '<span class="mr-1"></span> ' + t("edit");
      editBtn.disabled = false;
    }
    if (activeEditRowId === itemId) { activeEditRowId = null; }
  }

  function addButtonEl() {
    return (
      document.getElementById("add-item-btn") ||
      document.querySelector('button[data-action="invoke"][data-invoke="toggleAddItemForm"]')
    );
  }

  function toggleAddItemForm() {
    var formSection =
      document.getElementById("add-item-form-section") ||
      document.getElementById("add-item-form-section-empty");
    var addButton = addButtonEl();
    var formContainer =
      document.getElementById("add-item-form-container") ||
      document.getElementById("add-item-form-container-empty");

    if (!formSection || !formContainer) {
      console.error("Add item form elements not found");
      return;
    }

    if (formSection.classList.contains("hidden")) {
      formSection.classList.remove("hidden");
      if (addButton) {
        addButton.innerHTML = '<span class="mr-1">' + ic("clock") + "</span> " + t("loading");
        addButton.disabled = true;
      }
      fetch(base() + "/items/add/", {
        method: "GET",
        headers: { "HX-Request": "true", "X-Requested-With": "XMLHttpRequest" },
      })
        .then(function (response) { return response.text(); })
        .then(function (html) {
          formContainer.innerHTML = html;
          var firstInput = formContainer.querySelector("input, select, textarea");
          if (firstInput) { firstInput.focus(); }
        })
        .catch(function (error) {
          console.error("Error loading add form:", error);
          formContainer.innerHTML =
            '<div class="text-center text-red-400 py-4"><span class="mr-2">' +
            ic("x") + "</span>" + t("errLoadAdd") + "</div>";
          if (addButton) {
            addButton.innerHTML = '<span class="mr-1"></span> ' + t("addItem");
            addButton.disabled = false;
          }
        });
    } else {
      cancelAddItemForm();
    }
  }

  function cancelAddItemForm() {
    var formSection =
      document.getElementById("add-item-form-section") ||
      document.getElementById("add-item-form-section-empty");
    var addButton = addButtonEl();
    if (formSection) { formSection.classList.add("hidden"); }
    if (addButton) {
      addButton.innerHTML = '<span class="mr-1"></span> ' + t("addItem");
      addButton.disabled = false;
    }
  }

  function deleteOrderItem(itemId) {
    if (!window.confirm(t("confirmDelete"))) { return; }

    var csrfEl = document.querySelector("[name=csrfmiddlewaretoken]");
    var metaEl = document.querySelector('meta[name="csrf-token"]');
    var csrfToken = (csrfEl && csrfEl.value) || (metaEl && metaEl.getAttribute("content"));
    if (!csrfToken) {
      console.error("CSRF token not found");
      window.alert(t("csrfError"));
      return;
    }

    fetch(base() + "/items/" + itemId + "/delete/", {
      method: "POST",
      headers: {
        "X-CSRFToken": csrfToken,
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded",
      },
    })
      .then(function (response) { return response.json(); })
      .then(function (data) {
        if (data.success) {
          var itemRow = document.getElementById("order-item-" + itemId);
          var editRow = document.getElementById("edit-row-" + itemId);
          if (itemRow) { itemRow.remove(); }
          if (editRow) { editRow.remove(); }
          updateOrderTotals();
          if (activeEditRowId === itemId) { activeEditRowId = null; }
          showNotification("success", t("itemDeleted"));
        } else {
          window.alert(t("errorPrefix") + " " + (data.error || t("unknownError")));
        }
      })
      .catch(function (error) {
        console.error("Error deleting item:", error);
        window.alert(t("errDelete"));
      });
  }

  function refreshOrderItemsSection() {
    var orderItemsSection = document.getElementById("order-items-section");
    if (!orderItemsSection) { return; }
    fetch(base() + "/items/", {
      method: "GET",
      headers: { "HX-Request": "true", "X-Requested-With": "XMLHttpRequest" },
    })
      .then(function (response) { return response.text(); })
      .then(function (html) {
        orderItemsSection.outerHTML = html;
        refreshFinancialSummary();
      })
      .catch(function (error) { console.error("Error refreshing order items:", error); });
  }

  function refreshOrderItemsSmart() {
    var tableBody = document.querySelector("#order-items-section tbody");
    if (!tableBody) { refreshOrderItemsSection(); return; }
    fetch(base() + "/items/", {
      method: "GET",
      headers: { "HX-Request": "true", "X-Requested-With": "XMLHttpRequest" },
    })
      .then(function (response) { return response.text(); })
      .then(function (html) {
        var doc = new DOMParser().parseFromString(html, "text/html");
        var newTableBody = doc.querySelector("#order-items-section tbody");
        if (newTableBody) {
          tableBody.innerHTML = newTableBody.innerHTML;
        } else {
          refreshOrderItemsSection();
        }
        updateOrderTotals();
      })
      .catch(function (error) {
        console.error("Error smart refreshing order items:", error);
        refreshOrderItemsSection();
      });
  }

  function updateOrderTotals() {
    fetch(base() + "/items/", {
      method: "GET",
      headers: { "HX-Request": "true", "X-Requested-With": "XMLHttpRequest" },
    })
      .then(function (response) { return response.text(); })
      .then(function (html) {
        var doc = new DOMParser().parseFromString(html, "text/html");
        ["order-subtotal", "order-tax", "order-total"].forEach(function (id) {
          var fresh = doc.getElementById(id);
          var current = document.getElementById(id);
          if (fresh && current) { current.textContent = fresh.textContent; }
        });
        refreshFinancialSummary();
      })
      .catch(function (error) { console.error("Error updating order totals:", error); });
  }

  function refreshFinancialSummary() {
    var financialSummary = document.getElementById("financial-summary");
    if (!financialSummary) { return; }
    fetch(base() + "/", {
      method: "GET",
      headers: {
        "HX-Request": "true",
        "HX-Target": "financial-summary",
        "X-Requested-With": "XMLHttpRequest",
      },
    })
      .then(function (response) { return response.text(); })
      .then(function (html) {
        var doc = new DOMParser().parseFromString(html, "text/html");
        var fresh = doc.getElementById("financial-summary");
        if (fresh && financialSummary) { financialSummary.outerHTML = fresh.outerHTML; }
      })
      .catch(function (error) { console.error("Error refreshing financial summary:", error); });
  }

  function showNotification(type, message) {
    if (type !== "success") { return; }
    var notification = document.createElement("div");
    notification.className =
      "fixed top-4 right-4 bg-green-600 text-white px-4 py-2 rounded-lg shadow-lg z-50 transition-opacity";
    notification.innerHTML = '<span class="mr-2">' + ic("check") + "</span>" + message;
    document.body.appendChild(notification);
    setTimeout(function () {
      notification.style.opacity = "0";
      setTimeout(function () { notification.remove(); }, 300);
    }, 3000);
  }

  // Form submissions from expandable rows — one delegated listener for the page.
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (
      form.action &&
      form.action.indexOf("/items/") !== -1 &&
      (form.action.indexOf("/add/") !== -1 || form.action.indexOf("/edit/") !== -1)
    ) {
      e.preventDefault();
      fetch(form.action, {
        method: "POST",
        body: new FormData(form),
        headers: { "HX-Request": "true", "X-Requested-With": "XMLHttpRequest" },
      })
        .then(function (response) { return response.text(); })
        .then(function (html) {
          if (html.indexOf("error") !== -1 || html.indexOf("<form") !== -1) {
            var formContainer = form.closest('[id*="form-container"]');
            if (formContainer) { formContainer.innerHTML = html; }
          } else {
            updateOrderTotals();
            cancelAddItemForm();
            if (activeEditRowId) { cancelExpandableEdit(activeEditRowId); }
            setTimeout(function () { refreshOrderItemsSmart(); }, 100);
            showNotification("success", t("itemSaved"));
          }
        })
        .catch(function (error) {
          console.error("Form submission error:", error);
          window.alert(t("errSubmit"));
        });
    }
  });

  // ESC closes any open form.
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      if (activeEditRowId) { cancelExpandableEdit(activeEditRowId); }
      cancelAddItemForm();
    }
  });

  // Invoke targets + the cross-fragment names order_item_form's adapters call.
  window.toggleExpandableEditAction = function (el) { toggleExpandableEdit(el.dataset.itemId); };
  window.cancelExpandableEditAction = function (el) { cancelExpandableEdit(el.dataset.itemId); };
  window.deleteOrderItemAction = function (el) { deleteOrderItem(el.dataset.itemId); };
  window.toggleAddItemForm = toggleAddItemForm;
  window.cancelAddItemForm = cancelAddItemForm;
  window.toggleExpandableEdit = toggleExpandableEdit;
  window.cancelExpandableEdit = cancelExpandableEdit;
  window.deleteOrderItem = deleteOrderItem;

  // Cancel adapters used by the fetch-inserted add/edit form (order_item_form.html),
  // whose own inline <script> never executes. Call the list handler if present, else
  // the modal fallback — preserving the original typeof-guarded behaviour.
  window.cancelAddItemOrModal = function () {
    if (typeof window.cancelAddItemForm === "function") { window.cancelAddItemForm(); }
    else if (typeof window.hideAddItemModal === "function") { window.hideAddItemModal(); }
  };
  window.cancelEditItemOrModal = function (el) {
    if (typeof window.cancelExpandableEdit === "function") {
      window.cancelExpandableEdit(el.dataset.itemId);
    } else if (typeof window.hideEditItemModal === "function") {
      window.hideEditItemModal();
    }
  };
})();
