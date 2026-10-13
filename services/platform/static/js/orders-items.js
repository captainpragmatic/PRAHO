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
  // The server emits the order URL; a hard-coded "/app/orders/" prefix made every item
  // request 404, since orders are served under /orders/.
  function base() {
    return (cfg().orderUrl || "").replace(/\/$/, "");
  }
  // The edit page's list keeps its item controls when it is refetched.
  function itemsUrl() {
    return base() + "/items/?mode=edit";
  }

  // Global state for tracking open edit forms
  var activeEditRowId = null;

  // ── Item form behaviour ───────────────────────────────────────────────────
  // The item form arrives by fetch()+innerHTML, which never runs the scripts it carries, so
  // its domain field, automatic prices and price preview live here. The add form and an open
  // edit row share element ids, so everything works on the form the event came from.

  function itemForm(el) {
    return el && el.closest ? el.closest("form[data-order-item-form]") : null;
  }
  function field(form, name) {
    return form.querySelector('[name="' + name + '"]');
  }
  function integerValue(input, fallback) {
    var n = parseInt((input && input.value) || "", 10);
    return isNaN(n) ? fallback : n;
  }
  function selectedProduct(form) {
    var select = field(form, "product");
    return select && select.selectedIndex >= 0 ? select.options[select.selectedIndex] : null;
  }

  function updatePricePreview(form) {
    var currency = form.dataset.currency || "";
    var unit = integerValue(field(form, "unit_price_cents"), 0);
    var setup = integerValue(field(form, "setup_cents"), 0);
    var quantity = integerValue(field(form, "quantity"), 1);
    // As OrderItem computes it: the setup fee is charged once, not per unit.
    var amounts = { unit: unit, setup: setup, total: unit * quantity + setup };
    Object.keys(amounts).forEach(function (key) {
      var el = form.querySelector('[data-preview="' + key + '"]');
      if (el) { el.textContent = currency + " " + (amounts[key] / 100).toFixed(2); }
    });
  }

  function toggleDomainSection(form) {
    var section = form.querySelector("[data-domain-section]");
    if (!section) { return; }
    var option = selectedProduct(form);
    var required = !!option && option.dataset.requiresDomain === "true";
    section.classList.toggle("hidden", !required);
    var domain = field(form, "domain_name");
    if (domain) { domain.required = required; }
  }

  function autoPopulatePricing(form) {
    var option = selectedProduct(form);
    var period = field(form, "billing_period");
    var unit = field(form, "unit_price_cents");
    var setup = field(form, "setup_cents");
    if (!option || !option.value || !period || !period.value || !unit || !setup) { return; }
    var prices;
    try { prices = JSON.parse(option.dataset.prices || "{}"); } catch (e) { return; }
    var price = prices[period.value];
    // A price someone typed is kept; otherwise the catalog price for the period, or nothing
    // when the product has none, so a stale automatic price is never submitted as an override.
    if (!unit.dataset.manualOverride) { unit.value = price ? price.unit_cents : ""; }
    if (!setup.dataset.manualOverride) {
      setup.value = price ? price.setup_cents : (option.dataset.setupCents || "0");
    }
    updatePricePreview(form);
  }

  // A form fetch answered with a redirect or an error page must not be shown as the form.
  var REDIRECTED = new Error("redirected");
  function formHtml(response) {
    var redirectTo = response.headers.get("HX-Redirect");
    if (redirectTo) {
      window.location.assign(redirectTo);
      throw REDIRECTED;
    }
    if (!response.ok) { throw new Error("HTTP " + response.status); }
    return response.text();
  }

  function initItemForm(container) {
    var form = container && container.querySelector("form[data-order-item-form]");
    if (!form) { return; }
    // Only the domain field and the preview: an item being edited keeps the prices it has.
    toggleDomainSection(form);
    updatePricePreview(form);
  }

  function showFormError(form, message) {
    var box = form.querySelector("[data-form-error]");
    if (!box) {
      box = document.createElement("p");
      box.setAttribute("data-form-error", "");
      box.setAttribute("role", "alert");
      box.className = "text-sm text-red-400";
      form.insertBefore(box, form.firstChild);
    }
    box.textContent = message;
  }

  document.addEventListener("change", function (e) {
    var form = itemForm(e.target);
    if (!form) { return; }
    if (e.target.name === "product") {
      toggleDomainSection(form);
      autoPopulatePricing(form);
    } else if (e.target.name === "billing_period") {
      autoPopulatePricing(form);
    }
  });

  document.addEventListener("input", function (e) {
    var form = itemForm(e.target);
    if (!form) { return; }
    var name = e.target.name;
    if (name === "unit_price_cents" || name === "setup_cents") {
      e.target.dataset.manualOverride = "true";
      updatePricePreview(form);
    } else if (name === "quantity") {
      updatePricePreview(form);
    }
  });

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
        .then(formHtml)
        .then(function (html) {
          formContainer.innerHTML = html;
          initItemForm(formContainer);
          var firstInput = formContainer.querySelector("input, select, textarea");
          if (firstInput) { firstInput.focus(); }
        })
        .catch(function (error) {
          if (error === REDIRECTED) { return; }
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
        .then(formHtml)
        .then(function (html) {
          formContainer.innerHTML = html;
          initItemForm(formContainer);
          var firstInput = formContainer.querySelector("input, select, textarea");
          if (firstInput) { firstInput.focus(); }
        })
        .catch(function (error) {
          if (error === REDIRECTED) { return; }
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
          window.alert(t("errorPrefix") + " " + (data.message || t("unknownError")));
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
    fetch(itemsUrl(), {
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
    fetch(itemsUrl(), {
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
        .then(function (response) {
          var isJson = (response.headers.get("Content-Type") || "").indexOf("application/json") !== -1;
          var redirectTo = response.headers.get("HX-Redirect");
          return response.text().then(function (body) {
            return { ok: response.ok, isJson: isJson, redirectTo: redirectTo, body: body };
          });
        })
        .then(function (result) {
          var html = result.body;
          if (result.redirectTo) {
            // The server sends the whole page elsewhere (sign-in, or 2FA setup the staff policy requires).
            window.location.assign(result.redirectTo);
          } else if (result.isJson) {
            // A refusal (validation, price override) answers JSON; keep the form and say why.
            var data = {};
            try { data = JSON.parse(html); } catch (err) { data = {}; }
            showFormError(form, data.message || t("unknownError"));
          } else if (!result.ok || html.indexOf('id="order-items-section"') === -1) {
            // An error page, a sign-in page or anything else that is not the items list.
            showFormError(form, t("errSubmit"));
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

  // Cancel adapters for the standalone add/edit modal (order_item_form.html), which the
  // order-item view returns for a non-HX-Request navigation. (The in-page fetch flow here
  // sets HX-Request and gets order_item_inline_form.html instead, whose buttons call
  // cancelAddItemForm / cancelExpandableEdit directly.) Call the list handler if present,
  // else the modal fallback — preserving the original typeof-guarded behaviour.
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
