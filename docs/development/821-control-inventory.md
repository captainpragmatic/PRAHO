# #821 control inventory (working note, deleted in PR 2)

One row per `{# tmpl-allow TMPL002 #}` marker on master a50efcd5c (49). Line numbers are master's. "Owner" is whatever
holds the control's state today. A control is retained only for the reason given in its row.

Components: `icon_button` (alias of `{% button %}` with `icon_only`), `toggle_badge`, `disclosure`, and
`{% button variant="bare" %}`. `bare` keeps the caller's class string verbatim. "View row" means the view builds the
row's per-record values (target, indicator, an `attrs` mapping) and the template only passes them on.

| # | File:line | Markup today | Owner | Decision | PR |
|---|---|---|---|---|---|
| 1 | platform audit/partials/gdpr_export_requests_list.html:88 | icon-only chevron (raw svg `.chevron-icon`), hx-get detail, per-row hx-target/hx-indicator, invoke `toggleExportDetailAction`, `data-request-id`, title "View Details" | audit-fragments.js (rotates `.chevron-icon`, toggles `hidden`) | `icon_button "chevron-down"` bare, verbatim classes, `icon_size="md"`, `svg_class` keeps `chevron-icon`; view row gives hx_get/hx_target/hx_indicator and `{"data-request-id": id}`; name "View Details" | 1 |
| 2 | platform audit/partials/logs_list.html:69 | same, invoke `toggleEventDetailAction`, `data-event-id`; **no name** | audit-fragments.js | as row 1; name "View Details" (new) | 1 |
| 3 | platform base.html:204 | toast dismiss, filled `x-mark` md, colour by `message.tags`, untranslated aria-label | inline `dismissToastAction` | `icon_button "x-mark"` bare, `icon_style="filled"`, `icon_size="md"`, one branch per tag colour; name "Close notification" (shared catalog) | 1 |
| 4 | platform billing/proforma_form.html:510 | remove-line button inside the `addLineItem()` JS template literal | page JS | **retained**: built client-side in a JS template literal; a server tag cannot render it | — |
| 5 | platform customers/detail.html:213 | role drop-down trigger: `@click`, `@click.away`, role-coloured classes, role icon + role name + trailing chevron | inline `x-data="{ open: false }"` | **retained**: two icons (the role icon and a trailing chevron) around the role name, and `@click.away` on the button itself; the button renders one icon and one label | — |
| 6 | platform customers/detail.html:233 | submit `role=owner`, icon + name + subtitle span, current-role highlight | form POST | **retained**: structured inner markup (icon, role name, subtitle span) plus highlight class | — |
| 7 | platform customers/detail.html:243 | submit `role=billing`, as row 6 | form POST | **retained** (as row 6) | — |
| 8 | platform customers/detail.html:250 | submit `role=tech`, as row 6 | form POST | **retained** (as row 6) | — |
| 9 | platform customers/detail.html:257 | submit `role=viewer`, as row 6 | form POST | **retained** (as row 6) | — |
| 10 | platform customers/detail.html:418 | icon-only copy CUI, `data-copy`, `data-action="copy"`, aria-label "Copy CUI", title "Copy" | ui-actions.js copy | `icon_button "copy"` bare, verbatim classes, `data_copy`, `data_action="copy"`, title "Copy" | 1 |
| 11 | platform customers/list.html:88 | status filter tabs, active classes chosen at render time | the hidden select `platform-actions.js:126` drives | `tab kind="filter"` | 2 |
| 12 | platform customers/partials/customer_table.html:81 | copy CUI (desktop row) | ui-actions.js copy | as row 10 | 1 |
| 13 | platform customers/partials/customer_table.html:197 | copy CUI (mobile card) | ui-actions.js copy | as row 10 | 1 |
| 14 | platform products/partials/product_table.html:80 | active toggle (desktop), badge content, hx-post outerHTML, `hx-sync="this:drop"`, `catalog_lock` path | `Product.is_active`, view re-renders `status_toggle.html` | `toggle_badge` via `status_toggle.html` | 1 |
| 15 | platform products/partials/product_table.html:95 | public toggle (desktop) | `Product.is_public` | `toggle_badge` via `status_toggle.html` | 1 |
| 16 | platform products/partials/product_table.html:195 | active toggle (mobile) | `Product.is_active` | `toggle_badge` via `status_toggle.html` | 1 |
| 17 | platform products/partials/product_table.html:209 | public toggle (mobile) | `Product.is_public` | `toggle_badge` via `status_toggle.html` | 1 |
| 18 | platform products/partials/status_toggle.html:2 | the fragment the toggle views return | the views | becomes the one `toggle_badge` call every caller includes | 1 |
| 19 | platform products/product_detail.html:246 | active toggle (detail) | `Product.is_active` | `toggle_badge` via `status_toggle.html` | 1 |
| 20 | platform products/product_detail.html:263 | public toggle (detail) | `Product.is_public` | `toggle_badge` via `status_toggle.html` | 1 |
| 21 | platform products/product_detail.html:280 | featured toggle (detail) | `Product.is_featured` | `toggle_badge` via `status_toggle.html` | 1 |
| 22 | platform provisioning/partials/services_list.html:154 | icon-only suspend (desktop), `confirm-navigate`, `data-confirm` = prompt + name, `data-href`; **no name** | platform-actions.js confirm-navigate | `icon_button "clock"` bare, `icon_size="md"`, verbatim classes, `data_action="confirm-navigate"`; view row gives `{"data-confirm", "data-href"}`; name "Suspend" | 1 |
| 23 | platform provisioning/partials/services_list.html:162 | icon-only reactivate (desktop); **no name** | confirm-navigate | as row 22 with `"services"`; name "Reactivate" | 1 |
| 24 | platform provisioning/partials/services_list.html:233 | suspend (mobile); **no name** | confirm-navigate | as row 22 | 1 |
| 25 | platform provisioning/partials/services_list.html:241 | reactivate (mobile); **no name** | confirm-navigate | as row 23 | 1 |
| 26 | platform provisioning/virtualmin/account_detail.html:145 | Overview tab, inline `activeTab` | inline `activeTab` | `tab`/`tablist` + shared `tabs` | 2 |
| 27 | platform provisioning/virtualmin/account_detail.html:151 | Backups tab | inline `activeTab` | as row 26 | 2 |
| 28 | platform provisioning/virtualmin/account_detail.html:157 | Jobs tab | inline `activeTab` | as row 26 | 2 |
| 29 | platform provisioning/virtualmin/account_detail.html:163 | Settings tab | inline `activeTab` | as row 26 | 2 |
| 30 | platform provisioning/virtualmin/account_detail.html:219 | protection toggle, 7 per-account `data-*`, state-coloured classes | page JS `confirmProtectionToggle` | `{% button %}` bare, verbatim classes per state, `icon="lock"`, invoke; view builds the `attrs` mapping | 1 |
| 31 | platform provisioning/virtualmin/account_detail.html:238 | delete account, per-account `data-*` | page JS `confirmAccountDelete` | `{% button %}` bare, `icon="x"`, invoke; view builds the `attrs` mapping | 1 |
| 32 | platform provisioning/virtualmin/account_detail.html:249 | disabled delete with a "(Protected)" span | none | **retained**: a second, smaller "(Protected)" span beside the label; the button renders one label | — |
| 33 | platform provisioning/virtualmin/restore_form.html:134 | advanced-options toggle, two x-show label spans, rotating chevron | inline `x-data="{ showAdvanced: false }"` | `disclosure` bound to `showAdvanced`; the panel's `x-show` stays the only owner | 1 |
| 34 | platform provisioning/virtualmin/server_detail.html:234 | Live Domains tab, `showTabAction` | page-local `showTabAction` | `tab`/`tablist` + shared `tabs` | 2 |
| 35 | platform provisioning/virtualmin/server_detail.html:239 | PRAHO Accounts tab | `showTabAction` | as row 34 | 2 |
| 36 | platform provisioning/virtualmin/server_detail.html:244 | Recent Jobs tab | `showTabAction` | as row 34 | 2 |
| 37 | platform provisioning/virtualmin/server_form.html:170 | advanced-options toggle | inline `showAdvanced` | as row 33 | 1 |
| 38 | platform settings/partials/_sidebar.html:5 | mobile menu toggle, `@click`, x-text `+`/`−` | registered `settingsSidebar.navOpen` (open on desktop) | `disclosure` bound to `navOpen`, `icon="menu"`, both labels "Settings menu"; chevron replaces `+`/`−` | 1 |
| 39 | platform settings/partials/history_drawer.html:6 | close glyph `✕`, hx-get search into `#history-drawer`; **no name** | htmx swap | `icon_button "x"` bare, verbatim classes; name "Close" (shared catalog) | 1 |
| 40 | platform tickets/detail.html:146 | remove-file button inside `fileItem.innerHTML` | page JS | **retained**: built client-side in a JS template literal | — |
| 41 | platform users/mfa_backup_codes.html:92 | icon-only copy per code, `data-code`; **no name** | inline `copyCodeAction` | `icon_button "clipboard"` bare, `icon_size="md"`, invoke; view gives `{"data-code": code}` per row; name "Copy"; adds `focus:opacity-100` so keyboard focus is visible | 1 |
| 42 | platform users/mfa_setup.html:123 | icon-only copy secret, title only | inline `copySecret` | `icon_button "clipboard"` bare, `icon_size="md"`, invoke; name "Copy secret key" | 1 |
| 43 | portal e2e/csp_violation_positive_control.html:9 | inline `onclick` | none | **retained** by design: the CSP positive control | — |
| 44 | portal orders/partials/cart_updated.html:10 | cart toggle: icon, responsive "Cart" label, count badge `#cart-count` | `miniCart` Alpine (`toggle()`) | **retained**: the count badge (`#cart-count`, which later swaps update) sits beside the label; the button renders one label | — |
| 45 | portal orders/partials/error_message.html:21 | dismiss `×` glyph, `data-action="dismiss"`, literal `data-dismiss-target` | csp-actions.js dismiss | `icon_button "x"` bare, verbatim classes, literal `attrs`; name "Close notification" | 1 |
| 46 | portal orders/partials/mini_cart_content.html:40 | remove item: hx-post, CSRF hx-headers, per-item hx-vals, hx-confirm | htmx; cart session | `icon_button "x"` bare; view gives `remove_headers` and each item's `remove_vals` (JSON) | 1 |
| 47 | portal orders/product_catalog.html:26 | cart toggle, as row 44 | `miniCart` Alpine | **retained** (as row 44) | — |
| 48 | portal orders/product_catalog.html:87 | Monthly, `:class="tabClass(...)"` | `billingToggle` | `tab kind="filter"` driven by `billingToggle` | 2 |
| 49 | portal orders/product_catalog.html:94 | Annual with a "Save 20%" badge | `billingToggle` | as row 48 | 2 |

Totals: 28 migrate in PR 1, 10 in PR 2, 11 retained (rows 4, 5–9, 32, 40, 43, 44, 47).
