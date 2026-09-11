/*
 * Platform-only Alpine.data components (#284 unsafe-eval removal).
 *
 * Loaded with `defer` BEFORE the @alpinejs/csp build so the alpine:init listener is in
 * place when Alpine boots (order: alpine-shared-components.js -> alpine-components.js ->
 * alpine-csp.min.js). The CSP build has no new-Function evaluator, so directive
 * expressions must resolve component names/methods from this registry rather than eval
 * arbitrary JS. Per-request data (URLs, i18n) is read from data-* attributes / json_script
 * on the component root — never interpolated into the (parsed, not eval'd) expression.
 */
document.addEventListener("alpine:init", function () {
  // The confirm-dangerous-action modal renders its `message` via x-html (some callers
  // pass intentional markup, e.g. the critical-settings list below), so any dynamic
  // value interpolated into a message MUST be HTML-escaped first — otherwise a value
  // like a Virtualmin domain becomes an HTML-injection vector. This is normal module
  // JS (not an Alpine directive expression), so it is unaffected by the CSP build.
  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (ch) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
    });
  }

  // Dirty-only atomic change-set form (ADR-0042). Every control carries
  // data-setting-field/data-key/data-baseline; values are canonicalized client-side.
  Alpine.data("settingsForm", function (saveUrl) {
    return {
      dirty: {},
      errors: {},
      conflicts: [],
      saving: false,
      reason: "",
      get dirtyCount() { return Object.keys(this.dirty).length; },
      compute(el) {
        const kind = el.dataset.kind;
        if (kind === "toggle") return el.checked;
        if (kind === "list") return el.value.split(",").map((s) => s.trim()).filter(Boolean);
        return el.value;
      },
      initField(el) {
        el.dataset.value = JSON.stringify(this.compute(el));
        el.dataset.initial = el.dataset.value;
      },
      syncField(el) {
        el.dataset.value = JSON.stringify(this.compute(el));
        const key = el.dataset.key;
        if (el.dataset.value === el.dataset.initial) delete this.dirty[key];
        else this.dirty[key] = true;
        this.dirty = { ...this.dirty };
      },
      resetField(key) {
        const el = this.$root.querySelector(`[data-setting-field][data-key="${key}"]`);
        if (!el) return;
        const fallback = JSON.parse(el.dataset.default);
        if (el.dataset.kind === "toggle") el.checked = fallback;
        else if (el.dataset.kind === "list") el.value = fallback.join(", ");
        else el.value = fallback === null ? "" : String(fallback);
        this.syncField(el);
      },
      discard() { window.location.reload(); },
      async save() {
        if (!this.dirtyCount || this.saving) return;
        const criticalDirty = Array.from(
          this.$root.querySelectorAll("[data-setting-field][data-critical]")
        ).filter((el) => this.dirty[el.dataset.key]).map((el) => el.dataset.key);
        if (criticalDirty.length && !this._criticalOk) {
          this.$dispatch("confirm-dangerous-action", {
            title: this.$root.dataset.criticalTitle,
            message: this.$root.dataset.criticalMessage + "<br><code>" + criticalDirty.map(escapeHtml).join("</code><br><code>") + "</code>",
            confirmText: "CONFIRM",
            action: () => { this._criticalOk = true; this.save(); },
          });
          return;
        }
        this._criticalOk = false;
        this.saving = true;
        this.errors = {};
        this.conflicts = [];
        const changes = {}, baselines = {};
        this.$root.querySelectorAll("[data-setting-field]").forEach((el) => {
          const key = el.dataset.key;
          if (this.dirty[key]) {
            changes[key] = JSON.parse(el.dataset.value);
            baselines[key] = el.dataset.baseline || null;
          }
        });
        try {
          const response = await fetch(saveUrl, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-CSRFToken": document.querySelector("[name=csrfmiddlewaretoken]").value,
            },
            body: JSON.stringify({ changes, baselines, reason: this.reason || null }),
          });
          const data = await response.json();
          if (data.success) {
            Object.entries(data.saved).forEach(([key, entry]) => {
              const el = this.$root.querySelector(`[data-setting-field][data-key="${key}"]`);
              if (el) {
                el.dataset.baseline = entry.baseline;
                el.dataset.initial = el.dataset.value;
              }
            });
            this.dirty = {};
            this.reason = "";
            if (window.showToast) window.showToast("success", this.$root.dataset.savedMessage);
          } else if (response.status === 409) {
            this.conflicts = data.conflicts || [];
          } else {
            this.errors = data.errors || { __all__: data.error || this.$root.dataset.saveFailedMessage };
          }
        } catch (error) {
          this.errors = { __all__: error.message };
        } finally {
          this.saving = false;
        }
      },
    };
  });

  Alpine.data("settingsIntegrationTest", function () {
    return {
      testing: false,
      result: null,
      // The @alpinejs/csp interpreter evaluates BOTH operands of `&&` (no
      // short-circuit), so `result && result.success` in a template throws while
      // `result` is null. Guard the null in real JS via getters instead (#284).
      get resultSuccess() {
        return this.result ? this.result.success : false;
      },
      get resultMessage() {
        return this.result ? this.result.message : "";
      },
      testConnection() {
        this.testing = true;
        this.result = null;
        return fetch(this.$root.dataset.testUrl, {
          method: "POST",
          headers: { "X-CSRFToken": document.querySelector("[name=csrfmiddlewaretoken]").value },
        }).then((r) => r.json()).then((data) => {
          this.testing = false;
          this.result = data;
        });
      },
    };
  });

  Alpine.data("settingsSecretRow", function (configured) {
    return {
      replacing: false,
      secret: "",
      busy: false,
      message: "",
      configured: configured,
      clearCredential() {
        this.$dispatch("confirm-dangerous-action", {
          title: this.$root.dataset.clearTitle,
          message: this.$root.dataset.clearMessage,
          confirmText: this.$root.dataset.confirmText,
          action: async () => {
            const response = await fetch(this.$root.dataset.clearUrl, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": document.querySelector("[name=csrfmiddlewaretoken]").value,
              },
              body: JSON.stringify({ reason: "Cleared from settings UI" }),
            });
            const data = await response.json();
            if (data.success) this.configured = false;
          },
        });
      },
      saveSecret() {
        this.busy = true;
        return fetch(this.$root.dataset.setUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": document.querySelector("[name=csrfmiddlewaretoken]").value,
          },
          body: JSON.stringify({ value: this.secret }),
        }).then((r) => r.json()).then((data) => {
          this.busy = false;
          if (data.success) {
            this.configured = true;
            this.replacing = false;
            this.secret = "";
            this.message = "";
          } else {
            this.message = data.error;
          }
        });
      },
      cancelReplacement() {
        this.replacing = false;
        this.secret = "";
      },
    };
  });

  Alpine.data("settingsSidebar", function () {
    return {
      navOpen: false,
      init() { this.navOpen = window.innerWidth >= 1024; },
    };
  });

  Alpine.data("deploymentForm", function () {
    return {
      environment: "prd",
      nodeType: "sha",
      provider: "",
      region: "",
      nodeSize: "",
      hostname: "",
      fqdn: "",
      dnsZone: "",
      hostnamePreviewUrl: "",

      regions: JSON.parse(document.getElementById("regions-data").textContent),
      sizes: JSON.parse(document.getElementById("sizes-data").textContent),
      providers: JSON.parse(document.getElementById("providers-data").textContent),

      get filteredRegions() {
        if (!this.provider) return [];
        return this.regions.filter((r) => r.provider_id == this.provider);
      },
      get filteredSizes() {
        if (!this.provider) return [];
        return this.sizes.filter((s) => s.provider_id == this.provider);
      },

      // Labels for x-for rows: take the loop item as an argument (the CSP build allows
      // method calls with scope args, but NOT template literals inline in the template).
      regionLabel(r) {
        return `${r.name} (${r.country_code.toUpperCase()} / ${r.normalized_code})`;
      },
      sizeResourceLabel(size) {
        return `${size.vcpus} vCPU / ${size.memory_gb}GB / ${size.disk_gb}GB`;
      },
      sizePriceLabel(size) {
        return `€${size.monthly_cost_eur}/mo`;
      },
      sizeDomainsLabel(size) {
        return `~${size.max_domains} domains`;
      },

      get canSubmit() {
        return this.provider && this.region && this.nodeSize;
      },

      updateRegions() {
        this.region = "";
        this.nodeSize = "";
        this.updateHostname();
      },

      async updateHostname() {
        if (!this.provider || !this.region) {
          this.hostname = "";
          this.fqdn = "";
          return;
        }
        try {
          const response = await fetch(
            `${this.hostnamePreviewUrl}?environment=${this.environment}&node_type=${this.nodeType}&provider=${this.provider}&region=${this.region}`
          );
          const data = await response.json();
          this.hostname = data.hostname;
          this.fqdn = data.fqdn;
        } catch (e) {
          console.error("Failed to get hostname preview:", e);
        }
      },

      init() {
        this.dnsZone = this.$el.dataset.dnsZone;
        this.hostnamePreviewUrl = this.$el.dataset.hostnamePreviewUrl;
        this.$watch("environment", () => this.updateHostname());
        this.$watch("nodeType", () => this.updateHostname());
      },
    };
  });

  Alpine.data("virtualminQuickActions", function () {
    return {
      confirmProtectionToggle() {
        const data = this.$root.dataset;
        this.$dispatch("confirm-dangerous-action", {
          title: data.protectionTitle,
          message: 'Type "I really am sure I want to do this!" to confirm this protection change for ' + escapeHtml(data.domain),
          confirmText: "I really am sure I want to do this!",
          action: function () {
            htmx.ajax("POST", data.toggleProtectionUrl, {
              target: "#quick-actions-section",
              swap: "outerHTML",
              headers: { "X-CSRFToken": data.csrfToken },
            });
          },
        });
      },
      confirmAccountDelete() {
        const data = this.$root.dataset;
        this.$dispatch("confirm-dangerous-action", {
          title: "Delete Virtualmin Account",
          message: 'Type "I really am sure I want to do this!" to confirm permanent deletion of ' + escapeHtml(data.domain),
          confirmText: "I really am sure I want to do this!",
          action: function () {
            htmx.ajax("DELETE", data.deleteUrl, { target: "body" });
          },
        });
      },
    };
  });

  Alpine.data("apiTokenClipboard", function () {
    return {
      copyToken() {
        return navigator.clipboard.writeText(this.$refs.rawToken.textContent.trim());
      },
    };
  });
});

// Preserved from settings/_form_js.html: warn before leaving with unsaved settings.
window.addEventListener("beforeunload", function (event) {
  const form = document.querySelector("[data-settings-form]");
  if (form && form.__x && Object.keys(form.__x.$data.dirty).length > 0) {
    event.preventDefault();
  }
});
