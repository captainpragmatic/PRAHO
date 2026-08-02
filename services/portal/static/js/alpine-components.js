// Portal-only Alpine.data components (registered on alpine:init; this file loads
// with defer, before alpine.min.js, so the listener is in place when Alpine boots).
document.addEventListener('alpine:init', function () {

  Alpine.data('cookieConsent', function () {
      return {
          showBanner: false,
          showPreferences: false,
          preferences: {
              essential: true,
              functional: false,
              analytics: false,
              marketing: false
          },

          get showMainBanner() {
              return !this.showPreferences;
          },

          init() {
              const consent = this.getConsentCookie();
              if (!consent) {
                  this.showBanner = true;
              } else {
                  this.preferences = { ...this.preferences, ...consent };
                  this.applyConsent();
              }

              window.showCookiePreferences = () => {
                  this.showBanner = true;
                  this.showPreferences = true;
              };

              // Retry any pending consent that failed to persist server-side
              this.retryPendingConsent();
          },

          getConsentCookie() {
              const cookies = document.cookie.split(';');
              for (let cookie of cookies) {
                  const [name, value] = cookie.trim().split('=');
                  if (name === 'cookie_consent') {
                      try {
                          return JSON.parse(decodeURIComponent(value));
                      } catch {
                          return null;
                      }
                  }
              }
              return null;
          },

          setConsentCookie(preferences) {
              const expires = new Date();
              expires.setFullYear(expires.getFullYear() + 1);
              document.cookie = `cookie_consent=${encodeURIComponent(JSON.stringify(preferences))};expires=${expires.toUTCString()};path=/;SameSite=Lax`;
          },

          acceptAll() {
              this.preferences = {
                  essential: true,
                  functional: true,
                  analytics: true,
                  marketing: true
              };
              this.saveAndClose('accepted_all');
          },

          acceptEssential() {
              this.preferences = {
                  essential: true,
                  functional: false,
                  analytics: false,
                  marketing: false
              };
              this.saveAndClose('accepted_essential');
          },

          rejectAll() {
              this.preferences = {
                  essential: true,
                  functional: false,
                  analytics: false,
                  marketing: false
              };
              this.saveAndClose('accepted_essential');
          },

          savePreferences() {
              this.saveAndClose('customized');
          },

          saveAndClose(status) {
              const data = {
                  ...this.preferences,
                  status: status,
                  timestamp: new Date().toISOString()
              };

              // Set cookie + hide banner immediately (optimistic UX)
              this.setConsentCookie(data);
              this.applyConsent();
              this.showBanner = false;
              this.showPreferences = false;

              // Persist to server; queue for retry if it fails
              this.sendConsentToServer(data);
          },

          applyConsent() {
              if (this.preferences.analytics) {
                  this.enableAnalytics();
              }

              window.dispatchEvent(new CustomEvent('cookieConsentUpdated', {
                  detail: this.preferences
              }));
          },

          enableAnalytics() {
              console.log('Analytics enabled');
          },

          async sendConsentToServer(data) {
              try {
                  const response = await fetch('/api/cookie-consent/', {
                      method: 'POST',
                      headers: {
                          'Content-Type': 'application/json',
                          'X-CSRFToken': this.getCsrfToken()
                      },
                      body: JSON.stringify(data)
                  });

                  if (!response.ok) {
                      this.queueForRetry(data);
                      return;
                  }

                  const result = await response.json();
                  if (!result.success) {
                      // Server returned 200 but Platform persistence failed
                      this.queueForRetry(data);
                  } else {
                      // Server confirmed — clear any pending retry
                      localStorage.removeItem('pendingCookieConsent');
                  }
              } catch (error) {
                  console.error('Error saving consent:', error);
                  this.queueForRetry(data);
              }
          },

          queueForRetry(data) {
              try {
                  localStorage.setItem('pendingCookieConsent', JSON.stringify(data));
              } catch (e) {
                  // localStorage unavailable (private browsing) — best-effort only
              }
          },

          async retryPendingConsent() {
              try {
                  const pending = localStorage.getItem('pendingCookieConsent');
                  if (!pending) return;
                  const data = JSON.parse(pending);
                  await this.sendConsentToServer(data);
              } catch (e) {
                  // Silent — will retry on next page load
              }
          },

          getCsrfToken() {
              const cookies = document.cookie.split(';');
              for (let cookie of cookies) {
                  const [name, value] = cookie.trim().split('=');
                  if (name === 'csrftoken') {
                      return value;
                  }
              }
              return '';
          }
      };
  });

  Alpine.data('miniCart', function (initialOpen) {
    return {
      miniCartOpen: initialOpen,
      toggle() {
        this.miniCartOpen = !this.miniCartOpen;
      },
    };
  });

  // Billing period toggle (monthly / annual) — product_catalog.html.
  Alpine.data('billingToggle', function () {
    return {
      billingPeriod: 'monthly',
      tabClass(period) {
        return this.billingPeriod === period
          ? 'bg-blue-600 text-white shadow'
          : 'text-slate-400 hover:text-slate-200';
      },
      isPeriod(period) {
        return this.billingPeriod === period;
      },
    };
  });

  // Add-to-cart success toast trigger — partials/cart_updated.html.
  // The message is dynamic and Django-rendered, so it stays in the template on
  // data-toast-message (a static JS file is never template-rendered) and is read
  // here from the element dataset.
  Alpine.data('toastTrigger', function () {
    return {
      init() {
        if (window.showToast) {
          window.showToast('success', this.$el.dataset.toastMessage);
        }
      },
    };
  });

  Alpine.data('checkoutPayment', function () {
    return {
      paymentMethod: 'card',
      get isCard() {
        return this.paymentMethod === 'card';
      },
      get isBankTransfer() {
        return this.paymentMethod === 'bank_transfer';
      },
    };
  });

  // orders/order_confirmation.html — copy-to-clipboard widget (used by both the IBAN
  // and payment-reference buttons). The clipboard text and the two title labels are
  // Django-templated, so they are passed in as args (a static JS component can't hold
  // server-rendered values inline).
  Alpine.data('copyToClipboard', function (text, copiedLabel, copyLabel) {
    return {
      text: text,
      copiedLabel: copiedLabel,
      copyLabel: copyLabel,
      copied: false,
      copy() {
        var self = this;
        navigator.clipboard.writeText(this.text).then(function () {
          self.copied = true;
          setTimeout(function () {
            self.copied = false;
          }, 2000);
        });
      },
      get title() {
        return this.copied ? this.copiedLabel : this.copyLabel;
      },
      get notCopied() {
        return !this.copied;
      },
    };
  });

  Alpine.data('justAddedHighlight', function () { return { init() { var self = this; setTimeout(function () { self.$el.classList.remove('bg-green-900/30'); }, 2000); } }; });

  Alpine.data('tabGroup', function () { return { activeTab: 'overview', tabClass(name) { return this.activeTab === name ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-300'; }, isTab(name) { return this.activeTab === name; } }; });
});
