/**
 * ===============================================================================
 * PRAHO PLATFORM - ROMANIAN HOSTING PROVIDER JAVASCRIPT
 * ===============================================================================
 */

class PragmaticHostCRM {
  constructor() {
    this.init();
  }

  init() {
    this.setupFormValidation();
    this.setupCUIValidation();
    this.setupPhoneFormatting();
    this.setupCurrencyFormatting();
    this.setupHTMXEnhancements();
    this.setupKeyboardShortcuts();
  }

  // ===============================================================================
  // ROMANIAN BUSINESS VALIDATION
  // ===============================================================================

  setupCUIValidation() {
    const cuiInputs = document.querySelectorAll('input[name*="cui"]');

    cuiInputs.forEach(input => {
      input.addEventListener('input', (e) => {
        this.validateCUI(e.target);
      });

      input.addEventListener('blur', (e) => {
        this.formatCUI(e.target);
      });
    });
  }

  validateCUI(input) {
    const cui = input.value.trim().toUpperCase();
    const cuiPattern = /^RO\d{6,10}$/;

    // Remove previous validation classes
    input.classList.remove('cui-valid', 'cui-invalid');

    if (cui.length > 2) {
      if (cuiPattern.test(cui)) {
        input.classList.add('cui-valid');
        this.showValidationMessage(input, '✅ CUI valid', 'success');
      } else {
        input.classList.add('cui-invalid');
        this.showValidationMessage(input, '❌ Format CUI invalid (RO + 6-10 cifre)', 'error');
      }
    }
  }

  formatCUI(input) {
    let cui = input.value.trim().toUpperCase();

    // Auto-add RO prefix if missing
    if (cui && !cui.startsWith('RO') && /^\d{6,10}$/.test(cui)) {
      cui = 'RO' + cui;
      input.value = cui;
    }
  }

  setupPhoneFormatting() {
    const phoneInputs = document.querySelectorAll('input[name*="phone"], input[type="tel"]');

    phoneInputs.forEach(input => {
      input.addEventListener('input', (e) => {
        this.formatRomanianPhone(e.target);
      });
    });
  }

  formatRomanianPhone(input) {
    let phone = input.value.replace(/\D/g, '');

    // Romanian mobile: 07xx xxx xxx
    if (phone.startsWith('07') && phone.length === 10) {
      phone = phone.replace(/(\d{4})(\d{3})(\d{3})/, '$1 $2 $3');
    }
    // Romanian landline: 0xx xxx xxxx
    else if (phone.startsWith('0') && phone.length === 10) {
      phone = phone.replace(/(\d{3})(\d{3})(\d{4})/, '$1 $2 $3');
    }
    // International format: +40xxx xxx xxx
    else if (phone.startsWith('40') && phone.length === 11) {
      phone = '+40 ' + phone.substring(2).replace(/(\d{3})(\d{3})(\d{3})/, '$1 $2 $3');
    }

    input.value = phone;
  }

  // ===============================================================================
  // CURRENCY AND NUMBER FORMATTING
  // ===============================================================================

  setupCurrencyFormatting() {
    const currencyInputs = document.querySelectorAll('input[type="number"][step*="0.01"]');

    currencyInputs.forEach(input => {
      input.addEventListener('blur', (e) => {
        this.formatRomanianCurrency(e.target);
      });
    });

    // Format existing currency displays
    this.formatCurrencyDisplays();
  }

  formatRomanianCurrency(input) {
    const value = parseFloat(input.value);
    if (!isNaN(value)) {
      input.value = value.toFixed(2);
    }
  }

  formatCurrencyDisplays() {
    const currencyElements = document.querySelectorAll('.currency, [data-currency]');

    currencyElements.forEach(element => {
      const amount = parseFloat(element.textContent || element.dataset.amount);
      if (!isNaN(amount)) {
        element.textContent = this.formatRON(amount);
      }
    });
  }

  formatRON(amount) {
    return new Intl.NumberFormat('ro-RO', {
      style: 'currency',
      currency: 'RON',
      minimumFractionDigits: 2
    }).format(amount);
  }

  // ===============================================================================
  // FORM VALIDATION
  // ===============================================================================

  setupFormValidation() {
    const forms = document.querySelectorAll('form[data-validate]');

    forms.forEach(form => {
      form.addEventListener('submit', (e) => {
        if (!this.validateForm(form)) {
          e.preventDefault();
        }
      });
    });
  }

  validateForm(form) {
    let isValid = true;
    const requiredFields = form.querySelectorAll('[required]');

    requiredFields.forEach(field => {
      if (!this.validateField(field)) {
        isValid = false;
      }
    });

    return isValid;
  }

  validateField(field) {
    const value = field.value.trim();
    const fieldType = field.type || field.tagName.toLowerCase();

    // Remove previous validation
    field.classList.remove('field-valid', 'field-invalid');

    if (field.required && !value) {
      this.showFieldError(field, 'Acest câmp este obligatoriu');
      return false;
    }

    // Specific validations
    switch (fieldType) {
      case 'email':
        if (value && !this.isValidEmail(value)) {
          this.showFieldError(field, 'Adresa de email nu este validă');
          return false;
        }
        break;

      case 'tel':
        if (value && !this.isValidRomanianPhone(value)) {
          this.showFieldError(field, 'Numărul de telefon nu este valid');
          return false;
        }
        break;
    }

    field.classList.add('field-valid');
    this.clearFieldError(field);
    return true;
  }

  isValidEmail(email) {
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailPattern.test(email);
  }

  isValidRomanianPhone(phone) {
    const cleanPhone = phone.replace(/\s/g, '');
    const patterns = [
      /^\+40[2-9]\d{8}$/,  // +40 21 123 4567
      /^0[2-9]\d{8}$/,     // 021 123 4567
      /^\+407\d{8}$/,      // +40 712 345 678
      /^07\d{8}$/          // 0712 345 678
    ];

    return patterns.some(pattern => pattern.test(cleanPhone));
  }

  // ===============================================================================
  // HTMX ENHANCEMENTS
  // ===============================================================================

  setupHTMXEnhancements() {
    // Loading states
    document.body.addEventListener('htmx:beforeRequest', (e) => {
      this.showLoadingState(e.target);
    });

    document.body.addEventListener('htmx:afterRequest', (e) => {
      this.hideLoadingState(e.target);
    });

    // Error handling
    document.body.addEventListener('htmx:responseError', (e) => {
      this.handleHTMXError(e);
    });

    // Success notifications
    document.body.addEventListener('htmx:afterSettle', (e) => {
      this.checkForNotifications();
    });
  }

  showLoadingState(element) {
    element.classList.add('loading');
    const loadingText = element.dataset.loading || 'Se încarcă...';

    if (element.tagName === 'BUTTON') {
      element.dataset.originalText = element.textContent;
      element.textContent = loadingText;
      element.disabled = true;
    }
  }

  hideLoadingState(element) {
    element.classList.remove('loading');

    if (element.tagName === 'BUTTON' && element.dataset.originalText) {
      element.textContent = element.dataset.originalText;
      element.disabled = false;
      delete element.dataset.originalText;
    }
  }

  handleHTMXError(event) {
    console.error('HTMX Error:', event.detail);
    this.showNotification('A apărut o eroare. Vă rugăm să încercați din nou.', 'error');
  }

  // ===============================================================================
  // USER INTERFACE ENHANCEMENTS
  // ===============================================================================

  setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      // Ctrl+S or Cmd+S to save forms
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        const activeForm = document.querySelector('form:focus-within');
        if (activeForm) {
          e.preventDefault();
          activeForm.requestSubmit();
        }
      }

      // Escape to close modals
      if (e.key === 'Escape') {
        const modal = document.querySelector('.modal.open');
        if (modal) {
          this.closeModal(modal);
        }
      }
    });
  }

  // ===============================================================================
  // UTILITY FUNCTIONS
  // ===============================================================================

  showValidationMessage(input, message, type) {
    const existingMessage = input.parentNode.querySelector('.validation-message');
    if (existingMessage) {
      existingMessage.remove();
    }

    const messageEl = document.createElement('div');
    messageEl.className = `validation-message text-sm mt-1 ${type === 'error' ? 'text-red-400' : 'text-green-400'}`;
    messageEl.textContent = message;

    input.parentNode.appendChild(messageEl);
  }

  showFieldError(field, message) {
    field.classList.add('field-invalid');
    this.showValidationMessage(field, message, 'error');
  }

  clearFieldError(field) {
    const message = field.parentNode.querySelector('.validation-message');
    if (message) {
      message.remove();
    }
  }

  showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification fixed top-4 right-4 p-4 rounded-md shadow-lg z-50 ${type === 'error' ? 'bg-red-900 text-red-100' :
        type === 'success' ? 'bg-green-900 text-green-100' :
          'bg-blue-900 text-blue-100'
      }`;

    notification.innerHTML = `
            <div class="flex items-center">
                <span class="mr-2">${type === 'error' ? '❌' :
        type === 'success' ? '✅' : 'ℹ️'
      }</span>
                <span class="notification-message"></span>
                <button class="ml-4 text-white opacity-70 hover:opacity-100" onclick="this.parentElement.parentElement.remove()">
                    ✕
                </button>
            </div>
        `;
    notification.querySelector('.notification-message').textContent = message;

    document.body.appendChild(notification);

    // Auto-remove after 5 seconds
    setTimeout(() => {
      if (notification.parentNode) {
        notification.remove();
      }
    }, 5000);
  }

  checkForNotifications() {
    // Check for Django messages in the response
    const messages = document.querySelectorAll('.django-message');
    messages.forEach(message => {
      const type = message.classList.contains('error') ? 'error' :
        message.classList.contains('success') ? 'success' : 'info';
      this.showNotification(message.textContent, type);
    });
  }

  // ===============================================================================
  // ROMANIAN BUSINESS UTILITIES
  // ===============================================================================

  calculateVAT(netAmount, vatRate = 21) {
    const net = parseFloat(netAmount);
    const vat = (net * vatRate) / 100;
    const total = net + vat;

    return {
      net: net.toFixed(2),
      vat: vat.toFixed(2),
      total: total.toFixed(2)
    };
  }

  formatCUI(cui) {
    // Ensure proper CUI formatting
    let formatted = cui.toString().toUpperCase();
    if (!formatted.startsWith('RO')) {
      formatted = 'RO' + formatted;
    }
    return formatted;
  }

  generateInvoiceNumber(prefix = 'PH', year = new Date().getFullYear()) {
    // Generate Romanian invoice number format
    const timestamp = Date.now().toString().slice(-6);
    return `${prefix}-${year}-${timestamp}`;
  }
}

// ===============================================================================
// INITIALIZATION
// ===============================================================================

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  window.pragmaticCRM = new PragmaticHostCRM();
  console.log('🇷🇴 PRAHO Platform initialized');
});

// Global utility functions
window.formatRON = (amount) => {
  return new Intl.NumberFormat('ro-RO', {
    style: 'currency',
    currency: 'RON'
  }).format(amount);
};

window.validateCUI = (cui) => {
  const pattern = /^RO\d{6,10}$/;
  return pattern.test(cui.toString().toUpperCase());
};
