document.addEventListener('alpine:init', function () {
  Alpine.data('autoDismiss', function (ms) {
    return {
      show: true,
      init: function () {
        var self = this;
        setTimeout(function () { self.show = false; }, ms || 5000);
      },
      dismiss: function () { this.show = false; },
    };
  });

  Alpine.data('collapsibleSection', function () {
    return {
      open: true,
      toggle: function () { this.open = !this.open; },
    };
  });

  Alpine.data('toast', function (autoDismiss) {
    return {
      show: false,
      init: function () {
        var self = this;
        this.$nextTick(function () { self.show = true; });
        if (autoDismiss > 0) {
          setTimeout(function () {
            self.show = false;
            setTimeout(function () { self.$el.remove(); }, 400);
          }, autoDismiss);
        }
      },
      dismiss: function () {
        var self = this;
        this.show = false;
        setTimeout(function () {
          var alert = self.$el.closest('[role=alert]');
          if (alert) { alert.remove(); }
        }, 400);
      },
    };
  });

  Alpine.data('navDropdown', function () {
      return {
          open: false,

          toggle() {
              this.open = !this.open;
          },

          get triggerClass() {
              return { 'text-white bg-slate-700': this.open };
          },

          get chevronClass() {
              return { 'rotate-180': this.open };
          }
      };
  });

  Alpine.data('dangerousActionModal', function () {
      return {
          show: false,
          title: '',
          message: '',
          confirmText: '',
          userInput: '',
          action: null,

          open(data) {
              this.title = data.title || 'Confirm Action';
              this.message = data.message || 'Are you sure?';
              this.confirmText = data.confirmText || 'I understand';
              this.userInput = '';
              this.action = data.action;
              this.show = true;
          },

          close() {
              this.show = false;
              this.userInput = '';
              this.action = null;
          },

          confirm() {
              if (this.userInput === this.confirmText && this.action) {
                  this.action();
                  this.close();
              }
          },

          get isValid() {
              return this.userInput === this.confirmText;
          },

          onConfirmRequest(event) {
              this.open(event.detail);
          },

          submitIfValid() {
              if (this.isValid) {
                  this.confirm();
              }
          },

          get isInvalid() {
              return !this.isValid;
          },

          get confirmBtnClass() {
              return this.isValid ? 'bg-red-600 hover:bg-red-700 focus:ring-red-500' : 'bg-slate-600 cursor-not-allowed';
          }
      };
  });
});
