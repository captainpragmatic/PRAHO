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

  // Real tabs: the one owner of which panel shows. Tabs and panels (tab.html, tab_panel_attrs) carry their names in
  // data-*; the server marks the first selected tab, so the first paint and this state agree.
  Alpine.data('tabs', function () {
    return {
      selected: '',
      init: function () {
        var tab = this.$root.querySelector('[role="tab"][aria-selected="true"]') || this.$root.querySelector('[role="tab"]');
        this.selected = tab ? tab.dataset.tab : '';
      },
      isSelected: function (el) { return el.dataset.tab === this.selected; },
      isPanel: function (el) { return el.dataset.tabPanel === this.selected; },
      tabIndex: function (el) { return el.dataset.tab === this.selected ? 0 : -1; },
      tabClass: function (el) { return el.dataset.tab === this.selected ? el.dataset.activeClass : el.dataset.inactiveClass; },
      select: function (el) { this.selected = el.dataset.tab; },
      // Arrow keys wrap; Home and End go to the ends. Focus moves with the selection.
      onKeydown: function (event) {
        var list = event.currentTarget.closest('[role="tablist"]');
        var tabs = Array.prototype.slice.call(list.querySelectorAll('[role="tab"]'));
        var index = tabs.indexOf(event.currentTarget);
        var target = {
          ArrowRight: (index + 1) % tabs.length,
          ArrowLeft: (index - 1 + tabs.length) % tabs.length,
          Home: 0,
          End: tabs.length - 1,
        }[event.key];
        if (target === undefined) {
          return;
        }
        event.preventDefault();
        this.selected = tabs[target].dataset.tab;
        tabs[target].focus();
      },
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
              const defaults = this.$root.dataset;
              this.title = data.title || defaults.defaultTitle;
              this.message = data.message || defaults.defaultMessage;
              this.confirmText = data.confirmText || defaults.defaultConfirmText;
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
