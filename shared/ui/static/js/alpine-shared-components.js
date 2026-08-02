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
});
