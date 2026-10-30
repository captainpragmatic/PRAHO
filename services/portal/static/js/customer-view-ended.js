// A customer view has ended: take this tab back to the staff page it was opened from (ADR-0065).
// The address comes from the page's data attribute, which the portal builds from its settings.
(function () {
  "use strict";
  var target = document.querySelector("[data-platform-url]");
  var url = target && target.getAttribute("data-platform-url");
  if (url && /^https?:\/\//.test(url)) {
    window.location.replace(url);
  }
})();
