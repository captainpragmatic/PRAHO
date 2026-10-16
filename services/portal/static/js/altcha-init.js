// ===============================================================================
// ALTCHA — proof-of-work worker
// ===============================================================================
// The widget's "external" build bundles no worker, so the PBKDF2 one is registered here, from this
// origin: the portal's CSP admits no blob: workers. Loaded as a module by
// components/altcha_widget.html, after the widget script.

const widget = document.querySelector('altcha-widget[data-worker]');
if (widget && globalThis.$altcha) {
  const workerUrl = widget.dataset.worker;
  globalThis.$altcha.algorithms.set('PBKDF2/SHA-256', () => new Worker(workerUrl));
}
