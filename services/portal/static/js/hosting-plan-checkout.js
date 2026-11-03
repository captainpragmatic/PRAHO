/* Stripe owns every card field. Browser success only requests fresh Platform status. */
(() => {
  const form = document.getElementById('hosting-plan-payment-form');
  const configElement = document.getElementById('hosting-plan-payment-config');
  if (!form || !configElement) return;
  const errorElement = document.getElementById('hosting-plan-payment-error');
  const submit = form.querySelector('[type="submit"]');
  const showError = (message) => {
    errorElement.textContent = message || form.dataset.paymentError;
    errorElement.hidden = false;
    submit.disabled = false;
  };
  if (typeof Stripe === 'undefined') {
    showError();
    submit.disabled = true;
    return;
  }
  const config = JSON.parse(configElement.textContent);
  const stripe = Stripe(config.publishable_key);
  const elements = stripe.elements({clientSecret: config.client_secret, appearance: {theme: 'night'}});
  elements.create('payment').mount('#hosting-plan-payment-element');
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    submit.disabled = true;
    errorElement.hidden = true;
    try {
      const result = await stripe.confirmPayment({
        elements,
        confirmParams: {return_url: new URL(form.dataset.returnUrl, window.location.origin).href},
        redirect: 'if_required',
      });
      if (result.error) {
        showError(result.error.message);
        return;
      }
      document.getElementById('hosting-plan-refresh-form').requestSubmit();
    } catch {
      showError();
    }
  });
})();
