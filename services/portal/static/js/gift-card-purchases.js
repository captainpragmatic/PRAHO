/* Gift purchase forms use ordinary CSRF-protected POSTs; Stripe handles card data. */
(() => {
  const delivery = document.getElementById('id_delivery');
  if (delivery) {
    const updateRecipient = () => {
      const isGift = delivery.value === 'gift';
      const recipientFields = document.getElementById('gift-recipient-fields');
      recipientFields.hidden = !isGift;
      recipientFields.querySelectorAll('input, textarea').forEach(field => { field.disabled = !isGift; });
      document.getElementById('gift-for-me-help').hidden = isGift;
      document.getElementById('id_recipient_email').required = isGift;
    };
    delivery.addEventListener('change', updateRecipient);
    updateRecipient();
  }

  const paymentForm = document.getElementById('gift-card-payment-form');
  const configElement = document.getElementById('gift-card-payment-config');
  if (!paymentForm || !configElement) return;
  const errorElement = document.getElementById('gift-card-payment-error');
  const submit = paymentForm.querySelector('[type="submit"]');
  const showError = (message) => {
    errorElement.querySelector('.text-sm').textContent = message || paymentForm.dataset.paymentError;
    errorElement.hidden = false;
    submit.disabled = false;
  };
  if (typeof Stripe === 'undefined') {
    showError();
    submit.disabled = true;
    return;
  }
  const config = JSON.parse(configElement.textContent);
  const stripe = Stripe(config.public_key);
  const elements = stripe.elements({clientSecret: config.client_secret, appearance: {theme: 'night'}});
  elements.create('payment').mount('#gift-card-payment-element');
  paymentForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    submit.disabled = true;
    errorElement.hidden = true;
    try {
      const result = await stripe.confirmPayment({
        elements,
        confirmParams: {return_url: new URL(paymentForm.dataset.returnUrl, window.location.origin).href},
        redirect: 'if_required',
      });
      if (result.error) {
        showError(result.error.message);
        return;
      }
      // Only a fresh server verification may mark the gift card as funded.
      document.getElementById('gift-card-refresh-form').requestSubmit();
    } catch {
      showError();
    }
  });
})();
