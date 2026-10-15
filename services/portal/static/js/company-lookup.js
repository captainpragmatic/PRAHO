// ===============================================================================
// REGISTRATION FORM — company details from ANAF's register
// ===============================================================================
// Asks /company-lookup/ for the company with the CUI typed and fills in its details. When the page
// has the proof-of-work widget, it is solved first and reset afterwards, so the registration itself
// sends a fresh solution. Loaded as a module by register.html while Platform offers the lookup.

const lookup = document.getElementById('company-lookup');
const button = document.getElementById('company-lookup-button');
const message = document.getElementById('company-lookup-message');
const FIELDS = {
  name: 'id_company_name',
  registration_number: 'id_trade_registry_number',
  vat_number: 'id_vat_number',
  street: 'id_address_line1',
  city: 'id_city',
  county: 'id_county',
  postal_code: 'id_postal_code',
};

async function solvedChallenge(form) {
  const widget = form.querySelector('altcha-widget');
  if (!widget) return null;
  await widget.verify();
  if (widget.getState() !== 'verified') throw new Error('not verified');
  return form.querySelector('input[name="altcha"]')?.value || '';
}

if (lookup && button && message) {
  const form = button.closest('form');
  button.addEventListener('click', async () => {
    button.disabled = true;
    message.textContent = '';
    const widget = form.querySelector('altcha-widget');
    try {
      const body = new FormData();
      body.append('cui', document.getElementById('id_cui')?.value || '');
      body.append('csrfmiddlewaretoken', form.querySelector('input[name="csrfmiddlewaretoken"]').value);
      const payload = await solvedChallenge(form);
      if (payload !== null) body.append('altcha', payload);
      const response = await fetch(lookup.dataset.url, { method: 'POST', body, credentials: 'same-origin' });
      const data = await response.json();
      if (!data.company) {
        message.textContent = data.error || lookup.dataset.failed;
        return;
      }
      for (const [key, id] of Object.entries(FIELDS)) {
        const input = document.getElementById(id);
        if (input && data.company[key]) input.value = data.company[key];
      }
      message.textContent = lookup.dataset.filled;
    } catch {
      message.textContent = lookup.dataset.failed;
    } finally {
      // A solution is accepted once: the registration solves its own.
      if (widget) widget.reset();
      button.disabled = false;
    }
  });
}
