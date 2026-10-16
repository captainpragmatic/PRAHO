// ===============================================================================
// REGISTRATION FORM — Company/Individual Field Toggle
// ===============================================================================
// Toggles the company identifiers (VAT number; CUI and trade registry for a Romanian address) and
// auto-fills the company name for individuals.
// Loaded by register.html via <script src="{% static 'js/register-toggle.js' %}">

document.addEventListener('DOMContentLoaded', function () {
  const customerTypeField = document.getElementById('id_customer_type');
  const companyNameField = document.getElementById('id_company_name');
  const firstNameField = document.getElementById('id_first_name');
  const lastNameField = document.getElementById('id_last_name');
  const countryField = document.getElementById('id_country');
  const vatField = document.getElementById('vat-field');
  const romanianFields = document.getElementById('romanian-company-fields');
  const vatInput = document.getElementById('id_vat_number');
  const cuiInput = document.getElementById('id_cui');
  const tradeRegistryInput = document.getElementById('id_trade_registry_number');
  const ROMANIA = ['ro', 'romania', 'românia'];

  if (!customerTypeField) return;

  function getFullName() {
    const firstName = (firstNameField?.value || '').trim();
    const lastName = (lastNameField?.value || '').trim();
    return firstName && lastName ? firstName + ' ' + lastName : '';
  }

  function updateIndividualCompanyName() {
    if (customerTypeField.value === 'individual' && companyNameField) {
      const fullName = getFullName();
      if (fullName) companyNameField.value = fullName;
    }
  }

  function toggleIndividualFields(customerType) {
    if (customerType === 'individual') {
      if (vatField) vatField.style.display = 'none';
      updateIndividualCompanyName();
      if (vatInput) vatInput.value = '';
      if (cuiInput) cuiInput.value = '';
      if (tradeRegistryInput) tradeRegistryInput.value = '';
    } else {
      if (vatField) vatField.style.display = 'block';
      if (companyNameField && companyNameField.value === getFullName()) {
        companyNameField.value = '';
      }
    }
  }

  // The CUI and trade registry number are Romanian. The page opens as the server decided; a blank
  // country is the default country. A hidden identifier is cleared, so it is not sent.
  function toggleRomanianFields() {
    if (!romanianFields || !countryField) return;
    const country = countryField.value.trim().toLowerCase();
    const inRomania = country ? ROMANIA.includes(country) : romanianFields.dataset.defaultRomania === 'true';
    romanianFields.hidden = !inRomania;
    if (!inRomania) {
      if (cuiInput) cuiInput.value = '';
      if (tradeRegistryInput) tradeRegistryInput.value = '';
    }
  }

  // Set initial state based on current selection
  toggleIndividualFields(customerTypeField.value);

  // Handle customer type changes
  customerTypeField.addEventListener('change', function () {
    toggleIndividualFields(this.value);
  });

  if (countryField) countryField.addEventListener('input', toggleRomanianFields);

  // Update individual company name when name fields change
  if (firstNameField) firstNameField.addEventListener('input', updateIndividualCompanyName);
  if (lastNameField) lastNameField.addEventListener('input', updateIndividualCompanyName);

  // Make available globally for form onchange
  window.toggleIndividualFields = toggleIndividualFields;
});
