// ===============================================================================
// REGISTRATION FORM — Company/Individual Field Toggle
// ===============================================================================
// Toggles VAT/CNP fields and auto-fills company name for individuals.
// Loaded by register.html via <script src="{% static 'js/register-toggle.js' %}">

document.addEventListener('DOMContentLoaded', function () {
  const customerTypeField = document.getElementById('id_customer_type');
  const companyNameField = document.getElementById('id_company_name');
  const firstNameField = document.getElementById('id_first_name');
  const lastNameField = document.getElementById('id_last_name');
  const vatField = document.getElementById('vat-field');
  const cnpField = document.getElementById('cnp-field');
  const vatInput = document.getElementById('id_vat_number');
  const cnpInput = document.getElementById('id_cnp');

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
      if (cnpField) cnpField.style.display = 'block';
      updateIndividualCompanyName();
      if (vatInput) vatInput.value = '';
    } else {
      if (vatField) vatField.style.display = 'block';
      if (cnpField) cnpField.style.display = 'none';
      if (cnpInput) cnpInput.value = '';
      if (companyNameField && companyNameField.value === getFullName()) {
        companyNameField.value = '';
      }
    }
  }

  // Set initial state based on current selection
  toggleIndividualFields(customerTypeField.value);

  // Handle customer type changes
  customerTypeField.addEventListener('change', function () {
    toggleIndividualFields(this.value);
  });

  // Update individual company name when name fields change
  if (firstNameField) firstNameField.addEventListener('input', updateIndividualCompanyName);
  if (lastNameField) lastNameField.addEventListener('input', updateIndividualCompanyName);

  // Make available globally for form onchange
  window.toggleIndividualFields = toggleIndividualFields;
});
