function toggleCustomerSelector() {
  const dropdown = document.getElementById('customerSelectorDropdown');
  const btn = document.getElementById('customerSelectorBtn');

  if (dropdown.classList.contains('hidden')) {
    dropdown.classList.remove('hidden');
    btn.classList.add('text-white');
  } else {
    dropdown.classList.add('hidden');
    btn.classList.remove('text-white');
  }
}

// Close dropdown when clicking outside
document.addEventListener('click', function(event) {
  const container = document.querySelector('.customer-selector-container');
  const dropdown = document.getElementById('customerSelectorDropdown');

  if (!container.contains(event.target)) {
    dropdown.classList.add('hidden');
    document.getElementById('customerSelectorBtn').classList.remove('text-white');
  }
});
