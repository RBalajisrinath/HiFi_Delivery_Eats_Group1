document.addEventListener('DOMContentLoaded', function() {
    const addressForm = document.getElementById('checkoutForm');  
    const newLocationInput = document.getElementById('delivery_location');
    const defaultAddressDiv = document.getElementById('default_address');
    const validateButton = document.getElementById('validateButton');
    const orderNoteTextarea = document.getElementById('order-note');
    
    // List of accepted pincodes
    const available_pincodes = [743376, 743329, 743363, 743355, 743611, 743337, 743502, 743372, 743384, 743387];
    
    // Check for availability message on page load
    function checkAvailability() {
        const messageElement = document.getElementById('backend-message');
        const message = messageElement ? messageElement.getAttribute('data-message') : '';
        if (message && message.includes('following items are not available')) {
            alert(message);
            return false;
        }
        return true;
    }

    // Run availability check on page load
    checkAvailability();

    // Toggle address input based on radio selection
    document.querySelectorAll('input[name="delivery_option"]').forEach(radio => {
        radio.addEventListener('change', function() {
            if (this.value === 'default') {
                newLocationInput.style.display = 'none';
                defaultAddressDiv.style.display = 'block';
                validateButton.style.display = 'none';
                newLocationInput.value = '';
            } else {
                newLocationInput.style.display = 'block';
                defaultAddressDiv.style.display = 'none';
                validateButton.style.display = 'inline-block';
            }
        });
    });

    // Function to show errors
    function showError(message) {
        const errorDiv = document.getElementById('error-message');
        if (errorDiv) {
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            setTimeout(() => {
                errorDiv.style.display = 'none';
            }, 5000);
        } else {
            alert(message);
        }
    }

    // Validate location function - returns boolean without showing alert for success
    function validateLocation(silent = false) {
        const address = newLocationInput.value;
        const pincodeMatch = address.match(/\b\d{6}\b/);

        if (!pincodeMatch) {
            showError("No valid pincode found in the address.");
            return false;
        }

        const pincode = parseInt(pincodeMatch[0], 10);
        if (!available_pincodes.includes(pincode)) {
            showError("Sorry, delivery is not available in this area.");
            return false;
        }

        if (!silent) {
            alert("Delivery location is valid!");
        }
        return true;
    }

    // Add click handler for validate button
    if (validateButton) {
        validateButton.addEventListener('click', () => validateLocation(false));
    }

    // Handle form submission
    if (addressForm) {
        addressForm.addEventListener('submit', function(e) {
            e.preventDefault();
            console.log('Form submitted'); // Debug log

            if (!checkAvailability()) {
                return;
            }

            const formData = new FormData(addressForm);
            const deliveryOption = formData.get('delivery_option');

            // Log form data for debugging
            console.log('Delivery Option:', deliveryOption);
            console.log('Form Data:', Object.fromEntries(formData.entries()));
            
            // Validate delivery location for new address - silent mode
            if (deliveryOption === 'new') {
                const deliveryLocation = formData.get('delivery_location').trim();
                if (!deliveryLocation) {
                    showError('Please enter a delivery location');
                    return;
                }
                if (!validateLocation(true)) {
                    return;
                }
            }

            // Add order note to form data
            const orderNote = orderNoteTextarea.value.trim() || 'EMPTY';  // Default to 'EMPTY' if not filled
            formData.append('order_note', orderNote);
            
            // Get the current URL
            const currentUrl = window.location.href;
            console.log('Submitting to:', currentUrl); // Debug log

            // Submit the form
            fetch(currentUrl, {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                console.log('Response data:', data);
                if (data.status === 'success' && data.redirect_url) {
                    window.location.href = data.redirect_url;
                } else {
                    showError('An error occurred while processing your order');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showError('An error occurred while processing your order. Please try again.');
            });
        });
    }
});