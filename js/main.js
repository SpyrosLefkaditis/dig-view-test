document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('dnsForm');
    const resolverSelect = document.getElementById('resolver');
    const customResolverDiv = document.getElementById('customResolver');
    const customResolverInput = document.getElementById('customResolverInput');
    const resultsDiv = document.getElementById('results');
    const resultsBody = document.getElementById('resultsBody');

    // Handle custom resolver selection
    resolverSelect.addEventListener('change', function() {
        if (this.value === 'custom') {
            customResolverDiv.style.display = 'block';
            customResolverInput.required = true;
        } else {
            customResolverDiv.style.display = 'none';
            customResolverInput.required = false;
        }
    });

    // Validate custom resolver IP
    customResolverInput.addEventListener('input', function() {
        const ipPattern = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (this.value && !ipPattern.test(this.value)) {
            this.setCustomValidity('Please enter a valid IPv4 address');
        } else {
            this.setCustomValidity('');
        }
    });

    // Handle form submission
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const formData = new FormData(form);
        if (resolverSelect.value === 'custom') {
            formData.set('resolver', customResolverInput.value);
        }

        // Show loading state
        const submitButton = form.querySelector('button[type="submit"]');
        const originalButtonText = submitButton.innerHTML;
        submitButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Querying...';
        submitButton.disabled = true;

        // Send AJAX request
        fetch('backend.php', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            // Display results
            resultsDiv.style.display = 'block';
            resultsBody.innerHTML = '';
            
            if (data.records && data.records.length > 0) {
                data.records.forEach(record => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${record.record}</td>
                        <td>${record.geolocation || 'N/A'}</td>
                    `;
                    resultsBody.appendChild(row);
                });
            } else {
                resultsBody.innerHTML = '<tr><td colspan="2" class="text-center">No records found</td></tr>';
            }
        })
        .catch(error => {
            console.error('Error:', error);
            resultsBody.innerHTML = '<tr><td colspan="2" class="text-center text-danger">An error occurred while processing your request</td></tr>';
        })
        .finally(() => {
            // Reset button state
            submitButton.innerHTML = originalButtonText;
            submitButton.disabled = false;
        });
    });
}); 