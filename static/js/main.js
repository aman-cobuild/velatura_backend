// Main JavaScript file for the DocuSign Integration application

document.addEventListener('DOMContentLoaded', function() {
    console.log('DocuSign Integration App initialized');
    
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
    
    // File input enhancement
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            const fileName = e.target.files[0] ? e.target.files[0].name : 'No file chosen';
            const fileLabel = input.nextElementSibling;
            if (fileLabel && fileLabel.classList.contains('form-file-label')) {
                fileLabel.textContent = fileName;
            }
            
            // Validate file size
            if (e.target.files[0] && e.target.files[0].size > 16 * 1024 * 1024) { // 16MB
                alert('File size exceeds the maximum limit of 16MB. Please choose a smaller file.');
                input.value = '';
                if (fileLabel && fileLabel.classList.contains('form-file-label')) {
                    fileLabel.textContent = 'No file chosen';
                }
            }
        });
    });
    
    // Poll for envelope status if on the sign page
    if (window.location.pathname.includes('/sign')) {
        const statusCheckInterval = setInterval(() => {
            fetch('/status')
                .then(response => response.json())
                .catch(error => {
                    console.error('Error checking status:', error);
                });
        }, 30000); // Check every 30 seconds
        
        // Clear interval when leaving the page
        window.addEventListener('beforeunload', () => {
            clearInterval(statusCheckInterval);
        });
    }
});

// Function to check document status (can be called from templates)
function checkDocumentStatus() {
    fetch('/status')
        .then(response => {
            if (response.redirected) {
                window.location.href = response.url;
            }
        })
        .catch(error => {
            console.error('Error checking status:', error);
        });
}

// Confirm before deleting or canceling important actions
function confirmAction(message = 'Are you sure you want to proceed?') {
    return confirm(message);
}
