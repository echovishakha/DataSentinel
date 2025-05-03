// AI Safeguard: main JavaScript functionality

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Text analysis functionality
    const analyzeBtn = document.getElementById('analyze-btn');
    const clearBtn = document.getElementById('clear-btn');
    const textInput = document.getElementById('text-input');
    const resultsContainer = document.getElementById('results-container');
    const sensitiveCounter = document.getElementById('sensitive-counter');
    const confidenceLevel = document.getElementById('confidence-level');
    const configSelector = document.getElementById('config-selector');
    
    if (analyzeBtn && textInput) {
        analyzeBtn.addEventListener('click', function() {
            analyzeText();
        });
        
        // Add clear button functionality
        if (clearBtn) {
            clearBtn.addEventListener('click', function() {
                textInput.value = '';
                resultsContainer.innerHTML = '';
                sensitiveCounter.innerText = '0';
                confidenceLevel.innerText = 'Low';
                confidenceLevel.className = 'badge bg-success';
                showAlert('Text cleared successfully', 'info');
            });
        }
        
        // Also analyze on enter key in text area (with shift+enter for newline)
        textInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                analyzeText();
            }
        });
    }
    
    // Function to analyze text
    function analyzeText() {
        const text = textInput.value.trim();
        
        if (!text) {
            showAlert('Please enter some text to analyze', 'warning');
            return;
        }
        
        // Show loading state
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Analyzing...';
        
        // Prepare form data
        const formData = new FormData();
        formData.append('text', text);
        
        // Include selected configuration if available
        if (configSelector) {
            formData.append('config_id', configSelector.value);
        }
        
        // Send request to server
        fetch('/analyze', {
            method: 'POST',
            body: formData,
            headers: {
                'Accept': 'application/json',
                // No need to set Content-Type with FormData, browser sets it automatically with boundary
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok: ' + response.status);
            }
            return response.json();
        })
        .then(data => {
            displayResults(data, text);
        })
        .catch(error => {
            console.error('Error:', error);
            showAlert('Error analyzing text: ' + error.message, 'danger');
        })
        .finally(() => {
            // Reset button state
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = 'Analyze Text';
        });
    }
    
    // Function to display analysis results
    function displayResults(data, originalText) {
        if (!resultsContainer) return;
        
        // Check if there was an error in the response
        if (data.error) {
            showAlert(data.error, 'danger');
            return;
        }
        
        // Clear previous results
        resultsContainer.innerHTML = '';
        
        // Create results card
        const card = document.createElement('div');
        card.className = 'card mb-4';
        
        // Card header with risk level
        const cardHeader = document.createElement('div');
        cardHeader.className = 'card-header d-flex justify-content-between align-items-center';
        
        const riskBadge = document.createElement('span');
        riskBadge.className = `badge ${getRiskBadgeClass(data.risk_level)}`;
        riskBadge.textContent = `Risk Level: ${data.risk_level}`;
        
        const detectionCount = document.createElement('span');
        detectionCount.textContent = `${getTotalDetections(data.detections)} sensitive elements detected`;
        
        cardHeader.appendChild(riskBadge);
        cardHeader.appendChild(detectionCount);
        
        // Card body with highlighted text
        const cardBody = document.createElement('div');
        cardBody.className = 'card-body';
        
        // Create highlighted text
        const highlightedText = document.createElement('div');
        highlightedText.className = 'highlighted-text mb-4';
        highlightedText.innerHTML = getHighlightedText(originalText, data.detections);
        
        // Create detected items section
        const detectedItemsHeading = document.createElement('h5');
        detectedItemsHeading.className = 'mt-4 mb-3';
        detectedItemsHeading.textContent = 'Detected Sensitive Information';
        
        const detectedItems = document.createElement('div');
        detectedItems.className = 'detected-items';
        
        // Add each category of detections
        for (const [category, items] of Object.entries(data.detections)) {
            if (items.length > 0) {
                const categorySection = document.createElement('div');
                categorySection.className = 'mb-3';
                
                const categoryHeading = document.createElement('h6');
                categoryHeading.className = 'text-capitalize';
                categoryHeading.textContent = category.replace('_', ' ');
                
                const itemsList = document.createElement('ul');
                itemsList.className = 'list-group';
                
                items.forEach(item => {
                    const listItem = document.createElement('li');
                    listItem.className = 'list-group-item d-flex justify-content-between align-items-center';
                    
                    // Create censored version of sensitive data
                    const censoredText = censorSensitiveData(item.value, item.type);
                    
                    listItem.innerHTML = `
                        <div>
                            <strong>${item.type}:</strong> 
                            <code>${censoredText}</code>
                        </div>
                        <span class="badge ${getSeverityBadgeClass(item.severity)}">${item.severity}</span>
                    `;
                    
                    itemsList.appendChild(listItem);
                });
                
                categorySection.appendChild(categoryHeading);
                categorySection.appendChild(itemsList);
                detectedItems.appendChild(categorySection);
            }
        }
        
        // Add classification section if available
        if (data.classification) {
            const classificationSection = document.createElement('div');
            classificationSection.className = 'mt-4';
            
            const classificationHeading = document.createElement('h5');
            classificationHeading.className = 'mb-3';
            classificationHeading.textContent = 'Content Classification';
            
            const classificationList = document.createElement('ul');
            classificationList.className = 'list-group';
            
            for (const [category, confidence] of Object.entries(data.classification)) {
                const listItem = document.createElement('li');
                listItem.className = 'list-group-item d-flex justify-content-between align-items-center';
                
                const confidencePercentage = (confidence * 100).toFixed(1);
                const confidenceBadge = getConfidenceBadge(confidence);
                
                listItem.innerHTML = `
                    <span class="text-capitalize">${category.replace('_', ' ')}</span>
                    <div>
                        <div class="progress" style="width: 150px;">
                            <div class="progress-bar ${getProgressBarClass(confidence)}" 
                                 role="progressbar" 
                                 style="width: ${confidencePercentage}%" 
                                 aria-valuenow="${confidencePercentage}" 
                                 aria-valuemin="0" 
                                 aria-valuemax="100">
                                ${confidencePercentage}%
                            </div>
                        </div>
                    </div>
                `;
                
                classificationList.appendChild(listItem);
            }
            
            classificationSection.appendChild(classificationHeading);
            classificationSection.appendChild(classificationList);
            
            cardBody.appendChild(highlightedText);
            cardBody.appendChild(detectedItemsHeading);
            cardBody.appendChild(detectedItems);
            cardBody.appendChild(classificationSection);
        } else {
            cardBody.appendChild(highlightedText);
            cardBody.appendChild(detectedItemsHeading);
            cardBody.appendChild(detectedItems);
        }
        
        // Add recommendations if provided
        if (data.recommendations && data.recommendations.length > 0) {
            const recommendationsSection = document.createElement('div');
            recommendationsSection.className = 'mt-4';
            
            const recommendationsHeading = document.createElement('h5');
            recommendationsHeading.className = 'mb-3';
            recommendationsHeading.textContent = 'Recommendations';
            
            const recommendationsList = document.createElement('ul');
            recommendationsList.className = 'list-group';
            
            data.recommendations.forEach(recommendation => {
                const listItem = document.createElement('li');
                listItem.className = 'list-group-item';
                listItem.innerHTML = `<i class="fas fa-info-circle me-2 text-primary"></i> ${recommendation}`;
                recommendationsList.appendChild(listItem);
            });
            
            recommendationsSection.appendChild(recommendationsHeading);
            recommendationsSection.appendChild(recommendationsList);
            cardBody.appendChild(recommendationsSection);
        }
        
        // Assemble the card
        card.appendChild(cardHeader);
        card.appendChild(cardBody);
        
        // Add to results container
        resultsContainer.appendChild(card);
        
        // Update counters if they exist
        if (sensitiveCounter) {
            sensitiveCounter.textContent = getTotalDetections(data.detections);
        }
        
        if (confidenceLevel) {
            confidenceLevel.textContent = data.risk_level;
            confidenceLevel.className = `badge ${getRiskBadgeClass(data.risk_level)}`;
        }
        
        // Scroll to results
        resultsContainer.scrollIntoView({ behavior: 'smooth' });
    }
    
    // Helper function to get total number of detections
    function getTotalDetections(detections) {
        let total = 0;
        for (const category in detections) {
            total += detections[category].length;
        }
        return total;
    }
    
    // Helper function to highlight text with detected sensitive data
    function getHighlightedText(text, detections) {
        // Combine all detections into a single array
        let allDetections = [];
        for (const category in detections) {
            detections[category].forEach(item => {
                allDetections.push({
                    value: item.value,
                    start: item.position.start,
                    end: item.position.end,
                    severity: item.severity
                });
            });
        }
        
        // Sort by start position, in reverse order to avoid index shifting
        allDetections.sort((a, b) => b.start - a.start);
        
        // Convert text to HTML safe string
        let safeText = text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
        
        // Insert highlight spans around each detection
        allDetections.forEach(detection => {
            const before = safeText.substring(0, detection.start);
            const sensitive = safeText.substring(detection.start, detection.end);
            const after = safeText.substring(detection.end);
            
            const severityClass = getSeverityClass(detection.severity);
            
            safeText = before + 
                      `<span class="sensitive-text ${severityClass}" 
                             title="${detection.severity} risk">` + 
                      sensitive + 
                      `</span>` + 
                      after;
        });
        
        // Replace newlines with <br> tags
        return safeText.replace(/\n/g, '<br>');
    }
    
    // Helper function to get severity CSS class
    function getSeverityClass(severity) {
        switch (severity.toLowerCase()) {
            case 'high':
                return 'sensitive-text-high';
            case 'medium':
                return 'sensitive-text-medium';
            case 'low':
                return 'sensitive-text-low';
            default:
                return '';
        }
    }
    
    // Helper function to get risk badge CSS class
    function getRiskBadgeClass(risk) {
        switch (risk.toLowerCase()) {
            case 'high':
                return 'bg-danger';
            case 'medium':
                return 'bg-warning text-dark';
            case 'low':
                return 'bg-success';
            default:
                return 'bg-secondary';
        }
    }
    
    // Helper function to get severity badge CSS class
    function getSeverityBadgeClass(severity) {
        switch (severity.toLowerCase()) {
            case 'high':
                return 'bg-danger';
            case 'medium':
                return 'bg-warning text-dark';
            case 'low':
                return 'bg-info';
            default:
                return 'bg-secondary';
        }
    }
    
    // Helper function to get confidence badge
    function getConfidenceBadge(confidence) {
        if (confidence > 0.7) {
            return 'bg-danger';
        } else if (confidence > 0.4) {
            return 'bg-warning text-dark';
        } else {
            return 'bg-info';
        }
    }
    
    // Helper function to get progress bar class
    function getProgressBarClass(confidence) {
        if (confidence > 0.7) {
            return 'bg-danger';
        } else if (confidence > 0.4) {
            return 'bg-warning';
        } else {
            return 'bg-info';
        }
    }
    
    // Helper function to censor sensitive data
    function censorSensitiveData(value, type) {
        if (!value) return '';
        
        switch (type.toLowerCase()) {
            case 'credit card':
                // Show only last 4 digits
                return '••••-••••-••••-' + value.slice(-4);
            case 'api key':
            case 'password':
            case 'access token':
                // Show first and last 3 characters
                if (value.length <= 6) {
                    return '•'.repeat(value.length);
                }
                return value.slice(0, 3) + '•'.repeat(value.length - 6) + value.slice(-3);
            case 'email':
                // Show username initial and domain
                const parts = value.split('@');
                if (parts.length !== 2) return value;
                return parts[0].charAt(0) + '•'.repeat(parts[0].length - 1) + '@' + parts[1];
            default:
                // By default, show 30% of the beginning and end
                const visiblePart = Math.max(1, Math.floor(value.length * 0.3));
                const hiddenPart = value.length - (visiblePart * 2);
                if (hiddenPart <= 0) return value;
                return value.slice(0, visiblePart) + '•'.repeat(hiddenPart) + value.slice(-visiblePart);
        }
    }
    
    // Function to show alerts
    function showAlert(message, type = 'info') {
        const alertsContainer = document.getElementById('alerts-container');
        if (!alertsContainer) return;
        
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} alert-dismissible fade show`;
        alert.setAttribute('role', 'alert');
        
        alert.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        alertsContainer.appendChild(alert);
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    }
    
    // Configuration form validation
    const configForm = document.getElementById('config-form');
    if (configForm) {
        configForm.addEventListener('submit', function(event) {
            if (!configForm.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            configForm.classList.add('was-validated');
        });
    }
    
    // Sample demonstration texts
    const demoApiKeyBtn = document.getElementById('demo-api-key');
    const demoPersonalInfoBtn = document.getElementById('demo-personal-info');
    const demoCompanyInfoBtn = document.getElementById('demo-company-info');
    
    if (demoApiKeyBtn && textInput) {
        demoApiKeyBtn.addEventListener('click', function() {
            textInput.value = `I'm having trouble with the API integration. 
Here's my API key: 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

Can you help me debug why my requests are being rejected?`;
            textInput.focus();
        });
    }
    
    if (demoPersonalInfoBtn && textInput) {
        demoPersonalInfoBtn.addEventListener('click', function() {
            textInput.value = `Hi support team,

I recently created an account with the following details:
Name: Sarah Johnson
Email: sarah.johnson@example.com
Phone: (555) 123-4567
DOB: 04/25/1985
SSN: 123-45-6789
Address: 742 Evergreen Terrace, Springfield, IL 62701

I'm having trouble accessing my account. Can you help me reset my password?`;
            textInput.focus();
        });
    }
    
    if (demoCompanyInfoBtn && textInput) {
        demoCompanyInfoBtn.addEventListener('click', function() {
            textInput.value = `To: team@acmetech.com
Subject: Upcoming Product Launch Details

Team,

Here's an update on our confidential product launch:

- Launch Date: November 15, 2023
- Target Revenue: $4.5M first quarter
- Marketing Budget: $850K
- Primary Competitors: WidgetCorp, TechGiant

Our internal forecast shows we'll capture 15% market share in the enterprise segment.

The login for our sales portal is:
Username: admin_sales
Password: AcmeTech2023!

Please keep this information confidential.

John`;
            textInput.focus();
        });
    }
});
