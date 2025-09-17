document.addEventListener('DOMContentLoaded', () => {
    // Main elements
    const scanForm = document.getElementById('scan-form');
    const scannerDiv = document.getElementById('scanner');
    const urlInput = document.getElementById('urlInput');
    const checkButton = document.getElementById('checkButton');
    const scanAnotherButtons = document.querySelectorAll('.scan-another');

    // Result elements
    const resultContainer = document.getElementById('result-container');
    const resultHeader = document.getElementById('result-header');
    const resultIcon = document.getElementById('result-icon');
    const resultTitle = document.getElementById('result-title');
    const scannedUrlText = document.getElementById('scanned-url');
    const scanDurationText = document.getElementById('scan-duration');
    const confidenceFill = document.getElementById('confidence-fill');
    const confidenceText = document.getElementById('confidence-text');
    const assessmentGrid = document.getElementById('assessment-grid');
    const assessmentSection = document.getElementById('assessment-section');

    const apiUrl = '/predict'; // Flask endpoint

    const handleScan = () => {
        const urlToCheck = urlInput.value.trim();
        if (!urlToCheck) {
            alert('Please enter a URL to scan.');
            return;
        }

        // Show loader
        scanForm.classList.add('hidden');
        resultContainer.classList.add('hidden');
        scannerDiv.classList.remove('hidden');

        const startTime = Date.now();

        fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlToCheck })
        })
        .then(response => response.json())
        .then(data => {
            const endTime = Date.now();
            const duration = ((endTime - startTime)/1000).toFixed(2) + 's';

            // Build data object for display
            const resultData = {
                result: data.result,
                scannedUrl: data.url,
                scanDuration: duration,
                confidence: data.confidence,
                assessments: {
                    unencryptedHttp: data.https === 0,
                    suspiciousDomain: data.phishing_prob > 60,
                    recentlyRegistered: false,
                    knownPatterns: false
                }
            };

            displayResult(resultData);
        })
        .catch(err => {
            scannerDiv.classList.add('hidden');
            scanForm.classList.remove('hidden');
            alert('Error scanning URL: ' + err);
        });
    };

    const displayResult = (data) => {
        scannerDiv.classList.add('hidden');
        resultContainer.classList.remove('hidden');

        // Header
        resultHeader.classList.remove('safe', 'danger');
        if (data.result === 'Phishing') {
            resultHeader.classList.add('danger');
            resultIcon.className = 'fas fa-exclamation-triangle';
            resultTitle.textContent = 'Potential Risk Detected';
            resultTitle.setAttribute('data-text', 'Potential Risk Detected');
        } else {
            resultHeader.classList.add('safe');
            resultIcon.className = 'fas fa-check-circle';
            resultTitle.textContent = 'URL is Safe';
            resultTitle.setAttribute('data-text', 'URL is Safe');
        }

        // Summary
        scannedUrlText.textContent = data.scannedUrl;
        scanDurationText.textContent = data.scanDuration;

        // Confidence
        confidenceText.textContent = `${data.confidence}% Confidence`;
        confidenceFill.style.width = `${data.confidence}%`;
        confidenceFill.className = 'progress-fill';
        confidenceFill.classList.add(data.result === 'Phishing' ? 'danger' : 'safe');

        // Assessment grid
        assessmentGrid.innerHTML = '';
        if (data.result === 'Phishing') {
            assessmentSection.classList.remove('hidden');
            let delay = 0;
            const assessmentMap = {
                unencryptedHttp: { icon: 'fa-unlock', text: 'Unencrypted HTTP', type: 'danger' },
                suspiciousDomain: { icon: 'fa-file-signature', text: 'Suspicious Domain', type: 'warning' },
                recentlyRegistered: { icon: 'fa-calendar-day', text: 'Recently Registered', type: 'warning' },
                knownPatterns: { icon: 'fa-user-secret', text: 'Known Phishing Patterns', type: 'danger' }
            };

            for (const key in data.assessments) {
                if (data.assessments[key]) {
                    const details = assessmentMap[key];
                    const item = document.createElement('div');
                    item.className = 'assessment-item';
                    item.style.animationDelay = `${delay}ms`;
                    item.innerHTML = `<i class="fas ${details.icon} icon-${details.type}"></i> ${details.text}`;
                    assessmentGrid.appendChild(item);
                    delay += 150;
                }
            }
        } else {
            assessmentSection.classList.add('hidden');
        }
    };

    const resetUI = () => {
        resultContainer.classList.add('hidden');
        scannerDiv.classList.add('hidden');
        scanForm.classList.remove('hidden');
        urlInput.value = '';
    };

    scanAnotherButtons.forEach(button => button.addEventListener('click', resetUI));
    checkButton.addEventListener('click', handleScan);
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleScan();
    });
});
