document.addEventListener('DOMContentLoaded', () => {
    // Select main elements
    const scanForm = document.getElementById('scan-form');
    const scannerDiv = document.getElementById('scanner');
    const urlInput = document.getElementById('urlInput');
    const checkButton = document.getElementById('checkButton');
    const scanAnotherButtons = document.querySelectorAll('.scan-another');
    
    // Select the unified result container and its parts
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

    const apiUrl = 'http://127.0.0.1:5000/predict';

    const handleScan = () => {
        const urlToCheck = urlInput.value.trim();
        if (!urlToCheck) {
            alert('Please enter a URL to scan.');
            return;
        }

        scanForm.classList.add('hidden');
        resultContainer.classList.add('hidden');
        scannerDiv.classList.remove('hidden');

        const isPhishing = Math.random() > 0.4;
        const scanDuration = (Math.random() * 1.5 + 0.5).toFixed(2);
        const confidence = isPhishing ? (Math.random() * 15 + 85) : (Math.random() * 10 + 90);
        
        const fakeResult = {
            result: isPhishing ? 'Phishing' : 'Legitimate',
            scannedUrl: urlToCheck,
            scanDuration: `${scanDuration}s`,
            confidence: confidence.toFixed(2),
            assessments: {
                unencryptedHttp: isPhishing ? Math.random() > 0.7 : false,
                suspiciousDomain: isPhishing ? Math.random() > 0.5 : false,
                recentlyRegistered: isPhishing ? Math.random() > 0.6 : false,
                knownPatterns: isPhishing ? Math.random() > 0.5 : false,
            }
        };

        setTimeout(() => {
            displayResult(fakeResult);
        }, 2000);
    };

    const displayResult = (data) => {
        scannerDiv.classList.add('hidden');
        resultContainer.classList.remove('hidden');
        
        // 1. Update Header
        resultHeader.classList.remove('safe', 'danger');
        if (data.result === 'Phishing') {
            resultHeader.classList.add('danger');
            resultIcon.className = 'fas fa-exclamation-triangle';
            // Set text and data-text attribute for glitch
            resultTitle.textContent = 'Potential Risk Detected';
            resultTitle.setAttribute('data-text', 'Potential Risk Detected');
        } else {
            resultHeader.classList.add('safe');
            resultIcon.className = 'fas fa-check-circle';
            // Set text and data-text attribute for glitch
            resultTitle.textContent = 'URL is Safe';
            resultTitle.setAttribute('data-text', 'URL is Safe');
        }

        // 2. Populate Summary
        scannedUrlText.textContent = data.scannedUrl;
        scanDurationText.textContent = data.scanDuration;

        // 3. Update Confidence Score
        confidenceText.textContent = `${data.confidence}% Confidence`;
        confidenceFill.style.width = `${data.confidence}%`;
        confidenceFill.className = 'progress-fill';
        confidenceFill.classList.add(data.result === 'Phishing' ? 'danger' : 'safe');

        // 4. Build Assessment Grid
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
