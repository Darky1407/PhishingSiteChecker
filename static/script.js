document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scan-form');
    const scannerDiv = document.getElementById('scanner');
    const urlInput = document.getElementById('urlInput');
    const checkButton = document.getElementById('checkButton');
    const scanAnotherButtons = document.querySelectorAll('.scan-another');

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

    const apiUrl = '/predict';

    const handleScan = () => {
        const urlToCheck = urlInput.value.trim();
        if (!urlToCheck) return alert('Enter a URL');

        scanForm.classList.add('hidden');
        resultContainer.classList.add('hidden');
        scannerDiv.classList.remove('hidden');

        const startTime = Date.now();

        fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlToCheck })
        })
        .then(res => res.json())
        .then(data => {
            const duration = ((Date.now() - startTime)/1000).toFixed(2) + 's';
            const resultData = {
                result: data.result,
                scannedUrl: data.url,
                scanDuration: duration,
                confidence: data.confidence,
                assessments: {
                    unencryptedHttp: data.https === 0,
                    suspiciousDomain: data.phishing_prob > 60
                }
            };
            displayResult(resultData);
        })
        .catch(err => {
            scannerDiv.classList.add('hidden');
            scanForm.classList.remove('hidden');
            alert('Error: ' + err);
        });
    };

    const displayResult = (data) => {
        scannerDiv.classList.add('hidden');
        resultContainer.classList.remove('hidden');

        resultHeader.classList.remove('safe', 'danger');
        if (data.result === 'Phishing') {
            resultHeader.classList.add('danger');
            resultIcon.className = 'fas fa-exclamation-triangle';
            resultTitle.textContent = 'Potential Risk Detected';
        } else {
            resultHeader.classList.add('safe');
            resultIcon.className = 'fas fa-check-circle';
            resultTitle.textContent = 'URL is Safe';
        }

        scannedUrlText.textContent = data.scannedUrl;
        scanDurationText.textContent = data.scanDuration;

        confidenceText.textContent = `${data.confidence}% Confidence`;
        confidenceFill.style.width = `${data.confidence}%`;
        confidenceFill.className = 'progress-fill';
        confidenceFill.classList.add(data.result === 'Phishing' ? 'danger' : 'safe');

        assessmentGrid.innerHTML = '';
        if (data.result === 'Phishing') {
            assessmentSection.classList.remove('hidden');
            const assessmentMap = {
                unencryptedHttp: { icon: 'fa-unlock', text: 'Unencrypted HTTP', type: 'danger' },
                suspiciousDomain: { icon: 'fa-file-signature', text: 'Suspicious Domain', type: 'warning' }
            };
            let delay = 0;
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

    scanAnotherButtons.forEach(btn => btn.addEventListener('click', resetUI));
    checkButton.addEventListener('click', handleScan);
    urlInput.addEventListener('keypress', e => { if (e.key === 'Enter') handleScan(); });
});
