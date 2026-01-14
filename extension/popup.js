/**
 * Popup Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs[0];
        if (!tab) return;

        const tabId = tab.id.toString();

        chrome.storage.local.get([tabId], (result) => {
            const data = result[tabId];

            if (data && !data.error) {
                renderResults(data);
            } else {
                // If no data, ask content script to scan immediately
                chrome.tabs.sendMessage(tab.id, { type: "TRIGGER_SCAN" }, (response) => {
                    if (chrome.runtime.lastError) {
                        showError("Could not connect to page. Refresh the page and try again.");
                    } else {
                        // Wait briefly for background script to process result
                        setTimeout(() => {
                            chrome.storage.local.get([tabId], (reResult) => {
                                if (reResult[tabId]) renderResults(reResult[tabId]);
                                else showError("Still analyzing... please wait.");
                            });
                        }, 1000);
                    }
                });
            }
        });
    });
});

function renderResults(data) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('content').style.display = 'block';

    const resultText = document.getElementById('result-text');
    const statusBadge = document.getElementById('status-badge');
    const confidenceVal = document.getElementById('confidence-val');
    const reasonsList = document.getElementById('reasons-list');

    // Classification mapping
    const pred = data.prediction;
    const labels = {
        'good': 'Safe',
        'suspicious': 'Warning',
        'clickjacking': 'Danger'
    };

    // Apply dynamic colors to body and text
    document.body.className = pred;
    resultText.innerText = labels[pred];
    resultText.className = `card-value ${pred}`;

    statusBadge.innerText = labels[pred];
    statusBadge.className = `status-pill ${pred}`;
    confidenceVal.innerText = data.confidence;

    // Clean up reasons list
    reasonsList.innerHTML = '';
    if (data.reasons && data.reasons.length > 0) {
        data.reasons.forEach(reason => {
            const item = document.createElement('div');
            item.className = 'finding-row';
            item.innerHTML = `
                <div class="dot"></div>
                <div>${reason}</div>
            `;
            reasonsList.appendChild(item);
        });
    } else {
        reasonsList.innerHTML = '<div style="color: var(--text-muted); font-size: 13px; text-align: center; padding: 20px; background: var(--surface); border-radius: 12px; border: 1px dashed var(--border);">No structural threats identified.</div>';
    }
}

function showError(msg) {
    document.getElementById('loading').innerText = `Error: ${msg}`;
    document.getElementById('loading').style.color = '#ef4444';
}
