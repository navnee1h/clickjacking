/**
 * Popup Logic - Minimalist Redesign
 */

let currentUrl = '';
let currentDomain = '';

const THREAT_LABELS = {
    'good': 'Safe',
    'suspicious': 'Warning',
    'clickjacking': 'Danger'
};

document.addEventListener('DOMContentLoaded', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs[0];
        if (!tab) return;

        currentUrl = tab.url;
        currentDomain = extractDomain(currentUrl);

        const tabId = tab.id.toString();

        chrome.storage.local.get([tabId], (result) => {
            const data = result[tabId];

            if (data && !data.error) {
                renderResults(data);
                updateWhitelistUI(data);
            } else {
                fetchLatest(tab.id);
            }
        });
    });
});

function fetchLatest(tabId) {
    chrome.tabs.sendMessage(tabId, { type: "TRIGGER_SCAN" }, (response) => {
        if (chrome.runtime.lastError) {
            showError("Tab not responding");
        } else {
            setTimeout(() => {
                chrome.storage.local.get([tabId.toString()], (reResult) => {
                    const data = reResult[tabId.toString()];
                    if (data) {
                        renderResults(data);
                        updateWhitelistUI(data);
                    } else {
                        showError("Analysis in progress...");
                    }
                });
            }, 1000);
        }
    });
}

function renderResults(data) {
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('content').classList.remove('hidden');

    const pred = data.prediction;
    const threatValue = document.getElementById('threat-value');
    const statusBadge = document.getElementById('status-badge');
    const statusDot = document.getElementById('status-dot');
    const confidenceVal = document.getElementById('confidence-val');
    const indicatorsList = document.getElementById('indicators-list');

    threatValue.textContent = THREAT_LABELS[pred] || 'Unknown';
    statusBadge.textContent = THREAT_LABELS[pred] || 'Unknown';
    statusDot.className = `status-dot ${pred}`;
    confidenceVal.textContent = data.confidence;

    indicatorsList.innerHTML = '';
    if (data.reasons && data.reasons.length > 0) {
        data.reasons.forEach(reason => {
            const item = document.createElement('div');
            item.className = 'reason-item';
            item.textContent = reason;
            indicatorsList.appendChild(item);
        });
    } else {
        const empty = document.createElement('div');
        empty.style.color = '#ccc';
        empty.style.fontSize = '12px';
        empty.textContent = 'No structural threats identified';
        indicatorsList.appendChild(empty);
    }
}

async function updateWhitelistUI(data) {
    const whitelistSection = document.getElementById('whitelist-section');
    const whitelistDomainEl = document.getElementById('whitelist-domain');
    const whitelistLabel = document.getElementById('whitelist-label');
    const actionBtn = document.getElementById('action-btn');

    if (!currentDomain) {
        whitelistSection.classList.add('hidden');
        return;
    }

    whitelistSection.classList.remove('hidden');
    whitelistDomainEl.textContent = currentDomain;

    const isWhitelisted = await isParentDomainWhitelisted(currentUrl);
    const customWhitelist = await getCustomWhitelist();
    const isCustom = customWhitelist.includes(currentDomain);
    const isDefault = DEFAULT_WHITELISTED_DOMAINS.includes(currentDomain);

    if (isWhitelisted) {
        if (isDefault) {
            whitelistLabel.textContent = 'Permanently whitelisted domain';
            actionBtn.classList.add('hidden');
        } else if (isCustom) {
            whitelistLabel.textContent = 'Added by user';
            actionBtn.classList.remove('hidden');
            actionBtn.className = 'btn btn-remove';
            actionBtn.textContent = 'Remove Trust';

            actionBtn.onclick = async () => {
                await removeFromWhitelist(currentDomain);
                chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    if (tabs && tabs[0]) chrome.tabs.reload(tabs[0].id);
                    window.close();
                });
            };
        }
    } else {
        if (data.prediction && data.prediction !== 'good') {
            actionBtn.classList.remove('hidden');
            actionBtn.className = 'btn btn-trust';
            actionBtn.textContent = 'Trust this Site';
            whitelistLabel.textContent = 'Flagged as ' + (data.prediction === 'clickjacking' ? 'Danger' : 'Warning');

            actionBtn.onclick = async () => {
                await addToWhitelist(currentDomain);
                chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    if (tabs && tabs[0]) chrome.tabs.reload(tabs[0].id);
                    window.close();
                });
            };
        } else {
            whitelistSection.classList.add('hidden');
        }
    }
}

function showError(msg) {
    const loading = document.getElementById('loading');
    loading.innerHTML = `<p style="text-align: center; color: #e74c3c; font-size: 12px;">${msg}</p>`;
}
