/**
 * Alert UI Component - Managed through manifest.json
 */

function popSecurityAlert(prediction, reasons) {
    if (document.getElementById('shield-blur-overlay')) return;

    const isEvil = prediction === 'clickjacking';

    // 1. Create Blur Overlay
    const overlay = document.createElement('div');
    overlay.id = 'shield-blur-overlay';
    document.documentElement.appendChild(overlay);

    // 2. Create Banner
    const banner = document.createElement('div');
    banner.id = 'shield-top-banner';
    banner.innerHTML = `
        <div class="shield-info-group">
            <div class="shield-icon">${isEvil ? '🚨' : '🛡️'}</div>
            <div class="shield-text-stack">
                <span class="shield-title">Extension Security Alert</span>
                <span class="shield-subtitle">Structural anomalies identified on this resource</span>
            </div>
        </div>
        
        <div class="shield-action-group">
            <button id="shield-trust-cta" class="shield-btn shield-btn-trust">Trust Site</button>
            <button id="shield-back-cta" class="shield-btn shield-btn-black">Return to Safety</button>
            <button id="shield-ignore-cta" class="shield-btn shield-btn-ghost">Ignore</button>
        </div>
    `;
    document.documentElement.appendChild(banner);

    // 3. Trigger Animations
    setTimeout(() => {
        overlay.classList.add('active');
        banner.classList.add('active');
    }, 50);

    // 4. Handle Actions
    document.getElementById('shield-back-cta').onclick = () => {
        window.history.back();
        if (window.history.length <= 1) window.close();
    };

    document.getElementById('shield-trust-cta').onclick = async () => {
        if (typeof extractDomain === 'function' && typeof addToWhitelist === 'function') {
            const domain = extractDomain(window.location.href);
            if (domain) {
                await addToWhitelist(domain);
                // Reload to apply whitelist
                window.location.reload();
            }
        }
    };

    document.getElementById('shield-ignore-cta').onclick = () => {
        banner.classList.remove('active');
        overlay.classList.remove('active');
        setTimeout(() => {
            banner.remove();
            overlay.remove();
        }, 800);
    };
}

// Ensure the helper is available globally to content.js
window.popSecurityAlert = popSecurityAlert;

// Also listen for cleanup requests
chrome.runtime.onMessage.addListener((request) => {
    if (request.type === "REMOVE_BLUR") {
        const btn = document.getElementById('shield-ignore-cta');
        if (btn) btn.click();
    }
});
