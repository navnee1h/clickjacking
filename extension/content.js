/**
 * Content Script for Clickjacking Detection
 */

let clickMismatch = 0;

/**
 * Check if an iframe URL is from a trusted domain
 * @param {string} url - The iframe src URL
 * @returns {boolean} - True if from trusted domain or same-origin
 */
function isFromTrustedDomain(url) {
    if (!url) return true; // Empty src is not suspicious

    // Whitelist of trusted domains for common legitimate iframe sources
    const trustedDomains = [
        // Video players
        'youtube.com', 'youtube-nocookie.com', 'youtu.be',
        'vimeo.com', 'dailymotion.com', 'twitch.tv',
        // Payment/Commerce
        'paypal.com', 'stripe.com', 'shopify.com', 'checkout.shopify.com',
        // Social media embeds
        'facebook.com', 'fb.com', 'twitter.com', 'platform.twitter.com',
        'instagram.com', 'linkedin.com',
        // Analytics/Ads (legitimate)
        'google.com', 'doubleclick.net', 'googlesyndication.com',
        'googletagmanager.com', 'facebook.net', 'google-analytics.com',
        // Maps
        'openstreetmap.org', 'mapbox.com'
    ];

    try {
        // Handle data: and blob: URLs (often used in attacks)
        if (url.startsWith('data:') || url.startsWith('blob:')) {
            return false;
        }

        // Resolve relative URLs to absolute
        const urlObj = new URL(url, window.location.href);
        const hostname = urlObj.hostname.toLowerCase();

        // Same-origin iframes are trusted
        const currentDomain = window.location.hostname.toLowerCase();
        if (hostname === currentDomain) {
            return true;
        }

        // Check if hostname matches or is a subdomain of trusted domain
        return trustedDomains.some(domain =>
            hostname === domain || hostname.endsWith('.' + domain)
        );
    } catch (e) {
        // Invalid URL
        console.warn('Invalid iframe URL:', url, e);
        return false;
    }
}

// Feature extraction logic
function extractFeatures() {
    const iframes = Array.from(document.getElementsByTagName('iframe'));
    const vw = Math.max(document.documentElement.clientWidth || 0, window.innerWidth || 0);
    const vh = Math.max(document.documentElement.clientHeight || 0, window.innerHeight || 0);
    const viewportArea = vw * vh;

    let invisibleCount = 0;
    let largeIframeCount = 0;
    let zIndexHighCount = 0;
    let pointerEventsNoneCount = 0;
    let untrustedIframeCount = 0;

    iframes.forEach(iframe => {
        const style = window.getComputedStyle(iframe);
        const rect = iframe.getBoundingClientRect();

        // 1. Check Visibility/Opacity
        const isHidden = style.display === 'none' || style.visibility === 'hidden';
        const isTransparent = parseFloat(style.opacity) < 0.1;
        if (isHidden || isTransparent) {
            invisibleCount++;
        }

        // 2. Check Size
        const area = rect.width * rect.height;
        if (area > (viewportArea * 0.5)) {
            largeIframeCount++;
        }

        // 3. Check Z-Index
        const zIndex = parseInt(style.zIndex);
        if (zIndex > 100) {
            zIndexHighCount++;
        }

        // 4. Check Pointer Events
        if (style.pointerEvents === 'none') {
            pointerEventsNoneCount++;
        }

        // 5. Check Domain Trust (NEW FEATURE)
        const src = iframe.src || iframe.getAttribute('src') || '';
        if (src && !isFromTrustedDomain(src)) {
            untrustedIframeCount++;
            console.log('Untrusted iframe detected:', src);
        }
    });

    const features = {
        iframe_count: iframes.length,
        invisible_count: invisibleCount,
        large_iframe_count: largeIframeCount,
        z_index_high_count: zIndexHighCount,
        pointer_events_none_count: pointerEventsNoneCount,
        click_mismatch: clickMismatch,
        untrusted_iframe_count: untrustedIframeCount
    };

    return features;
}

// Behavioral feature: click mismatch detection
// This is a simple heuristic: if a click happens but the target is an element 
// that is behind a transparent iframe (hard to detect perfectly without more complexity),
// or if the click is on something unexpected.
document.addEventListener('mousedown', (e) => {
    // Basic heuristic: if the click is on an iframe or close to an invisible one
    // In a real scenario, this would compare e.pageX/Y with iframe positions
    console.log("Click detected at:", e.clientX, e.clientY);

    // For the sake of this simulation/MVP, we detect if a click occurs 
    // when there are large transparent iframes present.
    const iframes = Array.from(document.getElementsByTagName('iframe'));
    iframes.forEach(iframe => {
        const style = window.getComputedStyle(iframe);
        const rect = iframe.getBoundingClientRect();
        const isTransparent = parseFloat(style.opacity) < 0.1;

        if (isTransparent &&
            e.clientX >= rect.left && e.clientX <= rect.right &&
            e.clientY >= rect.top && e.clientY <= rect.bottom) {
            clickMismatch = 1; // Click was inside a transparent iframe!
        }
    });
});

// Periodic analysis or on load
function analyzePage() {
    const features = extractFeatures();
    features.url = window.location.href;
    console.log("Extracted Features:", features);

    // Send to background script for server-side prediction
    chrome.runtime.sendMessage({ type: "ANALYZE_PAGE", features: features }, (response) => {
        if (chrome.runtime.lastError) {
            console.error("Communication error:", chrome.runtime.lastError);
        } else {
            console.log("Backend response received in content script:", response);
        }
    });
}

// Initial delay to allow page to load some elements
setTimeout(analyzePage, 2000);

// Re-analyze on significant changes or clicks
document.addEventListener('click', () => {
    setTimeout(analyzePage, 500);
});

let alertShown = false;

// Listen for trigger from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === "TRIGGER_SCAN") {
        analyzePage();
        sendResponse({ status: "scanning" });
    } else if (request.type === "SHOW_ALERT") {
        if (!alertShown) {
            showSecurityAlert(request.prediction, request.reasons);
            alertShown = true;
        }
        sendResponse({ status: "alert_processed" });
    }
});

function showSecurityAlert(prediction, reasons) {
    if (document.getElementById('cj-detector-overlay')) return;

    // Load Font
    const link = document.createElement('link');
    link.href = 'https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700&display=swap';
    link.rel = 'stylesheet';
    document.head.appendChild(link);

    const overlay = document.createElement('div');
    overlay.id = 'cj-detector-overlay';
    overlay.style.cssText = `
        position: fixed;
        top: 0; left: 0; width: 100vw; height: 100vh;
        background: rgba(248, 250, 252, 0.9);
        backdrop-filter: blur(16px);
        z-index: 2147483647;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: 'Outfit', sans-serif;
    `;

    const isEvil = prediction === 'clickjacking';
    const accentColor = isEvil ? '#dc2626' : '#ca8a04';
    const severityLabel = isEvil ? 'Security Breach' : 'Suspicious Activity';

    overlay.innerHTML = `
        <div style="width: 440px; background: #ffffff; border-radius: 32px; padding: 48px; box-shadow: 0 40px 80px -15px rgba(0,0,0,0.15); border: 1px solid #f1f5f9; text-align: center; animation: modalPop 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);">
            <div style="width: 80px; height: 80px; background: ${accentColor + '15'}; border-radius: 24px; display: flex; align-items: center; justify-content: center; margin: 0 auto 32px; animation: pulseIcon 2.5s infinite;">
                <span style="font-size: 40px;">${isEvil ? '🛡️' : '⚠️'}</span>
            </div>
            
            <h1 style="font-size: 26px; font-weight: 700; color: #0f172a; margin-bottom: 12px; letter-spacing: -0.03em;">
                Access Restricted
            </h1>
            
            <p style="font-size: 15px; color: #64748b; line-height: 1.7; margin-bottom: 32px; font-weight: 400;">
                Our analysis engine has identified <strong>${severityLabel}</strong> indicators on this resource. Navigation has been halted to prevent unauthorized interactions.
            </p>

            <div style="text-align: left; background: #f8fafc; border-radius: 20px; padding: 20px; margin-bottom: 32px; border: 1px solid #f1f5f9;">
                <div style="font-size: 10px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 12px;">Automated Analysis Brief</div>
                <div style="font-size: 13px; color: #334155; display: flex; flex-direction: column; gap: 8px;">
                    ${reasons.map(r => `<div style="display: flex; gap: 10px; align-items: flex-start;"><span style="color: ${accentColor}">•</span> ${r}</div>`).join('')}
                </div>
            </div>

            <div style="display: flex; flex-direction: column; gap: 14px;">
                <button id="go-back-safe" style="background: #0f172a; color: #ffffff; border: none; padding: 18px; border-radius: 16px; font-weight: 600; font-size: 16px; cursor: pointer; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                    Return to Safety
                </button>
                <button id="continue-anyway" style="background: transparent; color: #94a3b8; border: none; padding: 10px; font-size: 13px; font-weight: 500; cursor: pointer; transition: color 0.2s;">
                    Proceed anyway
                </button>
            </div>
            <style>
                @keyframes modalPop {
                    0% { transform: scale(0.9); opacity: 0; }
                    100% { transform: scale(1); opacity: 1; }
                }
                @keyframes pulseIcon {
                    0% { transform: scale(1); box-shadow: 0 0 0 0 ${accentColor + '40'}; }
                    70% { transform: scale(1.05); box-shadow: 0 0 0 10px ${accentColor + '00'}; }
                    100% { transform: scale(1); box-shadow: 0 0 0 0 ${accentColor + '00'}; }
                }
                #go-back-safe:hover {
                    background: #1e293b;
                    transform: translateY(-2px);
                    box-shadow: 0 8px 24px rgba(0,0,0,0.2);
                }
                #continue-anyway:hover { color: #475569; }
            </style>
        </div>
    `;

    document.documentElement.appendChild(overlay);

    document.getElementById('go-back-safe').onclick = () => {
        window.history.back();
        if (window.history.length <= 1) window.close();
    };

    document.getElementById('continue-anyway').onclick = () => {
        overlay.remove();
    };
}

