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
async function extractFeatures() {
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

    // Check if parent domain is whitelisted (reduces false positives)
    // Use async version to support custom whitelist from storage
    const isWhitelisted = await isParentDomainWhitelisted(window.location.href);

    const features = {
        iframe_count: iframes.length,
        invisible_count: invisibleCount,
        large_iframe_count: largeIframeCount,
        z_index_high_count: zIndexHighCount,
        pointer_events_none_count: pointerEventsNoneCount,
        click_mismatch: clickMismatch,
        untrusted_iframe_count: untrustedIframeCount,
        parent_domain_whitelisted: isWhitelisted ? 1 : 0  // NEW: Parent domain check
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
async function analyzePage() {
    // Reset click mismatch to prevent stale data
    clickMismatch = 0;

    const features = await extractFeatures();
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

// Listener for background script commands
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === "TRIGGER_SCAN") {
        analyzePage();
        sendResponse({ status: "scanning" });
    } else if (request.type === "APPLY_BLUR") {
        if (window.popSecurityAlert) {
            window.popSecurityAlert(request.prediction, request.reasons);
        }
        sendResponse({ status: "alert_popped" });
    }
});





