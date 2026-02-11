/**
 * Whitelist Configuration
 * Parent domains that are trusted and should not be flagged as suspicious
 * even if they have invisible iframes or other borderline indicators
 */

const DEFAULT_WHITELISTED_DOMAINS = [
    // Search Engines
    'google.com',
    'google.co.in',
    'google.co.uk',
    'bing.com',
    'duckduckgo.com',
    'yahoo.com',

    // Social Media
    'facebook.com',
    'twitter.com',
    'x.com',
    'instagram.com',
    'linkedin.com',
    'reddit.com',

    // Video Platforms
    'youtube.com',
    'vimeo.com',
    'twitch.tv',
    'dailymotion.com',

    // E-commerce
    'amazon.com',
    'amazon.in',
    'ebay.com',
    'shopify.com',
    'etsy.com',

    // News & Media
    'nytimes.com',
    'bbc.com',
    'cnn.com',
    'theguardian.com',

    // Tech & Development
    'github.com',
    'stackoverflow.com',
    'medium.com',
    'dev.to',

    // Productivity
    'gmail.com',
    'outlook.com',
    'office.com',
    'docs.google.com',
    'drive.google.com',

    // Add your custom domains here
    'jobsiri.in',  // From your logs
];

// Storage key for custom whitelist
const CUSTOM_WHITELIST_KEY = 'customWhitelist';

/**
 * Get combined whitelist (default + custom)
 * @returns {Promise<Array<string>>} - Combined whitelist
 */
async function getCombinedWhitelist() {
    return new Promise((resolve) => {
        chrome.storage.local.get([CUSTOM_WHITELIST_KEY], (result) => {
            const customDomains = result[CUSTOM_WHITELIST_KEY] || [];
            const combined = [...DEFAULT_WHITELISTED_DOMAINS, ...customDomains];
            resolve(combined);
        });
    });
}

/**
 * Add domain to custom whitelist
 * @param {string} domain - Domain to add (e.g., 'example.com')
 * @returns {Promise<boolean>} - Success status
 */
async function addToWhitelist(domain) {
    return new Promise((resolve) => {
        chrome.storage.local.get([CUSTOM_WHITELIST_KEY], (result) => {
            const customDomains = result[CUSTOM_WHITELIST_KEY] || [];

            // Check if already in default or custom whitelist
            if (DEFAULT_WHITELISTED_DOMAINS.includes(domain) || customDomains.includes(domain)) {
                console.log(`Domain ${domain} already whitelisted`);
                resolve(false);
                return;
            }

            // Add to custom whitelist
            customDomains.push(domain);
            chrome.storage.local.set({ [CUSTOM_WHITELIST_KEY]: customDomains }, () => {
                console.log(`Added ${domain} to custom whitelist`);
                resolve(true);
            });
        });
    });
}

/**
 * Remove domain from custom whitelist
 * @param {string} domain - Domain to remove
 * @returns {Promise<boolean>} - Success status
 */
async function removeFromWhitelist(domain) {
    return new Promise((resolve) => {
        chrome.storage.local.get([CUSTOM_WHITELIST_KEY], (result) => {
            const customDomains = result[CUSTOM_WHITELIST_KEY] || [];
            const index = customDomains.indexOf(domain);

            if (index === -1) {
                console.log(`Domain ${domain} not in custom whitelist`);
                resolve(false);
                return;
            }

            customDomains.splice(index, 1);
            chrome.storage.local.set({ [CUSTOM_WHITELIST_KEY]: customDomains }, () => {
                console.log(`Removed ${domain} from custom whitelist`);
                resolve(true);
            });
        });
    });
}

/**
 * Get custom whitelist domains
 * @returns {Promise<Array<string>>} - Custom domains
 */
async function getCustomWhitelist() {
    return new Promise((resolve) => {
        chrome.storage.local.get([CUSTOM_WHITELIST_KEY], (result) => {
            resolve(result[CUSTOM_WHITELIST_KEY] || []);
        });
    });
}

/**
 * Extract domain or identifier from URL
 * @param {string} url - Full URL
 * @returns {string|null} - Domain/Identifier or null if invalid
 */
function extractDomain(url) {
    try {
        const urlObj = new URL(url);

        // Handle local files
        if (urlObj.protocol === 'file:') {
            // Use the filename as the identifier for local files
            const parts = urlObj.pathname.split('/');
            return parts[parts.length - 1] || 'local-file';
        }

        let hostname = urlObj.hostname.toLowerCase();

        // Remove 'www.' prefix if present
        if (hostname.startsWith('www.')) {
            hostname = hostname.substring(4);
        }

        return hostname;
    } catch (e) {
        console.warn('Invalid URL for domain extraction:', url);
        return null;
    }
}

/**
 * Check if current page is from a whitelisted parent domain
 * @param {string} url - The page URL (window.location.href)
 * @returns {Promise<boolean>} - True if parent domain is whitelisted
 */
async function isParentDomainWhitelisted(url) {
    try {
        const identifier = extractDomain(url);
        if (!identifier) return false;

        // Get combined whitelist
        const whitelist = await getCombinedWhitelist();

        return whitelist.some(domain =>
            identifier === domain || identifier.endsWith('.' + domain)
        );
    } catch (e) {
        console.warn('Error in whitelist check:', e);
        return false;
    }
}

/**
 * Synchronous version for backward compatibility (uses only default whitelist)
 * Note: This only checks default whitelist, not custom additions
 */
function isParentDomainWhitelistedSync(url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname.toLowerCase();

        // Only check default whitelist (custom whitelist requires async)
        return DEFAULT_WHITELISTED_DOMAINS.some(domain =>
            hostname === domain || hostname.endsWith('.' + domain)
        );
    } catch (e) {
        console.warn('Invalid URL for whitelist check:', url);
        return false;
    }
}
