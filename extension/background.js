/**
 * Background Service Worker - Native Notification Controller
 */

const SERVER_URL = 'http://localhost:5000/predict';
let activeNotifications = new Map(); // Map notificationId -> tabId

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "ANALYZE_PAGE") {
        const features = message.features;
        const tabId = sender.tab.id;

        // Ensure we handle potential connection issues gracefully
        fetch(SERVER_URL, {
            method: 'POST',
            mode: 'cors', // Explicitly set cors mode
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(features)
        })
            .then(response => response.json())
            .then(data => {
                updateBadge(tabId, data.prediction);
                chrome.storage.local.set({ [tabId]: data });

                if (data.prediction === "clickjacking" || data.prediction === "suspicious") {
                    // 1. Apply blur to the page immediately
                    chrome.tabs.sendMessage(tabId, {
                        type: "APPLY_BLUR",
                        prediction: data.prediction,
                        reasons: data.reasons
                    }).catch(e => console.log("Content script not ready"));

                    // 2. Trigger Native Notification with full URL for icon
                    const iconPath = "icons/icon128.png";
                    const title = data.prediction === "clickjacking" ? "🚨 Shield: Security Breach" : "⚠️ Shield: Suspicious Activity";

                    // Try to create notification, but don't let it crash the experience
                    try {
                        chrome.notifications.create(`threat-${tabId}-${Date.now()}`, {
                            type: "basic",
                            iconUrl: iconPath,
                            title: title,
                            message: `Structural anomalies detected. Access restricted.`,
                            priority: 2,
                            requireInteraction: true,
                            buttons: [
                                { title: "🛡️ Return to Safety" },
                                { title: "Ignore and Proceed" }
                            ]
                        }, (id) => {
                            if (chrome.runtime.lastError) {
                                // Silent fallback if notifications are blocked by OS/Settings
                                console.warn("Native Notification bypassed:", chrome.runtime.lastError.message);
                            } else {
                                activeNotifications.set(id, tabId);
                            }
                        });
                    } catch (e) {
                        console.warn("Notification API not available or blocked.");
                    }
                }
                sendResponse(data);
            })
            .catch(error => {
                console.error("Error:", error);
                updateBadge(tabId, "error");
                sendResponse({ error: "Failed to connect" });
            });

        return true;
    }
});

// Handle Native Notification Buttons
chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    const tabId = activeNotifications.get(notificationId);
    if (!tabId) return;

    if (buttonIndex === 0) {
        // Return to Safety
        chrome.tabs.goBack(tabId).catch(() => chrome.tabs.remove(tabId));
    } else {
        // Proceed anyway - Tell content script to remove blur
        chrome.tabs.sendMessage(tabId, { type: "REMOVE_BLUR" });
    }

    chrome.notifications.clear(notificationId);
    activeNotifications.delete(notificationId);
});

function updateBadge(tabId, prediction) {
    let color = "#95a5a6";
    let text = "N/A";

    if (prediction === "good") {
        color = "#2ecc71";
        text = "SAFE";
    } else if (prediction === "suspicious") {
        color = "#f1c40f";
        text = "WARN";
    } else if (prediction === "clickjacking") {
        color = "#e74c3c";
        text = "EVIL";
    }

    chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
    chrome.action.setBadgeText({ text: text, tabId: tabId });
}

