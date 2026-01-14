/**
 * Background Service Worker
 */

const SERVER_URL = 'http://localhost:5000/predict';

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "ANALYZE_PAGE") {
        const features = message.features;
        const tabId = sender.tab.id;

        fetch(SERVER_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(features)
        })
            .then(response => response.json())
            .then(data => {
                // Update badge and storage
                updateBadge(tabId, data.prediction);

                // Show alert/notification if suspicious or clickjacking
                if (data.prediction === "clickjacking" || data.prediction === "suspicious") {
                    chrome.tabs.sendMessage(tabId, {
                        type: "SHOW_ALERT",
                        prediction: data.prediction,
                        reasons: data.reasons
                    }).catch(e => console.log("Content script not ready for alert"));
                }

                // Save results for popup
                chrome.storage.local.set({ [tabId]: data });

                sendResponse(data);
            })
            .catch(error => {
                console.error("Error communicating with backend:", error);
                updateBadge(tabId, "error");
                sendResponse({ error: "Failed to connect to backend" });
            });

        return true; // Keep message channel open for async response
    }
});

function updateBadge(tabId, prediction) {
    let color = "#888888"; // Default gray
    let text = "N/A";

    if (prediction === "good") {
        color = "#4CAF50"; // Green
        text = "SAFE";
    } else if (prediction === "suspicious") {
        color = "#FFC107"; // Yellow/Amber
        text = "WARN";
    } else if (prediction === "clickjacking") {
        color = "#F44336"; // Red
        text = "EVIL";
    } else if (prediction === "error") {
        color = "#000000";
        text = "ERR";
    }

    chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
    chrome.action.setBadgeText({ text: text, tabId: tabId });
}
