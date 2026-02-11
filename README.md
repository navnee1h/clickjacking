# Shield: AI-Powered Clickjacking Defense System

## 🛡️ Project Overview

**Shield** is a state-of-the-art, real-time clickjacking detection and prevention system. It combines browser extension technology with a high-performance Machine Learning backend to identify and block UI redressing attacks before they can compromise user security.

By analyzing architectural anomalies, z-index layering, and behavioral patterns, Shield provides a "Glassmorphism" security layer that isolates threats while maintaining a premium, minimalist user experience.

---

## 🚀 Core Features

### 1. Intelligent Analysis Engine

- **ML Classificaton**: Uses a Random Forest Model (99.5% accuracy) to distinguish legitimate iframes from malicious overlays.
- **Structural Deep-Scan**: Analyzes 7+ weighted indicators including opacity gradients, viewport coverage, and untrusted source domains.
- **Real-Time Protection**: Scans pages within milliseconds of loading and re-evaluates on every user interaction.

### 2. Native Security UI (Legacy & Modern)

- **Top-Bar Dropdown Banner**: A sleek, native-style alert that slides from the browser's top bar when a threat is identified.
- **Ghost Blur Effect**: Automatically applies a crystal-clear `30px` white blur to suspicious pages, "freezing" the content until the user decides.
- **Native OS Notifications**: Triggers system-level alerts for immediate desktop visibility.

### 3. Dynamic Whitelisting (Trust Mode)

- **Direct Trust CTA**: One-click "Trust Site" button on the security banner.
- **Local & Web Support**: Intelligent domain extraction handles both global websites (`google.com`) and local development files (`test.html`).
- **Persistent Whitelist**: Stores your trusted sites in local storage for a seamless browsing experience.

---

## 🛠️ Technology Stack

| Layer | Technologies |
|-------|--------------|
| **Extension** | JavaScript (ES6+), CSS3 (Vanilla), Chrome Extension API V3 |
| **Backend** | Python 3, Flask, Flask-CORS |
| **Machine Learning** | Scikit-Learn (Random Forest), Pandas, Joblib |
| **Communications** | REST API (JSON), Secure Message Passing |

---

## 📂 Project Structure

```
clickjacking/
├── backend/
│   ├── server.py                # Flask REST API with ML Logic
│   ├── train_model.py           # ML Training Script
│   ├── model.pkl                 # Trained Model
│   ├── features.pkl              # Feature Order Definition
│   └── detected_sites.csv        # Automated Security Logs
├── extension/
│   ├── manifest.json             # Extension Configuration
│   ├── content.js                # Feature Extraction Engine
│   ├── background.js             # Service Worker & Router
│   ├── alert_ui.js               # Modular Alert Component (JS)
│   ├── alert_ui.css              # Modular Alert Component (CSS)
│   ├── whitelist.js              # Trust Management Logic
│   ├── popup.html/js             # Extension Toolbar GUI
│   └── icons/                    # High-Resolution Assets
├── test_attack.html              # Security Testing Playground
└── README.md                     # Project Documentation
```

---

## ⚡ Quick Start

### 1. Start the Backend

```bash
# Install dependencies
pip install flask flask-cors scikit-learn pandas joblib

# Run the server
python backend/server.py
```

*The server will run on `http://localhost:5000`.*

### 2. Install the Extension

1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer Mode** (toggle in upper right).
3. Click **Load Unpacked**.
4. Select the `extension/` folder from this project.

### 3. Test the Shield

- Open **`test_attack.html`** in your browser.
- Watch as the **Shield Banner** drops down and the page content is instantly blurred.
- Interact with the "Trust Site" or "Return to Safety" buttons to see the system in action.

---

## 📈 Security Insights

Shield doesn't just block; it explains. Every detection is logged with specific reasons:

- `High z-index elements detected`
- `Iframes covering >50% of viewport`
- `Structural anomalies on untrusted domains`
- `Suspicious coordinate mismatches`

---

## ⚖️ License & Attribution

Advanced cybersecurity implementation for academic research and professional web security. Created with ❤️ for a safer web.

**Last Updated**: February 11, 2026
