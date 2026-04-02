# Shield: Clickjacking Detection Extension

## Overview

Shield is a simple browser extension developed as a quick 2-hour project for my friend’s college submission. It is designed to detect basic clickjacking attacks by analyzing iframe behavior on web pages.

---

## Features

* Detects hidden or overlapping iframes
* Checks unusual z-index and opacity values
* Alerts users about possible threats
* Allows users to trust safe websites

---

## Technology Used

* JavaScript (Chrome Extension)
* Python (Flask backend)
* Scikit-learn for basic ML classification

---

## How It Works

1. The extension scans the webpage for suspicious iframe activity.
2. Key features are collected and sent to a backend server.
3. A simple machine learning model classifies the page.
4. If suspicious behavior is found, a warning is shown.

---

## Setup

1. Start the backend:

```bash
python server.py
```

2. Load the extension in Chrome using Developer Mode.

---

## Conclusion

This project shows a basic implementation of clickjacking detection using a browser extension and simple machine learning, built quickly for academic demonstration purposes.
