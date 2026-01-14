from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import pandas as pd
import os
import csv
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Enable CORS for browser extension communication

# Load model and feature names
BASE_DIR = os.path.dirname(__file__)
model = joblib.load(os.path.join(BASE_DIR, 'model.pkl'))
features = joblib.load(os.path.join(BASE_DIR, 'features.pkl'))

CLASS_NAMES = {"clickjacking": "clickjacking", "good": "good", "suspicious": "suspicious"}
LOG_FILE = os.path.join(BASE_DIR, 'detected_sites.csv')

# Initialize log file
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', 'URL', 'Classification', 'Confidence', 'Reasons'])

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        url = data.get('url', 'Unknown')
        
        # Extract features in the correct order
        feature_data = {}
        for feat in features:
            feature_data[feat] = [data.get(feat, 0)]
        
        # Create DataFrame to maintain feature names (fixes the warning)
        X_df = pd.DataFrame(feature_data)
        
        # Get prediction and probabilities
        prediction = model.predict(X_df)[0]
        probabilities = model.predict_proba(X_df)[0]
        confidence = float(np.max(probabilities))
        
        pred_label = CLASS_NAMES[prediction]
        # For Logistic Regression, we can look at the coefficients
        # But for simplicity in a 3-class model, we'll just report the values that are high
        reasons = []
        if data.get('invisible_count', 0) > 0:
            reasons.append(f"Detected {data['invisible_count']} invisible iframes")
        if data.get('large_iframe_count', 0) > 0:
            reasons.append("Large iframes detected covering the viewport")
        if data.get('z_index_high_count', 0) > 0:
            reasons.append("High z-index elements detected")
        if data.get('click_mismatch', 0) == 1:
            reasons.append("Suspicious click behavior detected (coordinate mismatch)")
        if data.get('untrusted_iframe_count', 0) > 0:
            reasons.append(f"Detected {data['untrusted_iframe_count']} iframes from untrusted domains")
        
        
        # Override classification ONLY for extreme attack patterns
        # Let the ML model handle normal cases (e.g., Google with 1 invisible iframe)
        # Only override if we see MULTIPLE strong indicators together
        if (data.get('invisible_count', 0) > 5 and 
            data.get('large_iframe_count', 0) > 2 and 
            data.get('click_mismatch', 0) == 1):
            # Very high confidence attack: Many invisible + large iframes + click mismatch
            pred_label = "clickjacking"
            confidence = 0.99
            reasons.append("OVERRIDE: Extreme attack pattern detected")
        elif (data.get('invisible_count', 0) > 8 and 
              data.get('z_index_high_count', 0) > 5):
            # Stealthy multi-iframe attack
            pred_label = "clickjacking"
            confidence = 0.95
            reasons.append("OVERRIDE: Multi-iframe layering attack detected")

        
        if not reasons:
            reasons.append("No common clickjacking markers identified")

        result = {
            "prediction": pred_label,
            "confidence": f"{confidence * 100:.2f}%",
            "reasons": reasons
        }

        # Log if it's not "good"
        if pred_label != "good":
            with open(LOG_FILE, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    url,
                    pred_label,
                    result['confidence'],
                    " | ".join(reasons)
                ])
        
        # Color mapping for terminal
        colors = {
            "good": "\033[92m",       # Green
            "suspicious": "\033[93m", # Yellow
            "clickjacking": "\033[91m" # Red
        }
        reset = "\033[0m"
        color = colors.get(pred_label, reset)
        
        print(f"Prediction for {url}: {color}{result['prediction'].upper()}{reset} ({result['confidence']})")
        return jsonify(result)

    except Exception as e:
        print(f"Error in prediction: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Running on 0.0.0.0 to be accessible
    app.run(host='0.0.0.0', port=5000)
