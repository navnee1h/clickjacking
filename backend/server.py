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
        
        # Generate reasons based on feature analysis
        reasons = []
        feature_details = []  # For ML-based reasoning
        
        # Check individual features with lower thresholds for warnings
        if data.get('invisible_count', 0) > 2:
            reasons.append(f"Detected {data['invisible_count']} invisible iframes")
        elif data.get('invisible_count', 0) > 0 and pred_label != 'good':
            feature_details.append(f"{data['invisible_count']} invisible iframe(s)")
            
        if data.get('large_iframe_count', 0) > 0:
            reasons.append("Large iframes detected covering the viewport")
            
        if data.get('z_index_high_count', 0) > 2:
            reasons.append("High z-index elements detected")
        elif data.get('z_index_high_count', 0) > 0 and pred_label != 'good':
            feature_details.append(f"{data['z_index_high_count']} high z-index element(s)")
            
        if data.get('click_mismatch', 0) == 1:
            reasons.append("Suspicious click behavior detected (coordinate mismatch)")
            
        if data.get('untrusted_iframe_count', 0) > 1:
            reasons.append(f"Detected {data['untrusted_iframe_count']} iframes from untrusted domains")
        elif data.get('untrusted_iframe_count', 0) == 1:
            if data.get('invisible_count', 0) > 3:
                reasons.append(f"Detected {data['untrusted_iframe_count']} iframe from untrusted domain")
            elif pred_label != 'good':
                feature_details.append(f"{data['untrusted_iframe_count']} untrusted iframe")
        
        if data.get('pointer_events_none_count', 0) > 0 and pred_label != 'good':
            feature_details.append(f"{data['pointer_events_none_count']} iframe(s) with disabled pointer events")
        
        # === WHITELIST-BASED FALSE POSITIVE REDUCTION ===
        is_whitelisted = data.get('parent_domain_whitelisted', 0) == 1
        
        if is_whitelisted:
            # If user explicitly whitelisted, we downgrade almost everything to "good"
            # unless it's an extreme override pattern (checked below)
            if pred_label in ["suspicious", "clickjacking"]:
                original_pred = pred_label
                pred_label = "good"
                confidence = 0.95
                reasons = [f"Domain is trusted by user (Whitelisted)"]
                print(f"  → Whitelisted domain: downgraded {original_pred} to good")
        
        # Override classification ONLY for extreme attack patterns (even if whitelisted, be cautious)
        # But for whitelisted ones, we keep them as good unless they are truly malicious
        if not is_whitelisted:
            if (data.get('invisible_count', 0) > 5 and 
                data.get('large_iframe_count', 0) > 2 and 
                data.get('click_mismatch', 0) == 1):
                pred_label = "clickjacking"
                confidence = 0.99
                reasons.append("OVERRIDE: Extreme attack pattern detected")
            elif (data.get('invisible_count', 0) > 8 and 
                  data.get('z_index_high_count', 0) > 5):
                pred_label = "clickjacking"
                confidence = 0.95
                reasons.append("OVERRIDE: Multi-iframe layering attack detected")

        # If no specific reasons but ML flagged it, provide ML-based reasoning
        if not reasons and pred_label != 'good':
            if feature_details:
                # Show the features that contributed
                reasons.append(f"ML model detected suspicious patterns: {', '.join(feature_details)}")
            else:
                # Generic ML reasoning based on prediction
                if pred_label == 'suspicious':
                    reasons.append(f"ML model flagged suspicious behavior (confidence: {confidence*100:.1f}%)")
                    if data.get('iframe_count', 0) > 0:
                        reasons.append(f"Page contains {data['iframe_count']} iframe(s) with borderline characteristics")
                elif pred_label == 'clickjacking':
                    reasons.append(f"ML model detected clickjacking patterns (confidence: {confidence*100:.1f}%)")
        
        # If still no reasons (shouldn't happen), provide default
        if not reasons:
            reasons.append("No security threats detected")

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
