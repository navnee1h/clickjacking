import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import os

def generate_synthetic_data(samples=10000):
    """
    Generate synthetic training data with realistic patterns for:
    - Legitimate sites (Google, YouTube, E-commerce, News)
    - Suspicious sites (borderline cases)
    - Clickjacking attacks (various techniques)
    """
    np.random.seed(42)
    
    data = []
    labels = []
    
    # Calculate samples per category (50% good, 30% suspicious, 20% clickjacking)
    good_samples = int(samples * 0.5)
    suspicious_samples = int(samples * 0.3)
    clickjacking_samples = samples - good_samples - suspicious_samples
    
    # ========== GOOD SITES (50%) ==========
    
    # 1. Analytics/Tracking Sites (Google, Facebook) - 20% of good samples
    for _ in range(int(good_samples * 0.2)):
        iframe_count = np.random.randint(1, 4)  # 1-3 iframes
        invisible_count = np.random.randint(1, 3)  # Small tracking pixels
        large_iframe_count = 0  # No large iframes
        z_index_high_count = 0  # Normal z-index
        pointer_events_none_count = invisible_count  # Tracking pixels don't capture clicks
        click_mismatch = 0
        untrusted_iframe_count = 0  # All from trusted domains (google.com, facebook.net)
        
        data.append([iframe_count, invisible_count, large_iframe_count, 
                     z_index_high_count, pointer_events_none_count, click_mismatch, untrusted_iframe_count])
        labels.append('good')
    
    # 2. Video Embedding Sites (YouTube, Vimeo) - 25% of good samples
    for _ in range(int(good_samples * 0.25)):
        iframe_count = np.random.randint(1, 3)  # 1-2 iframes
        invisible_count = np.random.randint(0, 2)  # Maybe 1 analytics iframe
        large_iframe_count = np.random.randint(1, 2)  # 1 large video player
        z_index_high_count = np.random.randint(0, 2)  # Video controls may have high z-index
        pointer_events_none_count = 0  # Video player is interactive
        click_mismatch = 0
        untrusted_iframe_count = 0  # From youtube.com, vimeo.com (trusted)
        
        data.append([iframe_count, invisible_count, large_iframe_count, 
                     z_index_high_count, pointer_events_none_count, click_mismatch, untrusted_iframe_count])
        labels.append('good')
    
    # 3. E-commerce Sites (Payment widgets, chat support) - 20% of good samples
    for _ in range(int(good_samples * 0.2)):
        iframe_count = np.random.randint(2, 5)  # Multiple widgets
        invisible_count = np.random.randint(0, 2)  # Maybe analytics
        large_iframe_count = 0  # Widgets are small
        z_index_high_count = np.random.randint(0, 2)  # Chat widget may float
        pointer_events_none_count = 0
        click_mismatch = 0
        untrusted_iframe_count = 0  # From stripe.com, paypal.com (trusted)
        
        data.append([iframe_count, invisible_count, large_iframe_count, 
                     z_index_high_count, pointer_events_none_count, click_mismatch, untrusted_iframe_count])
        labels.append('good')
    
    # 4. Clean Sites (No iframes or minimal) - 35% of good samples
    for _ in range(int(good_samples * 0.35)):
        iframe_count = np.random.randint(0, 2)  # 0-1 iframes
        invisible_count = 0
        large_iframe_count = 0
        z_index_high_count = 0
        pointer_events_none_count = 0
        click_mismatch = 0
        untrusted_iframe_count = 0
        
        data.append([iframe_count, invisible_count, large_iframe_count, 
                     z_index_high_count, pointer_events_none_count, click_mismatch, untrusted_iframe_count])
        labels.append('good')
    
    # ========== SUSPICIOUS SITES (30%) ==========
    
    # 1. Borderline Cases - Multiple iframes but not clearly malicious
    for _ in range(int(suspicious_samples * 0.5)):
        iframe_count = np.random.randint(3, 6)
        invisible_count = np.random.randint(1, 3)
        large_iframe_count = np.random.randint(0, 2)
        z_index_high_count = np.random.randint(1, 3)
        pointer_events_none_count = np.random.randint(0, 2)
        click_mismatch = 0  # No click mismatch
        untrusted_iframe_count = np.random.randint(0, 2)  # Maybe 1 untrusted iframe
        
        data.append([iframe_count, invisible_count, large_iframe_count, 
                     z_index_high_count, pointer_events_none_count, click_mismatch, untrusted_iframe_count])
        labels.append('suspicious')
    
    # 2. Ad-heavy Sites - Many iframes but legitimate
    for _ in range(int(suspicious_samples * 0.5)):
        iframe_count = np.random.randint(4, 8)
        invisible_count = np.random.randint(1, 3)
        large_iframe_count = np.random.randint(1, 2)
        z_index_high_count = np.random.randint(0, 2)
        pointer_events_none_count = np.random.randint(1, 3)
        click_mismatch = np.random.choice([0, 1], p=[0.9, 0.1])
        untrusted_iframe_count = np.random.randint(1, 3)  # Some ad networks may be untrusted
        
        data.append([iframe_count, invisible_count, large_iframe_count, 
                     z_index_high_count, pointer_events_none_count, click_mismatch, untrusted_iframe_count])
        labels.append('suspicious')
    
    # ========== CLICKJACKING ATTACKS (20%) ==========
    
    # 1. Classic Clickjacking - Large invisible iframe overlay
    for _ in range(int(clickjacking_samples * 0.3)):
        iframe_count = np.random.randint(1, 5)
        invisible_count = np.random.randint(1, 3)
        large_iframe_count = np.random.randint(1, 3)  # Large overlay
        z_index_high_count = np.random.randint(2, 6)  # High z-index to overlay
        pointer_events_none_count = np.random.randint(1, 4)
        click_mismatch = np.random.choice([0, 1], p=[0.3, 0.7])
        untrusted_iframe_count = np.random.randint(1, 3)  # Attack iframes from untrusted domains
        
        data.append([iframe_count, invisible_count, large_iframe_count, 
                     z_index_high_count, pointer_events_none_count, click_mismatch, untrusted_iframe_count])
        labels.append('clickjacking')
    
    # 2. Stealthy Multi-Iframe Attack - Many tiny invisible iframes
    for _ in range(int(clickjacking_samples * 0.3)):
        iframe_count = np.random.randint(8, 20)  # Many iframes
        invisible_count = np.random.randint(6, 15)  # Most are invisible
        large_iframe_count = np.random.randint(0, 2)  # Not necessarily large
        z_index_high_count = np.random.randint(3, 10)
        pointer_events_none_count = np.random.randint(4, 12)
        click_mismatch = np.random.choice([0, 1], p=[0.4, 0.6])
        untrusted_iframe_count = np.random.randint(3, 10)  # Many untrusted iframes
        
        data.append([iframe_count, invisible_count, large_iframe_count, 
                     z_index_high_count, pointer_events_none_count, click_mismatch, untrusted_iframe_count])
        labels.append('clickjacking')
    
    # 3. Opacity Gradient Attack - Low opacity iframes (0.01-0.09)
    for _ in range(int(clickjacking_samples * 0.2)):
        iframe_count = np.random.randint(2, 8)
        invisible_count = np.random.randint(2, 6)  # Detected as invisible
        large_iframe_count = np.random.randint(1, 4)
        z_index_high_count = np.random.randint(2, 8)
        pointer_events_none_count = np.random.randint(2, 6)
        click_mismatch = 1  # High chance of click mismatch
        untrusted_iframe_count = np.random.randint(1, 5)  # Untrusted overlay
        
        data.append([iframe_count, invisible_count, large_iframe_count, 
                     z_index_high_count, pointer_events_none_count, click_mismatch, untrusted_iframe_count])
        labels.append('clickjacking')
    
    # 4. Z-Index Layering Attack - Multiple overlapping iframes
    for _ in range(int(clickjacking_samples * 0.2)):
        iframe_count = np.random.randint(3, 10)
        invisible_count = np.random.randint(2, 5)
        large_iframe_count = np.random.randint(2, 4)
        z_index_high_count = np.random.randint(4, 10)  # Many high z-index
        pointer_events_none_count = np.random.randint(2, 6)
        click_mismatch = np.random.choice([0, 1], p=[0.2, 0.8])
        untrusted_iframe_count = np.random.randint(2, 6)  # Multiple untrusted layers
        
        data.append([iframe_count, invisible_count, large_iframe_count, 
                     z_index_high_count, pointer_events_none_count, click_mismatch, untrusted_iframe_count])
        labels.append('clickjacking')
    
    # Create DataFrame
    df = pd.DataFrame(data, columns=[
        'iframe_count', 
        'invisible_count', 
        'large_iframe_count', 
        'z_index_high_count', 
        'pointer_events_none_count', 
        'click_mismatch',
        'untrusted_iframe_count'
    ])
    df['label'] = labels
    
    return df

def train():
    print("=" * 60)
    print("CLICKJACKING DETECTION MODEL TRAINING")
    print("=" * 60)
    print("\nGenerating enhanced synthetic data with realistic patterns...")
    print("- Legitimate sites: Analytics, Video embedding, E-commerce")
    print("- Attack patterns: Classic overlay, Multi-iframe, Opacity gradient")
    
    df = generate_synthetic_data(10000)
    
    print(f"\nDataset size: {len(df)} samples")
    print(f"Class distribution:")
    print(df['label'].value_counts())
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("\n" + "=" * 60)
    print("Training Random Forest Classifier...")
    print("=" * 60)
    
    # Random Forest with optimized parameters
    model = RandomForestClassifier(
        n_estimators=100,      # 100 decision trees
        max_depth=10,          # Prevent overfitting
        min_samples_split=5,   # Require at least 5 samples to split
        random_state=42,
        n_jobs=-1              # Use all CPU cores
    )
    
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    
    print("\n" + "=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)
    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Clickjacking', 'Good', 'Suspicious']))
    
    print("\nConfusion Matrix:")
    print("(Rows: Actual, Columns: Predicted)")
    cm = confusion_matrix(y_test, y_pred, labels=['clickjacking', 'good', 'suspicious'])
    print(pd.DataFrame(cm, 
                      index=['Clickjacking', 'Good', 'Suspicious'],
                      columns=['Clickjacking', 'Good', 'Suspicious']))
    
    # Feature importance
    print("\n" + "=" * 60)
    print("FEATURE IMPORTANCE")
    print("=" * 60)
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    print(feature_importance.to_string(index=False))
    
    # Save the model
    model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
    joblib.dump(model, model_path)
    print(f"\n✓ Model saved to {model_path}")
    
    # Save feature names for reference in server
    features = list(X.columns)
    joblib.dump(features, os.path.join(os.path.dirname(__file__), 'features.pkl'))
    print("✓ Feature list saved")
    
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Restart the Flask server: python backend/server.py")
    print("2. Reload the browser extension")
    print("3. Test on Google, YouTube, and test_attack.html")

if __name__ == "__main__":
    train()
