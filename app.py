# app.py
from flask import Flask, render_template, request, jsonify
import joblib
import os
from url_extractor import FeatureExtractor

app = Flask(__name__)

# Load your pre-trained model
MODEL_PATH = os.path.join(os.path.dirname(__file__), "rf_phishing_model.pkl")
bundle = joblib.load(MODEL_PATH)
model = bundle["model"]
features = bundle["features"]

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    fe = FeatureExtractor(url)
    feature_dict = fe.get_features()

    # Ensure all model features are aligned
    X = [float(feature_dict.get(f, 0)) for f in features]

    prob = model.predict_proba([X])[0][1]
    label = 'Phishing' if prob > 0.5 else 'Legitimate'

    return jsonify({
        'url': url,
        'result': label,
        'confidence': round(prob * 100, 2),
        'https': feature_dict.get('ssl_final_state', 0),
        'phishing_prob': round(prob * 100, 2)
    })

if __name__ == "__main__":
    app.run(debug=True)
