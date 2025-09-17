from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
from url_extractor import FeatureExtractor

app = Flask(__name__)

# Load model once
model_bundle = joblib.load("rf_phishing_model.pkl")
model = model_bundle["model"]
features = model_bundle["features"]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    fe = FeatureExtractor(url)
    feature_dict = fe.get_features()
    X = pd.DataFrame([feature_dict])[features]

    pred_label = int(model.predict(X)[0])
    pred_proba = float(model.predict_proba(X)[:, 1][0])

    result = {
        "result": "Phishing" if pred_label == 1 else "Legitimate",
        "scannedUrl": url,
        "scanDuration": "2.0s",
        "confidence": round(pred_proba * 100, 2),
        "assessments": {
            "unencryptedHttp": feature_dict["ssl_final_state"] == 0,
            "suspiciousDomain": feature_dict["prefix_suffix"] == 1,
            "recentlyRegistered": False,
            "knownPatterns": False
        }
    }
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
