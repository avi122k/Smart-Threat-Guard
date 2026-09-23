from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import pickle
import json

from feature_extractor import extract_features
from security_analyzer import analyze_url
from database import (
    create_table,
    save_scan,
    get_all_scans,
    get_statistics,
    get_scan_by_id
)
# --------------------------------
# Create FastAPI application
# --------------------------------

app = FastAPI(
    title="Smart Threat Guard API",
    description="AI-powered phishing and malicious URL detection system",
    version="1.0"
)


# --------------------------------
# Create database table
# --------------------------------

create_table()


# --------------------------------
# Allow frontend to communicate
# --------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# --------------------------------
# Load trained ML model
# --------------------------------

with open("model.pkl", "rb") as file:
    model = pickle.load(file)


# --------------------------------
# Request format
# --------------------------------

class URLRequest(BaseModel):

    url: str


# --------------------------------
# Home API
# --------------------------------

@app.get("/")
def home():

    return {
        "message": "Smart Threat Guard API is running"
    }


# --------------------------------
# URL Scan API
# --------------------------------

@app.post("/scan")
def scan_url(request: URLRequest):

    # Get URL from request
    url = request.url


    # --------------------------------
    # Feature Extraction
    # --------------------------------

    features = extract_features(url)


    # --------------------------------
    # ML Prediction
    # --------------------------------

    prediction = model.predict(
        [features]
    )[0]


    # --------------------------------
    # Prediction Probability
    # --------------------------------

    probabilities = model.predict_proba(
        [features]
    )[0]

    phishing_probability = probabilities[1]


    # Convert to percentage
    risk_score = round(
        phishing_probability * 100,
        2
    )
    security_analysis = analyze_url(url)
    security_analysis = analyze_url(request.url)


    # --------------------------------
    # Risk Level
    # --------------------------------

    if risk_score >= 70:

        verdict = "HIGH RISK"

    elif risk_score >= 40:

        verdict = "MEDIUM RISK"

    else:

        verdict = "LOW RISK"


    # --------------------------------
    # Generate Explanation
    # --------------------------------

    reasons = []


    if len(url) > 75:

        reasons.append(
            "URL is unusually long"
        )


    if "@" in url:

        reasons.append(
            "URL contains @ symbol"
        )


    # Feature 11 = IP address usage
    if features[10] == 1:

        reasons.append(
            "IP address used instead of domain"
        )


    # Feature 12 = suspicious keywords
    if features[11] > 0:

        reasons.append(
            "Suspicious keywords detected"
        )


    # Feature 8 = subdomains
    if features[7] > 2:

        reasons.append(
            "Multiple subdomains detected"
        )


    if not reasons:

        reasons.append(
            "No major suspicious URL patterns detected"
        )


    # --------------------------------
    # Final Prediction
    # --------------------------------

    prediction_result = (
        "PHISHING"
        if prediction == 1
        else "LEGITIMATE"
    )


    # --------------------------------
    # Save scan to database
    # --------------------------------

    scan_id = save_scan(
    url=url,
    prediction=prediction_result,
    risk_score=risk_score,
    risk_level=verdict,
    reasons=json.dumps(reasons),
    features=json.dumps(features)
)


    # --------------------------------
    # Final Result
    # --------------------------------
    return {
    "scan_id": scan_id,
    "url": url,
    "risk_score": risk_score,
    "verdict": verdict,
    "prediction": prediction_result,
    "reasons": reasons,
    "security_checks": security_analysis["checks"],
    "security_warnings": security_analysis["warnings"]
}
# --------------------------------
# Scan History API
# --------------------------------

@app.get("/history")
def scan_history():

    scans = get_all_scans()

    history = []

    for scan in scans:

        history.append({
            "scan_id": scan["id"],
            "url": scan["url"],
            "prediction": scan["prediction"],
            "risk_score": scan["risk_score"],
            "risk_level": scan["risk_level"],
            "reasons": scan["reasons"],
            "scan_date": scan["scan_date"]
        })

    return {
        "total_scans": len(history),
        "scans": history
    }
# --------------------------------
# Statistics API
# --------------------------------

@app.get("/statistics")
def statistics():

    stats = get_statistics()

    return stats
# --------------------------------
# Get Individual Scan API
# --------------------------------

@app.get("/scan/{scan_id}")
def get_scan(scan_id: int):

    import json

    scan = get_scan_by_id(scan_id)

    if scan is None:

        return {
            "error": "Scan not found"
        }


    # --------------------------------
    # Get stored features
    # --------------------------------

    if scan["features"]:

        raw_features = json.loads(
            scan["features"]
        )

    else:

        # Older scans don't have
        # features stored in database.
        # Recalculate them from URL.

        raw_features = extract_features(
            scan["url"]
        )


    # --------------------------------
    # Feature names
    # --------------------------------

    feature_names = [

        "URL Length",

        "Dot Count",

        "Hyphen Count",

        "Underscore Count",

        "@ Symbol Count",

        "Digit Count",

        "Special Character Count",

        "Subdomain Count",

        "Path Length",

        "Query Length",

        "IP Address Usage",

        "Suspicious Keyword Count"

    ]


    # --------------------------------
    # Create feature dictionary
    # --------------------------------

    feature_analysis = {}


    for name, value in zip(
        feature_names,
        raw_features
    ):

        feature_analysis[name] = value


    # --------------------------------
    # Reasons
    # --------------------------------

    if scan["reasons"]:

        try:

            reasons = json.loads(
                scan["reasons"]
            )

        except:

            reasons = [
                scan["reasons"]
            ]

    else:

        reasons = []

    # --------------------------------
# Security analysis
# --------------------------------

    security_analysis = analyze_url(scan["url"]) 


    # --------------------------------
    # Final response
    # --------------------------------

    return {

        "scan_id":
            scan["id"],

        "url":
            scan["url"],

        "prediction":
            scan["prediction"],

        "risk_score":
            scan["risk_score"],

        "risk_level":
            scan["risk_level"],

        "reasons":
            reasons,

        "features":
            feature_analysis,

        "scan_date":
            scan["scan_date"],
         "security_checks":
            security_analysis["checks"],
        "security_warnings": 
            security_analysis["warnings"]

        

    }