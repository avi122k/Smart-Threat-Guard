from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from io import BytesIO
from datetime import datetime
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
import pickle
import json
import os


from feature_extractor import extract_features
from security_analyzer import analyze_url
from database import (
    create_table,
    save_scan,
    get_all_scans,
    get_statistics,
    get_scan_by_id
)
from fastapi import HTTPException, Depends
from pydantic import BaseModel, EmailStr
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user
)
from database import (
    create_user,
    get_user_by_email,
    get_user_by_username
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

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str

@app.post("/auth/register")
def register_user(request: RegisterRequest):
    username = request.username.strip()
    email = str(request.email).lower()
    password = request.password

    if len(username) < 3 or len(username) > 50:
        raise HTTPException(
            status_code=400,
            detail="Username must be between 3 and 50 characters"
        )

    if len(password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least 8 characters"
        )

    if get_user_by_email(email):
        raise HTTPException(
            status_code=409,
            detail="Email is already registered"
        )

    if get_user_by_username(username):
        raise HTTPException(
            status_code=409,
            detail="Username is already taken"
        )

    try:
        user_id = create_user(
            username=username,
            email=email,
            password_hash=hash_password(password)
        )
    except Exception:
        raise HTTPException(
            status_code=409,
            detail="Could not create account; check whether username or email already exists"
        )

    return {
        "message": "Account created successfully",
        "user_id": user_id
    }
@app.post("/auth/login")
def login_user(request: LoginRequest):
    user = get_user_by_email(str(request.email).lower())

    if not user or not verify_password(
        request.password,
        user["password_hash"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password"
        )

    token = create_access_token(user["id"])

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"]
        }
    }
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
def scan_url(
    request: URLRequest,
    current_user=Depends(get_current_user)
):

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
    features=json.dumps(features),
    user_id=current_user["id"]
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
def scan_history(current_user=Depends(get_current_user)):

    scans = get_all_scans(user_id=current_user["id"])

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
def statistics(current_user=Depends(get_current_user)):

    stats = get_statistics(user_id=current_user["id"])

    return stats

# --------------------------------
# Get Individual Scan API
# --------------------------------

@app.get("/scan/{scan_id}")
def get_scan(
    scan_id: int,
    current_user=Depends(get_current_user)
):

    import json
    scan = get_scan_by_id(
        scan_id,
        user_id=current_user["id"]
    )

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )



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
# --------------------------------
# Model Comparison API
# --------------------------------

@app.get("/model-comparison")
def model_comparison(current_user=Depends(get_current_user)):
    results_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "model_comparison.json"
    )

    if not os.path.exists(results_path):
        raise HTTPException(
            status_code=404,
            detail="Model comparison results not found. Run compare_models.py first."
        )

    try:
        with open(results_path, "r", encoding="utf-8") as file:
            results = json.load(file)
    except (OSError, json.JSONDecodeError):
        raise HTTPException(
            status_code=500,
            detail="Unable to read model comparison results."
        )

    return {"models": results}

@app.get("/scan/{scan_id}/report")
def download_scan_report(
    scan_id: int,
    current_user=Depends(get_current_user)
):
    # Only allow the logged-in user to access their own scan.
    scan = get_scan_by_id(scan_id, user_id=current_user["id"])

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    buffer = BytesIO()
    pdf = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title=f"Smart Threat Guard Scan Report {scan_id}"
    )

    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph(
        "Smart Threat Guard - URL Scan Report",
        styles["Title"]
    ))
    content.append(Spacer(1, 12))

    content.append(Paragraph(
        f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        styles["Normal"]
    ))
    content.append(Paragraph(f"Scan ID: {scan_id}", styles["Normal"]))
    content.append(Spacer(1, 12))

    # Display scan details while safely escaping special HTML characters.
    from xml.sax.saxutils import escape

    def safe_text(value):
        return escape(str(value if value is not None else "N/A"))

    if isinstance(scan, dict):
        details = scan
    else:
        details = dict(scan)

    fields = [
        ["Field", "Value"],
        ["URL", safe_text(details.get("url"))],
        ["Prediction", safe_text(details.get("prediction"))],
        ["Risk Level", safe_text(details.get("risk_level"))],
        ["Risk Score", safe_text(details.get("risk_score"))],
    ]

    table = Table(fields, colWidths=[120, 350], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))

    content.append(table)
    content.append(Spacer(1, 16))
    content.append(Paragraph(
        "Disclaimer: This report is an automated assessment, not a guarantee "
        "that a URL is safe or malicious. Verify suspicious links independently.",
        styles["BodyText"]
    ))

    pdf.build(content)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
                f'attachment; filename="scan_report_{scan_id}.pdf"'
        }
    )
