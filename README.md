# Smart Threat Guard

##  Phishing & Malicious URL Detection System

Smart Threat Guard is a machine-learning-based web application designed to detect potentially phishing or malicious URLs.

The system extracts URL-based features, uses a Random Forest classifier to predict whether a URL is phishing or legitimate, calculates a risk score, and performs additional rule-based security checks.

## Project Status

**Current Implementation: 80% Complete**

The current version includes:

- Machine learning model
- FastAPI backend
- URL feature extraction
- Risk score calculation
- Rule-based security analyzer
- SQLite scan history
- Dashboard
- Scan history
- Individual scan details
- URL feature analysis
- Professional web interface

---

## Features

- Phishing and legitimate URL classification
- Random Forest machine-learning model
- 12 URL-based features
- Risk score calculation
- Low, Medium, and High risk levels
- Rule-based URL security analyzer
- HTTPS security check
- IP address detection
- Suspicious domain extension detection
- URL shortener detection
- `@` symbol detection
- Suspicious keyword detection
- Subdomain analysis
- URL length analysis
- SQLite scan history
- Dashboard with statistics
- Scan history and search
- Individual scan details
- 12-feature URL analysis
- FastAPI REST API
- Responsive web interface

---

## Machine Learning

The current system uses a **Random Forest Classifier**.

### URL Features

The model uses these 12 features:

1. URL Length
2. Dot Count
3. Hyphen Count
4. Underscore Count
5. @ Symbol Count
6. Digit Count
7. Special Character Count
8. Subdomain Count
9. Path Length
10. Query Length
11. IP Address Usage
12. Suspicious Keyword Count

### Dataset

After preprocessing and duplicate removal, the dataset contains:

- Legitimate URLs: **30,016**
- Phishing URLs: **26,304**
- Total URLs: **56,320**

### Model Performance

The Random Forest model achieved approximately **98.9% accuracy on the held-out test split**.

| Algorithm | Accuracy | Precision | Recall | F1-Score |
|---|---:|---:|---:|---:|
| Random Forest | 98.90% | 1.00 | 0.98 | 0.99 |
| Decision Tree | 98.88% | 1.00 | 0.98 | 0.99 |
| Logistic Regression | 98.45% | 1.00 | 0.97 | 0.98 |

Random Forest is currently used as the main classification model.

> Note: The reported accuracy is based on the project's held-out test split. It should not be interpreted as guaranteed accuracy for every real-world URL.

---

## System Architecture

```text
User
  |
  v
Frontend URL Scanner
  |
  v
FastAPI Backend
  |
  +----------------------+
  |                      |
  v                      v
Feature Extraction   Security Analyzer
  |                      |
  v                      v
Random Forest        Rule-Based Checks
  |                      |
  +----------+-----------+
             |
             v
      Prediction & Risk Score
             |
             v
        SQLite Database
             |
       +-----+-----+
       |           |
       v           v
   Dashboard     History