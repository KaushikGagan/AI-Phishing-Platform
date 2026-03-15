# 🛡️ PhishGuard AI — Multilingual Phishing Detection Platform

> AI-Powered Phishing Detection & Threat Intelligence Platform for Indian Enterprises  
> Built for national-level hackathon demonstration

---

## 🏗️ Architecture

```
Email Input
    │
    ├─► Preprocessing        → Language detection, text cleaning, feature extraction
    ├─► NLP Engine           → TF-IDF + Random Forest phishing classifier
    ├─► URL Analyzer         → Feature extraction + rule-based risk scoring
    ├─► Anomaly Detector     → Isolation Forest sender behavioral analysis
    ├─► Risk Scorer          → Weighted combination → score 0–100
    └─► Explainability       → Human-readable explanation of detection
```

---

## 📁 Project Structure

```
phishing_ai_platform/
│
├── data/
│   ├── sample_emails.json       # 10 multilingual sample emails
│   └── url_dataset.csv          # Labeled URL dataset
│
├── models/                      # Auto-generated trained model files
│
├── preprocessing/
│   └── text_processor.py        # Text cleaning, language detection, feature extraction
│
├── nlp_engine/
│   └── phishing_detector.py     # TF-IDF + Random Forest NLP classifier
│
├── url_analysis/
│   └── url_analyzer.py          # URL feature extraction + risk scoring
│
├── anomaly_detection/
│   └── behavioral_analyzer.py   # Isolation Forest sender anomaly detection
│
├── risk_scoring/
│   └── scorer.py                # Weighted risk scoring engine
│
├── explainability/
│   └── explainer.py             # AI explanation generator
│
├── dashboard/
│   └── app.py                   # Streamlit dashboard
│
├── api/
│   └── server.py                # FastAPI REST API
│
├── main.py                      # Pipeline orchestrator
├── requirements.txt
└── README.md
```

---

## ⚡ Quick Start

### 1. Install dependencies
```bash
cd phishing_ai_platform
pip install -r requirements.txt
```

### 2. Run the CLI pipeline
```bash
python main.py
```

### 3. Launch the dashboard
```bash
streamlit run dashboard/app.py
```

### 4. Start the API server (optional)
```bash
uvicorn api.server:app --reload --port 8000
```
API docs available at: http://localhost:8000/docs

---

## 🔍 Detection Modules

### 1. NLP Phishing Engine
- TF-IDF vectorizer (bigrams, 5000 features)
- Random Forest classifier (100 trees, balanced class weights)
- Detects: urgency language, credential harvesting, impersonation

### 2. Multilingual Support
| Language | Detection Method |
|----------|-----------------|
| English  | TF-IDF + keyword patterns |
| Hindi    | Unicode range detection + Devanagari keywords |
| Hinglish | Mixed script detection + transliterated patterns |
| Tamil    | Unicode range U+0B80–U+0BFF |
| Telugu   | Unicode range U+0C00–U+0C7F |

### 3. URL Risk Analysis
Features extracted per URL:
- Structural: length, dots, subdomains, hyphens, slashes
- Security: HTTPS, IP address presence, suspicious TLD
- Lexical: phishing keyword count, domain entropy
- Reputation: trusted domain check

### 4. Behavioral Anomaly Detection
- Isolation Forest trained on sender patterns
- Detects: domain spoofing, odd-hour sending, suspicious TLDs, unknown domains

### 5. Risk Scoring Weights
| Module | Weight |
|--------|--------|
| NLP Score | 35% |
| URL Risk Score | 30% |
| Anomaly Score | 20% |
| Domain Reputation | 15% |

Risk Levels:
- 0–30 → ✅ Safe
- 31–60 → ⚠️ Suspicious  
- 61–100 → 🚨 High Risk

---

## 📊 Dashboard Features
- Real-time email scanning with instant results
- Risk score gauge visualization
- Language distribution charts
- Risk heatmap across all emails
- URL batch analyzer
- Exportable CSV/JSON security reports
- Model performance metrics & confusion matrix

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/analyze/email` | Analyze a full email |
| POST | `/analyze/urls` | Analyze multiple URLs |

### Example API call
```bash
curl -X POST http://localhost:8000/analyze/email \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "security@paypa1.com",
    "sender_name": "PayPal Security",
    "subject": "URGENT: Account suspended",
    "body": "Click here to verify your account immediately: http://paypa1.xyz/login",
    "urls": ["http://paypa1.xyz/login"]
  }'
```

---

## 📦 Public Datasets

| Dataset | Link |
|---------|------|
| Phishing Email Dataset | https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset |
| PhishTank URL Dataset | https://www.phishtank.com/developer_info.php |
| SpamAssassin | https://spamassassin.apache.org/old/publiccorpus/ |
| OpenPhish | https://openphish.com/phish_feed.txt |
| CEAS 2008 Spam | https://www.kaggle.com/datasets/rtatman/fraudulent-email-corpus |

---

## 🧪 Test Phishing Examples

```
Sender: security@paypa1.com
Subject: URGENT: Your account has been suspended
Body: Click here to verify: http://paypa1-secure.xyz/login

Sender: noreply@sbi-bank-verify.net  
Subject: Aapka account band hone wala hai
Body: OTP share karo aur account verify karein

Sender: admin@axis-bank-kyc.xyz
Subject: మీ ఖాతా నిలిపివేయబడుతుంది
Body: OTP మరియు పాస్వర్డ్ ఇప్పుడే నమోదు చేయండి
```

---

## 📈 Evaluation Metrics

The NLP model is evaluated on a held-out test set:
- Accuracy, Precision, Recall, F1 Score
- Confusion Matrix
- False Positive Rate

All metrics are displayed live in the **Model Info** tab of the dashboard.

---

## 🏆 Hackathon Highlights

- ✅ Multilingual detection (5 languages including Indian regional)
- ✅ Explainable AI — human-readable phishing explanations
- ✅ Real-time scanning pipeline
- ✅ Interactive Streamlit dashboard with Plotly charts
- ✅ Risk heatmap visualization
- ✅ REST API with FastAPI
- ✅ Exportable security reports (CSV + JSON)
- ✅ Behavioral anomaly detection with Isolation Forest
- ✅ Zero external API dependencies — fully offline capable
