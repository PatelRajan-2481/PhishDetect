# 🛡️ PhishDetect – Phishing Email & URL Detection System

PhishDetect is an intelligent web-based phishing detection tool that uses a hybrid approach of rule-based heuristics, machine learning models, and VirusTotal API integration. It allows users to scan suspicious **URLs** and **email bodies**, get instant classification (Safe / Suspicious / Malicious), and view scan history – all wrapped in a secure login-protected interface using **AWS Cognito**.

## 🔗 Live Demo

🌐 https://phishdetect.online  

👤 Admin Test User: `rhpatel27@myseneca.ca`  
🔑 Password: `Admin@1234` 

👤 Standard Test User: `rajanhpatel2481@gmail.com`  
🔑 Password: `SecureTest@123`  


> ⚠️ *You must log in before accessing any page.*

---

## 🧩 Features

- ✅ Scan Email body for phishing content
- ✅ Scan URLs with rule-based and VirusTotal results
- ✅ ML-powered phishing classifier trained on real dataset
- ✅ Visual scan history with CSV export & admin dashboard
- ✅ User authentication with AWS Cognito
- ✅ Cloud logging to AWS S3
- ✅ Email alerts on malicious detection (via AWS SES)
- ✅ HTTPS-enabled public deployment

---

## 🏗️ Tech Stack

| Layer            | Tools/Tech Used |
|------------------|-----------------|
| **Frontend**     | HTML, Bootstrap 5, JS, Jinja2 |
| **Backend**      | Flask (Python) |
| **ML Model**     | Scikit-learn, TF-IDF, Random Forest |
| **Cloud Services** | AWS Cognito, S3, SES |
| **Security**     | HTTPS (via Render), AWS IAM |
| **Deployment**   | Render.com (Free Tier) |

---

## 🔍 Architecture Diagram

![🔍Architecture Diagram](https://github.com/PatelRajan-2481/PhishDetect/blob/main/Architecture%20Diagram.png)

## 🚀 Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/PatelRajan-2481/phishdetect.git
cd phishing-backend
```
### 2. Create & Activate Virtual Environment
```bash
python -m venv venv
# For Linux/macOS:
source venv/bin/activate
# For Windows:
venv\Scripts\activate

```
### 3. Install Dependencies
```bash
pip install -r requirements.txt
```
### 4. Create Configuration
Create a file named config.py in the root directory with the following contents:
```python
VT_API_KEY = "your_virustotal_api_key"

AWS_REGION = "us-east-1"
COGNITO_USER_POOL_ID = "your_user_pool_id"
COGNITO_CLIENT_ID = "your_client_id"
S3_BUCKET_NAME = "your_s3_bucket_name"

SES_SENDER = "verified_sender@example.com"
SES_RECIPIENT = "your_email@example.com"
```

Make sure:
- The VT_API_KEY is valid from VirusTotal API.
- Your SES emails are verified.
- Your IAM role has access to S3 and SES.

### 5. Run the App Locally
```bash
python app.py
```
Then open http://127.0.0.1:5000 in your browser.

Note: You must log in first (via Cognito) to access the dashboard.


