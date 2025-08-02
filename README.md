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

```plaintext
+------------------+       +------------------+      +----------------+
|  User Browser    | <---> |  Flask Backend   | <--->|  ML Classifier |
| (URL/Email Input)|       | (PhishDetect App)|      | & Rule Engine  |
+------------------+       +------------------+      +----------------+
          |                         |
          |                         v
          |              +------------------+
          |              | VirusTotal API   |
          |              +------------------+
          |
          v
+------------------+      +------------------+
| AWS Cognito Auth |      | AWS S3 (Logs)    |
+------------------+      +------------------+
                             |
                             v
                     Email Notification (SES)
