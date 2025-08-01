from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import re
import datetime
import json
import os
import joblib
import requests
import boto3
from botocore.exceptions import ClientError

from config import VT_API_KEY, S3_BUCKET_NAME, S3_OBJECT_NAME, AWS_REGION
from cognito_auth import login_user

email_model = joblib.load("ml_model/email_model.joblib")
vectorizer = joblib.load("ml_model/vectorizer.joblib")

app = Flask(__name__)
app.secret_key = 'something-secure-and-random'

s3 = boto3.client('s3', region_name=AWS_REGION)

import boto3

SENDER_EMAIL = "patelrajankumar@gecg28.ac.in"
RECIPIENT_EMAIL = "rajanhpatel2481@gmail.com"

ses_client = boto3.client("ses", region_name="us-east-1")

def send_alert_email(subject, body):
    try:
        response = ses_client.send_email(
            Source=SENDER_EMAIL,
            Destination={"ToAddresses": [RECIPIENT_EMAIL]},
            Message={
                "Subject": {"Data": subject},
                "Body": {
                    "Text": {"Data": body}
                }
            }
        )
        print("✅ Email sent:", response['MessageId'])
    except Exception as e:
        print("❌ Email error:", str(e))


# Simple rule-based phishing detection
def classify_url(url):
    suspicious_keywords = ['update', 'secure', 'account', 'signin', 'submit','password', 'bank', 'confirm', 'webscr', 'support', 'auth', 'reset', 'unlock', 'access', 'invoice', 'payment', 'alert', 'wallet', 'recovery', 'id', 'confirm', 'change', 'verification', 'security']
    if any(kw in url.lower() for kw in suspicious_keywords):
        return "Suspicious"
    if re.match(r'https?://\d{1,3}(\.\d{1,3}){3}', url):
        return "Malicious"
    if len(url) > 75:
        return "Suspicious"
    return "Safe"

# Load scan history from S3
def load_scan_history():
    try:
        obj = s3.get_object(Bucket=S3_BUCKET_NAME, Key=S3_OBJECT_NAME)
        data = json.loads(obj['Body'].read().decode('utf-8'))
        return data
    except s3.exceptions.NoSuchKey:
        return []
    except ClientError as e:
        print("S3 load error:", e)
        return []

# Save scan to S3
def log_result(entry):
    data = load_scan_history()
    data.append(entry)
    try:
        s3.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=S3_OBJECT_NAME,
            Body=json.dumps(data, indent=4).encode('utf-8')
        )
    except ClientError as e:
        print("S3 write error:", e)

# VirusTotal scan
def check_virustotal(url):
    try:
        headers = {
            "x-apikey": VT_API_KEY
        }
        params = {"url": url}
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)
        if response.status_code != 200:
            return "Error contacting VirusTotal"

        scan_id = response.json()["data"]["id"]
        import time
        time.sleep(5)

        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        result = requests.get(report_url, headers=headers)
        if result.status_code != 200:
            return "Error retrieving report"

        stats = result.json()['data']['attributes']['stats']
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0:
            return "Malicious"
        elif suspicious > 0:
            return "Suspicious"
        else:
            return "Safe"
    except Exception as e:
        print("VirusTotal Error:", str(e))
        return "Scan Error"



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        token = login_user(email, password)
        if token:
            session['user'] = email
            session['is_admin'] = email.lower() == "rhpatel27@myseneca.ca"
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid credentials.")

    return render_template('login.html')

@app.route('/scan/url', methods=['POST'])
def scan_url():
    data = request.json
    url = data.get('url', '')
    if not url:
        return jsonify({"error": "Missing URL"}), 400

    rule_result = classify_url(url)
    vt_result = check_virustotal(url)

    final_result = "Malicious" if "Malicious" in [rule_result, vt_result] else \
                   "Suspicious" if "Suspicious" in [rule_result, vt_result] else "Safe"

    # 🚨 Send email if malicious
    if final_result == "Malicious":
        subject = "🚨 PhishDetect Alert: Malicious URL Detected"
        body = f"""A malicious URL was detected:

URL: {url}
Rule-based Result: {rule_result}
VirusTotal Result: {vt_result}
Final Classification: {final_result}
Time: {str(datetime.datetime.now())}
"""
        send_alert_email(subject, body)

    log_entry = {
        "type": "url",
        "input": url,
        "rule_based_result": rule_result,
        "virustotal_result": vt_result,
        "final_result": final_result,
        "timestamp": str(datetime.datetime.now())
    }
    log_result(log_entry)

    return jsonify({
        "url": url,
        "rule_based_result": rule_result,
        "virustotal_result": vt_result,
        "final_result": final_result
    })

@app.route('/scan/email', methods=['POST'])
def scan_email():
    data = request.json
    email_body = data.get('email', '')
    if not email_body:
        return jsonify({"error": "Missing email content"}), 400

    suspicious_keywords = [
        'account suspended', 'verify your identity', 'click here', 'urgent action required',
        'update your info', 'security alert', 'unauthorized access', 'payment failed',
        'login attempt', 'reactivate', 'reset your password', 'confirm your email',
        'suspicious activity', 'final notice', 'important update', 'limited time',
        'validate', 'urgent verification', 'locked account', 'unsubscribe', 'update your password'
    ]
    found = [kw for kw in suspicious_keywords if kw in email_body.lower()]

    rule_result = "Safe"
    if len(found) >= 2:
        rule_result = "Malicious"
    elif found:
        rule_result = "Suspicious"

    X = vectorizer.transform([email_body])
    ml_result = email_model.predict(X)[0].capitalize()

    if "Malicious" in [ml_result, rule_result]:
        final_result = "Malicious"
    elif rule_result == "Suspicious":
        final_result = "Suspicious"
    else:
        final_result = "Safe"

    # 🚨 Send email if malicious
    if final_result == "Malicious":
        subject = "🚨 PhishDetect Alert: Malicious Email Detected"
        body = f"""A malicious email body was detected:

Excerpt: {email_body[:100]}...
Rule-based Result: {rule_result}
ML Result: {ml_result}
Final Classification: {final_result}
Time: {str(datetime.datetime.now())}
"""
        send_alert_email(subject, body)

    log_entry = {
        "type": "email",
        "input": email_body[:100] + "...",
        "rule_based_result": rule_result,
        "ml_result": ml_result,
        "final_result": final_result,
        "timestamp": str(datetime.datetime.now())
    }
    log_result(log_entry)

    return jsonify({
        "email_excerpt": email_body[:100] + "...",
        "rule_based_result": rule_result,
        "ml_result": ml_result,
        "final_result": final_result
    })

@app.route('/history-page')
def history_view():
    if 'user' not in session:
        return redirect(url_for('login'))

    scans = load_scan_history()
    scans = sorted(scans, key=lambda x: x["timestamp"], reverse=True)
    return render_template("history.html", scans=scans)

@app.route('/admin')
def admin_dashboard_view():
    if not session.get('is_admin'):
        return "Unauthorized", 403

    scans = load_scan_history()
    scans = sorted(scans, key=lambda x: x["timestamp"], reverse=True)
    return render_template("dashboard.html", scans=scans)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=True)
