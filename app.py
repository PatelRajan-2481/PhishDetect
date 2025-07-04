from flask import Flask, request, jsonify, render_template
import re
import datetime
import json
import os

import requests
from config import VT_API_KEY

app = Flask(__name__)

# Simple rule-based phishing detection
def classify_url(url):
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account', 'signin', 'submit','password', 'bank', 'confirm', 'webscr', 'support', 'auth', 'reset', 'unlock', 'access', 'invoice', 'payment', 'ebay', 'paypal', 'alert', 'wallet', 'recovery', 'id', 'confirm', 'change', 'verification', 'security']
    if any(kw in url.lower() for kw in suspicious_keywords):
        return "Suspicious"
    if re.match(r'https?://\d{1,3}(\.\d{1,3}){3}', url):
        return "Malicious"
    if len(url) > 75:
        return "Suspicious"
    return "Safe"

# Save scan to a local file (can be changed to DynamoDB later)
def log_result(entry):
    filename = "scan_results.json"
    if os.path.exists(filename):
        with open(filename, "r") as f:
            data = json.load(f)
    else:
        data = []

    data.append(entry)

    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

def check_virustotal(url):
    try:
        headers = {
            "x-apikey": VT_API_KEY
        }
        params = {"url": url}
        # First, get a scan ID by submitting the URL
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)
        if response.status_code != 200:
            return "Error contacting VirusTotal"

        scan_id = response.json()["data"]["id"]

        # Then, get the analysis report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        import time
        time.sleep(5)  # Wait briefly for scan to complete

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

    suspicious_keywords = ['account suspended', 'verify your identity', 'click here', 'urgent action required','update your info', 'security alert', 'unauthorized access', 'payment failed','login attempt', 'reactivate', 'reset your password', 'confirm your email','suspicious activity', 'final notice', 'important update', 'limited time','dear user', 'validate', 'urgent verification', 'locked account']
    found = [kw for kw in suspicious_keywords if kw in email_body.lower()]

    result = "Safe"
    if len(found) >= 2:
        result = "Malicious"
    elif found:
        result = "Suspicious"

    log_entry = {
        "type": "email",
        "input": email_body[:100] + "...",  # preview
        "result": result,
        "timestamp": str(datetime.datetime.now())
    }
    log_result(log_entry)

    return jsonify({
        "email_excerpt": email_body[:100] + "...",
        "keywords_found": found,
        "result": result
    })
