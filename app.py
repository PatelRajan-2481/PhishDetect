from flask import Flask, request, jsonify, render_template
import re
import datetime
import json
import os

@app.route('/history', methods=['GET'])
def get_history():
    filename = "scan_results.json"
    if not os.path.exists(filename):
        return jsonify([])

    with open(filename, "r") as f:
        data = json.load(f)
    return jsonify(data)

