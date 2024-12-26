from flask import Flask, render_template, request, jsonify
import requests
import json
import time
import base64
import os

app = Flask(__name__)

# Ensure the uploads directory exists
UPLOAD_FOLDER = './uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Your VirusTotal API key
API_KEY = '7a0bb74fd4a8a9350319c42de96fe80df41080b11cf40fa07a95b1d338b50bba'

# Helper function to encode URLs for VirusTotal
def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')

# Function to analyze URL or file stats
def analyze_stats(stats):
    if stats is None:
        return {"message": "No analysis stats available."}
    return {
        "Malicious": stats.get('malicious', 0),
        "Undetected": stats.get('undetected', 0),
        "Harmless": stats.get('harmless', 0),
        "Suspicious": stats.get('suspicious', 0),
        "Timeout": stats.get('timeout', 0)
    }

# Function to check VirusTotal for a URL
def check_virustotal_url(url):
    headers = {'x-apikey': API_KEY}
    encoded_url = encode_url(url)
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{encoded_url}", headers=headers)
    data = json.loads(response.text)

    if response.status_code == 200:
        attributes = data['data']['attributes']
        stats = attributes['stats']
        return {"status": "success", "data": analyze_stats(stats)}
    else:
        return {"status": "error", "message": data.get('error', {}).get('message', 'Unknown error')}

# Function to upload and scan a file
def scan_file(file_path):
    headers = {'x-apikey': API_KEY}
    with open(file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
    data = json.loads(response.text)

    if response.status_code == 200:
        file_id = data['data']['id']
        # Poll the analysis results
        while True:
            time.sleep(10)  # Wait for 10 seconds before polling again
            response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{file_id}", headers=headers)
            data = json.loads(response.text)
            if data['data']['attributes']['status'] == 'completed':
                stats = data['data']['attributes']['stats']
                return {"status": "success", "data": analyze_stats(stats)}
    else:
        return {"status": "error", "message": data.get('error', {}).get('message', 'Unknown error')}

# Route to render the web interface
@app.route('/')
def home():
    return render_template('index.html')

# Route to handle URL scanning
@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.form.get('url')

    if not url:
        return jsonify({"status": "error", "message": "URL is required."}), 400

    result = check_virustotal_url(url)
    return jsonify(result)

# Route to handle file uploads
@app.route('/upload_file', methods=['POST'])
def upload_file():
    uploaded_file = request.files.get('file')

    if not uploaded_file:
        return jsonify({"status": "error", "message": "File is required."}), 400

    # Save the file locally
    file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
    uploaded_file.save(file_path)

    # Scan the uploaded file
    result = scan_file(file_path)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
