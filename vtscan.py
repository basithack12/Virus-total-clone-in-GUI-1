from flask import Flask, request, jsonify
import requests
import json
import time
import csv
import base64
import os

app = Flask(__name__)

# Helper function to encode URLs to the VirusTotal required format
def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')

# Function to write results to a CSV file
def write_to_csv(output_file, ip_address, stats):
    file_exists = os.path.isfile(output_file)
    with open(output_file, 'a', newline='') as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(['URL', 'Malicious', 'Undetected', 'Harmless', 'Suspicious', 'Timeout'])
        writer.writerow([ip_address, stats['malicious'], stats['undetected'], stats['harmless'], stats['suspicious'], stats['timeout']])

# Function to analyze the stats and format them for output
def analyze_stats(stats):
    if stats is None:
        return {"message": "No analysis stats available."}
    return {
        "Malicious": stats['malicious'],
        "Undetected": stats['undetected'],
        "Harmless": stats['harmless'],
        "Suspicious": stats['suspicious'],
        "Timeout": stats['timeout']
    }

# Function to check VirusTotal for a URL
def check_virustotal_url(api_key, url, output_file=None):
    headers = {'x-apikey': api_key}
    encoded_url = encode_url(url)
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{encoded_url}", headers=headers)
    data = json.loads(response.text)

    if response.status_code == 200:
        attributes = data['data']['attributes']
        stats = attributes['stats']
        if output_file:
            write_to_csv(output_file, url, stats)
        return {"status": "success", "data": analyze_stats(stats)}

    elif response.status_code == 404:
        headers = {'x-apikey': api_key, 'Content-Type': 'application/x-www-form-urlencoded'}
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=f"url={url}")
        data = json.loads(response.text)

        if response.status_code == 200:
            data_id = data['data']['id']

            # Polling until the scan completes
            while True:
                time.sleep(30)
                response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{data_id}", headers=headers)
                data = json.loads(response.text)
                if response.status_code == 200:
                    attributes = data['data']['attributes']
                    stats = attributes['stats']
                    if attributes['status'] == 'completed':
                        if output_file:
                            write_to_csv(output_file, url, stats)
                        return {"status": "success", "data": analyze_stats(stats)}
                else:
                    return {"status": "error", "message": data.get('error', {}).get('message', 'Unknown error')}
        else:
            return {"status": "error", "message": data.get('error', {}).get('message', 'Unknown error')}
    else:
        return {"status": "error", "message": data.get('error', {}).get('message', 'Unknown error')}

# Flask routes
@app.route('/check_url', methods=['POST'])
def check_url():
    api_key = request.json.get('api_key')
    url = request.json.get('url')
    output_file = request.json.get('output_file', None)

    if not api_key or not url:
        return jsonify({"status": "error", "message": "API key and URL are required."}), 400

    result = check_virustotal_url(api_key, url, output_file)
    return jsonify(result)

@app.route('/check_urls', methods=['POST'])
def check_urls():
    api_key = request.json.get('api_key')
    urls = request.json.get('urls', [])
    output_file = request.json.get('output_file', None)

    if not api_key or not urls:
        return jsonify({"status": "error", "message": "API key and a list of URLs are required."}), 400

    results = []
    for url in urls:
        result = check_virustotal_url(api_key, url, output_file)
        results.append({"url": url, "result": result})

    return jsonify({"status": "success", "results": results})

if __name__ == '__main__':
    app.run(debug=True)
