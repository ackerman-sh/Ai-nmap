from flask import Flask, render_template, request, Response, jsonify, json
import subprocess
import re
import requests

app = Flask(__name__)

# Load API Key from api.json
def load_api_key():
    try:
        with open("api.json", "r") as file:
            data = json.load(file)
            return data.get("NVD_API_KEY", None)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

NVD_API_KEY = load_api_key()

# Extract service names and versions from nmap output
def extract_services(nmap_output):
    services_and_versions = {}

    pattern = re.compile(r"(\d{1,5}/\w+)\s+open\s+([\w-]+)(?:\s+([\w\d\.\-]+))?")

    for match in pattern.findall(nmap_output):
        port, service, version = match
        services_and_versions[service] = version if version else ""

    return services_and_versions


# Query NVD for CVEs related to a specific service and version
def get_cve_data(service, version):
    if not NVD_API_KEY:
        return {"error": "Missing API key. Ensure api.json contains 'NVD_API_KEY'."}

    query = f"{service} {version}" if version != "" else service
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"
    headers = {"apiKey": NVD_API_KEY, "Content-Type": "application/json"}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            return [{"CVE": "No CVEs found", "Description": "No known vulnerabilities"}]

        cve_list = []
        for cve in vulnerabilities[:5]:
            cve_id = cve["cve"]["id"]
            description = cve["cve"]["descriptions"][0]["value"]

            cvss_data = cve.get("cve", {}).get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {})
            risk_score = cvss_data.get("baseScore", "N/A")
            exploitability = cvss_data.get("exploitabilityScore", "N/A")

            cve_list.append({
                "CVE": cve_id,
                "Description": description,
                "Risk Score": risk_score,
                "Exploitability": exploitability
            })

        return cve_list

    except requests.exceptions.RequestException as e:
        return {"error": f"API request failed: {str(e)}"}
nmap_scan =""

# Command Sanitization
def sanitize_command(user_input):
    allowed_pattern = re.compile(r"^[a-zA-Z0-9\s\-\/\.\:]+$")
    return bool(allowed_pattern.match(user_input)) and user_input.strip().startswith("nmap")

# Run Nmap Scan without Cleaning
def run_nmap_scan(nmap_command):
    global nmap_scan
    nmap_scan = ""
    if not sanitize_command(nmap_command):
        yield "data: [ERROR] Invalid command!\n\n"
        return

    process = subprocess.Popen(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) 

    for line in iter(process.stdout.readline, ''):
        nmap_scan += line
        yield f"data: {line.strip()}\n\n"  
        process.stdout.flush()

# Stream Nmap Scan Results
@app.route("/scan")
def scan():
    nmap_command = request.args.get("nmap_command", "")  
    return Response(run_nmap_scan(nmap_command), mimetype="text/event-stream")

# AI Report Generation
@app.route("/get_ai_report", methods=["POST"])
def get_ai_report():
    data = request.json
    ai_model = data.get("ai_model", "deepseek-ai/DeepSeek-R1")
    scan_data = data.get("scan_data", "").strip()

    AI_MODELS = [
        "NousResearch/Nous-Hermes-2-Mixtral-8x7B-DPO",
        "Qwen/QwQ-32B-Preview",
        "databricks/dbrx-instruct",
        "deepseek-ai/deepseek-llm-67b-chat",
        "mistralai/Mistral-Small-24B-Instruct-2501",
        "deepseek-ai/DeepSeek-R1",
        "deepseek-ai/DeepSeek-V3"
    ]

    if ai_model not in AI_MODELS:
        return jsonify({"error": "Invalid AI model selected."}), 400

    if not scan_data:
        return jsonify({"error": "Scan data is empty. Provide valid input."}), 400

    url = "https://api.blackbox.ai/api/chat"
    payload = {
	# Change Prompt if needed
        "messages": [{"content": f"Buddy! Analyse this scan report fully and also suggest 7 more commands with short description and matching current services on this report for further scans helping to find vulnerabilities : {scan_data}", "role": "user"}],
        "model": ai_model,
        "max_tokens": 1024
    }
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()                                                  # Raise an exception for 4xx and 5xx HTTP errors

        try:
            ai_response = response.json()                                            # Try parsing JSON response
            if isinstance(ai_response, dict) and "text" in ai_response:
                return jsonify({"response_text": ai_response["text"]})               # Expected JSON format
            else:
                return jsonify({"response_text": response.text})                     # If JSON doesn't contain "text" key, return raw text
        except ValueError:
            return jsonify({"response_text": response.text})                         # Return plain text if JSON parsing fails

    except requests.exceptions.Timeout:
        return jsonify({"error": "AI request timed out"}), 500

    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Failed to connect to AI API. Check your network or API URL."}), 500

    except requests.exceptions.HTTPError as http_err:
        return jsonify({"error": f"HTTP error occurred: {http_err}", "status_code": response.status_code}), 500

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"AI request failed: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500                # Catch-all for unexpected errors

#CVE Lookup
@app.route("/analyze", methods=["GET"])
def analyze():
    global nmap_scan

    if not nmap_scan.strip():
        return jsonify({"error": "Nmap scan is empty. Run a scan first."}), 400

    services = extract_services(nmap_scan)  
    if not services:
        return jsonify({"error": "No services found in the Nmap output."}), 400

    results = {service: get_cve_data(service, version) for service, version in services.items()}

    if not any(results.values()):  
        return jsonify({"error": "No CVEs found for detected services."}), 404

    # Formatting the response
    formatted_response = []

    for service, cve_list in results.items():
        service_name = f"Service: {service}"  
        formatted_response.append(service_name)

        for cve in cve_list:
            cve_entry = (
                f"CVE ID: {cve['CVE']}\n"
                f"Description: {cve['Description']}\n"
                f"Risk Score: {cve['Risk Score']} | Exploitability: {cve['Exploitability']}\n"
                "--------------------------------------------------"
            )
            formatted_response.append(cve_entry)

    return jsonify({"formatted_data": "\n".join(formatted_response)})



# Home route
@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=False)
