from flask import Flask, render_template, request, Response, jsonify, json
import subprocess
import re
import requests
import os
import time
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential
from azure.ai.inference.models import UserMessage

app = Flask(__name__)

# Load API Key from api.json
def load_api_key(key_name):
    try:
        with open("api.json", "r") as file:
            data = json.load(file)
            return data.get(key_name, None)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

# Load API keys
NVD_API_KEY = load_api_key("NVD_API_KEY")
GITHUB_TOKEN = load_api_key("GITHUB_TOKEN")

if not GITHUB_TOKEN:
    raise ValueError("❌ GITHUB_TOKEN is missing in api.json!")
if not NVD_API_KEY:
    raise ValueError("❌ NVD_API_KEY is missing in api.json!")

client = ChatCompletionsClient(
    endpoint="https://models.inference.ai.azure.com",
    credential=AzureKeyCredential(GITHUB_TOKEN)
)

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
        return [{"CVE": "Error", "Description": "Missing API key. Ensure api.json contains 'NVD_API_KEY'."}]

    query = f"{service} {version}" if version else service
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
        return [{"CVE": "Error", "Description": f"API request failed: {str(e)}"}]
    
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
    global nmap_scan
    data = request.json
    scan_data = data.get(nmap_scan, "").strip()

    if not nmap_scan:
        return jsonify({"error": "Scan data is empty. Provide valid input."}), 400
	
    user_query = f"Analyze this scan report and suggest further commands:\n{nmap_scan}"  # Change Prompt if needed

    def generate_response():
        yield "Initializing GitHub AI Chat Client...\n\n"
        yield "✅ Successfully authenticated with GitHub AI endpoint\n\n"
        yield "📩 Sending query to DeepSeek-R1 model:\n----------------------------------------\n\n"
        yield f"{nmap_scan}\n\n"
        yield "----------------------------------------\n\n"
        yield "⌛ Please be patient for a minute... Fetching AI analysis...\n\n"
        yield "----------------------------------------\n\n"
        start_time = time.time()
        
        try:
            response = client.complete(
                messages=[UserMessage(user_query)],
                model="DeepSeek-R1",
                max_tokens=2048,
                temperature=0.7
            )

            elapsed_time = time.time() - start_time



            yield f"⏱️ Received response in {elapsed_time:.2f} seconds\n\n"
            yield f"🛠️ Model parameters:\n  - Model: {response.model}\n  - Tokens used: {response.usage.total_tokens}\n  - Finish reason: {response.choices[0].finish_reason}\n\n"

            yield "📝 Response content:\n==================================================\n\n"
            for chunk in response.choices[0].message.content.split("\n"):
                yield f"{chunk}\n\n"
                time.sleep(0.1) 

            yield "==================================================\n\n"
            yield "✅ AI Analysis Complete!\n\n"

        except Exception as e:
            yield f"🔥 Critical error occurred: {str(e)}\n\n"
            yield "⚠️ Troubleshooting tips:\n - Verify your GITHUB_TOKEN is valid and has proper permissions\n - Check network connectivity to GitHub AI endpoint\n - Ensure the DeepSeek-R1 model is available in your region\n\n"
         
            print(f"\n🔥 Critical error occurred: {str(e)}")
            print("⚠️ Troubleshooting tips:")
            print("- Verify your GITHUB_TOKEN is valid and has proper permissions")
            print("- Check network connectivity to GitHub AI endpoint")
            print("- Ensure the DeepSeek-R1 model is available in your region")
            raise  # Re-raise exception after logging
        
        print("\n✨ Chat completion process completed successfully!")

    return Response(generate_response(), mimetype="text/event-stream")

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

    formatted_response = []

    for service, cve_list in results.items():
        service_name = f"Service: {service}"  
        formatted_response.append(service_name)

        for cve in cve_list:
            if not isinstance(cve, dict): 
                continue  

            cve_entry = (
                f"CVE ID: {cve.get('CVE', 'Unknown')}\n"
                f"Description: {cve.get('Description', 'No description available')}\n"
                f"Risk Score: {cve.get('Risk Score', 'N/A')} | Exploitability: {cve.get('Exploitability', 'N/A')}\n"
                "--------------------------------------------------"
             )
            formatted_response.append(cve_entry)


    return jsonify({"formatted_data": "\n".join(formatted_response)})

# Home route
@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
