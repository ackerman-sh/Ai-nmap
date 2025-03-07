# AI-Assisted Nmap Scanner

## Overview

AI-Assisted Nmap is a web-based tool that integrates Nmap scanning with AI-powered analysis. It enables users to execute Nmap scans, extract service details, query the NVD API for vulnerabilities, and generate AI-assisted reports for deeper analysis and reconnaissance recommendations.

## Features

- **Run Nmap Scans:** Execute Nmap commands through a web interface.
- **Extract Service Information:** Parse Nmap output to identify running services and versions.
- **CVE Lookup:** Query the NVD API for CVEs related to detected services.
- **AI-Powered Analysis:** Utilize AI models to analyze scan results and suggest further reconnaissance steps.
- **Real-Time Scan Streaming:** Display scan progress in real-time.
- **Custom AI Model Selection:** Choose from multiple AI models for analysis.

## Supported AI Models

Users can select AI models from the GitHub marketplace for scan result analysis:

GitHub Models Marketplace: https://github.com/marketplace/models

   **Default Model:** `DeepSeek-R1`

## Prerequisites

- Python 3.x
- Flask
- Nmap
- API key for NVD (stored in `api.json`)
- GitHub API token for model selection
- Internet connection for CVE and AI analysis

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ackerman-sh/Ai-nmap.git
   cd Ai-nmap
   ```
2. Run the installation script:
   ```bash
   bash install.sh
   ```
3. Verify that Nmap is installed:
   ```bash
   nmap --version
   ```
4. Add your NVD API key and GitHub API token to `api.json`:
   ```json
   {
       "NVD_API_KEY": "your_api_key_here",
       "GITHUB_TOKEN": "your_fine-grained_api_key_here"
   }
   ```
   - Request an NVD API key: https://nvd.nist.gov/developers/request-an-api-key
   - Generate a GitHub fine-grained api token: https://github.com/settings/tokens

## Usage

1. Activate the virtual environment:
   ```bash
   source myenv/bin/activate
   ```
2. Start the Flask server:
   ```bash
   python app.py
   ```
3. Open the web interface:
   ```
   http://127.0.0.1:5000
   ```
4. Enter an Nmap command and initiate the scan.
5. Analyze detected services for CVEs.
6. Generate an AI-powered report for further insights.

## API Endpoints

### `/scan`
- **Method:** GET  
- **Params:** `nmap_command` (string)  
- **Description:** Executes an Nmap scan and streams the results.

### `/analyze`
- **Method:** GET  
- **Description:** Extracts services from the last Nmap scan and queries the NVD API for CVE data.

### `/get_ai_report`
- **Method:** POST  
- **Payload:**  
  ```json
  {
      "ai_model": "deepseek-ai/DeepSeek-R1",
      "scan_data": "Nmap scan results"
  }
  ```
- **Description:** Sends scan data to an AI model for analysis and recommendations.

## Customizing AI Prompts

Users can modify the AI prompt for analysis by editing the `app.py` file at the designated section:

```python
# Modify AI prompt if needed
```

This allows customization of how AI interprets and responds to scan results.

## Security Considerations

- Only sanitized Nmap commands are allowed to prevent arbitrary code execution.
- Uses `subprocess.Popen()` for real-time scan streaming.
- Supports multiple AI models for analysis.

## Future Enhancements

- UI improvements
- Additional AI models for advanced analysis
- Enhanced security measures

