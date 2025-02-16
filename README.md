# AI-Assisted Nmap Scanner

## Overview

AI-Assisted Nmap is a web-based tool that integrates Nmap scanning with AI-powered analysis. It allows users to run Nmap scans, extract service information, check for vulnerabilities via NVD API, and generate AI-assisted reports for deeper analysis and further reconnaissance suggestions.

## Features

- **Run Nmap Scans:** Execute Nmap commands via the web interface.
- **Extract Service Information:** Parse Nmap output to identify running services and versions.
- **CVE Lookup:** Query NVD API for CVEs related to detected services.
- **AI-Powered Analysis:** Use AI models to analyze scan results and suggest further reconnaissance steps.
- **Real-time Scan Streaming:** Display scan progress in real time.
- **Custom AI Model Selection:** Choose from multiple AI models for analysis.

## Supported AI Models

The tool allows users to select from the following AI models for scan result analysis:

- `NousResearch/Nous-Hermes-2-Mixtral-8x7B-DPO`
- `Qwen/QwQ-32B-Preview`
- `databricks/dbrx-instruct`
- `deepseek-ai/deepseek-llm-67b-chat`
- `mistralai/Mistral-Small-24B-Instruct-2501`
- `deepseek-ai/DeepSeek-R1`
- `deepseek-ai/DeepSeek-V3`

## Prerequisites

- Python 3.x
- Flask
- Nmap
- API Key for NVD (stored in `api.json`)
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
3. Ensure Nmap is installed on your system:
   ```bash
   nmap --version
   ```
4. Add your NVD API key to `api.json`:
   ```json
   {
       "NVD_API_KEY": "your_api_key_here"
   }
   ```

## Usage

1. Activate the virtual environment:
   ```bash
   source myenv/bin/activate
   ```
2. Start the Flask server:
   ```bash
   python app.py
   ```
3. Open the web interface at:
   ```
   http://127.0.0.1:5000
   ```
4. Enter an Nmap command and run the scan.
5. Analyze detected services for CVEs.
6. Generate an AI-powered report for further analysis.
7. Select an AI model from the available choices for analysis.

## API Endpoints

### `/scan`

- **Method:** GET
- **Params:** `nmap_command` (string)
- **Description:** Runs an Nmap scan and streams results.

### `/analyze`

- **Method:** GET
- **Description:** Extracts services from the last Nmap scan and queries the NVD API for CVE data.

### `/get_ai_report`

- **Method:** POST
- **Payload:**
  ```json
  {
      "ai_model": "deepseek-ai/DeepSeek-R1",
      "scan_data": "Nmap scan results here"
  }
  ```
- **Description:** Sends scan data to an AI model for analysis and recommendations.

## Editing AI Prompt

Users can modify the AI prompt used for analysis by editing the `app.py` file at the section marked with:

```python
# Change Prompt if needed
```

This allows customization of how AI interprets and responds to scan results.

## Notes

- Only allows sanitized Nmap commands to prevent arbitrary code execution.
- Uses `subprocess.Popen()` for real-time scan streaming.
- Supports multiple AI models for analysis.

## Future Enhancements

- UI improvements.
- More AI models for enhanced analysis.
- Additional security hardening.

