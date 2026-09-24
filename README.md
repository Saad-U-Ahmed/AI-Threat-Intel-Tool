# Agentic Threat Intelligence Tool

An AI-powered cybersecurity tool that researches open-source threat intelligence and maps observed attacker behavior to the **MITRE ATT&CK** framework.

## What It Does

This tool lets users enter a threat intelligence topic and automatically researches it using open-source security information.

It then analyzes the findings and maps observed attacker behavior to MITRE ATT&CK techniques, providing supporting evidence, confidence scores, sources, and defensive recommendations.

Inputs:

query - The threat intelligence topic you want the agent to research.
sources - Optional sources to use. Set to null to let the agent find relevant sources.
max_sources - Maximum number of sources the agent should research.
```

The AI agent researches the topic, gathers relevant threat intelligence, analyzes the findings, and produces a structured threat intelligence report.

## Analysis Output

The final analysis includes:

* **Executive Summary** - Overview of the key findings
* **Threat Actors** - Identified threat groups
* **Malware & Tools** - Malware or software associated with the activity
* **MITRE ATT&CK TTPs** - Techniques mapped to attacker behavior
* **Indicators of Compromise (IOCs)** - Relevant technical indicators
* **Recommendations** - Defensive actions based on the findings
* **Sources** - Articles and other sources used during research
* **Confidence Notes** - Additional context about the reliability of the findings

Each identified MITRE ATT&CK technique includes:

```json
{
  "technique_id": "T1486",
  "name": "Data Encrypted for Impact",
  "tactic": ["impact"],
  "confidence": 0.95,
  "evidence": "The primary goal of ransomware is to encrypt data and demand ransom."
}
```

This provides both the ATT&CK mapping and the evidence supporting the mapping.

## How It Works

The project uses an agentic AI workflow:

```text
User Query
    ↓
AI Research Agent
    ↓
Open-Source Threat Intelligence
    ↓
Evidence Analysis
    ↓
MITRE ATT&CK Mapping
    ↓
Structured Threat Intelligence Report
```

The research agent gathers information from available sources and the analysis stage converts the findings into a structured response.

## Example

A user can submit:

```json
{
  "query": "recent ransomware targeting healthcare",
  "sources": null,
  "max_sources": 3
}
```

The tool can return findings such as:

```text
Executive Summary
        ↓
Threat Actors
        ↓
Malware / Tools
        ↓
MITRE ATT&CK Techniques
        ↓
Indicators of Compromise
        ↓
Recommendations
        ↓
Research Sources
```

For example, a ransomware analysis may identify **T1486 - Data Encrypted for Impact**, along with a confidence score and supporting evidence.

## Tech Stack

* **Python** - Core programming language
* **LangChain** - AI agent and tool orchestration
* **OpenAI API** - LLM-powered research and analysis
* **FastAPI** - REST API
* **MITRE ATT&CK** - Framework for mapping attacker behavior
* **Pydantic** - Data validation and structured responses

## Project Structure

```text
threat-intel-tool/
├── requirements.txt
├── .env.example
├── app/
│   ├── config.py          # Environment and API settings
│   ├── models.py          # Request and response models
│   ├── mitre_attack.py    # MITRE ATT&CK data and search
│   ├── tools.py           # Tools available to the AI agent
│   ├── agent.py           # Research and synthesis pipeline
│   └── main.py            # FastAPI application
├── examples/
│   └── client_example.py  # Example API client
└── data/                  # Cached MITRE ATT&CK data
```

## Setup

Clone the repository:

```bash
git clone <your-repository-url>
cd threat-intel-tool
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate it:

### macOS / Linux

```bash
source venv/bin/activate
```

### Windows

```bash
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create the environment file:

```bash
cp .env.example .env
```

Add your API keys:

```env
OPENAI_API_KEY=your_openai_api_key
TI_API_KEY=your_threat_intelligence_api_key
```

## Running the Project

Start the FastAPI server:

```bash
uvicorn app.main:app --reload --port 8000
```

Open the interactive API documentation:

```text
http://localhost:8000/docs
```

The `/docs` page allows you to interact with and test the API directly from your browser.

You can also use the example client:

```bash
python examples/client_example.py "recent ransomware targeting healthcare"
```

## API

### `POST /analyze`

The main endpoint accepts a cybersecurity research query.

### Request

```json
{
  "query": "recent ransomware targeting healthcare",
  "sources": null,
  "max_sources": 3
}
```

### Response

The endpoint returns a structured analysis containing:

```text
query
executive_summary
threat_actors
malware_or_tools
ttps
iocs
recommendations
sources
confidence_notes
```

## MITRE ATT&CK Integration

The tool uses the MITRE ATT&CK framework to map observed attacker behavior to standardized techniques.

For each technique, the analysis can provide:

* Technique ID
* Technique name
* ATT&CK tactic
* Confidence score
* Supporting evidence
* ATT&CK URL when available

This helps connect unstructured threat intelligence reports with a standardized cybersecurity framework.


## Disclaimer

This project is intended for educational and defensive cybersecurity research purposes.

It uses publicly available threat intelligence and does not perform attacks against systems.
