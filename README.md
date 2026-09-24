# Agentic Threat Intelligence Tool

An AI-powered cybersecurity tool that researches open-source threat intelligence and maps observed attacker behavior to the **MITRE ATT&CK** framework.

## What It Does

This tool lets users enter a **threat intelligence topic** and automatically researches it using open-source security information.

It analyzes the findings and maps observed attacker behavior to MITRE ATT&CK techniques, providing supporting evidence, confidence scores, sources, and defensive recommendations.

## Input

* `query` - The threat intelligence topic you want the agent to research.
* `sources` - Optional sources to use. Set to `null` to let the agent find relevant sources.
* `max_sources` - Maximum number of sources the agent should research.

## Analysis Output

The final analysis includes:

* **Executive Summary** - Overview of key findings
* **Threat Actors** - Identified threat groups
* **Malware & Tools** - Malware or software associated with the activity
* **MITRE ATT&CK TTPs** - Techniques mapped to attacker behavior
* **Indicators of Compromise (IOCs)** - Relevant technical indicators
* **Recommendations** - Defensive actions based on the findings
* **Sources** - Sources used during research
* **Confidence Notes** - Context about the reliability of the findings

Each MITRE ATT&CK technique includes supporting evidence and a confidence score.

## How It Works

```text
Threat Intelligence Topic
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


## Tech Stack

* **Python**
* **LangChain**
* **OpenAI API**
* **FastAPI**
* **MITRE ATT&CK**
* **Pydantic**

## Project Structure

```text
threat-intel-tool/
├── requirements.txt
├── .env.example
├── app/
│   ├── config.py
│   ├── models.py
│   ├── mitre_attack.py
│   ├── tools.py
│   ├── agent.py
│   └── main.py
├── examples/
│   └── client_example.py
└── data/
```

## Setup

```bash
cd threat-intel-tool

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
```

Add your API keys to `.env`:

```env
OPENAI_API_KEY=your_openai_api_key
TI_API_KEY=your_threat_intelligence_api_key
```

## Run

Start the FastAPI server:

```bash
uvicorn app.main:app --reload --port 8000
```

Open **http://localhost:8000/docs** to test the API interactively.

You can also run:

```bash
python examples/client_example.py "recent ransomware targeting healthcare"
```

## MITRE ATT&CK Integration

The tool maps observed attacker behavior to standardized MITRE ATT&CK techniques.

Each technique can include:

* Technique ID
* Technique name
* Tactic
* Confidence score
* Supporting evidence
* ATT&CK URL when available

## Disclaimer

This project is intended for educational and defensive cybersecurity research purposes only.

It uses publicly available threat intelligence and does not perform attacks against systems.
