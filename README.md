# Agentic Threat Intelligence Tool

LangChain + OpenAI agent that autonomously gathers open-source threat intel
and maps observed behavior to MITRE ATT&CK techniques.

## Setup

```bash
cd threat-intel-tool
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# then edit .env and set OPENAI_API_KEY and TI_API_KEY
```

## Run

```bash
uvicorn app.main:app --reload --port 8000
```

Visit `http://localhost:8000/docs` to try it interactively, or:

```bash
python examples/client_example.py "your topic here"
```

## Project layout

```
threat-intel-tool/
├── requirements.txt
├── .env.example
├── app/
│   ├── config.py        # .env -> settings object
│   ├── models.py        # request/response shapes
│   ├── mitre_attack.py  # ATT&CK download, cache, search
│   ├── tools.py         # tools the agent can call
│   ├── agent.py         # research + synthesis pipeline
│   └── main.py          # FastAPI routes
├── examples/
│   └── client_example.py
└── data/                 # cached ATT&CK bundle lands here
```

## Known issues & fixes

**`TypeError: Client.__init__() got an unexpected keyword argument 'proxies'`**
A newer `httpx` than `openai==1.54.4` expects gets installed by default. Fix:
```bash
pip install "httpx==0.27.2"
```
Then fully restart the server (Ctrl+C, then `uvicorn app.main:app --reload --port 8000` again).

**`401 Unauthorized` on `/analyze`**
`X-API-Key` header doesn't match `TI_API_KEY` in `.env`. Common causes: edited `.env.example` instead of `.env` by mistake, or edited `.env` but didn't restart the server (it only reads `.env` once, at startup — changes don't apply until you stop and re-run `uvicorn`).

**`openai.RateLimitError: ... insufficient_quota`**
Your OpenAI account has no billing/credits. Add a payment method at platform.openai.com/settings/organization/billing — no code changes needed once credits are added.

**`attack_techniques_loaded: 0` from `/health`**
The ATT&CK STIX bundle download failed or hadn't finished. Check the terminal log right after "Loading MITRE ATT&CK knowledge base..." for the real error, and try restarting the server.

**General rule:** any time you edit `.env` or install a new package, fully stop (`Ctrl+C`) and restart `uvicorn` — neither change takes effect on a server that's already running.
