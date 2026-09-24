"""
FastAPI entrypoint for the agentic threat intelligence tool.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.agent import run_threat_intel_agent
from app.config import settings
from app.mitre_attack import knowledge_base
from app.models import AnalyzeRequest, HealthResponse, TechniqueDetail, ThreatReport
from app.tools import DEFAULT_FEEDS

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("threat_intel.main")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(key: str = Security(api_key_header)) -> None:
    """Simple shared-secret check against TI_API_KEY."""
    if not key or key != settings.ti_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-API-Key header.",
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Runs once at startup (before yield) and once at shutdown (after)."""
    logger.info("Loading MITRE ATT&CK knowledge base...")
    try:
        knowledge_base.load()
    except Exception as exc:
        logger.error("Failed to load ATT&CK data at startup: %s", exc)
    yield


app = FastAPI(
    title="Agentic Threat Intelligence Tool",
    description=(
        "LangChain + OpenAI agent that autonomously gathers open-source threat "
        "intel and maps observed behavior to MITRE ATT&CK techniques."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    """No auth required -- handy for uptime checks."""
    return HealthResponse(
        status="ok" if knowledge_base.count > 0 else "degraded (ATT&CK data not loaded)",
        attack_techniques_loaded=knowledge_base.count,
        openai_model=settings.openai_model,
    )


@app.get("/feeds", tags=["meta"])
async def list_feeds() -> dict:
    """No auth required -- public info about what the tool can read."""
    return DEFAULT_FEEDS


@app.get(
    "/techniques/{technique_id}",
    response_model=TechniqueDetail,
    tags=["mitre-attack"],
    dependencies=[Depends(require_api_key)],
)
async def get_technique(technique_id: str) -> TechniqueDetail:
    tech = knowledge_base.get(technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail=f"Technique '{technique_id}' not found.")
    return TechniqueDetail(
        technique_id=tech.technique_id,
        name=tech.name,
        description=tech.description,
        tactics=tech.tactics,
        url=tech.url,
        platforms=tech.platforms,
    )


@app.post(
    "/analyze",
    response_model=ThreatReport,
    tags=["analysis"],
    dependencies=[Depends(require_api_key)],
    summary="Run the agent to research a topic and return a structured, MITRE ATT&CK-mapped threat report",
)
async def analyze(req: AnalyzeRequest) -> ThreatReport:
    if knowledge_base.count == 0:
        raise HTTPException(
            status_code=503,
            detail="MITRE ATT&CK knowledge base is not loaded; check server logs / network access.",
        )
    try:
        report = run_threat_intel_agent(
            query=req.query, sources=req.sources, max_sources=req.max_sources
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception:
        logger.exception("Unhandled error during /analyze")
        raise HTTPException(status_code=500, detail="Internal error while running the agent.")
    return report
