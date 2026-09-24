"""Pydantic schemas shared across the API and the agent."""
from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    rss = "rss"
    url = "url"


class AnalyzeRequest(BaseModel):
    query: str = Field(
        ...,
        description="What to investigate: a threat actor/group name, campaign, malware "
        "family, CVE, or a free-text topic (e.g. 'recent ransomware targeting healthcare').",
        min_length=3,
        max_length=500,
    )
    sources: Optional[List[str]] = Field(
        default=None,
        description="Optional explicit list of URLs or RSS feed URLs to ground the "
        "research in. If omitted, the agent chooses from its default OSINT feed list.",
    )
    max_sources: int = Field(default=6, ge=1, le=15)


class MappedTechnique(BaseModel):
    technique_id: str = Field(..., description="ATT&CK technique ID, e.g. T1566.001")
    name: str
    tactic: List[str] = Field(default_factory=list, description="Kill-chain tactic(s), e.g. ['initial-access']")
    url: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0, description="Heuristic match confidence 0-1")
    evidence: str = Field(..., description="Snippet of source text that justified this mapping")


class IOC(BaseModel):
    type: str = Field(..., description="ip | domain | url | hash | email | cve")
    value: str


class SourceRef(BaseModel):
    title: Optional[str] = None
    url: str
    published: Optional[str] = None


class ThreatReport(BaseModel):
    query: str
    executive_summary: str
    threat_actors: List[str] = Field(default_factory=list)
    malware_or_tools: List[str] = Field(default_factory=list)
    ttps: List[MappedTechnique] = Field(default_factory=list)
    iocs: List[IOC] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    sources: List[SourceRef] = Field(default_factory=list)
    confidence_notes: Optional[str] = Field(
        default=None, description="Caveats about coverage/recency/source reliability."
    )


class TechniqueDetail(BaseModel):
    technique_id: str
    name: str
    description: str
    tactics: List[str]
    url: str
    platforms: List[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str
    attack_techniques_loaded: int
    openai_model: str
