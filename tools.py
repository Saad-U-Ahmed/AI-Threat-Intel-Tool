"""
LangChain tools available to the agent:
- list_default_feeds, fetch_rss_feed, fetch_article_text,
  mitre_attack_lookup, mitre_attack_technique
"""
from __future__ import annotations

import logging
from typing import List, Optional

import feedparser
import requests
from bs4 import BeautifulSoup
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from app.config import settings
from app.mitre_attack import knowledge_base

logger = logging.getLogger("threat_intel.tools")

# A small, hand-picked list of reputable security news sources. Deliberately
# short -- we want the agent reading a few good sources per run.
DEFAULT_FEEDS = {
    "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Microsoft Security Blog": "https://www.microsoft.com/en-us/security/blog/feed/",
    "Talos Intelligence": "https://blog.talosintelligence.com/rss/",
}

_HEADERS = {"User-Agent": "ThreatIntelAgent/1.0 (+security research tool)"}


@tool
def list_default_feeds() -> str:
    """List the curated default OSINT RSS feeds this tool can pull from,
    as 'name: url' lines. Use this first if the user didn't supply sources."""
    return "\n".join(f"{name}: {url}" for name, url in DEFAULT_FEEDS.items())


class FetchRSSArgs(BaseModel):
    feed_url: str = Field(..., description="RSS/Atom feed URL to fetch.")
    max_entries: int = Field(default=6, ge=1, le=20)
    query_filter: Optional[str] = Field(
        default=None,
        description="Optional keyword/phrase to filter entry titles+summaries by "
        "(case-insensitive substring match). Use this to narrow a broad feed "
        "down to the topic being researched.",
    )


@tool("fetch_rss_feed", args_schema=FetchRSSArgs)
def fetch_rss_feed(feed_url: str, max_entries: int = 6, query_filter: Optional[str] = None) -> str:
    """Fetch recent entries from an RSS/Atom feed. Returns a numbered list of
    'title | published | link | summary' for each matching entry. Use
    query_filter to narrow results to a specific actor/malware/topic."""
    try:
        parsed = feedparser.parse(feed_url)
    except Exception as exc:
        return f"ERROR fetching feed {feed_url}: {exc}"

    if parsed.bozo and not parsed.entries:
        return f"ERROR: could not parse feed at {feed_url}"

    entries = parsed.entries
    if query_filter:
        q = query_filter.lower()
        entries = [
            e for e in entries
            if q in (e.get("title", "") + " " + e.get("summary", "")).lower()
        ]

    entries = entries[:max_entries]
    if not entries:
        return f"No entries found in {feed_url}" + (f" matching '{query_filter}'" if query_filter else "")

    lines = []
    for i, e in enumerate(entries, 1):
        summary = BeautifulSoup(e.get("summary", ""), "html.parser").get_text(strip=True)[:300]
        lines.append(
            f"{i}. {e.get('title', 'Untitled')} | {e.get('published', 'n/a')} | "
            f"{e.get('link', 'n/a')} | {summary}"
        )
    return "\n".join(lines)


class FetchArticleArgs(BaseModel):
    url: str = Field(..., description="Full article URL to fetch and extract readable text from.")
    max_chars: int = Field(default=4000, ge=500, le=12000)


@tool("fetch_article_text", args_schema=FetchArticleArgs)
def fetch_article_text(url: str, max_chars: int = 4000) -> str:
    """Fetch a web page and extract its main readable text (script/style/nav
    stripped). Use this to read the full content of an article surfaced by
    fetch_rss_feed before summarizing or extracting TTPs/IOCs from it."""
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=settings.request_timeout_seconds)
        resp.raise_for_status()
    except requests.RequestException as exc:
        return f"ERROR fetching {url}: {exc}"

    soup = BeautifulSoup(resp.text, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header", "form", "aside"]):
        tag.decompose()

    text = " ".join(soup.get_text(separator=" ").split())
    if not text:
        return f"ERROR: no extractable text at {url}"
    return text[:max_chars]


class MitreLookupArgs(BaseModel):
    text: str = Field(..., description="Free text describing observed adversary behavior, "
                                        "e.g. an article excerpt or incident description.")
    top_k: int = Field(default=8, ge=1, le=20)


@tool("mitre_attack_lookup", args_schema=MitreLookupArgs)
def mitre_attack_lookup(text: str, top_k: int = 8) -> str:
    """Map free-text threat reporting onto candidate MITRE ATT&CK (Enterprise)
    techniques using keyword matching. Returns candidate technique_id, name,
    tactic(s), a heuristic confidence 0-1, and the evidence snippet. This is a
    SHORTLIST for you to reason over -- discard low-confidence/irrelevant
    matches rather than reporting every candidate."""
    if knowledge_base.count == 0:
        return "ERROR: ATT&CK knowledge base not loaded."

    matches = knowledge_base.match(text, top_k=top_k)
    if not matches:
        return "No candidate ATT&CK techniques matched this text."

    lines = []
    for m in matches:
        lines.append(
            f"{m['technique_id']} | {m['name']} | tactics: {', '.join(m['tactic']) or 'n/a'} "
            f"| confidence: {m['confidence']} | evidence: \"{m['evidence']}\""
        )
    return "\n".join(lines)


class TechniqueDetailArgs(BaseModel):
    technique_id: str = Field(..., description="ATT&CK technique ID, e.g. T1566 or T1566.001")


@tool("mitre_attack_technique", args_schema=TechniqueDetailArgs)
def mitre_attack_technique(technique_id: str) -> str:
    """Look up the full name, tactics, platforms, and description for a
    specific MITRE ATT&CK technique ID."""
    tech = knowledge_base.get(technique_id)
    if not tech:
        return f"No technique found for ID '{technique_id}'."
    desc = tech.description[:600]
    return (
        f"{tech.technique_id} - {tech.name}\n"
        f"Tactics: {', '.join(tech.tactics) or 'n/a'}\n"
        f"Platforms: {', '.join(tech.platforms) or 'n/a'}\n"
        f"URL: {tech.url}\n"
        f"Description: {desc}"
    )


def get_all_tools() -> List:
    """Bundles every tool above into one list for the agent to use."""
    return [
        list_default_feeds,
        fetch_rss_feed,
        fetch_article_text,
        mitre_attack_lookup,
        mitre_attack_technique,
    ]
