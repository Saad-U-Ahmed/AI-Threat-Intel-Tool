"""
MITRE ATT&CK (Enterprise) integration.

Downloads and caches the official ATT&CK STIX bundle, parses it into an
in-memory catalog of techniques, and provides simple keyword-based search
so free-text threat reporting can be mapped to candidate technique IDs.
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import requests

from app.config import settings

logger = logging.getLogger("threat_intel.mitre_attack")

# Common English filler words, plus threat-intel-specific filler words that
# show up in nearly every technique description and would otherwise match
# almost everything, making the search useless.
_STOPWORDS = {
    "the", "a", "an", "of", "to", "and", "or", "in", "on", "for", "with",
    "by", "is", "are", "was", "were", "this", "that", "as", "at", "from",
    "via", "using", "used", "use", "it", "its", "be", "been", "which",
    "attackers", "threat", "actor", "actors", "adversary", "adversaries",
}


def _tokenize(text: str) -> List[str]:
    """Break text into lowercase words, dropping punctuation, very short
    words, and stopwords."""
    words = re.findall(r"[a-zA-Z][a-zA-Z0-9\-]{2,}", text.lower())
    return [w for w in words if w not in _STOPWORDS]


@dataclass
class Technique:
    technique_id: str
    name: str
    description: str
    tactics: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    url: str = ""
    _keyword_set: set = field(default_factory=set, repr=False)

    def build_keywords(self) -> None:
        """Pre-compute this technique's keyword set once, so search is a
        fast set operation instead of re-scanning text every time."""
        tokens = set(_tokenize(self.name))
        tokens |= set(_tokenize(self.description)[:80])
        self._keyword_set = tokens


class AttackKnowledgeBase:
    """In-memory index over MITRE ATT&CK Enterprise techniques."""

    def __init__(self) -> None:
        self._techniques: Dict[str, Technique] = {}
        self._loaded_at: Optional[float] = None

    def _cache_is_fresh(self, path: Path) -> bool:
        if not path.exists():
            return False
        age_days = (time.time() - path.stat().st_mtime) / 86400
        return age_days < settings.attack_cache_max_age_days

    def _download_bundle(self, path: Path) -> None:
        logger.info("Downloading ATT&CK STIX bundle from %s", settings.attack_stix_url)
        resp = requests.get(settings.attack_stix_url, timeout=settings.request_timeout_seconds * 4)
        resp.raise_for_status()
        path.write_bytes(resp.content)
        logger.info("Cached ATT&CK bundle to %s (%d bytes)", path, len(resp.content))

    def load(self, force_refresh: bool = False) -> None:
        """Main entry point -- called once when the server starts up."""
        path = settings.attack_cache_file
        if force_refresh or not self._cache_is_fresh(path):
            try:
                self._download_bundle(path)
            except requests.RequestException as exc:
                if path.exists():
                    logger.warning("Download failed (%s); using stale cache at %s", exc, path)
                else:
                    raise RuntimeError(
                        f"No ATT&CK data available and download failed: {exc}"
                    ) from exc

        self._parse_bundle(path)
        self._loaded_at = time.time()

    def _parse_bundle(self, path: Path) -> None:
        techniques: Dict[str, Technique] = {}
        try:
            import sys

            if sys.version_info >= (3, 12):
                # mitreattack-python depends on distutils, removed in 3.12+.
                raise ImportError("skipping mitreattack-python on Python 3.12+ (no distutils)")

            from mitreattack.stix20 import MitreAttackData

            mad = MitreAttackData(str(path))
            for t in mad.get_techniques(remove_revoked_deprecated=True):
                ext_refs = t.get("external_references", [])
                attack_id, url = None, ""
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        attack_id = ref.get("external_id")
                        url = ref.get("url", "")
                        break
                if not attack_id:
                    continue
                tactics = [
                    phase.get("phase_name", "").replace("-", " ")
                    for phase in t.get("kill_chain_phases", [])
                    if phase.get("kill_chain_name") == "mitre-attack"
                ]
                tech = Technique(
                    technique_id=attack_id,
                    name=t.get("name", ""),
                    description=t.get("description", "") or "",
                    tactics=tactics,
                    platforms=t.get("x_mitre_platforms", []) or [],
                    url=url,
                )
                tech.build_keywords()
                techniques[attack_id] = tech
        except Exception as exc:
            logger.warning("mitreattack-python parse failed (%s); using manual STIX parse", exc)
            techniques = self._parse_bundle_manual(path)

        if not techniques:
            raise RuntimeError("Parsed zero ATT&CK techniques from bundle; check the cache file.")

        self._techniques = techniques
        logger.info("Loaded %d ATT&CK techniques", len(techniques))

    def _parse_bundle_manual(self, path: Path) -> Dict[str, Technique]:
        """Backup reader: walk the raw STIX JSON by hand, for environments
        where mitreattack-python can't be used (e.g. Python 3.12+)."""
        data = json.loads(path.read_text())
        techniques: Dict[str, Technique] = {}
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            attack_id, url = None, ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id")
                    url = ref.get("url", "")
                    break
            if not attack_id:
                continue
            tactics = [
                phase.get("phase_name", "").replace("-", " ")
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]
            tech = Technique(
                technique_id=attack_id,
                name=obj.get("name", ""),
                description=obj.get("description", "") or "",
                tactics=tactics,
                platforms=obj.get("x_mitre_platforms", []) or [],
                url=url,
            )
            tech.build_keywords()
            techniques[attack_id] = tech
        return techniques

    @property
    def count(self) -> int:
        return len(self._techniques)

    def get(self, technique_id: str) -> Optional[Technique]:
        return self._techniques.get(technique_id.upper())

    def match(self, text: str, top_k: int = 8, min_overlap: int = 2) -> List[dict]:
        """Given a chunk of text, return the techniques whose keywords
        overlap with it the most."""
        text_tokens = set(_tokenize(text))
        if not text_tokens:
            return []

        scored = []
        for tech in self._techniques.values():
            overlap = text_tokens & tech._keyword_set
            if len(overlap) < min_overlap:
                continue

            score = len(overlap) / max(len(tech._keyword_set), 1)
            score = min(1.0, score * 3)
            evidence = self._extract_evidence(text, overlap)
            scored.append({
                "technique_id": tech.technique_id,
                "name": tech.name,
                "tactic": tech.tactics,
                "url": tech.url,
                "confidence": round(score, 2),
                "evidence": evidence,
                "matched_keywords": sorted(overlap),
            })

        scored.sort(key=lambda r: r["confidence"], reverse=True)
        return scored[:top_k]

    @staticmethod
    def _extract_evidence(text: str, overlap: set) -> str:
        """Find an actual sentence containing a matched keyword, so the
        report can show a real quote instead of just a bare ID."""
        sentences = re.split(r"(?<=[.!?])\s+", text)
        for sent in sentences:
            low = sent.lower()
            if any(kw in low for kw in overlap):
                return sent.strip()[:280]
        return text[:280]


# One shared instance, created when this module is first imported. Every
# other file that does `from app.mitre_attack import knowledge_base` gets
# this same object, so the expensive download/parse only happens once.
knowledge_base = AttackKnowledgeBase()
