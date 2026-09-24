"""
Minimal example client for the Threat Intel Tool API.

Usage:
    python examples/client_example.py "APT29 recent phishing campaigns"
"""
import sys

import requests

API_BASE = "http://localhost:8000"
API_KEY = "change-me"  # must match TI_API_KEY in your .env


def main() -> None:
    query = sys.argv[1] if len(sys.argv) > 1 else "recent ransomware targeting healthcare"

    resp = requests.post(
        f"{API_BASE}/analyze",
        headers={"X-API-Key": API_KEY},
        json={"query": query, "max_sources": 6},
        timeout=180,
    )
    resp.raise_for_status()
    report = resp.json()

    print(f"\n=== Threat Report: {report['query']} ===\n")
    print(report["executive_summary"], "\n")

    if report["threat_actors"]:
        print("Threat actors:", ", ".join(report["threat_actors"]))
    if report["malware_or_tools"]:
        print("Malware/tools:", ", ".join(report["malware_or_tools"]))

    print("\nMapped ATT&CK TTPs:")
    for t in report["ttps"]:
        print(f"  - {t['technique_id']} {t['name']} (tactics: {', '.join(t['tactic'])}, "
              f"confidence: {t['confidence']})")

    print("\nRecommendations:")
    for r in report["recommendations"]:
        print(f"  - {r}")

    print("\nSources:")
    for s in report["sources"]:
        print(f"  - {s.get('title', '')} {s['url']}")


if __name__ == "__main__":
    main()
