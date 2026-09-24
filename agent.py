"""
Agentic threat-intel pipeline.

Stage 1 (research agent): autonomously reads sources + checks ATT&CK.
Stage 2 (structured synthesis): forces the findings into a strict schema.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI

from app.config import settings
from app.models import ThreatReport
from app.tools import get_all_tools

logger = logging.getLogger("threat_intel.agent")

RESEARCH_SYSTEM_PROMPT = """You are an autonomous cyber threat intelligence (CTI) analyst agent.

Goal: research the user's query using ONLY the tools provided (open-source
RSS feeds and article fetching), then identify the MITRE ATT&CK techniques
(TTPs) evidenced by what you read, using the mitre_attack_lookup tool.

Rules:
- Ground every claim in something you actually fetched with a tool. Do not
  invent articles, IOCs, or techniques from general knowledge alone.
- Prefer recent, reputable sources. If sources conflict, note the disagreement.
- Call mitre_attack_lookup on relevant excerpts (not the whole article) to
  get focused technique candidates, then sanity-check each candidate against
  what the excerpt actually describes -- discard weak/irrelevant matches.
- Use mitre_attack_technique to confirm a technique's definition before
  citing it, if you're unsure it fits.
- If default feeds don't have relevant coverage, try fetch_rss_feed on a
  couple of different feeds from list_default_feeds before giving up, or
  fetch any URLs the user explicitly supplied.
- Work efficiently: aim for {max_sources} distinct sources, not more.
- Finish with a clear narrative answer covering: executive summary, named
  threat actors/malware if any, the TTPs you mapped (with technique IDs),
  any IOCs you observed (only ones actually present in fetched text), source
  URLs used, and practical defensive recommendations tied to the mapped TTPs.
"""


def _build_llm(temperature: Optional[float] = None) -> ChatOpenAI:
    """Creates a connection to an OpenAI model, configured a certain way."""
    if not settings.openai_api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not set. Configure it in your environment or .env file."
        )
    return ChatOpenAI(
        model=settings.openai_model,
        temperature=settings.openai_temperature if temperature is None else temperature,
        api_key=settings.openai_api_key,
    )


def build_research_agent() -> AgentExecutor:
    """Wires together: the AI model + the tools + the prompt template."""
    llm = _build_llm()
    tools = get_all_tools()

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", RESEARCH_SYSTEM_PROMPT),
            ("human", "{input}"),
            MessagesPlaceholder("agent_scratchpad"),
        ]
    )

    agent = create_tool_calling_agent(llm, tools, prompt)
    return AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=False,
        max_iterations=12,
        max_execution_time=90,
        return_intermediate_steps=True,
        handle_parsing_errors=True,
    )


def _summarize_tool_trace(intermediate_steps) -> str:
    """Turns the agent's tool-call history into one compact block of text."""
    lines = []
    for action, observation in intermediate_steps:
        tool_name = getattr(action, "tool", "unknown_tool")
        tool_input = getattr(action, "tool_input", "")
        obs = str(observation)
        if len(obs) > 1200:
            obs = obs[:1200] + " …[truncated]"
        lines.append(f"[TOOL: {tool_name}] input={tool_input}\nresult: {obs}")
    return "\n\n".join(lines)


def synthesize_report(query: str, agent_final_answer: str, evidence_log: str) -> ThreatReport:
    """Stage 2: force everything the agent found into the strict
    ThreatReport shape defined in models.py."""
    llm = _build_llm(temperature=0.0)
    structured_llm = llm.with_structured_output(ThreatReport)

    synthesis_prompt = f"""You are converting a completed threat-intel research pass into a
strict structured report. Use ONLY information present in the agent's
answer and evidence log below -- do not add facts that aren't there.

Original query: {query}

=== AGENT FINAL ANSWER ===
{agent_final_answer}

=== EVIDENCE LOG (tool calls + observations) ===
{evidence_log}

Populate the ThreatReport fields accordingly. For `ttps`, only include
techniques that the evidence log actually supports (via mitre_attack_lookup
or mitre_attack_technique results), each with its technique_id, name,
tactic(s), a confidence 0-1, and a short evidence snippet. For `sources`,
extract real URLs seen in the evidence log (from fetch_rss_feed /
fetch_article_text results) -- never fabricate a URL. If information for a
field is genuinely unavailable, leave it empty rather than guessing.
"""
    report = structured_llm.invoke(synthesis_prompt)
    report.query = query
    return report


def run_threat_intel_agent(query: str, sources: Optional[List[str]], max_sources: int) -> ThreatReport:
    """The full end-to-end pipeline: research, then synthesize."""
    executor = build_research_agent()

    user_msg = f"Research query: {query}\n"
    if sources:
        user_msg += (
            "The user supplied these explicit sources -- prioritize fetching "
            f"them with fetch_article_text or fetch_rss_feed as appropriate:\n"
            + "\n".join(f"- {s}" for s in sources)
            + "\n"
        )
    else:
        user_msg += (
            "No explicit sources were supplied. Start with list_default_feeds, "
            "then pull and filter relevant feeds.\n"
        )

    result = executor.invoke(
        {"input": user_msg, "max_sources": max_sources},
    )

    final_answer = result.get("output", "")
    evidence_log = _summarize_tool_trace(result.get("intermediate_steps", []))

    if not final_answer and not evidence_log:
        raise RuntimeError("Agent produced no output and no tool trace; cannot synthesize a report.")

    return synthesize_report(query, final_answer, evidence_log)
