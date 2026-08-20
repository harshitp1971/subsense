"""AI triage stage (opt-in): asks the local Ollama model to rank findings by likely
real-world impact/exploitability, annotating each with `ai_priority` and `ai_notes`.

This never changes a finding's `severity` or `tier` — those come from deterministic check logic.
Triage only adds a ranking hint on top, and always degrades gracefully: if Ollama is unavailable
or returns something unusable, findings pass through with ranking fields left as None and the
report falls back to its default severity-based sort.
"""

from __future__ import annotations

import logging

from subsense.ai.client import OllamaClient, OllamaError
from subsense.ai.prompts import TRIAGE_SYSTEM, triage_prompt
from subsense.config import AiConfig
from subsense.models import Finding

logger = logging.getLogger(__name__)


async def triage_findings(
    findings: list[Finding],
    *,
    config: AiConfig,
    client: OllamaClient | None = None,
) -> list[Finding]:
    if not findings:
        return findings

    client = client or OllamaClient(config)
    findings_payload = [
        {
            "id": f.id,
            "severity": f.severity.value,
            "tier": f.tier.value,
            "check_name": f.check_name,
            "subdomain": f.subdomain,
            "title": f.title,
        }
        for f in findings
    ]

    try:
        result = await client.generate_json(triage_prompt(findings_payload), system=TRIAGE_SYSTEM)
    except OllamaError as exc:
        logger.warning("ai triage: Ollama call failed, leaving findings unranked: %s", exc)
        return findings

    if not isinstance(result, list):
        logger.warning("ai triage: expected a JSON list, got %s", type(result))
        return findings

    by_id = {f.id: f for f in findings}
    ranked: dict[str, Finding] = {}
    for entry in result:
        if not isinstance(entry, dict):
            continue
        finding = by_id.get(entry.get("id"))
        if finding is None:
            continue
        priority = entry.get("ai_priority")
        notes = entry.get("ai_notes")
        update = {}
        if isinstance(priority, int):
            update["ai_priority"] = priority
        if isinstance(notes, str):
            update["ai_notes"] = notes
        ranked[finding.id] = finding.model_copy(update=update) if update else finding

    return [ranked.get(f.id, f) for f in findings]
