"""Prompt templates for the Ollama-backed stages. Kept as plain functions returning strings so
they're easy to eyeball/tune without digging through client/orchestration code.
"""

from __future__ import annotations

PERMUTATION_SYSTEM = (
    "You are a subdomain naming-convention analyst helping an authorized security tester "
    "enumerate subdomains for a domain they have permission to test. You infer naming patterns "
    "from already-discovered subdomains and propose plausible additional subdomain labels that "
    "fit the same convention. You NEVER invent unrelated words; every suggestion must be a "
    "structural variation (different env/region/service token) on patterns you were shown. "
    "Respond with JSON only: a list of short subdomain labels (the part before the root domain), "
    "no explanations."
)


def permutation_prompt(root_domain: str, discovered_labels: list[str], batch_size: int) -> str:
    sample = "\n".join(f"- {label}" for label in discovered_labels)
    return (
        f"Root domain: {root_domain}\n\n"
        f"Already-discovered subdomain labels (label only, root domain stripped):\n{sample}\n\n"
        f"Task: infer the naming convention(s) in use (environment tiers like dev/staging/prod, "
        f"service names, regions, numbering, abbreviations, etc.) and propose up to "
        f"{batch_size} NEW candidate labels that plausibly exist but are not in the list above — "
        f"in particular, fill gaps where a service appears with some env/region tokens but not "
        f"others (e.g. if you see payments-dev, payments-staging, payments-prod but only "
        f"orders-dev, propose orders-staging and orders-prod).\n\n"
        f'Respond with a JSON array of strings, e.g. ["orders-staging", "orders-prod"]. '
        f"No other text."
    )


TRIAGE_SYSTEM = (
    "You are a security triage assistant helping an authorized penetration tester prioritize "
    "automated scan findings for manual review. You do not decide anything is a confirmed "
    "vulnerability yourself — you rank and annotate findings the tool already produced, to help "
    "a human reviewer spend their time on the highest-signal items first. Respond with JSON only."
)


def triage_prompt(findings: list[dict]) -> str:
    findings_json = "\n".join(
        f"- id={f['id']} severity={f['severity']} tier={f['tier']} check={f['check_name']} "
        f"subdomain={f['subdomain']} title={f['title']!r}"
        for f in findings
    )
    return (
        f"Here are {len(findings)} findings from an automated DNS/subdomain security scan:\n\n"
        f"{findings_json}\n\n"
        f"For each finding, assign an integer `ai_priority` (1 = review first) reflecting "
        f"likely real-world impact and exploitability, considering severity, tier "
        f"(tier_1 = tool-confirmed, tier_2 = lead needing manual verification), and whether the "
        f"subdomain name suggests production/customer-facing use vs internal/dev/test. Also add "
        f"a one-sentence `ai_notes` explaining the priority.\n\n"
        f'Respond with a JSON array like: '
        f'[{{"id": "<finding id>", "ai_priority": 1, "ai_notes": "..."}}, ...] '
        f"covering every finding id given. No other text."
    )
