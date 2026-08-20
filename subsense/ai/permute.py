"""Pattern-understanding permutation — the "sense" in subsense.

Two techniques, meant to be used together (see `active/permute.py` for the feedback loop that
drives both):

- `StatisticalPermuter`: pure Python, no model. Splits discovered labels into tokens on common
  delimiters, then fills gaps in the observed prefix x suffix matrix (e.g. saw
  payments-dev/staging/prod but only orders-dev -> proposes orders-staging, orders-prod).
- `llm_generate_candidates`: opt-in, Ollama-backed. Feeds discovered labels to the model and
  asks it to infer the naming convention and propose targeted candidates.

Guesses from either technique are NEVER trusted directly — the caller must resolve/validate
every candidate before treating it as a real subdomain.
"""

from __future__ import annotations

import logging
import re
from collections import Counter

from subsense.ai.client import OllamaClient, OllamaError
from subsense.ai.prompts import PERMUTATION_SYSTEM, permutation_prompt
from subsense.config import AiConfig

logger = logging.getLogger(__name__)

_DELIMITERS = re.compile(r"[-_.]")


class StatisticalPermuter:
    """Token frequency + gap-filling over the delimiter-split labels seen so far."""

    def __init__(self, delimiter: str = "-"):
        self.delimiter = delimiter
        self.token_freq: Counter[str] = Counter()
        self.prefix_freq: Counter[str] = Counter()
        self.suffix_freq: Counter[str] = Counter()
        self.known_pairs: set[tuple[str, str]] = set()
        self._single_tokens: set[str] = set()

    def observe(self, labels: set[str]) -> None:
        for label in labels:
            tokens = [t for t in _DELIMITERS.split(label) if t]
            self.token_freq.update(tokens)
            if len(tokens) >= 2:
                prefix, suffix = tokens[0], self.delimiter.join(tokens[1:])
                self.prefix_freq[prefix] += 1
                self.suffix_freq[suffix] += 1
                self.known_pairs.add((prefix, suffix))
            elif tokens:
                self._single_tokens.add(tokens[0])

    def generate_candidates(self, top_n: int = 100) -> list[str]:
        """Cross the observed prefixes with observed suffixes; return unseen pairs ranked by
        combined frequency (both tokens common across the target -> more plausible guess).
        """
        scored: list[tuple[float, str]] = []
        for prefix in self.prefix_freq:
            for suffix in self.suffix_freq:
                if (prefix, suffix) in self.known_pairs:
                    continue
                score = self.prefix_freq[prefix] * self.suffix_freq[suffix]
                candidate = f"{prefix}{self.delimiter}{suffix}"
                scored.append((score, candidate))

        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [candidate for _, candidate in scored[:top_n]]


async def llm_generate_candidates(
    discovered_labels: list[str],
    *,
    root_domain: str,
    config: AiConfig,
    client: OllamaClient | None = None,
) -> list[str]:
    """Ask the local Ollama model to propose candidate labels. Returns [] on any failure —
    the statistical technique always has results even if the model is unavailable/misbehaves.
    """
    if not discovered_labels:
        return []

    client = client or OllamaClient(config)
    prompt = permutation_prompt(root_domain, discovered_labels, config.batch_size)

    try:
        result = await client.generate_json(prompt, system=PERMUTATION_SYSTEM)
    except OllamaError as exc:
        logger.warning("ai permute: Ollama call failed, skipping LLM candidates: %s", exc)
        return []

    if not isinstance(result, list):
        logger.warning("ai permute: expected a JSON list of labels, got %s", type(result))
        return []

    return [str(item).strip().lower() for item in result if str(item).strip()]
