"""Active permutation stage (opt-in, --active): the feedback loop described in CLAUDE.md's
"Pattern-understanding permutation" section.

generated candidates -> resolve (validate) -> newly-resolved feed back into the analyzer
(may reveal new tokens) -> loop until diminishing returns.

Guesses from `ai/permute.py` are never trusted directly: every candidate is filtered through
scope, then only kept if it actually resolves.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path

from subsense.active.bruteforce import resolve_wordlist_with_puredns
from subsense.active.resolve import resolve_subdomains
from subsense.ai.permute import StatisticalPermuter, llm_generate_candidates
from subsense.config import Config
from subsense.models import Subdomain
from subsense.ratelimit import RateLimiter
from subsense.scope import ScopeFilter

logger = logging.getLogger(__name__)

_MAX_ITERATIONS = 5
_MIN_NEW_PER_ITERATION = 2
_STATISTICAL_TOP_N = 150


def _label_of(hostname: str, root_domain: str) -> str:
    return hostname[: -(len(root_domain) + 1)] if hostname.endswith("." + root_domain) else hostname


async def run_permutation(
    known_subdomains: list[Subdomain],
    *,
    root_domain: str,
    config: Config,
    scope: ScopeFilter,
    limiter: RateLimiter,
) -> list[Subdomain]:
    """Runs the statistical (+ optional LLM) permutation feedback loop.

    Returns newly-discovered, resolved, in-scope `Subdomain`s (already carrying DNS records via
    the resolve stage) — callers merge these into the run's overall subdomain set.
    """
    known_hosts = {s.hostname for s in known_subdomains}
    known_labels = {_label_of(h, root_domain) for h in known_hosts}

    permuter = StatisticalPermuter()
    permuter.observe(known_labels)

    discovered: list[Subdomain] = []

    for iteration in range(_MAX_ITERATIONS):
        candidates = set(permuter.generate_candidates(top_n=_STATISTICAL_TOP_N))

        if config.ai.enabled:
            llm_candidates = await llm_generate_candidates(
                sorted(known_labels), root_domain=root_domain, config=config.ai
            )
            candidates |= set(llm_candidates)

        candidates -= known_labels
        candidate_hosts = {f"{label}.{root_domain}" for label in candidates if label}
        candidate_hosts = {h for h in candidate_hosts if h not in known_hosts and scope.is_in_scope(h)}

        if not candidate_hosts:
            logger.info("permute: no new candidates at iteration %d, stopping", iteration)
            break

        resolved_hosts = await _validate_candidates(candidate_hosts, root_domain, config=config, scope=scope)
        newly = resolved_hosts - known_hosts

        logger.info(
            "permute: iteration %d generated %d candidates, %d newly resolved",
            iteration, len(candidate_hosts), len(newly),
        )

        if not newly:
            break

        new_subs = [
            Subdomain(hostname=h, root_domain=root_domain, sources={"ai_permute"}) for h in newly
        ]
        new_subs = await resolve_subdomains(new_subs, root_domain=root_domain, config=config, limiter=limiter)
        new_subs = [s for s in new_subs if s.resolved]

        discovered.extend(new_subs)
        known_hosts |= {s.hostname for s in new_subs}
        new_labels = {_label_of(s.hostname, root_domain) for s in new_subs}
        known_labels |= new_labels
        permuter.observe(new_labels)  # feed back: newly resolved hosts may reveal new tokens

        if len(newly) < _MIN_NEW_PER_ITERATION:
            logger.info("permute: diminishing returns (%d < %d), stopping", len(newly), _MIN_NEW_PER_ITERATION)
            break

    return discovered


async def _validate_candidates(
    candidate_hosts: set[str], root_domain: str, *, config: Config, scope: ScopeFilter
) -> set[str]:
    """Validate candidates by resolution. Prefers puredns (matches the bruteforce path /
    respects massdns-level throttling); falls back to native aiodns resolution when puredns
    isn't installed so permutation still works out of the box.
    """
    labels = {_label_of(h, root_domain) for h in candidate_hosts}

    if shutil.which(config.active.puredns_bin) is not None:
        tmp_wordlist = Path(tempfile.mkstemp(suffix=".txt")[1])
        try:
            tmp_wordlist.write_text("\n".join(sorted(labels)) + "\n")
            return await resolve_wordlist_with_puredns(tmp_wordlist, root_domain, config=config, scope=scope)
        finally:
            tmp_wordlist.unlink(missing_ok=True)

    import aiodns
    from aiodns.error import DNSError

    resolver = aiodns.DNSResolver(nameservers=config.dns.resolvers, timeout=config.dns.timeout_seconds)
    resolved: set[str] = set()
    for host in candidate_hosts:
        try:
            await resolver.query(host, "A")
            resolved.add(host)
        except DNSError:
            continue
        except Exception:  # noqa: BLE001
            continue
    return resolved
