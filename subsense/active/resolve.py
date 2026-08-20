"""Resolve stage (always on): async A/AAAA/CNAME resolution via aiodns, wildcard-DNS filtering,
and a confidence score per subdomain.

Wildcard filtering: many zones answer `*.domain` with a catch-all A/CNAME. Without filtering,
every bruteforce/permutation guess would "resolve" to that catch-all and look like a real host.
We probe a handful of random, near-certainly-nonexistent labels first; any subdomain whose
resolved IP set matches the wildcard's IP set is flagged `wildcard_match` and its confidence
is heavily discounted rather than dropped outright (a real host can coincidentally share a
load-balancer IP with the wildcard).
"""

from __future__ import annotations

import asyncio
import logging
import random
import string

import aiodns
from aiodns.error import DNSError

from subsense.config import Config
from subsense.models import DnsRecord, RecordType, Subdomain
from subsense.ratelimit import RateLimiter

logger = logging.getLogger(__name__)

_RECORD_TYPES = ("A", "AAAA", "CNAME")


async def resolve_subdomains(
    subdomains: list[Subdomain],
    *,
    root_domain: str,
    config: Config,
    limiter: RateLimiter,
) -> list[Subdomain]:
    resolver = aiodns.DNSResolver(nameservers=config.dns.resolvers, timeout=config.dns.timeout_seconds)

    wildcard_ips = await _detect_wildcard(resolver, root_domain, limiter)
    if wildcard_ips:
        logger.info("resolve: wildcard DNS detected for *.%s -> %s", root_domain, wildcard_ips)

    tasks = [_resolve_one(resolver, sub, wildcard_ips, limiter) for sub in subdomains]
    return await asyncio.gather(*tasks)


async def _detect_wildcard(resolver: aiodns.DNSResolver, root_domain: str, limiter: RateLimiter) -> set[str]:
    probes = [f"{_random_label()}.{root_domain}" for _ in range(3)]
    ip_sets: list[set[str]] = []

    for probe in probes:
        guard = limiter.guard()
        async with guard:
            ips = await _query_a_aaaa(resolver, probe)
        if ips:
            ip_sets.append(ips)

    if len(ip_sets) < 2:
        return set()

    # Only call it a wildcard if the probes agree — otherwise it's just transient/unrelated IPs.
    common = set.intersection(*ip_sets)
    return common


async def _resolve_one(
    resolver: aiodns.DNSResolver,
    sub: Subdomain,
    wildcard_ips: set[str],
    limiter: RateLimiter,
) -> Subdomain:
    records: list[DnsRecord] = []

    guard = limiter.guard()
    async with guard:
        for rtype in _RECORD_TYPES:
            try:
                result = await resolver.query(sub.hostname, rtype)
            except DNSError:
                continue
            except Exception as exc:  # noqa: BLE001
                logger.debug("resolve: %s query for %s failed: %s", rtype, sub.hostname, exc)
                continue

            if rtype == "CNAME":
                target = getattr(result, "cname", None)
                if target:
                    records.append(DnsRecord(record_type=RecordType.CNAME, value=target))
            else:
                entries = result if isinstance(result, list) else [result]
                for entry in entries:
                    host = getattr(entry, "host", None)
                    if host:
                        records.append(DnsRecord(record_type=RecordType(rtype), value=host))

    resolved = len(records) > 0
    resolved_ips = {r.value for r in records if r.record_type in (RecordType.A, RecordType.AAAA)}
    wildcard_match = resolved and bool(wildcard_ips) and resolved_ips.issubset(wildcard_ips) and bool(resolved_ips)

    confidence = _confidence(sub, resolved=resolved, wildcard_match=wildcard_match)

    return sub.model_copy(
        update={
            "records": records,
            "resolved": resolved,
            "wildcard_match": wildcard_match,
            "confidence": confidence,
        }
    )


def _confidence(sub: Subdomain, *, resolved: bool, wildcard_match: bool) -> float:
    if not resolved:
        return 0.0
    score = 0.5 + min(len(sub.sources), 4) * 0.1  # more independent sources -> more confidence
    if wildcard_match:
        score *= 0.3  # heavily discount but don't zero out — could be a real shared LB IP
    return round(min(score, 1.0), 2)


async def _query_a_aaaa(resolver: aiodns.DNSResolver, hostname: str) -> set[str]:
    ips: set[str] = set()
    for rtype in ("A", "AAAA"):
        try:
            result = await resolver.query(hostname, rtype)
        except DNSError:
            continue
        except Exception:  # noqa: BLE001
            continue
        entries = result if isinstance(result, list) else [result]
        for entry in entries:
            host = getattr(entry, "host", None)
            if host:
                ips.add(host)
    return ips


def _random_label(length: int = 20) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
