"""HTTP probe stage (always on): fetches each resolved, in-scope subdomain over HTTP(S),
recording status code, page title, and a lightweight tech fingerprint from headers/body.
"""

from __future__ import annotations

import asyncio
import logging
import re

import aiohttp

from subsense.config import Config
from subsense.models import Subdomain
from subsense.ratelimit import RateLimiter

logger = logging.getLogger(__name__)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# header/body signature -> technology label. Deliberately small; extend as needed.
_TECH_SIGNATURES: list[tuple[str, str, str]] = [
    ("header", "server", "nginx"),
    ("header", "server", "apache"),
    ("header", "server", "cloudflare"),
    ("header", "x-powered-by", "express"),
    ("header", "x-powered-by", "php"),
    ("header", "x-powered-by", "asp.net"),
    ("body", "", "wordpress"),
    ("body", "", "react"),
    ("body", "", "next.js"),
    ("body", "", "shopify"),
]


async def probe_subdomains(
    subdomains: list[Subdomain], *, config: Config, limiter: RateLimiter
) -> list[Subdomain]:
    targets = [s for s in subdomains if s.resolved and s.in_scope]
    if not targets:
        return subdomains

    connector = aiohttp.TCPConnector(limit=config.ratelimit.max_concurrency, ssl=False)
    timeout = aiohttp.ClientTimeout(total=config.http.timeout_seconds)
    headers = {"User-Agent": config.http.user_agent}

    probed_by_host: dict[str, Subdomain] = {}
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
        tasks = [_probe_one(session, sub, config, limiter) for sub in targets]
        results = await asyncio.gather(*tasks)
        for sub in results:
            probed_by_host[sub.hostname] = sub

    return [probed_by_host.get(s.hostname, s) for s in subdomains]


async def _probe_one(
    session: aiohttp.ClientSession, sub: Subdomain, config: Config, limiter: RateLimiter
) -> Subdomain:
    guard = limiter.guard()
    async with guard:
        for scheme in ("https", "http"):
            try:
                async with session.get(
                    f"{scheme}://{sub.hostname}/",
                    allow_redirects=config.http.follow_redirects,
                    max_redirects=config.http.max_redirects,
                ) as resp:
                    body = await resp.text(errors="replace")
                    title = _extract_title(body)
                    tech = _detect_tech(resp.headers, body)
                    guard.success()
                    return sub.model_copy(
                        update={"http_status": resp.status, "http_title": title, "http_tech": tech}
                    )
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
            except Exception as exc:  # noqa: BLE001
                logger.debug("http probe: %s failed: %s", sub.hostname, exc)
                continue

        guard.failure()
    return sub


def _extract_title(body: str) -> str | None:
    match = _TITLE_RE.search(body)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200] or None


def _detect_tech(headers, body: str) -> list[str]:
    found: set[str] = set()
    body_lower = body.lower()
    for kind, key, label in _TECH_SIGNATURES:
        if kind == "header":
            value = headers.get(key, "")
            if label in value.lower():
                found.add(label)
        else:
            if label.replace(".", "") in body_lower.replace(".", ""):
                found.add(label)
    return sorted(found)
