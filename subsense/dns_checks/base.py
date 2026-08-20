"""Base class for DNS-layer vulnerability checks — the tool's core differentiator.

Two check levels:
- "domain": runs once against the target root domain (e.g. AXFR against its nameservers,
  SPF/DMARC lookup, NSEC zone walk).
- "subdomain": runs once per resolved, in-scope `Subdomain` (e.g. takeover fingerprint match
  against a dangling CNAME).

Subclass, implement `run`, and register with `@register_dns_check("name")`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

from subsense.config import Config
from subsense.models import Finding, Subdomain
from subsense.ratelimit import RateLimiter


@dataclass
class DnsCheckContext:
    root_domain: str
    config: Config
    limiter: RateLimiter
    subdomain: Subdomain | None = None  # set when check.level == "subdomain"
    all_subdomains: list[Subdomain] | None = None  # full set, for checks that need cross-reference


class DnsCheck(ABC):
    name: str
    level: Literal["domain", "subdomain"] = "subdomain"

    @abstractmethod
    async def run(self, ctx: DnsCheckContext) -> list[Finding]:
        """Return any findings. Implementations must not raise on ordinary failure (timeouts,
        NXDOMAIN, refused transfer) — that's an expected negative result, not an error; return
        an empty list. Only truly unexpected exceptions should propagate.
        """
        raise NotImplementedError
