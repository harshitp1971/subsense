"""Base class for passive enumeration sources. Subclass this, implement `discover`, and
register with `@register_source("name")`. See `subsense/sources/crtsh.py` for a reference impl.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

from subsense.config import Config
from subsense.ratelimit import RateLimiter


@dataclass
class SourceContext:
    """Shared resources handed to every source's `discover()` call."""

    root_domain: str
    config: Config
    limiter: RateLimiter
    http_client: httpx.AsyncClient


class Source(ABC):
    """A passive subdomain enumeration source (e.g. crt.sh, subfinder wrapper)."""

    name: str

    @abstractmethod
    async def discover(self, ctx: SourceContext) -> set[str]:
        """Return every hostname this source found for `ctx.root_domain`.

        Implementations MUST use `ctx.limiter.guard()` around network calls and MUST NOT
        raise on ordinary failure (timeouts, empty results, API errors) — log and return
        whatever was collected so one flaky source doesn't abort the whole passive stage.
        """
        raise NotImplementedError
