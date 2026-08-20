"""crt.sh passive source: queries the crt.sh certificate transparency log JSON API.

Native (no subprocess) — this is the Phase 1 foundation source that makes subsense runnable
end-to-end without any external tool installed.
"""

from __future__ import annotations

import logging

from subsense.registry import register_source
from subsense.sources.base import Source, SourceContext

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"


@register_source("crtsh")
class CrtShSource(Source):
    name = "crtsh"

    async def discover(self, ctx: SourceContext) -> set[str]:
        hostnames: set[str] = set()

        guard = ctx.limiter.guard()
        async with guard:
            try:
                resp = await ctx.http_client.get(
                    CRTSH_URL,
                    params={"q": f"%.{ctx.root_domain}", "output": "json"},
                    timeout=30.0,
                )
                if resp.status_code == 429:
                    guard.failure(retry_after=_retry_after(resp))
                    return hostnames
                resp.raise_for_status()
            except Exception as exc:  # noqa: BLE001 - one flaky source must not abort the stage
                logger.warning("crtsh: request failed: %s", exc)
                guard.failure()
                return hostnames

            try:
                data = resp.json()
            except ValueError:
                logger.warning("crtsh: non-JSON response")
                guard.failure()
                return hostnames

        for entry in data:
            name_value = entry.get("name_value", "")
            for line in name_value.splitlines():
                host = line.strip().lower().lstrip("*.")
                if host and host.endswith(ctx.root_domain):
                    hostnames.add(host)

        return hostnames


def _retry_after(resp) -> float | None:
    value = resp.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None
