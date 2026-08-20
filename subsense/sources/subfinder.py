"""subfinder passive source: wraps the external `subfinder` binary (subprocess only — everything
else in subsense is native Python per CLAUDE.md's tech stack rules).

Degrades gracefully: if `subfinder` isn't installed, this source logs a warning and returns an
empty set rather than failing the passive stage.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil

from subsense.registry import register_source
from subsense.sources.base import Source, SourceContext

logger = logging.getLogger(__name__)

SUBFINDER_BIN = "subfinder"
# subfinder's own default -max-time is 10 minutes, which is too long for the "default run is
# low-noise and fast" passive stage. Bound it explicitly; our own asyncio timeout below is just
# the safety net in case the binary ignores the flag or hangs on process teardown.
MAX_TIME_MINUTES = 2
PROCESS_TIMEOUT_SECONDS = 180


@register_source("subfinder")
class SubfinderSource(Source):
    name = "subfinder"

    async def discover(self, ctx: SourceContext) -> set[str]:
        hostnames: set[str] = set()

        if shutil.which(SUBFINDER_BIN) is None:
            logger.info("subfinder: binary not found on PATH, skipping")
            return hostnames

        guard = ctx.limiter.guard()
        async with guard:
            cmd = [
                SUBFINDER_BIN, "-d", ctx.root_domain, "-silent", "-json",
                "-max-time", str(MAX_TIME_MINUTES),
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=PROCESS_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                logger.warning("subfinder: timed out after %ds, killing process", PROCESS_TIMEOUT_SECONDS)
                proc.kill()
                await proc.wait()
                guard.failure()
                return hostnames
            except OSError as exc:
                logger.warning("subfinder: execution failed: %s", exc)
                guard.failure()
                return hostnames

            if proc.returncode != 0:
                logger.warning(
                    "subfinder: exited %s: %s", proc.returncode, stderr.decode(errors="replace")
                )
                guard.failure()
                return hostnames

        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                host = record.get("host", "")
            except ValueError:
                host = line  # non-JSON fallback: plain hostname per line
            host = host.strip().lower()
            if host and host.endswith(ctx.root_domain):
                hostnames.add(host)

        return hostnames
