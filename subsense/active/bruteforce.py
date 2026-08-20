"""Active bruteforce enumeration (opt-in, --active): wraps the external `puredns` binary
(massdns under the hood) to resolve a wordlist of candidate labels against the target domain.

This is an active stage — every candidate must pass `scope.py` before puredns ever sends it a
query, even though candidates are constructed as `label.root_domain` (and so are in-namespace
by construction, exclude patterns can still carve out sub-zones the client wants left alone).
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
from pathlib import Path

from subsense.config import Config
from subsense.scope import ScopeFilter

logger = logging.getLogger(__name__)

_BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "api", "dev", "staging", "stage", "test", "prod", "admin",
    "app", "portal", "vpn", "remote", "internal", "intranet", "git", "gitlab", "jenkins",
    "jira", "confluence", "grafana", "kibana", "elastic", "prometheus", "status", "docs",
    "blog", "shop", "store", "cdn", "static", "assets", "img", "images", "media", "video",
    "auth", "sso", "login", "id", "accounts", "billing", "pay", "payments", "checkout",
    "orders", "order", "cart", "support", "help", "wiki", "kb", "beta", "demo", "sandbox",
    "old", "new", "legacy", "backup", "db", "database", "sql", "redis", "cache", "mq",
    "ws", "websocket", "socket", "stream", "live", "webmail", "mx", "smtp", "imap", "pop",
    "ns1", "ns2", "dns", "monitor", "monitoring", "metrics", "logs", "log", "ci", "cd",
    "build", "deploy", "k8s", "kube", "docker", "registry", "npm", "pypi", "artifactory",
]


async def run_bruteforce(root_domain: str, *, config: Config, scope: ScopeFilter) -> set[str]:
    wordlist_path = config.active.wordlist
    tmp_wordlist: Path | None = None
    if wordlist_path is None:
        tmp_wordlist = Path(tempfile.mkstemp(suffix=".txt")[1])
        tmp_wordlist.write_text("\n".join(_BUILTIN_WORDLIST) + "\n")
        wordlist_path = tmp_wordlist

    try:
        return await resolve_wordlist_with_puredns(wordlist_path, root_domain, config=config, scope=scope)
    finally:
        if tmp_wordlist is not None:
            tmp_wordlist.unlink(missing_ok=True)


async def resolve_wordlist_with_puredns(
    wordlist_path: Path, root_domain: str, *, config: Config, scope: ScopeFilter, timeout_seconds: int = 1800
) -> set[str]:
    """Resolve every `label` in `wordlist_path` as `label.root_domain` via puredns bruteforce.

    Returns an empty set (with a warning logged) if `puredns` isn't installed — callers that
    have a native fallback (e.g. active/permute.py) should use that in this case.
    """
    hostnames: set[str] = set()

    puredns_bin = config.active.puredns_bin
    if shutil.which(puredns_bin) is None:
        logger.warning("bruteforce: '%s' not found on PATH, skipping puredns resolution", puredns_bin)
        return hostnames

    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "resolved.txt"
        cmd = [puredns_bin, "bruteforce", str(wordlist_path), root_domain, "--quiet", "-w", str(out_path)]
        if config.active.resolvers_file:
            cmd += ["-r", str(config.active.resolvers_file)]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            logger.warning("bruteforce: puredns timed out after %ds, killing process", timeout_seconds)
            proc.kill()
            await proc.wait()
            return hostnames
        except OSError as exc:
            logger.warning("bruteforce: puredns execution failed: %s", exc)
            return hostnames

        if proc.returncode != 0:
            logger.warning("bruteforce: puredns exited %s: %s", proc.returncode, stderr.decode(errors="replace"))

        if out_path.exists():
            for line in out_path.read_text().splitlines():
                host = line.strip().lower()
                if host and scope.is_in_scope(host):
                    hostnames.add(host)

    return hostnames
