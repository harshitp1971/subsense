"""DNSSEC NSEC zone-walk check. NSEC records prove non-existence by naming the *next* record in
canonical zone order — chaining NSEC queries "walks" the entire zone, enumerating every name
even ones with no public footprint. NSEC3 hashes owner names specifically to prevent this, so
this check both detects NSEC (walkable) and flags it. Tier 1 — tool-confirmed.

Some online/on-the-fly DNSSEC signers (e.g. Cloudflare) don't return real adjacent zone
records at all — they synthesize a minimally-covering "white lie" NSEC per query (RFC 4470,
"Minimally Covering NSEC Records and DNSSEC On-line Signing"), whose `next` name is just the
queried name with a single zero-octet label prepended. Chasing that literally walks forever (it
never repeats and never wraps to the apex), so we detect the self-referential growth pattern and
bail out early rather than burning hundreds of real queries on a zone that has already proven
itself non-walkable. A wall-clock budget is the general backstop for any other slow/pathological
chain, including signers that use a different synthesis scheme than RFC 4470's exact construction.
"""

from __future__ import annotations

import asyncio
import logging
import time

import dns.flags
import dns.rdatatype
import dns.resolver

from subsense.dns_checks.base import DnsCheck, DnsCheckContext
from subsense.models import Finding, FindingTier, Severity
from subsense.registry import register_dns_check

logger = logging.getLogger(__name__)

MAX_WALK_STEPS = 200
WALK_TIME_BUDGET_SECONDS = 20.0


@register_dns_check("zonewalk")
class ZoneWalkCheck(DnsCheck):
    name = "zonewalk"
    level = "domain"

    async def run(self, ctx: DnsCheckContext) -> list[Finding]:
        findings: list[Finding] = []
        resolver = _resolver(ctx)

        guard = ctx.limiter.guard()
        async with guard:
            try:
                answer = await asyncio.to_thread(
                    resolver.resolve, ctx.root_domain, "NSEC", raise_on_no_answer=False
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("zonewalk: NSEC probe failed for %s: %s", ctx.root_domain, exc)
                guard.failure()
                return findings

        if answer is None or answer.rrset is None:
            # No NSEC on the apex directly — DNSSEC may still be present with NSEC3, or absent.
            # Either way there's nothing to walk from here without a signed negative response.
            return findings

        walked = [ctx.root_domain]
        current = str(answer.rrset[0].next).rstrip(".")
        synthesized_white_lie = False
        deadline = time.monotonic() + WALK_TIME_BUDGET_SECONDS

        for _ in range(MAX_WALK_STEPS):
            if not current or current in walked:
                break
            if time.monotonic() > deadline:
                logger.debug("zonewalk: time budget exhausted for %s after %d steps", ctx.root_domain, len(walked))
                break
            if _is_synthesized_next(current, walked[-1]):
                # RFC 4470 "white lies": next = "\000." + queried name. The chain will never
                # repeat or converge — it's proof NSEC walking is blocked, not enabled.
                synthesized_white_lie = True
                break

            walked.append(current)
            guard2 = ctx.limiter.guard()
            async with guard2:
                try:
                    step = await asyncio.to_thread(
                        resolver.resolve, current, "NSEC", raise_on_no_answer=False
                    )
                except Exception:  # noqa: BLE001
                    guard2.failure()
                    break
            if step is None or step.rrset is None:
                break
            current = str(step.rrset[0].next).rstrip(".")
            if current == ctx.root_domain:
                break  # wrapped back to the apex — full zone walked

        if synthesized_white_lie:
            return findings  # NSEC present but online-signed with minimally-covering records: not walkable

        if len(walked) > 1:
            findings.append(
                Finding(
                    subdomain=ctx.root_domain,
                    check_name=self.name,
                    tier=FindingTier.TIER_1,
                    severity=Severity.HIGH,
                    title="DNSSEC NSEC zone walk enumerates the full zone",
                    description=(
                        f"Zone uses NSEC (not NSEC3) — chaining NSEC 'next domain name' records "
                        f"enumerated {len(walked)} names, including any with no public footprint."
                    ),
                    evidence={"walked_count": len(walked), "sample": walked[:50]},
                    remediation="Migrate to NSEC3 with opt-out, or NSEC3 with a salted hash, to prevent zone enumeration.",
                )
            )

        return findings


def _is_synthesized_next(candidate_next: str, previous: str) -> bool:
    """True if `candidate_next` looks like a minimally-covering NSEC synthesized for
    `previous` per RFC 4470 (a single zero-octet label appended to the queried name, which
    dnspython renders as the escaped label "\\000") rather than a real adjacent owner name from
    the zone. A real next name can also be exactly one label deeper (e.g. mail.example.com after
    example.com), so we must key on the specific zero-octet marker, not just "one extra label".
    Note this only catches RFC 4470's exact construction (append \\000); a signer using a
    different minimally-covering scheme won't be recognized here and instead relies on the
    wall-clock budget above to avoid walking indefinitely.
    """
    if not candidate_next.endswith("." + previous):
        return False
    prefix = candidate_next[: -(len(previous) + 1)]
    return prefix == "\\000"


def _resolver(ctx: DnsCheckContext) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ctx.config.dns.resolvers
    resolver.timeout = ctx.config.dns.timeout_seconds
    resolver.lifetime = ctx.config.dns.timeout_seconds
    resolver.use_edns(0, dns.flags.DO, 4096)
    return resolver
