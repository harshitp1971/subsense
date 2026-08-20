"""Tests for active/resolve.py's wildcard-DNS filtering, using a fake duck-typed resolver
(matching aiodns.DNSResolver's `.query()` contract) so these run offline and deterministically —
real aiodns/c-ares objects aren't easily mockable, but resolve.py only relies on `.host`/.cname`
attributes and DNSError, which we can reproduce exactly.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from aiodns.error import DNSError

from subsense.active.resolve import _confidence, _detect_wildcard, _resolve_one
from subsense.models import RecordType, Subdomain
from subsense.ratelimit import RateLimiter
from subsense.config import RateLimitConfig


class FakeResolver:
    """answers: {(hostname, rtype): "NXDOMAIN"} or {(hostname, rtype): [ip, ip, ...]} for
    A/AAAA, or {(hostname, "CNAME"): "target.example.com"} for CNAME.
    """

    def __init__(self, answers: dict):
        self.answers = answers

    async def query(self, hostname: str, rtype: str):
        key = (hostname, rtype)
        if key not in self.answers or self.answers[key] == "NXDOMAIN":
            raise DNSError("NXDOMAIN")
        value = self.answers[key]
        if rtype == "CNAME":
            return SimpleNamespace(cname=value)
        return [SimpleNamespace(host=ip) for ip in value]


def _limiter() -> RateLimiter:
    return RateLimiter(RateLimitConfig(max_concurrency=50, requests_per_second=100000))


@pytest.mark.asyncio
async def test_wildcard_detected_when_probes_agree():
    # _detect_wildcard generates its own random probe names, so we need a resolver that
    # answers ANY hostname the same way to simulate a true wildcard.
    class AnyHostWildcardResolver(FakeResolver):
        async def query(self, hostname, rtype):
            if rtype == "A":
                return [SimpleNamespace(host="198.51.100.9")]
            raise DNSError("NXDOMAIN")

    wildcard_ips = await _detect_wildcard(AnyHostWildcardResolver({}), "example.com", _limiter())
    assert wildcard_ips == {"198.51.100.9"}


@pytest.mark.asyncio
async def test_no_wildcard_when_probes_dont_resolve():
    class NoWildcardResolver(FakeResolver):
        async def query(self, hostname, rtype):
            raise DNSError("NXDOMAIN")

    wildcard_ips = await _detect_wildcard(NoWildcardResolver({}), "example.com", _limiter())
    assert wildcard_ips == set()


@pytest.mark.asyncio
async def test_real_host_sharing_wildcard_ip_is_discounted_not_dropped():
    """A real host coincidentally resolving to the same IP as the wildcard should still be
    marked resolved (never silently dropped), just with heavily reduced confidence."""
    resolver = FakeResolver({("shared.example.com", "A"): ["198.51.100.9"]})
    sub = Subdomain(hostname="shared.example.com", root_domain="example.com", sources={"crtsh"})

    result = await _resolve_one(resolver, sub, wildcard_ips={"198.51.100.9"}, limiter=_limiter())

    assert result.resolved is True
    assert result.wildcard_match is True
    assert 0 < result.confidence < 0.3  # heavily discounted, per _confidence's 0.3x multiplier


@pytest.mark.asyncio
async def test_real_host_not_matching_wildcard_gets_full_confidence():
    resolver = FakeResolver({("real.example.com", "A"): ["203.0.113.42"]})
    sub = Subdomain(hostname="real.example.com", root_domain="example.com", sources={"crtsh", "subfinder"})

    result = await _resolve_one(resolver, sub, wildcard_ips={"198.51.100.9"}, limiter=_limiter())

    assert result.resolved is True
    assert result.wildcard_match is False
    assert result.confidence >= 0.5


@pytest.mark.asyncio
async def test_nxdomain_host_marked_unresolved():
    resolver = FakeResolver({})  # everything NXDOMAINs
    sub = Subdomain(hostname="ghost.example.com", root_domain="example.com")

    result = await _resolve_one(resolver, sub, wildcard_ips=set(), limiter=_limiter())

    assert result.resolved is False
    assert result.confidence == 0.0
    assert result.records == []


def test_confidence_scales_with_source_count():
    sub_one_source = Subdomain(hostname="a.example.com", root_domain="example.com", sources={"crtsh"})
    sub_many_sources = Subdomain(
        hostname="b.example.com", root_domain="example.com", sources={"crtsh", "subfinder", "active", "ai"}
    )
    c1 = _confidence(sub_one_source, resolved=True, wildcard_match=False)
    c2 = _confidence(sub_many_sources, resolved=True, wildcard_match=False)
    assert c2 > c1


def test_confidence_never_exceeds_one():
    sub = Subdomain(
        hostname="a.example.com", root_domain="example.com", sources={"a", "b", "c", "d", "e", "f"}
    )
    assert _confidence(sub, resolved=True, wildcard_match=False) <= 1.0
