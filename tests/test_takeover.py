import pytest

from subsense.config import Config
from subsense.dns_checks.base import DnsCheckContext
from subsense.dns_checks.takeover import TakeoverCheck, _match_fingerprint
from subsense.models import DnsRecord, FindingTier, RecordType, Severity, Subdomain
from subsense.ratelimit import RateLimiter


def test_match_fingerprint_hits_known_service():
    fp = _match_fingerprint("myapp.herokuapp.com")
    assert fp is not None
    assert fp["service"] == "Heroku"


def test_match_fingerprint_no_match_for_unrelated_cname():
    assert _match_fingerprint("mail.protection.outlook.com") is None


def test_match_fingerprint_is_substring_not_exact():
    # cname list entries are matched as substrings, e.g. any *.s3-website* variant
    fp = _match_fingerprint("bucket.s3-website-us-east-1.amazonaws.com")
    assert fp is not None
    assert fp["service"] == "AWS S3"


def _ctx(sub: Subdomain) -> DnsCheckContext:
    config = Config.load()
    return DnsCheckContext(
        root_domain="example.com", config=config, limiter=RateLimiter(config.ratelimit), subdomain=sub
    )


@pytest.mark.asyncio
async def test_dangling_cname_flagged_without_network_probe():
    """A CNAME to a known-vulnerable service that doesn't resolve at all is a clear-cut
    takeover — must be flagged from DNS state alone, no HTTP probe needed."""
    sub = Subdomain(
        hostname="forgotten.example.com",
        root_domain="example.com",
        records=[DnsRecord(record_type=RecordType.CNAME, value="forgotten.github.io")],
        resolved=False,
    )
    findings = await TakeoverCheck().run(_ctx(sub))
    assert len(findings) == 1
    f = findings[0]
    assert f.tier == FindingTier.TIER_1
    assert f.severity == Severity.CRITICAL
    assert f.evidence["reason"] == "cname_does_not_resolve"
    assert f.evidence["service"] == "GitHub Pages"


@pytest.mark.asyncio
async def test_resolved_service_cname_probed_for_error_page(monkeypatch):
    """If the CNAME resolves, the check must probe the live page for the service's known
    'unclaimed' error signature before concluding takeover — resolving alone isn't proof."""
    sub = Subdomain(
        hostname="shop.example.com",
        root_domain="example.com",
        records=[DnsRecord(record_type=RecordType.CNAME, value="shop.myshopify.com")],
        resolved=True,
    )

    async def fake_probe_body(self, ctx, hostname, fp):
        assert hostname == "shop.example.com"
        return "Sorry, this shop is currently unavailable"

    monkeypatch.setattr(TakeoverCheck, "_probe_body", fake_probe_body)

    findings = await TakeoverCheck().run(_ctx(sub))
    assert len(findings) == 1
    assert findings[0].evidence["reason"] == "error_page_match"
    assert findings[0].evidence["service"] == "Shopify"


@pytest.mark.asyncio
async def test_resolved_service_cname_not_flagged_when_page_looks_normal(monkeypatch):
    """Resolves to a fingerprinted service AND serves a normal page -> not a takeover."""
    sub = Subdomain(
        hostname="shop.example.com",
        root_domain="example.com",
        records=[DnsRecord(record_type=RecordType.CNAME, value="shop.myshopify.com")],
        resolved=True,
    )

    async def fake_probe_body(self, ctx, hostname, fp):
        return None  # no error-page signature matched

    monkeypatch.setattr(TakeoverCheck, "_probe_body", fake_probe_body)

    findings = await TakeoverCheck().run(_ctx(sub))
    assert findings == []


@pytest.mark.asyncio
async def test_no_cname_no_findings():
    sub = Subdomain(
        hostname="api.example.com",
        root_domain="example.com",
        records=[DnsRecord(record_type=RecordType.A, value="203.0.113.5")],
        resolved=True,
    )
    findings = await TakeoverCheck().run(_ctx(sub))
    assert findings == []
