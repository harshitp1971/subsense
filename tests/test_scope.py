from subsense.config import ScopeConfig
from subsense.models import Subdomain
from subsense.scope import ScopeFilter


def test_in_namespace_required():
    f = ScopeFilter(ScopeConfig(), "example.com")
    assert f.is_in_scope("www.example.com")
    assert f.is_in_scope("example.com")
    assert not f.is_in_scope("example.com.evil.com")
    assert not f.is_in_scope("notexample.com")


def test_exclude_wins_over_include():
    f = ScopeFilter(ScopeConfig(include=[r".*\.example\.com$"], exclude=[r"^internal\."]), "example.com")
    assert f.is_in_scope("www.example.com")
    assert not f.is_in_scope("internal.example.com")


def test_include_restricts_when_present():
    f = ScopeFilter(ScopeConfig(include=[r"^api\."]), "example.com")
    assert f.is_in_scope("api.example.com")
    assert not f.is_in_scope("www.example.com")


def test_apply_sets_in_scope_without_mutating_input():
    f = ScopeFilter(ScopeConfig(exclude=[r"^out\."]), "example.com")
    sub = Subdomain(hostname="out.example.com", root_domain="example.com")
    result = f.apply(sub)
    assert sub.in_scope is True  # original untouched
    assert result.in_scope is False


def test_filter_in_scope_drops_out_of_scope_hosts():
    f = ScopeFilter(ScopeConfig(exclude=[r"^out\."]), "example.com")
    subs = [
        Subdomain(hostname="www.example.com", root_domain="example.com"),
        Subdomain(hostname="out.example.com", root_domain="example.com"),
    ]
    kept = f.filter_in_scope(subs)
    assert [s.hostname for s in kept] == ["www.example.com"]
