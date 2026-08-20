from subsense.models import ScanState, Stage, Subdomain


def test_subdomain_merge_unions_sources():
    a = Subdomain(hostname="www.example.com", root_domain="example.com", sources={"crtsh"})
    b = Subdomain(hostname="www.example.com", root_domain="example.com", sources={"subfinder"}, resolved=True)
    a.merge(b)
    assert a.sources == {"crtsh", "subfinder"}
    assert a.resolved is True


def test_scan_state_stage_tracking():
    state = ScanState(target_domain="example.com")
    assert not state.is_stage_complete(Stage.PASSIVE_ENUM)
    state.mark_stage_complete(Stage.PASSIVE_ENUM)
    assert state.is_stage_complete(Stage.PASSIVE_ENUM)
    assert not state.is_stage_complete(Stage.RESOLVE)
