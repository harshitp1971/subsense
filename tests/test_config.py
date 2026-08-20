from pathlib import Path

from subsense.config import Config


def test_load_defaults():
    config = Config.load()
    assert config.dns.resolvers == ["1.1.1.1", "8.8.8.8"]
    assert config.ratelimit.max_concurrency == 20
    assert config.active.enabled is False
    assert config.ai.model == "phi4-mini"


def test_load_merges_override(tmp_path: Path):
    override = tmp_path / "custom.yaml"
    override.write_text(
        "ratelimit:\n  requests_per_second: 2.0\n"
        "scope:\n  exclude:\n    - '^internal\\.'\n"
    )
    config = Config.load(override)
    # overridden values apply...
    assert config.ratelimit.requests_per_second == 2.0
    assert config.scope.exclude == ["^internal\\."]
    # ...and untouched sections keep their defaults (deep merge, not replace).
    assert config.ratelimit.max_concurrency == 20
    assert config.dns.resolvers == ["1.1.1.1", "8.8.8.8"]
