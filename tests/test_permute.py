from subsense.ai.permute import StatisticalPermuter


def test_gap_filling_from_claude_md_example():
    """Saw payments-dev/staging/prod but only orders-dev -> should propose orders-staging
    and orders-prod (the exact example from CLAUDE.md's pattern-permutation section)."""
    permuter = StatisticalPermuter()
    permuter.observe({"payments-dev", "payments-staging", "payments-prod", "orders-dev"})

    candidates = permuter.generate_candidates(top_n=50)

    assert "orders-staging" in candidates
    assert "orders-prod" in candidates
    # already-known pairs must not be re-proposed
    assert "payments-dev" not in candidates
    assert "orders-dev" not in candidates


def test_no_candidates_from_single_token_labels():
    permuter = StatisticalPermuter()
    permuter.observe({"www", "mail", "api"})
    assert permuter.generate_candidates() == []


def test_candidates_ranked_by_combined_frequency():
    permuter = StatisticalPermuter()
    permuter.observe(
        {"a-dev", "a-staging", "a-prod", "b-dev", "b-staging", "c-dev"}
    )
    candidates = permuter.generate_candidates(top_n=100)
    # c-prod pairs the two least-frequent tokens (c:1, prod:1) -> lowest score, should rank last.
    assert candidates[-1] == "c-prod"
    # b-prod (b:2 * prod:1 = 2) should outrank c-prod (c:1 * prod:1 = 1).
    assert candidates.index("b-prod") < candidates.index("c-prod")
    assert "a-dev" not in candidates
