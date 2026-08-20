from subsense.dns_checks.zonewalk import _is_synthesized_next


def test_detects_null_label_white_lie():
    # Regression test for the real hang observed against example.com (Cloudflare-signed):
    # each NSEC query returns "\000." + queried_name as `next`, which never converges.
    assert _is_synthesized_next("\\000.example.com", "example.com")
    assert _is_synthesized_next("\\000.\\000.example.com", "\\000.example.com")


def test_real_adjacent_name_not_flagged():
    # A genuine next-in-canonical-order NSEC target can legitimately be one label deeper
    # (e.g. the very first record in the zone) or an unrelated sibling — neither is the
    # RFC 9276 zero-octet marker, so neither should be flagged as synthesized.
    assert not _is_synthesized_next("mail.example.com", "example.com")
    assert not _is_synthesized_next("zzz.example.com", "aaa.example.com")


def test_multi_label_child_not_flagged():
    assert not _is_synthesized_next("a.b.example.com", "example.com")


def test_similar_but_not_exact_label_not_flagged():
    # Only the exact zero-octet marker counts — a label that merely starts with digits
    # (e.g. a real "007.example.com" host) must not be mistaken for it.
    assert not _is_synthesized_next("007.example.com", "example.com")
    assert not _is_synthesized_next("\\0001.example.com", "example.com")
