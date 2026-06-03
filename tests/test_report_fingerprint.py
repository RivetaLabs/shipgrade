from shipgrade.report.fingerprint import (
    GOLDEN_FINGERPRINT,
    GOLDEN_INPUT,
    fingerprint,
)


def test_fingerprint_is_32_lowercase_hex():
    fp = fingerprint("LLM07", "p1", "", "system_prompt.txt")
    assert len(fp) == 32
    assert all(c in "0123456789abcdef" for c in fp)


def test_fingerprint_is_deterministic():
    assert fingerprint("LLM07", "p1", "", "t") == fingerprint("LLM07", "p1", "", "t")


def test_each_tuple_member_changes_the_hash():
    base = fingerprint("LLM07", "p1", "", "t")
    assert fingerprint("LLM01", "p1", "", "t") != base
    assert fingerprint("LLM07", "p2", "", "t") != base
    assert fingerprint("LLM07", "p1", "R1", "t") != base
    assert fingerprint("LLM07", "p1", "", "u") != base


def test_golden_vector_locks_the_recipe():
    # If this fails, the recipe changed and every committed waiver and dismissed
    # GitHub alert silently re-keys. Treat as an architecture-gate change (5.5.1).
    assert fingerprint(*GOLDEN_INPUT) == GOLDEN_FINGERPRINT
