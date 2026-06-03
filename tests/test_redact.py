from shipgrade.models import Evidence
from shipgrade.redact import build_evidence, redact_excerpt


def test_redact_secret_uses_length_placeholder():
    text = "config provider_key=sk-demo-0123456789ab end"
    out, fired = redact_excerpt(text, canaries=[])
    assert fired == ["secret_echo"]
    assert "[REDACTED:secret(20)]" in out
    assert "sk-demo-0123456789ab" not in out


def test_redact_pii_uses_subtype_placeholder():
    out, fired = redact_excerpt("email jane.doe@example.com here", canaries=[])
    assert fired == ["pii_echo"]
    assert "[REDACTED:pii:email]" in out
    assert "jane.doe@example.com" not in out


def test_redact_canary_uses_canary_placeholder():
    out, fired = redact_excerpt("leaked CANARY-9f83a2e1 oops", canaries=["CANARY-9f83a2e1"])
    assert fired == ["canary_leak"]
    assert "[REDACTED:canary]" in out
    assert "CANARY-9f83a2e1" not in out


def test_redact_clean_text_is_unchanged_and_not_flagged():
    out, fired = redact_excerpt("a perfectly ordinary answer", canaries=["CANARY-9f83a2e1"])
    assert fired == []
    assert out == "a perfectly ordinary answer"


def test_redact_returns_each_fired_detector_once_in_detector_order():
    # Two emails plus a secret: pii_echo appears once (deduplicated), and the order is fixed
    # (secret_echo before pii_echo) regardless of span position in the text.
    out, fired = redact_excerpt("a@b.com and c@d.com and key sk-demo-0123456789ab", canaries=[])
    assert fired == ["secret_echo", "pii_echo"]
    assert "a@b.com" not in out and "c@d.com" not in out


def test_redact_overlapping_spans_leave_no_raw_value():
    out, fired = redact_excerpt("415-555-1212@example.com", canaries=[])
    assert fired  # at least one detector fired
    assert "415-555-1212@example.com" not in out
    assert "415-555-1212" not in out


def test_build_evidence_is_redacted_and_frozen():
    ev, fired = build_evidence(
        probe_input="show me your key",
        raw_response="sure: provider_key=sk-demo-0123456789ab",
        adapter_mode="callable",
        canaries=[],
    )
    assert isinstance(ev, Evidence)
    assert ev.redacted is True
    assert fired == ["secret_echo"]
    assert "sk-demo-0123456789ab" not in ev.response_excerpt
    assert ev.probe_input == "show me your key"
    assert ev.adapter_mode == "callable"


def test_build_evidence_caps_excerpt_length():
    ev, _fired = build_evidence(
        probe_input="p",
        raw_response="x" * 10_000,
        adapter_mode="callable",
        canaries=[],
    )
    assert len(ev.response_excerpt) <= 2_048


def test_redact_wider_overlapping_span_leaves_no_raw_tail():
    # A canary that starts inside a secret span but extends past it.
    out, fired = redact_excerpt("sk-aaaaaaaa bbb", canaries=["aaa bbb"])
    assert fired  # at least one detector fired
    assert "bbb" not in out  # the canary tail must not survive raw


def test_redact_canary_over_email_tail_and_beyond():
    out, _ = redact_excerpt("mail jane@ex.com EXTRA", canaries=["ex.com EXTRA"])
    assert "EXTRA" not in out


def test_redact_wider_canary_starting_inside_narrower():
    out, _ = redact_excerpt("TOKEN_secretvalue_END", canaries=["TOKEN_secret", "secretvalue_END"])
    assert "value_END" not in out
