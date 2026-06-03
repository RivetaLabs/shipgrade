from shipgrade.adapters.base import AdapterError, summarize_target
from shipgrade.models import Target


def test_http_identity_is_host_only_no_secrets():
    t = Target(mode="http", ref="https://api.example.com/v1/chat?token=secret123")
    s = summarize_target(t)
    assert s.identity == "api.example.com"
    assert "secret123" not in s.identity
    assert "token" not in s.identity


def test_prompt_file_identity_is_filename():
    t = Target(mode="prompt_file", ref="/home/me/private/system_prompt.txt")
    assert summarize_target(t).identity == "system_prompt.txt"


def test_callable_identity_is_module_func():
    t = Target(mode="callable", ref="my_app.target:respond")
    assert summarize_target(t).identity == "my_app.target:respond"


def test_summary_carries_provider_and_model():
    t = Target(
        mode="prompt_file", ref="p.txt", target_provider="anthropic", target_model="claude-x"
    )
    s = summarize_target(t)
    assert s.target_provider == "anthropic"
    assert s.target_model == "claude-x"


def test_adapter_error_is_an_exception():
    assert issubclass(AdapterError, Exception)
