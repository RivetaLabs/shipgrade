import asyncio

import httpx
import pytest
import respx

from shipgrade.adapters.base import AdapterError
from shipgrade.adapters.http import HttpAdapter
from shipgrade.models import Target


def _target(**kw) -> Target:
    base = Target(
        mode="http",
        ref="https://api.example.com/chat",
        method="POST",
        body_template='{"q": "{{prompt}}"}',
        allow_private_targets=True,  # skip DNS in HTTP tests; SSRF is tested in test_ssrf.py
        authorized_target=True,  # silence the owned-target notice
    )
    return base.model_copy(update=kw)


@respx.mock
def test_sends_body_template_and_returns_text():
    route = respx.post("https://api.example.com/chat").mock(
        return_value=httpx.Response(200, text="the model reply")
    )
    out = asyncio.run(HttpAdapter(_target()).respond("buy NVDA?"))
    assert out == "the model reply"
    assert b'"q": "buy NVDA?"' in route.calls.last.request.content


@respx.mock
def test_response_path_extracts_json_field():
    respx.post("https://api.example.com/chat").mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"content": "hello"}}]})
    )
    adapter = HttpAdapter(_target(response_path="choices.0.message.content"))
    assert asyncio.run(adapter.respond("hi")) == "hello"


@respx.mock
def test_oversized_response_is_capped():
    big = "z" * 6_000_000
    respx.post("https://api.example.com/chat").mock(return_value=httpx.Response(200, text=big))
    adapter = HttpAdapter(_target(max_response_bytes=5_000_000))
    with pytest.raises(AdapterError, match="cap"):
        asyncio.run(adapter.respond("hi"))


@respx.mock
def test_redirect_is_not_chased():
    respx.post("https://api.example.com/chat").mock(
        return_value=httpx.Response(302, headers={"Location": "http://169.254.169.254/"})
    )
    # follow_redirects=False: the 3xx is the recorded response, the metadata host is never hit.
    out = asyncio.run(HttpAdapter(_target()).respond("hi"))
    assert out == ""  # empty body, not the redirect target's content


@respx.mock
def test_transport_error_is_actionable():
    respx.post("https://api.example.com/chat").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(AdapterError, match="could not reach target"):
        asyncio.run(HttpAdapter(_target()).respond("hi"))
