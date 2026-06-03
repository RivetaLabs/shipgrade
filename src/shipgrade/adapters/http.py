"""HTTP adapter (spec 5.1, 5.1.1). Sends each probe to a user-supplied URL with the SSRF
guard, no redirects, separate connect/read timeouts, and a streamed response-size cap.
The only adapter that touches an arbitrary network target, so the safety guards live here
(abuse cases 4, 8)."""

from __future__ import annotations

import json
import sys
from urllib.parse import urlparse

import httpx

from shipgrade.adapters._ssrf import assert_public_host
from shipgrade.adapters.base import AdapterError
from shipgrade.models import Target

_PLACEHOLDER = "{{prompt}}"


class HttpAdapter:
    def __init__(self, target: Target) -> None:
        self._t = target
        self._notice_shown = False

    async def respond(self, prompt: str) -> str:
        t = self._t
        host = urlparse(t.ref).hostname
        if host is None:
            raise AdapterError(f"http target ref is not a valid URL: {t.ref!r}")
        assert_public_host(host, allow_private=t.allow_private_targets)
        self._maybe_notice()
        body = (t.body_template or _PLACEHOLDER).replace(_PLACEHOLDER, prompt)
        timeout = httpx.Timeout(
            connect=t.connect_timeout_s,
            read=t.read_timeout_s,
            write=t.read_timeout_s,
            pool=t.connect_timeout_s,
        )
        try:
            async with (
                httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client,
                client.stream(
                    t.method or "POST", t.ref, content=body, headers=t.headers or {}
                ) as resp,
            ):
                data = await _read_capped(resp, t.max_response_bytes)
        except httpx.HTTPError as exc:
            raise AdapterError(f"could not reach target at {host}: {exc}") from exc
        return _extract(data, t.response_path)

    def _maybe_notice(self) -> None:
        if not self._notice_shown and not self._t.authorized_target:
            print(
                "shipgrade sends adversarial probes; only scan targets you own or are "
                "authorized to test",
                file=sys.stderr,
            )
        self._notice_shown = True


async def _read_capped(resp: httpx.Response, cap: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in resp.aiter_bytes():
        total += len(chunk)
        if total > cap:
            raise AdapterError(f"target response exceeded {cap} bytes; aborted (response-size cap)")
        chunks.append(chunk)
    return b"".join(chunks)


def _extract(raw: bytes, response_path: str | None) -> str:
    text = raw.decode("utf-8", errors="replace")
    if not response_path:
        return text
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AdapterError(
            f"response_path {response_path!r} set but body is not JSON: {exc}"
        ) from exc
    for part in response_path.split("."):
        try:
            obj = obj[int(part)] if isinstance(obj, list) else obj[part]
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            raise AdapterError(
                f"response_path {response_path!r} does not resolve in the response: {exc}"
            ) from exc
    if not isinstance(obj, str):
        raise AdapterError(f"response_path {response_path!r} did not resolve to a string")
    return obj
