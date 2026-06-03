"""SSRF guard for the HTTP adapter (spec 5.1.1, abuse case 4). Resolve the target host and
refuse to connect when the resolved IP is non-public: loopback, link-local (covers the
169.254.169.254 cloud-metadata endpoint), RFC1918 private, IPv6 ULA, or the 0.0.0.0
wildcard. v1 ships resolve-and-validate; the residual DNS-rebinding window between this
check and httpx's own resolve is a documented limitation (doc 03), with connection-level
IP pinning deferred to the roadmap (spec 5.1.1)."""

from __future__ import annotations

import ipaddress
import socket

from shipgrade.adapters.base import AdapterError


def assert_public_host(host: str, *, allow_private: bool) -> None:
    if allow_private:
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise AdapterError(f"could not resolve target host {host!r}: {exc}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise AdapterError(
                f"target {host} resolves to non-public address {ip}; "
                f"pass --allow-private-targets to scan internal hosts"
            )
