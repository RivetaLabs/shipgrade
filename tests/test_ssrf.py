import pytest

from shipgrade.adapters._ssrf import assert_public_host
from shipgrade.adapters.base import AdapterError


def _patch_resolve(monkeypatch, ip: str):
    monkeypatch.setattr(
        "shipgrade.adapters._ssrf.socket.getaddrinfo",
        lambda host, port, *a, **k: [(2, 1, 6, "", (ip, 0))],
    )


def test_public_ip_passes(monkeypatch):
    _patch_resolve(monkeypatch, "93.184.216.34")  # example.com
    assert_public_host("example.com", allow_private=False)  # no raise


def test_loopback_is_blocked(monkeypatch):
    _patch_resolve(monkeypatch, "127.0.0.1")
    with pytest.raises(AdapterError, match="non-public"):
        assert_public_host("localhost", allow_private=False)


def test_cloud_metadata_is_blocked(monkeypatch):
    _patch_resolve(monkeypatch, "169.254.169.254")
    with pytest.raises(AdapterError, match="non-public"):
        assert_public_host("metadata", allow_private=False)


def test_rfc1918_is_blocked(monkeypatch):
    _patch_resolve(monkeypatch, "10.0.0.5")
    with pytest.raises(AdapterError, match="10.0.0.5"):
        assert_public_host("internal", allow_private=False)


def test_allow_private_bypasses(monkeypatch):
    _patch_resolve(monkeypatch, "10.0.0.5")
    assert_public_host("internal", allow_private=True)  # no raise, no resolve needed


def test_unresolvable_host_is_actionable(monkeypatch):
    import socket as _socket

    def _boom(*a, **k):
        raise _socket.gaierror("name resolution failed")

    monkeypatch.setattr("shipgrade.adapters._ssrf.socket.getaddrinfo", _boom)
    with pytest.raises(AdapterError, match="could not resolve"):
        assert_public_host("nope.invalid", allow_private=False)
