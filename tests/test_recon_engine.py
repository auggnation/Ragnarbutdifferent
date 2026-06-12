"""Tests for recon_engine.py — helpers, engine fanout, and scope guard."""

from __future__ import annotations

import sys
import os
import time
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_split_host_port_https_url():
    from recon_engine import _split_host_port
    assert _split_host_port("https://example.com/path", 443) == ("example.com", 443)


def test_split_host_port_explicit_port():
    from recon_engine import _split_host_port
    assert _split_host_port("https://example.com:8443/", 443) == ("example.com", 8443)


def test_split_host_port_bare_host():
    from recon_engine import _split_host_port
    assert _split_host_port("example.com", 443) == ("example.com", 443)


def test_split_host_port_host_with_port():
    from recon_engine import _split_host_port
    assert _split_host_port("example.com:9443", 443) == ("example.com", 9443)


def test_split_host_port_http_url_defaults_80():
    from recon_engine import _split_host_port
    assert _split_host_port("http://example.com/", 443) == ("example.com", 80)


def test_normalize_base_url_with_scheme():
    from recon_engine import _normalize_base_url
    assert _normalize_base_url("https://example.com/path/") == "https://example.com"


def test_normalize_base_url_bare_host():
    from recon_engine import _normalize_base_url
    assert _normalize_base_url("example.com") == "https://example.com"


def test_registrable_domain_simple():
    from recon_engine import _registrable_domain
    assert _registrable_domain("api.example.com") == "example.com"


def test_registrable_domain_multi_label_tld():
    from recon_engine import _registrable_domain
    result = _registrable_domain("foo.bar.co.uk")
    assert result in ("bar.co.uk", "co.uk")


def test_registrable_domain_empty():
    from recon_engine import _registrable_domain
    assert _registrable_domain("") is None


def test_is_interesting_path_admin():
    from recon_engine import _is_interesting_path
    assert _is_interesting_path("admin/", 200) is True


def test_is_interesting_path_env():
    from recon_engine import _is_interesting_path
    assert _is_interesting_path(".env", 200) is True


def test_is_interesting_path_skips_forbidden():
    from recon_engine import _is_interesting_path
    assert _is_interesting_path("admin/", 403) is False


def test_is_interesting_path_boring():
    from recon_engine import _is_interesting_path
    assert _is_interesting_path("index.html", 200) is False


def test_recon_result_serialization():
    from recon_engine import ReconResult, ReconType
    result = ReconResult(recon_type=ReconType.TLS_AUDIT, target="https://example.com")
    result.status = "ok"
    result.duration_seconds = 1.5
    d = result.to_dict()
    assert d["recon_type"] == "tls_audit"
    assert d["target"] == "https://example.com"
    assert d["status"] == "ok"
    assert d["duration_seconds"] == 1.5
    assert d["findings"] == []


def test_recon_scan_state_serialization():
    from recon_engine import ReconScanState, ReconType
    state = ReconScanState(
        scan_id="RECON-test",
        target="https://example.com",
        recon_types=[ReconType.TLS_AUDIT, ReconType.DNS_PASSIVE],
    )
    d = state.to_dict()
    assert d["scan_id"] == "RECON-test"
    assert d["recon_types"] == ["tls_audit", "dns_passive"]
    assert d["handed_off"] is False
    assert d["status"] == "pending"


def test_engine_fanout_partial_failure(monkeypatch):
    """One runner failing must not block the others."""
    from recon_engine import ReconEngine, ReconType, ReconResult

    engine = ReconEngine.__new__(ReconEngine)
    engine._lock = __import__("threading").Lock()
    engine.active_scans = {}
    engine._tool_paths = {}
    from collections import deque
    engine._scan_history = deque(maxlen=100)

    def ok_runner(target):
        return ReconResult(recon_type=ReconType.TLS_AUDIT, target=target, status="ok")

    def failing_runner(target):
        raise RuntimeError("simulated failure")

    def slow_ok_runner(target):
        time.sleep(0.05)
        return ReconResult(recon_type=ReconType.CONTENT_DISCOVERY, target=target, status="ok")

    monkeypatch.setattr(engine, "_run_tls_audit", ok_runner)
    monkeypatch.setattr(engine, "_run_dns_passive", failing_runner)
    monkeypatch.setattr(engine, "_run_content_discovery", slow_ok_runner)

    from recon_engine import ReconScanState
    state = ReconScanState(
        scan_id="TEST",
        target="https://example.com",
        recon_types=[ReconType.TLS_AUDIT, ReconType.DNS_PASSIVE, ReconType.CONTENT_DISCOVERY],
    )
    engine.active_scans["TEST"] = state

    engine._run_scan("TEST", "https://example.com",
                    [ReconType.TLS_AUDIT, ReconType.DNS_PASSIVE, ReconType.CONTENT_DISCOVERY],
                    timeout=10)

    assert state.status == "completed"
    assert state.results[ReconType.TLS_AUDIT].status == "ok"
    assert state.results[ReconType.DNS_PASSIVE].status == "error"
    assert "simulated failure" in state.results[ReconType.DNS_PASSIVE].error_message
    assert state.results[ReconType.CONTENT_DISCOVERY].status == "ok"


def test_assert_handoff_scope_same_domain():
    from recon_engine import ReconEngine, ReconScanState, ReconType
    engine = ReconEngine.__new__(ReconEngine)
    engine._lock = __import__("threading").Lock()
    engine.active_scans = {
        "S1": ReconScanState(scan_id="S1", target="https://example.com", recon_types=[ReconType.DNS_PASSIVE]),
    }
    violations = engine.assert_handoff_scope("S1", ["api.example.com", "dev.example.com"])
    assert violations == []


def test_assert_handoff_scope_cross_domain():
    from recon_engine import ReconEngine, ReconScanState, ReconType
    engine = ReconEngine.__new__(ReconEngine)
    engine._lock = __import__("threading").Lock()
    engine.active_scans = {
        "S1": ReconScanState(scan_id="S1", target="https://example.com", recon_types=[ReconType.DNS_PASSIVE]),
    }
    violations = engine.assert_handoff_scope("S1", ["api.example.com", "evil.com"])
    assert violations == ["evil.com"]


def test_assert_handoff_scope_force_bypass():
    from recon_engine import ReconEngine, ReconScanState, ReconType
    engine = ReconEngine.__new__(ReconEngine)
    engine._lock = __import__("threading").Lock()
    engine.active_scans = {
        "S1": ReconScanState(scan_id="S1", target="https://example.com", recon_types=[ReconType.DNS_PASSIVE]),
    }
    violations = engine.assert_handoff_scope("S1", ["evil.com"], force=True)
    assert violations == []


def test_get_handoff_options_after_ok_scan():
    from recon_engine import ReconEngine, ReconScanState, ReconType, ReconResult
    engine = ReconEngine.__new__(ReconEngine)
    engine._lock = __import__("threading").Lock()

    state = ReconScanState(scan_id="S1", target="https://example.com",
                           recon_types=[ReconType.DNS_PASSIVE, ReconType.CONTENT_DISCOVERY])
    state.results[ReconType.DNS_PASSIVE] = ReconResult(
        recon_type=ReconType.DNS_PASSIVE, target="https://example.com", status="ok",
        artifacts={"subdomains": [{"name": "api.example.com", "alive": True}]},
    )
    state.results[ReconType.CONTENT_DISCOVERY] = ReconResult(
        recon_type=ReconType.CONTENT_DISCOVERY, target="https://example.com", status="ok",
        artifacts={"hits": [{"path": "admin/", "status": 200, "length": 1024}]},
    )
    engine.active_scans = {"S1": state}

    options = engine.get_handoff_options("S1")
    assert options is not None
    assert options["subdomains"] == [{"name": "api.example.com", "alive": True}]
    assert options["paths"] == [{"path": "admin/", "status": 200, "length": 1024}]


def test_get_handoff_options_missing_scan():
    from recon_engine import ReconEngine
    engine = ReconEngine.__new__(ReconEngine)
    engine._lock = __import__("threading").Lock()
    engine.active_scans = {}
    assert engine.get_handoff_options("nope") is None


def test_cancel_scan_marks_state():
    from recon_engine import ReconEngine, ReconScanState, ReconType
    engine = ReconEngine.__new__(ReconEngine)
    engine._lock = __import__("threading").Lock()
    state = ReconScanState(scan_id="S1", target="x", recon_types=[ReconType.TLS_AUDIT])
    state.status = "running"
    engine.active_scans = {"S1": state}
    assert engine.cancel_scan("S1") is True
    assert state.status == "cancelled"


def test_cancel_scan_returns_false_when_already_done():
    from recon_engine import ReconEngine, ReconScanState, ReconType
    engine = ReconEngine.__new__(ReconEngine)
    engine._lock = __import__("threading").Lock()
    state = ReconScanState(scan_id="S1", target="x", recon_types=[ReconType.TLS_AUDIT])
    state.status = "completed"
    engine.active_scans = {"S1": state}
    assert engine.cancel_scan("S1") is False


if __name__ == "__main__":
    import sys
    rc = __import__("pytest").main([__file__, "-v"])
    sys.exit(rc)
