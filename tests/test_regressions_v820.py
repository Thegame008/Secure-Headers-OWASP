from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

import safewebheaders as swh


def test_manual_headers_preserve_duplicates_status_and_folded_values() -> None:
    raw = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Set-Cookie: one=secret; Secure\r\n"
        "set-cookie: two=secret; HttpOnly\r\n"
        "Content-Security-Policy: default-src 'self';\r\n"
        "  object-src 'none'\r\n"
    )
    snapshots, warnings = swh.parse_manual_response_headers(
        raw, "https://evidence.example/login#token"
    )
    assert warnings == []
    assert len(snapshots) == 1
    snapshot = snapshots[0]
    assert snapshot.url == "https://evidence.example/login"
    assert snapshot.status_code == 200
    assert snapshot.http_version == "HTTP/1.1"
    assert snapshot.all("set-cookie") == [
        "one=secret; Secure",
        "two=secret; HttpOnly",
    ]
    assert snapshot.first("content-security-policy").endswith("object-src 'none'")


def test_manual_report_labels_unverified_evidence_origin() -> None:
    report = swh.create_manual_headers_report(
        "HTTP/2 200 OK\nContent-Type: text/html\nX-Frame-Options: DENY\n",
        "https://client.example/portal",
    )
    assert report.final_url == "https://client.example/portal"
    assert report.method == "EVIDENCIA MANUAL"
    assert report.tls_verification == "no comprobada (entrada manual)"
    assert any(
        "no se realizó ninguna solicitud de red" in note for note in report.notes
    )
    assert any("no comprobó" in note for note in report.notes)


def test_manual_csp_supports_enforced_and_report_only_with_evidence_url() -> None:
    report = swh.create_manual_csp_report(
        "Content-Security-Policy: default-src 'self'; object-src 'none'\n"
        "Content-Security-Policy-Report-Only: script-src 'unsafe-inline'",
        "https://client.example/login",
    )
    assert report.final_url == "https://client.example/login"
    assert report.response_headers["content-security-policy"] == [
        "default-src 'self'; object-src 'none'"
    ]
    assert report.response_headers["content-security-policy-report-only"] == [
        "script-src 'unsafe-inline'"
    ]
    serialized = report.to_dict()
    assert serialized["final_url"] == "https://client.example/login"
    assert serialized["categories"]
    csp_entry = next(
        finding
        for category in serialized["categories"]
        for finding in category["findings"]
        if finding["header"] == "Content-Security-Policy"
    )
    assert all("spans" in policy for policy in csp_entry["policy_spans"])


def test_web_service_redacts_sensitive_raw_values_by_default() -> None:
    payload = {
        "mode": "headers",
        "evidence_url": "https://client.example/",
        "raw_headers": (
            "HTTP/1.1 200 OK\nContent-Type: text/html\n"
            "Set-Cookie: session=top-secret; Secure; HttpOnly\n"
        ),
        "options": {"evaluate_cookies": True},
    }
    result = swh.analyze_web_payload(payload)
    report = result["results"][0]
    assert result["mode"] == "headers"
    assert "top-secret" not in report["raw_header_blocks"][0]["text"]
    assert "session=<redactado>" in report["raw_header_blocks"][0]["text"]
    assert report["header_tones"]["set-cookie"] == "cookies"


def test_web_wrapper_redacts_sensitive_target_urls_and_errors() -> None:
    result = swh.analyze_web_payload(
        {
            "mode": "url",
            "targets": "http://127.0.0.1:1/?token=very-secret-value",
            "options": {"timeout": 1},
        }
    )

    assert "very-secret-value" not in str(result)
    assert "%3Credactado%3E" in result["requested_targets"][0]


def test_web_service_accepts_more_than_fifty_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service_module = __import__(
        swh.analyze_web_payload.__module__, fromlist=["create_report"]
    )

    def fail_fast(*_args: Any, **_kwargs: Any) -> Any:
        raise swh.ScanError("objetivo simulado")

    monkeypatch.setattr(service_module, "create_report", fail_fast)
    result = swh.analyze_web_payload(
        {
            "mode": "url",
            "targets": "\n".join(
                f"https://host-{index}.example" for index in range(75)
            ),
            "options": {},
        }
    )
    assert len(result["requested_targets"]) == 75
    assert len(result["errors"]) == 75


class WebScanHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: Any) -> None:
        del args

    def do_GET(self) -> None:
        body = b"<html>ok</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def scan_target() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), WebScanHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_web_service_scans_a_real_local_target(scan_target: str) -> None:
    result = swh.analyze_web_payload(
        {
            "mode": "url",
            "targets": scan_target,
            "options": {"follow_redirects": True, "timeout": 3},
        }
    )
    assert result["errors"] == []
    report = result["results"][0]
    assert report["status_code"] == 200
    assert report["final_url"] == scan_target
    assert report["raw_header_blocks"][0]["text"].startswith("HTTP/1.1 200 OK")


@pytest.fixture
def gui_server() -> Iterator[tuple[str, Any]]:
    server = swh.create_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def read_json_response(request: Request) -> dict[str, Any]:
    with urlopen(request, timeout=5) as response:  # nosec B310 - servidor local
        return cast(dict[str, Any], json.loads(response.read()))


def test_gui_serves_assets_with_security_headers_and_injected_token(
    gui_server: tuple[str, Any],
) -> None:
    base_url, server = gui_server
    with urlopen(base_url + "/", timeout=5) as response:  # nosec B310
        body = response.read().decode("utf-8")
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert "Analizador de cabeceras" in body
    assert "__SWH_TOKEN__" not in body
    assert server.api_token in body


def test_gui_rejects_missing_token_and_accepts_valid_local_json(
    gui_server: tuple[str, Any],
) -> None:
    base_url, server = gui_server
    body = json.dumps(
        {
            "mode": "csp",
            "evidence_url": "https://client.example/",
            "csp_policy": "default-src 'self'; object-src 'none'",
            "options": {},
        }
    ).encode()
    missing = Request(
        base_url + "/api/analyze",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(HTTPError) as error:
        urlopen(missing, timeout=5)  # nosec B310
    assert error.value.code == 403

    valid = Request(
        base_url + "/api/analyze",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Origin": base_url,
            "X-SafeWebHeaders-Token": server.api_token,
        },
        method="POST",
    )
    result = read_json_response(valid)
    assert result["mode"] == "csp"
    assert result["results"][0]["final_url"] == "https://client.example/"


def test_gui_assets_contain_all_requested_modes_and_raw_view(
    gui_server: tuple[str, Any],
) -> None:
    base_url, _server = gui_server
    with urlopen(base_url + "/", timeout=5) as response:  # nosec B310
        html = response.read().decode("utf-8")
    with urlopen(base_url + "/app.js", timeout=5) as response:  # nosec B310
        javascript = response.read().decode("utf-8")
    assert "Una URL" in html
    assert "Varias URL" in html
    assert "Pegar cabeceras" in html
    assert "Solo CSP" in html
    assert "URL asociada a la evidencia" in html
    assert "Cabeceras HTTP · vista RAW" in javascript


def test_cli_web_mode_starts_local_server_without_requiring_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: dict[str, Any] = {}

    def fake_run_server(port: int, *, open_browser: bool) -> int:
        called.update(port=port, open_browser=open_browser)
        return 0

    monkeypatch.setattr("safewebheaders.web.server.run_server", fake_run_server)
    assert swh.main(["--web", "--web-port", "9090", "--no-browser"]) == 0
    assert called == {"port": 9090, "open_browser": False}
