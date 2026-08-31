from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar
from urllib.request import urlopen

import pytest

import safewebheaders as swh


class MethodTargetHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    observed: ClassVar[list[dict[str, str]]] = []

    def log_message(self, _format: str, *args: Any) -> None:
        del args

    def _respond(self, status: int, body: bytes = b"") -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        self.observed.append(
            {
                "method": "POST",
                "path": self.path,
                "body": body,
                "content_type": self.headers.get("Content-Type", ""),
            }
        )
        if self.path == "/meta":
            self._respond(
                200,
                b'<html><meta http-equiv="refresh" content="0; url=/landing"></html>',
            )
        else:
            self._respond(200, b"<html>post ok</html>")

    def do_OPTIONS(self) -> None:
        self.observed.append(
            {"method": "OPTIONS", "path": self.path, "body": "", "content_type": ""}
        )
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, OPTIONS, POST")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        self.observed.append(
            {"method": "GET", "path": self.path, "body": "", "content_type": ""}
        )
        self._respond(200, b"<html>landing</html>")


@pytest.fixture
def method_target() -> Iterator[str]:
    MethodTargetHandler.observed.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), MethodTargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_cli_exposes_safe_audit_methods_and_validates_post_body() -> None:
    parser = swh.build_parser()
    for method in ("GET", "HEAD", "OPTIONS", "POST"):
        assert (
            parser.parse_args(["https://example.test", "--method", method]).method
            == method
        )

    invalid = parser.parse_args(["https://example.test", "--data", "a=1"])
    with pytest.raises(swh.ScanError, match="solo se usan con --method POST"):
        swh.validate_args(invalid)

    valid = parser.parse_args(
        [
            "https://example.test",
            "--method",
            "POST",
            "--data",
            '{"ok":true}',
            "--content-type",
            "application/json",
        ]
    )
    swh.validate_args(valid)


def test_post_body_file_is_bounded_and_custom_content_type_wins(
    tmp_path: Path, method_target: str
) -> None:
    body_file = tmp_path / "body.json"
    body_file.write_text('{"from":"file"}', encoding="utf-8")
    args = swh.build_parser().parse_args(
        [
            "https://example.test",
            "--method",
            "POST",
            "--data-file",
            str(body_file),
            "--content-type",
            "application/json",
            "-H",
            "Content-Type: text/plain",
        ]
    )
    swh.validate_args(args)
    session = swh.build_session(args)
    try:
        assert session.headers["Content-Type"] == "text/plain"
        assert vars(session)["_safewebheaders_request_body"] == body_file.read_bytes()
        response = swh.request_target(session, method_target + "/file", args)
        response.close()
    finally:
        session.close()
    assert MethodTargetHandler.observed[-1] == {
        "method": "POST",
        "path": "/file",
        "body": '{"from":"file"}',
        "content_type": "text/plain",
    }

    oversized = tmp_path / "oversized.bin"
    oversized.write_bytes(b"x" * (swh.REQUEST_BODY_LIMIT + 1))
    oversized_args = swh.build_parser().parse_args(
        [
            "https://example.test",
            "--method",
            "POST",
            "--data-file",
            str(oversized),
        ]
    )
    swh.validate_args(oversized_args)
    with pytest.raises(swh.ScanError, match="supera 1 MiB"):
        swh.build_session(oversized_args)


def test_gui_post_sends_exact_body_without_copying_it_to_report(
    method_target: str,
) -> None:
    secret_body = '{"proof":"unique-secret-840"}'
    result = swh.analyze_web_payload(
        {
            "mode": "url",
            "targets": method_target + "/post",
            "options": {
                "method": "POST",
                "request_body": secret_body,
                "request_content_type": "application/json",
                "timeout": 3,
            },
        }
    )

    assert result["errors"] == []
    assert MethodTargetHandler.observed[-1] == {
        "method": "POST",
        "path": "/post",
        "body": secret_body,
        "content_type": "application/json",
    }
    report = result["results"][0]
    assert report["method"] == "POST"
    assert "unique-secret-840" not in json.dumps(result)
    assert any("POST por solicitud expresa" in note for note in report["notes"])


def test_gui_options_audits_the_options_response(method_target: str) -> None:
    result = swh.analyze_web_payload(
        {
            "mode": "url",
            "targets": method_target + "/options",
            "options": {"method": "OPTIONS", "timeout": 3},
        }
    )

    assert result["errors"] == []
    report = result["results"][0]
    assert report["status_code"] == 204
    assert report["method"] == "OPTIONS"
    assert MethodTargetHandler.observed[-1]["method"] == "OPTIONS"


def test_meta_refresh_after_post_switches_to_get_without_resending_body(
    method_target: str,
) -> None:
    result = swh.analyze_web_payload(
        {
            "mode": "url",
            "targets": method_target + "/meta",
            "options": {
                "method": "POST",
                "request_body": "must-not-be-forwarded",
                "request_content_type": "text/plain",
                "follow_redirects": True,
                "timeout": 3,
            },
        }
    )

    assert result["errors"] == []
    assert [item["method"] for item in MethodTargetHandler.observed] == ["POST", "GET"]
    assert MethodTargetHandler.observed[-1]["body"] == ""
    report = result["results"][0]
    assert report["method"] == "POST → GET"
    assert any("no volvió a enviar el cuerpo" in note for note in report["notes"])


def test_cookie_analysis_state_is_serialized_even_without_set_cookie() -> None:
    report = swh.create_manual_headers_report(
        "HTTP/1.1 200 OK\nContent-Type: text/html\nX-Frame-Options: DENY\n",
        "https://evidence.example/",
        evaluate_cookies=True,
    )
    assert report.to_dict()["cookie_analysis_enabled"] is True
    assert report.to_dict()["summary"]["cookies"] == 0


def test_gui_branding_navigation_and_category_semantics_are_explicit() -> None:
    asset_dir = (
        Path(__file__).resolve().parents[1] / "safewebheaders" / "web" / "assets"
    )
    html = (asset_dir / "index.html").read_text(encoding="utf-8")
    javascript = (asset_dir / "app.js").read_text(encoding="utf-8")
    styles = (asset_dir / "styles.css").read_text(encoding="utf-8")
    logo = (asset_dir / "logo.svg").read_text(encoding="utf-8")

    assert '<link rel="icon" href="/logo.svg"' in html
    assert '<img src="/logo.svg"' in html
    assert "GET · página completa" in html
    assert "POST · cuerpo explícito" in html
    assert "Automático (recomendado)" in html
    assert "Perfil de análisis" in html
    # 8.5.0: la navegación por objetivo pasó del submenú incrustado a un menú
    # lateral de secciones, y el área de cookies se nombró explícitamente.
    assert "section-nav" in javascript
    assert "renderSectionNav" in javascript
    assert 'label: "Validador de cookies"' in javascript
    assert 'id = "report-cookies"' in javascript
    assert "--accent: #1769ff" in styles
    assert ".category.ausentes .category-title" in styles
    assert ".category.incorrectas .category-title" in styles
    assert "border-left: 3px" not in styles
    assert "#125fff" in logo


def test_gui_serves_the_same_svg_used_as_favicon() -> None:
    server = swh.create_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urlopen(  # nosec B310 - servidor efímero sobre loopback
            f"http://127.0.0.1:{server.server_port}/logo.svg", timeout=5
        ) as response:
            body = response.read().decode("utf-8")
            assert response.headers["Content-Type"] == "image/svg+xml"
        assert "SafeWebHeaders" in body
        assert "<svg" in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_cli_banner_is_the_text_equivalent_of_the_shield() -> None:
    report = swh.create_manual_csp_report(
        "default-src 'self'; object-src 'none'", "https://evidence.example/"
    )
    rendered = swh.render_console(report, color=False, reveal_sensitive=False)
    # 8.5.0: el escudo se dibuja con bloques de media altura y reproduce la
    # pila de cabeceras del SVG en un tono distinto al del cuerpo.
    assert rendered.startswith(" \u2584\u2588")
    assert "\u2588" in rendered
    assert "HTTP SECURITY AUDITOR" in rendered
