"""Regresiones de SafeWebHeaders 8.4.2.

Cubren las mejoras de interfaz solicitadas sobre 8.4.1:

1. Color exclusivo para las cabeceras heredadas u obsoletas, unificado entre la
   CLI y la GUI.
2. Favicon del objetivo incrustado por el servidor, e inventario compacto de
   cabeceras por categoría.
3. Ocultación selectiva de cabeceras desde la interfaz web.
4. Escala tipográfica mayor.
5. Área de pruebas de concepto servidas desde el servidor local, incluida la de
   CORS con el Origin real de la interfaz.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

import safewebheaders as swh

ASSETS = Path(__file__).resolve().parents[1] / "safewebheaders" / "web" / "assets"


def read_asset(name: str) -> str:
    return (ASSETS / name).read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# 1. Color exclusivo de las cabeceras obsoletas
# --------------------------------------------------------------------------


def test_legacy_headers_have_their_own_console_color() -> None:
    colors = swh.DISPLAY_CATEGORY_COLOR
    assert colors["obsoletas"] == "yellow"
    # El color no puede repetirse con ninguna otra categoría visible.
    assert len(set(colors.values())) == len(colors)


def test_legacy_headers_have_their_own_web_tone() -> None:
    styles = read_asset("styles.css")
    assert "--legacy:" in styles
    assert ".category.obsoletas .category-title { color: var(--legacy); }" in styles
    assert ".metric.legacy strong { color: var(--legacy); }" in styles
    assert ".legend .legacy::before { background: var(--legacy); }" in styles
    # El naranja de las incorrectas ya no se reutiliza para las obsoletas.
    assert ".category.obsoletas .category-title { color: var(--warning); }" not in styles


def test_web_tone_map_separates_legacy_from_incorrect() -> None:
    from safewebheaders.web.service import CATEGORY_TONES, TONE_PRIORITY

    assert CATEGORY_TONES["obsoletas"] == "legacy"
    assert CATEGORY_TONES["incorrectas"] == "incorrect"
    assert CATEGORY_TONES["obsoletas"] != CATEGORY_TONES["incorrectas"]
    assert "legacy" in TONE_PRIORITY


def test_legacy_tone_reaches_the_serialized_report() -> None:
    raw = "\n".join(
        [
            "HTTP/1.1 200 OK",
            "Content-Type: text/html; charset=utf-8",
            "X-XSS-Protection: 1; mode=block",
        ]
    )
    result = swh.analyze_web_payload(
        {
            "mode": "headers",
            "evidence_url": "https://cliente.example/",
            "raw_headers": raw,
            "options": {"all_headers": True},
        }
    )
    tones = result["results"][0]["header_tones"]
    assert tones["x-xss-protection"] == "legacy"


# --------------------------------------------------------------------------
# 2. Inventario de cabeceras y favicon
# --------------------------------------------------------------------------


def manual_report(raw: str, **options: object) -> dict:
    result = swh.analyze_web_payload(
        {
            "mode": "headers",
            "evidence_url": "https://cliente.example/",
            "raw_headers": raw,
            "options": {"all_headers": True, **options},
        }
    )
    return result["results"][0]


def test_header_inventory_groups_names_by_category() -> None:
    raw = "\n".join(
        [
            "HTTP/1.1 200 OK",
            "Content-Type: text/html; charset=utf-8",
            "Server: nginx/1.24.0",
            "X-XSS-Protection: 1; mode=block",
            "Strict-Transport-Security: max-age=300",
        ]
    )
    inventory = manual_report(raw)["header_inventory"]
    assert "Strict-Transport-Security" in inventory["incorrectas"]
    assert "X-XSS-Protection" in inventory["obsoletas"]
    assert "Server" in inventory["divulgacion"]
    assert "X-Frame-Options" in inventory["ausentes"]
    # El inventario solo lleva nombres, nunca valores ni observaciones.
    for names in inventory.values():
        assert all(":" not in name for name in names)


def test_header_inventory_does_not_repeat_a_header_inside_a_group() -> None:
    raw = "\n".join(
        [
            "HTTP/1.1 200 OK",
            "Content-Type: text/html; charset=utf-8",
            "Set-Cookie: a=1",
            "Set-Cookie: b=2",
        ]
    )
    inventory = manual_report(raw, evaluate_cookies=True)["header_inventory"]
    for names in inventory.values():
        assert len(names) == len({name.lower() for name in names})


def test_manual_reports_never_carry_a_favicon_or_poc() -> None:
    report = manual_report("HTTP/1.1 200 OK\nContent-Type: text/html")
    assert report["favicon"] is None
    assert report["poc_id"] is None
    assert report["poc"]["available"] is False


def test_favicon_markup_uses_embedded_data_only() -> None:
    javascript = read_asset("app.js")
    assert 'report.favicon.startsWith("data:image/")' in javascript
    # La interfaz nunca construye una URL remota para el icono.
    assert "favicon.ico" not in javascript


# --------------------------------------------------------------------------
# 3. Ocultar cabeceras desde la interfaz web
# --------------------------------------------------------------------------


def test_web_can_hide_headers_from_the_report() -> None:
    raw = "\n".join(
        [
            "HTTP/1.1 200 OK",
            "Content-Type: text/html; charset=utf-8",
            "Server: nginx/1.24.0",
        ]
    )
    report = manual_report(raw, excluded_headers="Server")
    assert report["excluded_headers"] == ["server"]
    inventory = report["header_inventory"]
    assert "Server" not in inventory.get("divulgacion", [])


def test_hidden_headers_accept_several_separators() -> None:
    from safewebheaders.web.service import _excluded_headers

    assert _excluded_headers({"excluded_headers": "Server, X-Powered-By"}) == [
        "Server",
        "X-Powered-By",
    ]
    assert _excluded_headers({"excluded_headers": "Server\nX-Powered-By"}) == [
        "Server",
        "X-Powered-By",
    ]
    assert _excluded_headers({"excluded_headers": ["Server", "server"]}) == ["Server"]
    assert _excluded_headers({}) == []


def test_hidden_headers_reject_invalid_names() -> None:
    from safewebheaders.web.service import _excluded_headers

    with pytest.raises(swh.ScanError):
        _excluded_headers({"excluded_headers": "Server; rm -rf /"})
    with pytest.raises(swh.ScanError):
        _excluded_headers({"excluded_headers": ["a" * 200]})
    with pytest.raises(swh.ScanError):
        _excluded_headers({"excluded_headers": 5})


# --------------------------------------------------------------------------
# 4. Escala tipográfica
# --------------------------------------------------------------------------


def test_interface_uses_the_larger_type_scale() -> None:
    styles = read_asset("styles.css")
    assert "font-size: 9px" not in styles
    assert "font-size: 10.5px" in styles
    assert "font-size: 15px" in styles


# --------------------------------------------------------------------------
# 5. Pruebas de concepto en la interfaz web
# --------------------------------------------------------------------------


class PocTargetHandler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # pragma: no cover - silencio
        return

    def do_GET(self) -> None:
        body = b"<html><body>objetivo</body></html>"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def poc_target() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), PocTargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def gui_server() -> Iterator[object]:
    server = swh.create_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def gui_post(server: object, path: str, payload: dict) -> dict:
    base = f"http://127.0.0.1:{server.server_port}"  # type: ignore[attr-defined]
    request = Request(
        base + path,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Origin": base,
            "X-SafeWebHeaders-Token": server.api_token,  # type: ignore[attr-defined]
        },
    )
    with urlopen(request, timeout=10) as response:  # nosec B310 - loopback efímero
        return json.load(response)


def test_live_scan_exposes_poc_options(gui_server: object, poc_target: str) -> None:
    result = gui_post(
        gui_server,
        "/api/analyze",
        {"mode": "url", "targets": poc_target, "options": {"timeout": 5}},
    )
    report = result["results"][0]
    assert report["poc"]["available"] is True
    assert report["poc_id"]
    kinds = {item["kind"]: item for item in report["poc"]["kinds"]}
    assert set(kinds) == {"frame", "frame-overlay", "cors", "csp"}
    assert kinds["frame"]["enabled"] is True
    # Sin sonda previa, la PoC de CORS se ofrece pero deshabilitada.
    assert kinds["cors"]["enabled"] is False


def test_generated_pocs_are_served_by_the_local_server(
    gui_server: object, poc_target: str
) -> None:
    result = gui_post(
        gui_server,
        "/api/analyze",
        {"mode": "url", "targets": poc_target, "options": {"timeout": 5}},
    )
    poc_id = result["results"][0]["poc_id"]
    for kind in ("frame", "frame-overlay", "csp"):
        created = gui_post(gui_server, "/api/poc", {"poc_id": poc_id, "kind": kind})
        assert created["kind"] == kind
        assert created["url"].endswith(f"/poc/{poc_id}/{kind}")
        with urlopen(created["url"], timeout=10) as response:  # nosec B310
            body = response.read().decode("utf-8")
            assert response.headers["Content-Type"] == "text/html; charset=utf-8"
            # La PoC no puede ser enmarcada ni filtrar el referer.
            assert response.headers["X-Frame-Options"] == "DENY"
            assert response.headers["Referrer-Policy"] == "no-referrer"
        assert body.startswith("<!doctype html>")


def test_cors_poc_uses_the_interface_origin_for_the_probe(
    gui_server: object, poc_target: str
) -> None:
    base = f"http://127.0.0.1:{gui_server.server_port}"  # type: ignore[attr-defined]
    result = gui_post(
        gui_server,
        "/api/analyze",
        {
            "mode": "url",
            "targets": poc_target,
            "options": {"timeout": 5, "prepare_cors_poc": True},
        },
    )
    report = result["results"][0]
    # La sonda usa el Origin real desde el que se servirá la PoC, de modo que el
    # veredicto estático y la comprobación en el navegador son comparables.
    assert report["poc"]["cors_probe_origin"] == base
    kinds = {item["kind"]: item for item in report["poc"]["kinds"]}
    assert kinds["cors"]["enabled"] is True
    created = gui_post(
        gui_server, "/api/poc", {"poc_id": report["poc_id"], "kind": "cors"}
    )
    with urlopen(created["url"], timeout=10) as response:  # nosec B310
        body = response.read().decode("utf-8")
    assert base in body


def test_cors_poc_requires_get(gui_server: object, poc_target: str) -> None:
    with pytest.raises(HTTPError):
        gui_post(
            gui_server,
            "/api/analyze",
            {
                "mode": "url",
                "targets": poc_target,
                "options": {
                    "timeout": 5,
                    "prepare_cors_poc": True,
                    "method": "POST",
                    "request_body": "x",
                },
            },
        )


def test_poc_endpoint_rejects_unknown_identifiers(gui_server: object) -> None:
    with pytest.raises(HTTPError):
        gui_post(gui_server, "/api/poc", {"poc_id": "corto", "kind": "frame"})
    with pytest.raises(HTTPError):
        gui_post(
            gui_server,
            "/api/poc",
            {"poc_id": "A" * 24, "kind": "no-existe"},
        )


def test_unrendered_poc_paths_are_not_served(gui_server: object) -> None:
    base = f"http://127.0.0.1:{gui_server.server_port}"  # type: ignore[attr-defined]
    with pytest.raises(HTTPError):
        urlopen(f"{base}/poc/{'A' * 24}/frame", timeout=5)  # nosec B310
    with pytest.raises(HTTPError):
        urlopen(f"{base}/poc/../styles.css", timeout=5)  # nosec B310


def test_poc_area_is_present_in_the_interface() -> None:
    javascript = read_asset("app.js")
    styles = read_asset("styles.css")
    assert 'id = "report-poc"' in javascript
    assert "Pruebas de concepto locales" in javascript
    assert 'label: "Pruebas de concepto"' in javascript
    assert ".poc-card" in styles
    # El aviso de autorización debe existir antes de cualquier botón.
    assert "autorización escrita" in javascript
