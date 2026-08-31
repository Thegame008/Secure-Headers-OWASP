from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

import safewebheaders as swh


def complete_manual_headers() -> str:
    return (
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/html; charset=UTF-8\n"
        "Strict-Transport-Security: max-age=63072000; includeSubDomains\n"
        "Content-Security-Policy: default-src 'self'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'\n"
        "X-Frame-Options: DENY\n"
        "Referrer-Policy: no-referrer\n"
        "X-Content-Type-Options: nosniff\n"
        "Permissions-Policy: camera=(), microphone=(), geolocation=()\n"
    )


def visible_header_names(report: swh.ScanReport) -> set[str]:
    return {
        swh.normalize_header_name(finding["header"])
        for category in report.to_dict()["categories"]
        for finding in category["findings"]
    }


def test_cli_defaults_to_essential_and_all_headers_enables_complete_scope() -> None:
    parser = swh.build_parser()
    default = parser.parse_args(["https://example.test"])
    complete = parser.parse_args(["https://example.test", "--all-headers"])

    assert default.essential_only is True
    assert complete.essential_only is False
    assert "--all-headers" in parser.format_help()
    assert "--essential-only" not in parser.format_help()


def test_legacy_essential_only_name_remains_accepted_but_hidden() -> None:
    args = swh.build_parser().parse_args(["https://example.test", "--essential-only"])
    assert args.essential_only is True


def test_manual_and_gui_services_use_essential_scope_by_default() -> None:
    manual = swh.create_manual_headers_report(
        complete_manual_headers(), "https://evidence.example/"
    )
    assert manual.essential_only is True
    assert "referrer-policy" not in visible_header_names(manual)
    assert any("predeterminado" in note for note in manual.notes)

    gui = swh.analyze_web_payload(
        {
            "mode": "headers",
            "evidence_url": "https://evidence.example/",
            "raw_headers": complete_manual_headers(),
            "options": {},
        }
    )["results"][0]
    assert gui["essential_only"] is True
    gui_names = {
        swh.normalize_header_name(finding["header"])
        for category in gui["categories"]
        for finding in category["findings"]
    }
    assert "referrer-policy" not in gui_names


def test_all_headers_enables_complete_scope_in_manual_and_gui() -> None:
    manual = swh.create_manual_headers_report(
        complete_manual_headers(),
        "https://evidence.example/",
        essential_only=False,
    )
    assert "referrer-policy" in visible_header_names(manual)
    assert "permissions-policy" in visible_header_names(manual)

    gui = swh.analyze_web_payload(
        {
            "mode": "headers",
            "evidence_url": "https://evidence.example/",
            "raw_headers": complete_manual_headers(),
            "options": {"all_headers": True},
        }
    )["results"][0]
    assert gui["essential_only"] is False
    gui_names = {
        swh.normalize_header_name(finding["header"])
        for category in gui["categories"]
        for finding in category["findings"]
    }
    assert {"referrer-policy", "permissions-policy"} <= gui_names


def test_gui_and_web_are_equivalent_cli_aliases() -> None:
    parser = swh.build_parser()
    assert parser.parse_args(["--web"]).web is True
    assert parser.parse_args(["--gui"]).web is True


def test_server_falls_back_to_an_operating_system_selected_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_module = __import__(swh.run_server.__module__, fromlist=["create_server"])
    calls: list[int] = []
    fallback_server = SimpleNamespace(server_port=54321)

    def fake_create_server(port: int) -> Any:
        calls.append(port)
        if port == 8080:
            raise PermissionError(13, "Intento de acceso a un socket no permitido")
        return fallback_server

    monkeypatch.setattr(server_module, "create_server", fake_create_server)
    server, error = server_module._create_server_with_fallback(8080)

    assert calls == [8080, 0]
    assert server is fallback_server
    assert isinstance(error, PermissionError)


def test_gui_assets_expose_all_headers_checkbox_without_fixed_batch_count() -> None:
    server_module = __import__(
        swh.run_server.__module__, fromlist=["SafeWebHeadersHandler"]
    )
    server = swh.create_server(0)
    try:
        handler = SimpleNamespace(app_server=server)
        html = server_module.SafeWebHeadersHandler._asset_bytes(
            handler, "index.html"
        ).decode()
    finally:
        server.server_close()

    assert 'id="all-headers"' in html
    assert 'id="essential-only"' not in html
    assert "Máximo 50" not in html
    assert "Sin límite fijo de cantidad" in html
