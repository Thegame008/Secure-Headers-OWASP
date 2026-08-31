from __future__ import annotations

import io
import threading
from collections.abc import Iterator
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import Any, cast

import pytest
import requests
from requests import PreparedRequest, Response
from urllib3.response import HTTPResponse

import safewebheaders as swh


def response(
    url: str,
    status: int,
    *,
    body: bytes = b"",
    reason: str = "OK",
    **headers: str,
) -> Response:
    item = Response()
    item.url = url
    item.status_code = status
    item.reason = reason
    normalized_headers = {
        name.replace("_", "-"): value for name, value in headers.items()
    }
    item.headers.update(normalized_headers)
    item.elapsed = timedelta(milliseconds=4)
    request = PreparedRequest()
    request.prepare(method="GET", url=url)
    item.request = request
    item.raw = HTTPResponse(
        body=io.BytesIO(body),
        headers=normalized_headers,
        status=status,
        preload_content=False,
    )
    item.history = []
    return item


class BrokenDowngradeSession:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def request(self, **kwargs: Any) -> Response:
        url = str(kwargs["url"])
        self.calls.append(url)
        if len(self.calls) == 1:
            first = response(
                "https://www.example.test/",
                301,
                reason="Moved Permanently",
                Location="http://example.test/",
            )
            kwargs["hooks"]["response"](first)
            failed = PreparedRequest()
            failed.prepare(method="GET", url="http://example.test/")
            raise requests.ReadTimeout("read timed out", request=failed)
        return response(
            "https://example.test/",
            200,
            Content_Type="text/html; charset=UTF-8",
        )


def transport_args() -> SimpleNamespace:
    return SimpleNamespace(
        insecure=False,
        ca_bundle=None,
        method="GET",
        connect_timeout=1.0,
        read_timeout=1.0,
        timeout=1.0,
        follow_redirects=True,
        max_redirects=20,
    )


def test_failed_downgrade_retries_https_and_keeps_evidence() -> None:
    session = BrokenDowngradeSession()
    final = swh.request_target(
        cast(requests.Session, session),
        "https://www.example.test/",
        transport_args(),
    )
    assert session.calls == ["https://www.example.test/", "https://example.test/"]
    assert final.url == "https://example.test/"
    assert len(final.history) == 1
    first = final.history[0]
    first_any: Any = first
    assert first.headers["Location"] == "http://example.test/"
    assert (
        first_any._safewebheaders_effective_redirect_target == "https://example.test/"
    )


class MinticLikeSession:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def request(self, **kwargs: Any) -> Response:
        url = str(kwargs["url"])
        self.calls.append(url)
        if len(self.calls) == 1:
            first = response(
                "https://www.mintic.test/",
                301,
                reason="Moved Permanently",
                Location="http://mintic.test/",
            )
            kwargs["hooks"]["response"](first)
            failed = PreparedRequest()
            failed.prepare(method="GET", url="http://mintic.test/")
            raise requests.ReadTimeout("read timed out", request=failed)
        if len(self.calls) == 2:
            return response(
                "https://mintic.test/",
                200,
                body=(
                    b'<meta http-equiv="Refresh" content="0;url='
                    b'http://www.mintic.test/portal/715/w3-channel.html">'
                ),
                Content_Type="text/html; charset=UTF-8",
            )
        middle = response(
            "https://www.mintic.test/portal/715/w3-channel.html",
            302,
            reason="Found",
            Location="https://www.mintic.test/portal/inicio/",
        )
        final = response(
            "https://www.mintic.test/portal/inicio/",
            200,
            Content_Type="text/html; charset=UTF-8",
            X_Proof="portal-final",
        )
        final.history = [middle]
        return final


def test_mintic_like_downgrade_meta_refresh_and_302_reach_the_portal() -> None:
    session = MinticLikeSession()
    result = swh.collect_navigation(
        cast(requests.Session, session),
        "https://www.mintic.test/",
        transport_args(),
    )
    try:
        assert session.calls == [
            "https://www.mintic.test/",
            "https://mintic.test/",
            "https://www.mintic.test/portal/715/w3-channel.html",
        ]
        assert [item.status_code for item in result.snapshots] == [301, 200, 302, 200]
        assert result.final_snapshot.url == "https://www.mintic.test/portal/inicio/"
        assert result.final_snapshot.first("x-proof") == "portal-final"
        first, meta, middle, _final = result.snapshots
        assert first.redirect_target == "http://mintic.test/"
        assert first.effective_redirect_target == "https://mintic.test/"
        assert first.redirect_followed
        assert meta.redirect_kind == "meta-refresh"
        assert (
            meta.redirect_target == "http://www.mintic.test/portal/715/w3-channel.html"
        )
        assert (
            meta.effective_redirect_target
            == "https://www.mintic.test/portal/715/w3-channel.html"
        )
        assert meta.redirect_followed
        assert middle.redirect_target == "https://www.mintic.test/portal/inicio/"
        assert middle.redirect_followed
        assert any("reintentó de forma segura" in note for note in result.notes)
        assert any("priorizó su variante segura" in note for note in result.notes)
    finally:
        for item in result.responses:
            item.close()


class NavigationHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: Any) -> None:
        del args

    def send_payload(
        self, status: int, body: bytes = b"", *, location: str = ""
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        if location:
            self.send_header("Location", location)
        if self.path == "/final":
            self.send_header("X-Proof", "final-response")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        server = cast("NavigationServer", self.server)
        server.requests_seen.append(self.path)
        if self.path == "/meta":
            self.send_payload(
                200,
                b'<html><meta http-equiv="refresh" content="0; url=/middle"></html>',
            )
        elif self.path == "/middle":
            self.send_payload(302, location="/final")
        elif self.path == "/final":
            self.send_payload(200, b"<html>final</html>")
        else:
            self.send_payload(404)


class NavigationServer(ThreadingHTTPServer):
    requests_seen: list[str]


@pytest.fixture
def navigation_server() -> Iterator[tuple[str, NavigationServer]]:
    server = NavigationServer(("127.0.0.1", 0), NavigationHandler)
    server.requests_seen = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_follow_redirects_continues_meta_refresh_and_http_chain_to_final_headers(
    navigation_server: tuple[str, NavigationServer],
) -> None:
    base_url, server = navigation_server
    args = swh.build_parser().parse_args(
        [f"{base_url}/meta", "--follow-redirects", "--no-resolve"]
    )
    report = swh.create_report(args)

    assert server.requests_seen == ["/meta", "/middle", "/final"]
    assert report.final_url == f"{base_url}/final"
    assert report.response_headers["x-proof"] == ["final-response"]
    assert [hop.status_code for hop in report.redirects] == [200, 302, 200]
    assert report.redirects[0].redirect_kind == "meta-refresh"
    assert report.redirects[0].redirect_target == f"{base_url}/middle"
    assert report.redirects[0].effective_redirect_target == f"{base_url}/middle"
    assert report.redirects[0].redirect_followed
    assert report.redirects[1].redirect_kind == "http"
    assert report.redirects[1].redirect_followed
    assert report.redirect_count == 1
    assert report.client_redirect_count == 1
    assert report.navigation_count == 2


def test_redirect_export_distinguishes_announced_requested_and_final_urls(
    navigation_server: tuple[str, NavigationServer],
) -> None:
    base_url, _server = navigation_server
    args = swh.build_parser().parse_args(
        [f"{base_url}/meta", "--follow-redirects", "--no-resolve"]
    )
    report = swh.create_report(args)
    data = report.to_dict()
    first = data["redirects"][0]
    assert data["redirect_count"] == 1
    assert data["client_redirect_count"] == 1
    assert data["navigation_count"] == 2
    assert first["redirect_kind"] == "meta-refresh"
    assert first["redirect_target"] == f"{base_url}/middle"
    assert first["effective_redirect_target"] == f"{base_url}/middle"
    assert first["redirect_followed"] is True


def test_notes_are_rendered_as_a_separate_important_block(
    navigation_server: tuple[str, NavigationServer],
) -> None:
    base_url, _server = navigation_server
    args = swh.build_parser().parse_args(
        [f"{base_url}/meta", "--follow-redirects", "--no-resolve"]
    )
    report = swh.create_report(args)
    console = swh.render_console(report, color=False, reveal_sensitive=False)
    html = swh.render_html(report, reveal_sensitive=False)

    # 8.5.0: el bloque de notas conserva su separación, pero la banda de
    # signos de admiración se sustituyó por una regla horizontal.
    assert "NOTAS DE LA EVALUACIÓN" in console
    assert "\u2500" * 72 in console
    assert "!" * 20 not in console
    assert '<section class="important-notes">' in html
    assert html.index('class="important-notes"') > html.index('class="findings"')
