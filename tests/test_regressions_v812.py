from __future__ import annotations

import csv
import io
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

import pytest

import safewebheaders as swh


def snapshot(
    *,
    url: str = "https://example.test/",
    status_code: int = 200,
    reason: str = "OK",
    body_preview: str = "",
    **headers: str | list[str],
) -> swh.ResponseSnapshot:
    normalized: dict[str, list[str]] = {}
    for name, value in headers.items():
        key = swh.normalize_header_name(name)
        normalized[key] = list(value) if isinstance(value, list) else [value]
    return swh.ResponseSnapshot(
        url=url,
        status_code=status_code,
        reason=reason,
        headers=normalized,
        display_names={key: swh.canonical_header(key) for key in normalized},
        elapsed_ms=8,
        response_kind="document",
        http_version="HTTP/1.1",
        body_preview=body_preview,
    )


def report_from_snapshot(
    snap: swh.ResponseSnapshot,
    *,
    findings: list[swh.Finding] | None = None,
    notes: list[str] | None = None,
    essential_only: bool = False,
) -> swh.ScanReport:
    return swh.ScanReport(
        tool="SafeWebHeaders",
        version=swh.VERSION,
        timestamp="2026-08-18T12:00:00Z",
        requested_url=snap.url,
        final_url=snap.url,
        method="GET",
        status_code=snap.status_code,
        reason=snap.reason,
        profile="web",
        tls_verification="activa",
        elapsed_ms=snap.elapsed_ms,
        redirect_following=False,
        redirects=[],
        excluded_headers=[],
        findings=findings or [],
        response_headers=snap.headers,
        display_names=snap.display_names,
        show_headers=False,
        notes=notes or [],
        essential_only=essential_only,
    )


def analyze(
    snap: swh.ResponseSnapshot,
    *,
    essential_only: bool,
    evaluate_cookies: bool = False,
) -> list[swh.Finding]:
    return swh.run_analysis(
        snap,
        snapshots=[snap],
        excluded=set(),
        profile="web",
        follow_redirects=False,
        evaluate_cookies=evaluate_cookies,
        essential_only=essential_only,
    )


def csp_entry(report: swh.ScanReport) -> swh.DisplayEntry:
    return next(
        entry
        for entries in swh.build_display_groups(report).values()
        for entry in entries
        if swh.normalize_header_name(entry.finding.header) == "content-security-policy"
    )


def full_snapshot(*, csp: str | list[str]) -> swh.ResponseSnapshot:
    return snapshot(
        Content_Type="text/html; charset=UTF-8",
        Strict_Transport_Security="max-age=63072000; includeSubDomains; preload",
        Content_Security_Policy=csp,
        X_Frame_Options="SAMEORIGIN",
        Referrer_Policy="no-referrer",
        X_Content_Type_Options="nosniff",
        Permissions_Policy="geolocation=()",
        Cross_Origin_Opener_Policy="same-origin",
        Cross_Origin_Embedder_Policy="require-corp",
        Cross_Origin_Resource_Policy="same-origin",
        Cache_Control="no-store",
        Set_Cookie="sid=secret; Secure; HttpOnly; SameSite=Strict",
        Access_Control_Allow_Origin="*",
        X_XSS_Protection="1; mode=block",
        Server="nginx/1.2.3",
    )


def test_essential_scope_is_default_and_all_headers_is_opt_in() -> None:
    parser = swh.build_parser()
    default = parser.parse_args(["https://example.test"])
    complete = parser.parse_args(["https://example.test", "--all-headers"])
    assert default.essential_only
    assert not complete.essential_only
    assert "--all-headers" in parser.format_help()
    assert "--essential-only" not in parser.format_help()


def test_essential_only_keeps_core_legacy_and_disclosure_only() -> None:
    snap = full_snapshot(
        csp=(
            "default-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'self'; form-action 'self'"
        )
    )
    essential = analyze(snap, essential_only=True)
    names = {swh.normalize_header_name(item.header) for item in essential}
    assert names <= {
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-xss-protection",
        "server",
    }
    assert {
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-xss-protection",
        "server",
    } <= names
    assert not any(item.status == "informativa" for item in essential)

    complete_names = {
        swh.normalize_header_name(item.header)
        for item in analyze(
            snap,
            essential_only=False,
            evaluate_cookies=True,
        )
    }
    assert {
        "referrer-policy",
        "x-content-type-options",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cache-control",
        "set-cookie",
        "access-control-allow-origin",
    } <= complete_names


@pytest.mark.parametrize("output_format", ["console", "txt", "html", "json", "csv"])
def test_essential_note_is_visible_in_every_output(output_format: str) -> None:
    snap = full_snapshot(
        csp=(
            "default-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
    )
    report = report_from_snapshot(
        snap,
        findings=analyze(snap, essential_only=True),
        notes=[swh.ESSENTIAL_ONLY_NOTE],
        essential_only=True,
    )
    batch = swh.BatchReport(
        tool="SafeWebHeaders",
        version=swh.VERSION,
        timestamp=report.timestamp,
        requested_targets=[snap.url],
        reports=[report],
        errors=[],
    )
    rendered = swh.render_batch_format(
        batch,
        output_format,
        reveal_sensitive=False,
        color=False,
    )
    assert "Modo esencial predeterminado activo" in rendered

    if output_format == "json":
        payload = json.loads(rendered)
        assert payload["results"][0]["essential_only"] is True
        assert payload["results"][0]["notes"] == [swh.ESSENTIAL_ONLY_NOTE]
    elif output_format == "csv":
        rows = list(csv.DictReader(io.StringIO(rendered)))
        assert any(
            row["tipo_registro"] == "nota"
            and row["observacion"] == swh.ESSENTIAL_ONLY_NOTE
            for row in rows
        )


def test_csp_current_value_is_raw_and_multiple_policies_are_separate() -> None:
    policies = [
        (
            "default-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        ),
        (
            "script-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors https://frames.example; form-action 'self'"
        ),
    ]
    snap = full_snapshot(csp=policies)
    report = report_from_snapshot(snap, findings=analyze(snap, essential_only=False))
    entry = csp_entry(report)
    assert entry.current_value == "\n".join(policies)
    assert "Política aplicada #" not in entry.current_value
    assert entry.policies == policies
    assert "2 políticas" in entry.policy_context
    assert "intersección" in entry.policy_context

    serialized = swh.serialize_display_entry(entry)
    assert serialized["current_value"] == "\n".join(policies)
    assert serialized["policies"] == [
        {"index": 1, "value": policies[0]},
        {"index": 2, "value": policies[1]},
    ]
    assert serialized["policy_context"] == entry.policy_context


def test_csp_uses_the_same_bad_and_good_tokens_in_console_and_html() -> None:
    policy = (
        "default-src 'self'; "
        "script-src 'nonce-MDEyMzQ1Njc4OWFiY2RlZg==' 'strict-dynamic' 'unsafe-eval'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'self'; form-action 'self'"
    )
    snap = full_snapshot(csp=policy)
    report = report_from_snapshot(snap, findings=analyze(snap, essential_only=False))
    entry = csp_entry(report)
    tones = {text: tone for text, tone in entry.policy_spans[0] if text.strip()}
    assert tones["'unsafe-eval'"] == "bad"
    assert tones["'strict-dynamic'"] == "good"
    assert tones["'nonce-<oculto>'"] == "good"
    assert tones["object-src"] == "good"
    assert tones["'none'"] == "good"

    console = swh.render_console(report, color=True, reveal_sensitive=False)
    assert "\x1b[91m\x1b[1m'unsafe-eval'\x1b[0m" in console
    assert "\x1b[92m\x1b[1m'strict-dynamic'\x1b[0m" in console

    rendered_html = swh.render_html(report, reveal_sensitive=False)
    assert '<span class="csp-bad">&#x27;unsafe-eval&#x27;</span>' in rendered_html
    assert '<span class="csp-good">&#x27;strict-dynamic&#x27;</span>' in rendered_html
    assert '<span class="csp-good">object-src</span>' in rendered_html


def test_csp_marks_weak_nonce_and_wildcard_bad_without_overrating_strict_dynamic() -> (
    None
):
    policy = (
        "default-src *; script-src 'nonce-YWJj' 'strict-dynamic'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    snap = full_snapshot(csp=policy)
    report = report_from_snapshot(snap, findings=analyze(snap, essential_only=False))
    entry = csp_entry(report)
    tones = {text: tone for text, tone in entry.policy_spans[0] if text.strip()}
    assert tones["*"] == "bad"
    assert tones["'nonce-<oculto>'"] == "bad"
    assert any(
        "'strict-dynamic'" in text and tone == ""
        for text, tone in entry.policy_spans[0]
    )


def test_csp_findings_are_rendered_in_summary_then_detail_passes() -> None:
    policy = (
        "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    snap = full_snapshot(csp=policy)
    report = report_from_snapshot(snap, findings=analyze(snap, essential_only=False))
    entry = csp_entry(report)
    assert len(entry.details) >= 2

    console = swh.render_console(report, color=False, reveal_sensitive=False)
    # 8.5.0: los encabezados internos del bloque CSP van en versalitas y
    # precedidos de una línea en blanco para separarlos de la política.
    summary_at = console.index("RESUMEN DE HALLAZGOS CSP")
    details_at = console.index("ANÁLISIS DETALLADO DE CSP")
    first_title = entry.details[0].title
    first_summary_title = console.index(first_title, summary_at)
    first_detail_title = console.index(first_title, first_summary_title + 1)
    assert summary_at < first_summary_title < details_at < first_detail_title
    assert "Protección:" in console[first_detail_title:]
    assert "para los tipos de recurso" in console or "destinos" in console

    rendered_html = swh.render_html(report, reveal_sensitive=False)
    html_summary_at = rendered_html.index("Resumen de hallazgos CSP")
    html_details_at = rendered_html.index("Análisis detallado de CSP")
    html_first_summary = rendered_html.index(first_title, html_summary_at)
    html_first_detail = rendered_html.index(first_title, html_first_summary + 1)
    assert html_summary_at < html_first_summary < html_details_at < html_first_detail
    assert "<dt>Protección</dt>" in rendered_html[html_first_detail:]

    serialized = swh.serialize_display_entry(entry)
    assert [item["title"] for item in serialized["details"]] == [
        item.title for item in entry.details
    ]
    assert all(item["purpose"] for item in serialized["details"])


class RedirectDiagnosticHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: Any) -> None:
        del args

    def send_payload(
        self,
        status: int,
        body: bytes = b"",
        *,
        content_type: str = "text/html; charset=UTF-8",
        **headers: str,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers.items():
            self.send_header(name.replace("_", "-"), value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        server = cast("DiagnosticServer", self.server)
        server.requests_seen.append(self.path)
        if self.path == "/start":
            self.send_payload(301, Location="/middle")
        elif self.path == "/middle":
            self.send_payload(302, Location="/final")
        elif self.path == "/final":
            self.send_payload(200, b"<html><title>Final</title></html>")
        elif self.path == "/meta":
            self.send_payload(
                200,
                (
                    b"<html><head><meta content='0; URL=\"/client-final?from=meta\"' "
                    b"http-equiv='REFRESH'></head></html>"
                ),
            )
        elif self.path == "/client-final?from=meta":
            self.send_payload(200, b"<html>Client final</html>")
        elif self.path == "/sso":
            self.send_payload(401, WWW_Authenticate="Negotiate, NTLM")
        else:
            self.send_payload(404, b"Not found", content_type="text/plain")


class DiagnosticServer(ThreadingHTTPServer):
    requests_seen: list[str]


@pytest.fixture
def diagnostic_server() -> Iterator[tuple[str, DiagnosticServer]]:
    server = DiagnosticServer(("127.0.0.1", 0), RedirectDiagnosticHandler)
    server.requests_seen = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_real_multi_hop_redirect_chain_is_preserved(
    diagnostic_server: tuple[str, DiagnosticServer],
) -> None:
    base_url, server = diagnostic_server
    args = swh.build_parser().parse_args(
        [f"{base_url}/start", "--follow-redirects", "--no-resolve"]
    )
    report = swh.create_report(args)
    assert report.redirect_following
    assert report.redirect_count == 2
    assert [hop.status_code for hop in report.redirects] == [301, 302, 200]
    assert [hop.location for hop in report.redirects] == ["/middle", "/final", ""]
    assert report.final_url == f"{base_url}/final"
    assert server.requests_seen == ["/start", "/middle", "/final"]


def test_meta_refresh_is_reported_without_executing_the_destination(
    diagnostic_server: tuple[str, DiagnosticServer],
) -> None:
    base_url, server = diagnostic_server
    args = swh.build_parser().parse_args([f"{base_url}/meta", "--no-resolve"])
    report = swh.create_report(args)
    destination = f"{base_url}/client-final?from=meta"
    assert report.redirect_count == 0
    assert any(
        "redirección del lado del cliente (meta refresh)" in note
        and destination in note
        and "no puede seguirla automáticamente" in note
        for note in report.notes
    )
    assert server.requests_seen == ["/meta"]


def test_negotiate_or_ntlm_barrier_has_an_explicit_diagnostic(
    diagnostic_server: tuple[str, DiagnosticServer],
) -> None:
    base_url, _server = diagnostic_server
    args = swh.build_parser().parse_args([f"{base_url}/sso", "--no-resolve"])
    report = swh.create_report(args)
    assert any(
        "WWW-Authenticate" in note
        and "SSO/NTLM" in note
        and "No se trata de una redirección HTTP fallida" in note
        for note in report.notes
    )
