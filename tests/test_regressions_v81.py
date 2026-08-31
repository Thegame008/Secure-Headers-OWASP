from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import safewebheaders as swh


def snapshot(
    *,
    url: str = "https://example.test/",
    status_code: int = 200,
    reason: str = "OK",
    kind: str = "document",
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
        response_kind=kind,
        http_version="HTTP/1.1",
    )


def report_from_snapshot(
    snap: swh.ResponseSnapshot,
    *,
    findings: list[swh.Finding] | None = None,
    redirects: list[swh.RedirectHop] | None = None,
    show_headers: bool = False,
) -> swh.ScanReport:
    return swh.ScanReport(
        tool="SafeWebHeaders",
        version=swh.VERSION,
        timestamp="2026-08-12T12:00:00-05:00",
        requested_url=snap.url,
        final_url=snap.url,
        method="GET",
        status_code=snap.status_code,
        reason=snap.reason,
        profile="web",
        tls_verification="activa",
        elapsed_ms=snap.elapsed_ms,
        redirect_following=bool(redirects and len(redirects) > 1),
        redirects=redirects or [],
        excluded_headers=[],
        findings=findings or [],
        response_headers=snap.headers,
        display_names=snap.display_names,
        show_headers=show_headers,
    )


def test_web_baseline_has_exactly_four_required_security_headers() -> None:
    snap = snapshot(Content_Type="text/html; charset=UTF-8")
    findings = swh.run_analysis(
        snap,
        snapshots=[snap],
        excluded=set(),
        profile="web",
        follow_redirects=False,
        essential_only=False,
    )
    absent = {item.header for item in findings if item.status == "ausente"}
    assert absent == {
        "X-Frame-Options",
        "Referrer-Policy",
        "Strict-Transport-Security",
        "Content-Security-Policy",
    }
    names = {item.header for item in findings}
    assert "X-Content-Type-Options" not in names
    assert "Permissions-Policy" not in names


def test_permissions_policy_is_optional_for_all_response_types() -> None:
    assert swh.analyze_permissions_policy(snapshot(), set(), "web") == []
    api = snapshot(kind="api", Content_Type="application/json")
    assert swh.analyze_permissions_policy(api, set(), "api") == []


def test_permissions_policy_validates_present_policy_without_inventing_directives() -> (
    None
):
    complete = snapshot(Permissions_Policy="geolocation=(), camera=(), microphone=()")
    partial = snapshot(Permissions_Policy="geolocation=()")
    broad = snapshot(Permissions_Policy="camera=*")
    assert swh.analyze_permissions_policy(complete, set(), "web")[0].status == (
        "correcta"
    )
    partial_finding = swh.analyze_permissions_policy(partial, set(), "web")[0]
    assert partial_finding.status == "correcta"
    assert swh.analyze_permissions_policy(broad, set(), "web")[0].status == (
        "advertencia"
    )


def test_xcto_and_content_type_are_optional_but_invalid_values_are_reported() -> None:
    empty = snapshot()
    assert swh.analyze_x_content_type_options(empty, set()) == []
    assert swh.analyze_content_type(empty, set()) == []

    assert (
        swh.analyze_x_content_type_options(
            snapshot(X_Content_Type_Options="invalid"), set()
        )[0].status
        == "incorrecta"
    )
    assert swh.analyze_content_type(snapshot(Content_Type="invalid"), set())[
        0
    ].status == ("incorrecta")


def test_permissions_policy_accepts_current_report_to_parameter() -> None:
    policy = (
        'geolocation=();report-to=permissions, camera=(); report-to="security", '
        "microphone=()"
    )
    directives, invalid = swh.parse_permissions_policy(policy)
    assert invalid == []
    assert directives == {
        "geolocation": "()",
        "camera": "()",
        "microphone": "()",
    }
    finding = swh.analyze_permissions_policy(
        snapshot(Permissions_Policy=policy), set(), "web"
    )[0]
    assert finding.status == "correcta"


def test_present_cache_control_is_always_analyzed() -> None:
    snap = snapshot(
        Content_Type="text/html; charset=UTF-8",
        Cache_Control="public, max-age=300",
    )
    findings = swh.run_analysis(
        snap,
        snapshots=[snap],
        excluded=set(),
        profile="web",
        follow_redirects=False,
        essential_only=False,
    )
    assert any(item.header == "Cache-Control" for item in findings)


def test_new_cli_names_are_public_and_legacy_names_remain_compatible() -> None:
    parser = swh.build_parser()
    help_text = parser.format_help()
    for option in (
        "--analyze-csp",
        "--response-type",
        "--timeout",
        "--header",
        "--forward-custom-secrets",
        "--use-environment",
        "--value-cookie",
        "--reveal-sensitive",
    ):
        assert option in help_text
    for option in (
        "--csp-policy",
        "--profile",
        "--max-redirects",
        "--list-excludable-headers",
        "--trust-env",
        "--show-sensitive",
        "--value-cookies",
        "--check-cookies",
    ):
        assert option not in help_text

    args = parser.parse_args(
        [
            "https://example.test",
            "--timeout",
            "30",
            "-H",
            "Origin: https://origin.test",
        ]
    )
    swh.validate_args(args)
    assert args.connect_timeout == 30
    assert args.read_timeout == 30
    assert args.resolve_timeout == 30
    assert args.request_header == ["Origin: https://origin.test"]
    assert not args.value_cookie

    cookie_args = parser.parse_args(["https://example.test", "--value-cookie"])
    assert cookie_args.value_cookie

    legacy = parser.parse_args(
        ["https://example.test", "--profile", "api", "--show-sensitive"]
    )
    assert legacy.profile == "api"
    assert legacy.show_sensitive


def test_timeout_must_be_positive() -> None:
    args = swh.build_parser().parse_args(["https://example.test", "--timeout", "0"])
    with pytest.raises(swh.ScanError, match="--timeout"):
        swh.validate_args(args)


def test_value_cookie_requires_an_http_target() -> None:
    args = swh.build_parser().parse_args(
        ["--analyze-csp", "default-src 'self'", "--value-cookie"]
    )
    with pytest.raises(swh.ScanError, match="contextuales de red"):
        swh.validate_args(args)


def test_redirect_count_counts_a_pending_3xx_without_following_it() -> None:
    snap = snapshot(
        status_code=302,
        reason="Found",
        kind="redirect",
        Location="https://example.test/final",
    )
    hop = swh.RedirectHop(
        snap.url,
        snap.status_code,
        snap.first("location"),
        snap.elapsed_ms,
        reason=snap.reason,
        http_version=snap.http_version,
        headers=snap.headers,
        display_names=snap.display_names,
    )
    report = report_from_snapshot(snap, redirects=[hop])
    assert report.redirect_count == 1
    assert report.to_dict()["redirect_count"] == 1
    rendered = swh.render_console(report, color=False, reveal_sensitive=False)
    assert "Redirecciones" in rendered
    assert "no fue solicitado" in rendered


def test_show_headers_is_curl_like_for_every_redirect_and_redacts_secrets() -> None:
    first = swh.RedirectHop(
        "https://example.test/start",
        302,
        "https://example.test/final?token=secret",
        4,
        reason="Found",
        http_version="HTTP/1.1",
        headers={
            "location": ["https://example.test/final?token=secret"],
            "set-cookie": ["session=secret; Secure; HttpOnly"],
            "x-secret": ["response-secret"],
        },
        display_names={
            "location": "Location",
            "set-cookie": "Set-Cookie",
            "x-secret": "X-Secret",
        },
    )
    second = swh.RedirectHop(
        "https://example.test/final",
        200,
        "",
        5,
        reason="OK",
        http_version="HTTP/2",
        headers={"x-test": ["one", "two"]},
        display_names={"x-test": "X-Test"},
    )
    snap = snapshot(X_Test=["one", "two"])
    report = report_from_snapshot(
        snap,
        redirects=[first, second],
        show_headers=True,
    )
    report.redirect_following = True
    rendered = swh.render_console(report, color=False, reveal_sensitive=False)
    assert "tipo curl (reconstruida, no bytes RAW)" in rendered
    assert "HTTP/1.1 302 Found" in rendered
    assert "HTTP/2 200 OK" in rendered
    assert "X-Test: one" in rendered
    assert "X-Test: two" in rendered
    assert "session=<redactado>" in rendered
    assert "token=secret" not in rendered
    assert "response-secret" not in rendered


def test_http_version_is_extracted_from_transport_response() -> None:
    assert swh.response_http_version(
        SimpleNamespace(raw=SimpleNamespace(version=11))
    ) == ("HTTP/1.1")
    assert swh.response_http_version(
        SimpleNamespace(raw=SimpleNamespace(version=20))
    ) == ("HTTP/2")


@pytest.mark.parametrize(
    "name",
    ["X-Secret", "X-Service-Token", "X-Client-Credential", "X-Session-ID"],
)
def test_additional_custom_secret_names_are_protected_on_redirect(name: str) -> None:
    assert swh.is_sensitive_request_header(name)


def test_frame_overlay_fades_the_overlay_and_updates_capture_live(
    tmp_path: Path,
) -> None:
    snap = snapshot(X_Frame_Options="SAMEORIGIN")
    report = report_from_snapshot(snap)
    path = swh.generate_frame_poc(report, tmp_path, interactive=True)
    content = path.read_text(encoding="utf-8")
    assert "Opacidad del overlay" in content
    assert "decoy-surface" in content
    assert "surface.style.opacity" in content
    assert "frame.style.opacity" not in content
    assert 'user.addEventListener("input", updateCapture)' in content
    assert 'pass.addEventListener("input", updateCapture)' in content
    assert "form-action 'none'" in content
    assert "No se envía ni almacena información" in content


def test_cors_poc_has_browser_timeout_and_explicit_verdicts(tmp_path: Path) -> None:
    snap = snapshot()
    report = report_from_snapshot(snap)
    report.cors_probe_status_code = 200
    report.cors_probe_headers = {
        "access-control-allow-origin": ["http://127.0.0.1:8000"],
        "access-control-allow-credentials": ["true"],
    }
    path = swh.generate_cors_poc(
        report,
        tmp_path,
        "http://127.0.0.1:8000",
    )
    content = path.read_text(encoding="utf-8")
    assert "Resultado esperado" in content
    assert "AbortController" in content
    assert "controller.abort()" in content
    assert "final_url=" in content
    assert "Confirma en DevTools que viajaron cookies" in content
    assert "Esta página no exfiltra información" in content
