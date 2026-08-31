from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

import safewebheaders as swh


def snapshot(
    url: str = "https://example.test/",
    status_code: int = 200,
    **headers: str | list[str],
) -> swh.ResponseSnapshot:
    normalized: dict[str, list[str]] = {}
    for name, value in headers.items():
        normalized[swh.normalize_header_name(name)] = (
            list(value) if isinstance(value, list) else [value]
        )
    return swh.ResponseSnapshot(
        url=url,
        status_code=status_code,
        reason="OK",
        headers=normalized,
        display_names={key: swh.canonical_header(key) for key in normalized},
        elapsed_ms=1,
    )


def report(snap: swh.ResponseSnapshot, findings: list[swh.Finding]) -> swh.ScanReport:
    return swh.ScanReport(
        tool="SafeWebHeaders",
        version=swh.VERSION,
        timestamp="2026-08-12T12:00:00+00:00",
        requested_url=snap.url,
        final_url=snap.url,
        method="GET",
        status_code=snap.status_code,
        reason=snap.reason,
        profile="web",
        tls_verification="activa",
        elapsed_ms=1,
        redirect_following=False,
        redirects=[],
        excluded_headers=[],
        findings=findings,
        response_headers=snap.headers,
        display_names=snap.display_names,
        show_headers=True,
    )


def test_cross_origin_redirect_removes_custom_secrets() -> None:
    session = swh.SafeRedirectSession()
    previous = requests.Request(
        "GET", "https://one.test/start", headers={"X-API-Key": "secret"}
    ).prepare()
    response = requests.Response()
    response.request = previous
    redirected = requests.Request(
        "GET", "https://two.test/end", headers={"X-API-Key": "secret"}
    ).prepare()

    session.rebuild_auth(redirected, response)

    assert "X-API-Key" not in redirected.headers
    session.close()


def test_same_origin_redirect_keeps_custom_secrets() -> None:
    session = swh.SafeRedirectSession()
    previous = requests.Request("GET", "https://one.test/start").prepare()
    response = requests.Response()
    response.request = previous
    redirected = requests.Request(
        "GET", "https://one.test/end", headers={"X-API-Key": "secret"}
    ).prepare()

    session.rebuild_auth(redirected, response)

    assert redirected.headers["X-API-Key"] == "secret"
    session.close()


@pytest.mark.parametrize("value", ["=1+1", " +SUM(A1:A2)", "\t@cmd", "-2+3"])
def test_csv_cells_neutralize_formulas(value: str) -> None:
    assert swh.csv_safe_cell(value).startswith("'")


def test_terminal_controls_are_rendered_as_text() -> None:
    rendered = swh.sanitize_terminal_text("safe\x1b]8;;https://evil.test\x07x\nnext")
    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert "\n" not in rendered
    assert "\\x1b" in rendered
    assert "\\x0a" in rendered


@pytest.mark.parametrize(
    ("status_code", "headers", "kind"),
    [
        (204, {}, "empty"),
        (304, {}, "empty"),
        (302, {"location": "https://example.test/next"}, "redirect"),
        (200, {"content_type": "image/png"}, "asset"),
        (200, {"content_type": "application/pdf"}, "download"),
        (200, {"content_type": "application/problem+json"}, "api"),
        (200, {"content_type": "text/html; charset=UTF-8"}, "document"),
    ],
)
def test_response_kind_classifier(
    status_code: int, headers: dict[str, str], kind: str
) -> None:
    assert (
        swh.detect_response_kind(snapshot(status_code=status_code, **headers)) == kind
    )


def test_empty_response_does_not_invent_representation_headers() -> None:
    snap = snapshot(status_code=204)
    profile = swh.detect_profile("auto", snap)
    findings = swh.run_analysis(
        snap,
        snapshots=[snap],
        excluded=set(),
        profile=profile,
        follow_redirects=False,
    )
    checked = {
        swh.normalize_header_name(item.header)
        for item in findings
        if item.status == "ausente"
    }
    assert not checked & {
        "content-type",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
    }


def test_content_type_rejects_garbage_and_empty_charset() -> None:
    malformed = swh.analyze_content_type(
        snapshot(content_type="text/html garbage"), set()
    )[0]
    empty_charset = swh.analyze_content_type(
        snapshot(content_type="text/html; charset="), set()
    )[0]
    assert malformed.status == "incorrecta"
    assert empty_charset.status == "incorrecta"


@pytest.mark.parametrize(
    "value",
    [
        "text/html; charset=UTF-8 garbage",
        "text/html; charset=UTF-8;",
        'text/html; charset="UTF-8" trailing',
    ],
)
def test_content_type_rejects_malformed_parameters(value: str) -> None:
    assert swh.analyze_content_type(snapshot(content_type=value), set())[0].status == (
        "incorrecta"
    )


def test_content_type_accepts_a_quoted_charset() -> None:
    finding = swh.analyze_content_type(
        snapshot(content_type='text/html; charset="UTF-8"'), set()
    )[0]
    assert finding.status == "correcta"


def test_csp_combined_field_is_split_into_multiple_policies() -> None:
    raw = "default-src 'self'; object-src 'none', default-src 'none'"
    assert len(swh.parse_csp_header_values([raw])) == 2
    findings = swh.analyze_csp_headers(
        snapshot(content_security_policy=raw, content_type="text/html"),
        set(),
        "web",
    )
    assert any("varias políticas" in item.title.lower() for item in findings)


def test_csp_none_is_not_mislabeled_as_an_allowlist() -> None:
    findings = swh.analyze_csp_headers(
        snapshot(
            content_security_policy=(
                "default-src 'none'; object-src 'none'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'self'"
            ),
            content_type="text/html",
        ),
        set(),
        "web",
    )
    assert not any("basada en allowlists" in item.title for item in findings)


def test_csp_exclusions_are_independent() -> None:
    snap = snapshot(
        content_security_policy_report_only="default-src 'none'",
        content_type="text/html",
    )
    findings = swh.analyze_csp_headers(snap, {"content-security-policy"}, "web")
    assert any(
        item.header == "Content-Security-Policy" and item.status == "excluida"
        for item in findings
    )
    assert any(
        item.header == "Content-Security-Policy-Report-Only"
        and item.status != "excluida"
        for item in findings
    )


def test_permissions_policy_rejects_arbitrary_suffix() -> None:
    finding = swh.analyze_permissions_policy(
        snapshot(permissions_policy="camera=(); ignored=true"), set(), "web"
    )[0]
    assert finding.status == "incorrecta"


def test_corp_rejects_semicolon_junk_even_for_api() -> None:
    finding = swh.analyze_cross_origin_headers(
        snapshot(cross_origin_resource_policy="same-origin; junk"), set(), "api"
    )[0]
    assert finding.status == "incorrecta"


def test_integrity_policy_rejects_unknown_destination() -> None:
    finding = swh.analyze_integrity_policy(
        snapshot(integrity_policy="blocked-destinations=(script image)"),
        set(),
        "web",
    )[0]
    assert finding.status == "incorrecta"
    assert "image" in finding.evidence


def test_integrity_policy_exclusions_are_independent() -> None:
    findings = swh.analyze_integrity_policy(
        snapshot(
            integrity_policy_report_only="blocked-destinations=(script), sources=(inline)"
        ),
        {"integrity-policy"},
        "web",
    )
    assert any(item.status == "excluida" for item in findings)
    assert any(item.header == "Integrity-Policy-Report-Only" for item in findings)


def test_content_disposition_detects_path_components() -> None:
    finding = swh.analyze_content_disposition(
        snapshot(content_disposition='attachment; filename="../../report.html"'),
        set(),
    )[0]
    assert finding.status == "advertencia"


def test_cors_rejects_a_comma_delimited_origin_list() -> None:
    finding = swh.analyze_cors(
        snapshot(access_control_allow_origin="https://a.test, https://b.test"), set()
    )[0]
    assert finding.status == "incorrecta"


def test_cors_validates_all_vary_fields_and_duplicate_credentials() -> None:
    probe = snapshot(
        access_control_allow_origin="https://probe.invalid",
        access_control_allow_credentials=["true", "true"],
        vary=["Accept-Encoding", "Origin"],
    )
    findings = swh.analyze_cors(
        snapshot(), set(), probe=probe, probe_origin="https://probe.invalid"
    )
    assert any(item.header == "Access-Control-Allow-Credentials" for item in findings)
    assert not any(item.header == "Vary" for item in findings)


def test_query_secrets_and_sensitive_headers_are_redacted_from_json() -> None:
    snap = snapshot(
        url="https://example.test/callback?client_secret=secret&visible=yes",
        x_api_key="secret",
        content_security_policy="script-src 'nonce-c2VjcmV0bm9uY2U='",
    )
    payload = report(snap, []).to_dict()
    rendered = str(payload)
    assert "client_secret=secret" not in rendered
    assert "'X-Api-Key': ['secret']" not in rendered
    assert "c2VjcmV0bm9uY2U=" not in rendered
    assert "visible" in rendered


def test_sensitive_finding_evidence_is_redacted() -> None:
    snap = snapshot(x_debug_token="debug-secret")
    findings = swh.analyze_disclosure(snap, set())
    rendered = str(report(snap, findings).to_dict())
    assert "debug-secret" not in rendered


def test_operational_errors_redact_urls_with_secrets() -> None:
    batch = swh.BatchReport(
        tool="SafeWebHeaders",
        version=swh.VERSION,
        timestamp="2026-08-12T12:00:00+00:00",
        requested_targets=["https://example.test/?token=secret"],
        reports=[],
        errors=[
            swh.ScanFailure(
                requested_url="https://example.test/?token=secret",
                timestamp="2026-08-12T12:00:00+00:00",
                error="Falló https://example.test/?token=secret",
            )
        ],
    )
    rendered = str(batch.to_dict())
    assert "token=secret" not in rendered


def test_atomic_output_refuses_overwrite_without_force() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "report.txt"
        swh.atomic_write_text(path, "first", encoding="utf-8")
        with pytest.raises(swh.ScanError):
            swh.atomic_write_text(path, "second", encoding="utf-8")
        assert path.read_text(encoding="utf-8") == "first"


def test_fail_on_policy_is_machine_readable() -> None:
    item = swh.Finding(
        category="incorrectas",
        status="incorrecta",
        severity="media",
        header="Example",
        title="Issue",
    )
    batch = SimpleNamespace(reports=[SimpleNamespace(findings=[item])])
    assert swh.batch_triggers_fail_on(batch, "incorrect")
    assert not swh.batch_triggers_fail_on(batch, "warning")


def test_fail_on_returns_distinct_cli_exit_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = swh.main(
        [
            "--csp-policy",
            "script-src *",
            "--fail-on",
            "any",
            "--no-color",
        ]
    )
    capsys.readouterr()
    assert exit_code == 3


def test_request_header_names_use_http_token_syntax() -> None:
    with pytest.raises(swh.ScanError):
        swh.parse_request_headers(["Bad Header: value"])


def test_request_headers_reject_case_insensitive_duplicates() -> None:
    with pytest.raises(swh.ScanError):
        swh.parse_request_headers(["X-API-Key: one", "x-api-key: two"])
