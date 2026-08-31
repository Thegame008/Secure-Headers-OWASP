"""Regresiones de SafeWebHeaders 8.4.1.

Cubren las correcciones detectadas en la auditoría de código de 8.4.0:

1. ``Access-Control-Allow-Credentials`` se redactaba como si fuera un secreto.
2. ``frame-ancestors https://*`` se consideraba una allowlist restrictiva.
3. ``script-src https://*`` recibía menor severidad que ``script-src https:``
   y las directivas granulares no normalizaban mayúsculas.
4. El alcance esencial descartaba las observaciones contextuales de HSTS y la
   cadena de navegación, dejando informes vacíos.
5. Los prefijos de cookie se comparaban distinguiendo mayúsculas.
6. El coloreado CSP identificaba directivas por substring.
"""

from __future__ import annotations

import pytest

import safewebheaders as swh

# ``tests/test_mejora.py`` sustituye ``sys.modules["safewebheaders"]`` por el
# módulo plano ``safewebheaders.py``. Por eso esta suite se apoya únicamente en
# la API pública reexportada y nunca en ``safewebheaders.<submódulo>``.


def snapshot(
    *,
    url: str = "https://example.test/",
    status_code: int = 200,
    reason: str = "OK",
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
        http_version="HTTP/1.1",
        response_kind="document",
    )


def policy_findings(policy: str) -> list[swh.Finding]:
    snap = snapshot()
    return swh.analyze_single_csp(swh.parse_csp(policy), label="x", snapshot=snap)


def titled(findings: list[swh.Finding], fragment: str) -> swh.Finding | None:
    return next((item for item in findings if fragment in item.title), None)


# --------------------------------------------------------------------------
# 1. Redacción de cabeceras CORS
# --------------------------------------------------------------------------


def serialized(name: str, value: str) -> str:
    key = swh.normalize_header_name(name)
    rendered = swh.serializable_headers(
        {key: [value]}, {key: swh.canonical_header(key)}, False
    )
    return next(iter(rendered.values()))[0]


def test_cors_credentials_header_is_never_redacted() -> None:
    assert serialized("Access-Control-Allow-Credentials", "true") == "true"
    assert serialized("Access-Control-Expose-Headers", "X-Total") == "X-Total"
    # El heurístico de sufijos debe seguir protegiendo secretos reales.
    assert serialized("X-Api-Key", "s3cr3t") == "<redactado>"
    assert serialized("X-Vendor-Client-Secret", "s3cr3t") == "<redactado>"


def test_cors_credentials_evidence_stays_readable() -> None:
    item = swh.Finding(
        category="cors",
        status="incorrecta",
        severity="media",
        header="Access-Control-Allow-Credentials",
        title="Access-Control-Allow-Credentials usa un valor no reconocido",
        evidence="Access-Control-Allow-Credentials: TRUE",
    )
    assert swh.finding_evidence(item) == "Access-Control-Allow-Credentials: TRUE"


def test_raw_view_shows_the_credentials_value() -> None:
    raw = "\n".join(
        [
            "HTTP/1.1 200 OK",
            "Content-Type: application/json",
            "Access-Control-Allow-Origin: https://app.example.test",
            "Access-Control-Allow-Credentials: true",
        ]
    )
    report = swh.create_manual_headers_report(
        raw, "https://api.example.test/", essential_only=False
    )
    _, block = swh.response_header_blocks(report, False)[0]
    assert "Access-Control-Allow-Credentials: true" in block
    assert "<redactado>" not in block


# --------------------------------------------------------------------------
# 2 y 3. Fuentes globales equivalentes a un esquema completo
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    ["*", "https:", "http:", "ws:", "https://*", "http://*", "*://*", "*:*", "HTTPS://*"],
)
def test_global_sources_are_detected(token: str) -> None:
    assert swh.csp_source_is_global(token)


@pytest.mark.parametrize(
    "token",
    ["'self'", "'none'", "https://x.example", "*.example.test", "https://*.example.test"],
)
def test_concrete_sources_are_not_global(token: str) -> None:
    assert not swh.csp_source_is_global(token)


@pytest.mark.parametrize("token", ["https://*", "http://*", "*://*", "*:*"])
def test_frame_ancestors_wildcard_host_is_not_restrictive(token: str) -> None:
    assert not swh.frame_ancestors_is_restrictive([token])
    assert not swh.frame_ancestors_is_restrictive(["'none'", token])


def test_frame_ancestors_allowlist_stays_restrictive() -> None:
    assert swh.frame_ancestors_is_restrictive(["'self'"])
    assert swh.frame_ancestors_is_restrictive(["https://socio.example"])
    assert swh.frame_ancestors_is_restrictive(["*.example.test"])


def test_frame_ancestors_wildcard_host_produces_a_finding() -> None:
    item = titled(
        policy_findings("default-src 'self'; frame-ancestors https://*"),
        "frame-ancestors permite un conjunto global",
    )
    assert item is not None
    assert (item.status, item.severity) == ("incorrecta", "alta")


@pytest.mark.parametrize("token", ["https:", "https://*", "*://*"])
def test_script_src_global_hosts_share_the_scheme_severity(token: str) -> None:
    item = titled(
        policy_findings(f"script-src {token}"), "esquemas demasiado amplios"
    )
    assert item is not None
    assert (item.status, item.severity) == ("incorrecta", "alta")


def test_script_src_global_host_is_not_reported_twice() -> None:
    findings = policy_findings("script-src https://*")
    assert titled(findings, "hosts con comodín") is None


def test_script_src_partial_wildcard_keeps_its_own_finding() -> None:
    item = titled(policy_findings("script-src *.cdn.example"), "hosts con comodín")
    assert item is not None
    assert item.status == "advertencia"


def test_granular_script_directives_normalize_case() -> None:
    item = titled(
        policy_findings("script-src 'self'; script-src-elem HTTPS:"),
        "fuentes globales o esquemas amplios",
    )
    assert item is not None
    assert (item.status, item.severity) == ("incorrecta", "alta")


# --------------------------------------------------------------------------
# 4. Alcance esencial
# --------------------------------------------------------------------------


def essential(
    snap: swh.ResponseSnapshot,
    *,
    snapshots: list[swh.ResponseSnapshot] | None = None,
    profile: str = "web",
    follow_redirects: bool = False,
) -> list[swh.Finding]:
    return swh.run_analysis(
        snap,
        snapshots=snapshots or [snap],
        excluded=set(),
        profile=profile,
        follow_redirects=follow_redirects,
        essential_only=True,
    )


def test_http_redirect_to_https_still_explains_hsts_in_essential_scope() -> None:
    snap = snapshot(
        url="http://example.test/",
        status_code=301,
        Location="https://example.test/",
        Content_Type="text/html",
    )
    findings = essential(snap, profile="api")
    hsts = titled(findings, "HSTS debe evaluarse en el destino HTTPS")
    assert hsts is not None, "el alcance esencial dejaba el informe completamente vacío"
    assert titled(findings, "el seguimiento está desactivado") is not None


def test_ip_host_keeps_the_hsts_explanation_in_essential_scope() -> None:
    snap = snapshot(url="https://10.0.0.5/", Content_Type="text/html")
    findings = essential(snap)
    assert titled(findings, "HSTS no se almacena para direcciones IP") is not None
    headers = {swh.normalize_header_name(item.header) for item in findings}
    assert "strict-transport-security" in headers


def test_https_to_http_downgrade_is_visible_in_essential_scope() -> None:
    first = snapshot(
        url="https://example.test/",
        status_code=302,
        Location="http://example.test/",
        Content_Type="text/html",
    )
    last = snapshot(url="http://example.test/", Content_Type="text/html")
    findings = essential(
        last, snapshots=[first, last], follow_redirects=True
    )
    downgrade = titled(findings, "La cadena degrada de HTTPS a HTTP")
    assert downgrade is not None
    assert (downgrade.status, downgrade.severity) == ("incorrecta", "alta")


def test_essential_scope_still_omits_non_essential_informative_findings() -> None:
    snap = snapshot(
        Content_Type="text/html",
        Strict_Transport_Security="max-age=63072000; includeSubDomains",
        X_Frame_Options="DENY",
        X_DNS_Prefetch_Control="off",
        Content_Security_Policy=(
            "default-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        ),
    )
    headers = {swh.normalize_header_name(item.header) for item in essential(snap)}
    assert "x-dns-prefetch-control" not in headers
    assert "referrer-policy" not in headers


def test_scope_note_mentions_the_preserved_context() -> None:
    assert "cadena de navegación" in swh.ESSENTIAL_ONLY_NOTE


# --------------------------------------------------------------------------
# 5. Prefijos de cookie
# --------------------------------------------------------------------------


def cookie_issues(raw: str, *, url: str = "https://example.test/") -> str:
    snap = snapshot(url=url, Set_Cookie=raw)
    findings = swh.analyze_cookies(snap, set())
    return findings[0].evidence


@pytest.mark.parametrize("name", ["__Host-token", "__HOST-token", "__host-token"])
def test_host_prefix_is_case_insensitive(name: str) -> None:
    evidence = cookie_issues(f"{name}=v; Secure; HttpOnly; SameSite=Lax")
    assert "prefijo __Host- sin Path=/" in evidence


@pytest.mark.parametrize("name", ["__Secure-token", "__SECURE-token"])
def test_secure_prefix_is_case_insensitive(name: str) -> None:
    evidence = cookie_issues(f"{name}=v; SameSite=Lax")
    assert "prefijo __Secure- sin Secure" in evidence


def test_host_http_alias_without_hyphen_is_recognized() -> None:
    evidence = cookie_issues("__HostHttp-token=v; Secure; Path=/; SameSite=Lax")
    assert "prefijo __Host-Http- sin HttpOnly" in evidence
    assert "prefijo __Host- sin Secure" not in evidence


def test_compliant_host_cookie_has_no_prefix_issue() -> None:
    evidence = cookie_issues("__Host-token=v; Secure; HttpOnly; Path=/; SameSite=Lax")
    assert "prefijo" not in evidence


# --------------------------------------------------------------------------
# 6. Coloreado CSP por token completo
# --------------------------------------------------------------------------


def test_referrer_policy_text_does_not_activate_the_csp_directive() -> None:
    item = swh.Finding(
        category="csp",
        status="advertencia",
        severity="baja",
        header="Content-Security-Policy",
        title="Revisa la interacción con Referrer-Policy",
        evidence="Referrer-Policy: no-referrer",
    )
    spans = swh.csp_policy_spans("referrer no-referrer; default-src 'self'", [item])
    assert not any(tone == "bad" for _text, tone in spans)


def test_spans_do_not_paint_script_src_for_a_granular_only_issue() -> None:
    policy = "script-src 'nonce-YWJjZGVmZ2hpamtsbW5vcHFy'; script-src-elem *"
    item = swh.Finding(
        category="csp",
        status="incorrecta",
        severity="alta",
        header="Content-Security-Policy",
        title="script-src-elem contiene fuentes globales o esquemas amplios",
        evidence="script-src-elem: *",
    )
    spans = swh.csp_policy_spans(policy, [item])
    painted_bad = {text.strip() for text, tone in spans if tone == "bad"}
    assert "script-src-elem" in painted_bad
    assert "script-src" not in painted_bad
