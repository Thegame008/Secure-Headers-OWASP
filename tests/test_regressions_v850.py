"""Regresiones de SafeWebHeaders 8.5.0.

Cubren las mejoras de presentación solicitadas sobre 8.4.2:

1. Encabezados internos de CSP separados y realzados en consola.
2. Bloque de notas sin la banda de signos de admiración.
3. Resaltado de la URL y de los valores de cabecera ajustado al texto.
4. Logo rediseñado, compartido por el favicon web y el banner de la CLI.
5. Menú lateral por secciones, gráficas de cabeceras y tema claro/oscuro.
6. Descubrimiento de favicon mediante ``<link rel="icon">``.
"""

from __future__ import annotations

import io
import re
from pathlib import Path

import pytest

import safewebheaders as swh

ASSETS = Path(__file__).resolve().parents[1] / "safewebheaders" / "web" / "assets"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def read_asset(name: str) -> str:
    return (ASSETS / name).read_text(encoding="utf-8")


def sample_report(policy: str = "default-src 'self' 'unsafe-inline'") -> swh.ScanReport:
    raw = "\n".join(
        [
            "HTTP/1.1 200 OK",
            "Content-Type: text/html; charset=utf-8",
            "Strict-Transport-Security: max-age=300",
            f"Content-Security-Policy: {policy}",
        ]
    )
    return swh.create_manual_headers_report(
        raw, "https://cliente.example/ruta/", essential_only=False
    )


def console(report: swh.ScanReport, *, color: bool = False) -> str:
    return swh.render_console(
        report, color=color, reveal_sensitive=False, include_banner=False
    )


# --------------------------------------------------------------------------
# 1. Encabezados internos de CSP
# --------------------------------------------------------------------------


def test_csp_block_titles_are_separated_and_highlighted() -> None:
    text = console(sample_report())
    for title in ("RESUMEN DE HALLAZGOS CSP", "ANÁLISIS DETALLADO DE CSP"):
        assert title in text
        position = text.index(title)
        preceding = text[:position].rstrip("\n").splitlines()[-1]
        # El título nunca queda pegado al contenido anterior.
        assert preceding.strip() == "|", preceding
        underline = text[position:].splitlines()[1]
        assert "─" in underline


def test_csp_block_titles_keep_summary_before_detail() -> None:
    text = console(sample_report())
    assert text.index("RESUMEN DE HALLAZGOS CSP") < text.index(
        "ANÁLISIS DETALLADO DE CSP"
    )


# --------------------------------------------------------------------------
# 2. Bloque de notas
# --------------------------------------------------------------------------


def test_notes_block_uses_a_rule_instead_of_exclamation_marks() -> None:
    text = console(sample_report())
    assert "NOTAS DE LA EVALUACIÓN" in text
    assert "─" * 72 in text
    # La banda de signos de admiración desaparece por completo.
    assert "!!!!" not in text


def test_notes_are_numbered() -> None:
    report = sample_report()
    assert len(report.notes) >= 2
    text = console(report)
    tail = text[text.index("NOTAS DE LA EVALUACIÓN") :]
    assert "\n 1. " in tail
    assert "\n 2. " in tail


# --------------------------------------------------------------------------
# 3. Resaltados ajustados al texto
# --------------------------------------------------------------------------


def test_url_badge_has_no_lateral_padding() -> None:
    palette = swh.Palette(True)
    badge = palette.url_badge("https://cliente.example/ruta/")
    assert "m https://" not in badge
    assert "/ \x1b[0m" not in badge
    assert "https://cliente.example/ruta/\x1b[0m" in badge


def test_url_badge_is_plain_without_color() -> None:
    palette = swh.Palette(False)
    assert palette.url_badge("https://x.test/") == "https://x.test/"


def test_header_value_is_highlighted_without_overflowing() -> None:
    lines: list[str] = []
    palette = swh.Palette(True)
    long_value = "max-age=63072000; includeSubDomains; preload; " + "a=1; " * 40
    swh.append_field(
        lines, palette, "Configuración actual en la URL", long_value, highlight=True
    )
    assert len(lines) > 1, "el valor debe envolverse en varias líneas"
    for line in lines:
        # Cada línea abre y cierra su propio resaltado: el fondo nunca queda
        # abierto al final de la línea ni se extiende hasta el borde.
        assert line.count("\x1b[48;5;236m") == 1
        assert line.endswith("\x1b[0m")
        assert not ANSI.sub("", line).endswith(" ")


def test_highlight_is_opt_in() -> None:
    lines: list[str] = []
    swh.append_field(lines, swh.Palette(True), "Riesgo", "texto normal")
    assert "\x1b[48;5;236m" not in lines[0]


# --------------------------------------------------------------------------
# 4. Logo y banner
# --------------------------------------------------------------------------


def test_logo_contains_the_shield_headers_and_seal() -> None:
    logo = read_asset("logo.svg")
    assert logo.count("<rect") == 3, "la pila de cabeceras son tres barras"
    assert "swh-seal" in logo, "el sello de verificación"
    assert "#125fff" in logo
    assert "SafeWebHeaders" in logo


def test_console_banner_renders_the_shield_in_blocks() -> None:
    lines = swh.console_brand_banner(swh.Palette(False), "9.9.9")
    body = "\n".join(lines)
    assert "█" in body
    assert f"SafeWebHeaders 9.9.9" in body
    assert "HTTP SECURITY AUDITOR" in body
    # El escudo se estrecha hacia la punta inferior.
    widths = [len(line.rstrip()) for line in lines if set(line.strip()) <= set("▀▄█ ")]
    assert widths[-1] < widths[0]


def test_banner_ink_rows_use_a_different_tone() -> None:
    colored = "\n".join(swh.console_brand_banner(swh.Palette(True), "9.9.9"))
    # Cuerpo del escudo en azul y pila de cabeceras en blanco.
    assert "\x1b[94m" in colored
    assert "\x1b[97m" in colored


def test_banner_animation_is_skipped_for_non_interactive_output() -> None:
    stream = io.StringIO()
    swh.animate_brand_banner(stream, swh.Palette(False), "9.9.9")
    expected = "\n".join(swh.console_brand_banner(swh.Palette(False), "9.9.9")) + "\n"
    assert stream.getvalue() == expected
    # Sin terminal interactiva no se emite ninguna secuencia de control extra.
    assert "\x1b[" not in stream.getvalue()


# --------------------------------------------------------------------------
# 5. Menú lateral, gráficas y tema
# --------------------------------------------------------------------------


def test_interface_declares_the_workspace_sidebar() -> None:
    html = read_asset("index.html")
    javascript = read_asset("app.js")
    assert 'id="section-nav"' in html
    assert "workspace-nav" in html
    assert "renderSectionNav" in javascript
    assert 'label: "Pruebas de concepto"' in javascript
    assert 'label: "Validador de cookies"' in javascript


def test_theme_switch_is_present_and_accessible() -> None:
    html = read_asset("index.html")
    javascript = read_asset("app.js")
    styles = read_asset("styles.css")
    assert 'id="theme-toggle"' in html
    assert 'role="switch"' in html
    assert "aria-label=" in html
    assert "applyTheme" in javascript
    assert 'prefers-color-scheme: light' in javascript
    assert ':root[data-theme="light"]' in styles
    assert "color-scheme: light" in styles


def test_light_theme_redefines_colors_without_touching_structure() -> None:
    styles = read_asset("styles.css")
    start = styles.index(':root[data-theme="light"] {')
    block = styles[start : styles.index("}", start)]
    # La regla del tema claro solo redefine tokens de color: si tocara la
    # rejilla o los tamaños, las dos superficies dejarían de coincidir.
    declarations = [
        line.strip()
        for line in block.split("{", 1)[1].split(";")
        if line.strip()
    ]
    assert declarations, "el tema claro debe declarar variables"
    for declaration in declarations:
        assert declaration.startswith("--") or declaration.startswith("color-scheme")
    for token in ("--bg:", "--panel:", "--text:", "--legacy:", "--incorrect:"):
        assert token in block


def test_header_charts_are_drawn_without_external_libraries() -> None:
    javascript = read_asset("app.js")
    assert "renderHeaderCharts" in javascript
    assert "createElementNS" in javascript
    assert "donutChart" in javascript and "barChart" in javascript
    # Ninguna gráfica puede depender de un recurso remoto.
    assert "cdn." not in javascript
    assert "https://" not in javascript.replace(
        'http://www.w3.org/2000/svg', ""
    ).replace("https://www.w3.org/2000/svg", "")


def test_chart_tones_reuse_the_category_palette() -> None:
    styles = read_asset("styles.css")
    for tone, token in [
        ("tone-success", "--success"),
        ("tone-absent", "--risk"),
        ("tone-incorrect", "--incorrect"),
        ("tone-legacy", "--legacy"),
        ("tone-recon", "--recon"),
        ("tone-cookies", "--cookies"),
    ]:
        assert f".{tone} {{ stroke: var({token}); background: var({token}); }}" in styles


# --------------------------------------------------------------------------
# 6. Descubrimiento del favicon
# --------------------------------------------------------------------------


def test_favicon_candidates_prefer_the_declared_icon() -> None:
    from safewebheaders.web.evidence import _favicon_candidates

    report = sample_report()
    report.final_url = "https://cliente.example/ruta/"
    report.document_preview = (
        '<html><head><link rel="shortcut icon" href="/assets/marca.png">'
        "</head><body></body></html>"
    )
    candidates = _favicon_candidates(report)
    assert candidates[0] == "https://cliente.example/assets/marca.png"
    # El respaldo por convención sigue disponible.
    assert "https://cliente.example/favicon.ico" in candidates


def test_favicon_candidates_fall_back_to_well_known_paths() -> None:
    from safewebheaders.web.evidence import _favicon_candidates

    report = sample_report()
    report.document_preview = ""
    candidates = _favicon_candidates(report)
    assert candidates[0] == "https://cliente.example/favicon.ico"
    assert any(candidate.endswith("/apple-touch-icon.png") for candidate in candidates)


def test_document_preview_never_reaches_the_public_report() -> None:
    report = sample_report()
    report.document_preview = "<html>secreto</html>"
    assert "document_preview" not in report.to_dict()


@pytest.mark.parametrize(
    "url", ["file:///tmp/x.html", "data:text/html,x", "about:blank"]
)
def test_favicon_is_not_attempted_for_non_http_targets(url: str) -> None:
    from safewebheaders.web.evidence import _favicon_candidates

    report = sample_report()
    report.final_url = url
    assert _favicon_candidates(report) == []


# --------------------------------------------------------------------------
# 7. Correcciones 8.5.1: API del DOM y ocultamiento de cabeceras
# --------------------------------------------------------------------------


def test_no_chained_append_on_dom_nodes() -> None:
    """``Element.append()`` devuelve ``undefined``: encadenar sobre él rompe.

    Este fallo dejó la interfaz sin poder auditar ninguna URL en 8.5.0, con el
    mensaje «Cannot set properties of undefined (setting 'textContent')».
    """

    javascript = read_asset("app.js")
    assert not re.search(r"\.append\([^;]*\)\s*\.\w", javascript)


def test_hidden_header_suggestions_are_offered_before_scanning() -> None:
    html = read_asset("index.html")
    javascript = read_asset("app.js")
    assert 'list="excludable-headers"' in html
    assert '<datalist id="excludable-headers">' in html
    assert 'id="excluded-suggestions"' in html
    assert "QUICK_SUGGESTIONS" in javascript
    assert "loadExcludableCatalog" in javascript


def test_health_endpoint_publishes_the_excludable_catalog() -> None:
    from safewebheaders.web.service import excludable_header_catalog

    catalog = excludable_header_catalog()
    assert "Server" in catalog
    assert "X-Powered-By" in catalog
    assert "Strict-Transport-Security" in catalog
    # Nombres canónicos, ordenados y sin duplicados.
    assert catalog == sorted(set(catalog))


def test_post_scan_hiding_is_a_view_filter_only() -> None:
    javascript = read_asset("app.js")
    assert "renderHideControls" in javascript
    assert "hiddenByTarget" in javascript
    # El filtro se aplica a hallazgos, inventario y gráficas, nunca al RAW.
    assert "visibleFindings" in javascript
    raw_section = javascript[javascript.index("function renderRaw(report)") :]
    raw_section = raw_section[: raw_section.index("\nfunction ", 10)]
    assert "isHidden" not in raw_section
    assert "hiddenByTarget" not in raw_section


def test_excluding_a_header_never_alters_the_raw_view() -> None:
    raw = "\n".join(
        [
            "HTTP/1.1 200 OK",
            "Content-Type: text/html; charset=utf-8",
            "Server: nginx/1.24.0",
            "X-Powered-By: PHP/8.1",
        ]
    )
    report = swh.create_manual_headers_report(
        raw,
        "https://cliente.example/",
        essential_only=False,
        excluded=["Server", "X-Powered-By"],
    )
    _url, block = swh.response_header_blocks(report, False)[0]
    # La exclusión omite la comprobación, no la evidencia.
    assert "Server: nginx/1.24.0" in block
    assert "X-Powered-By: PHP/8.1" in block
    assert report.excluded_headers == ["server", "x-powered-by"]


# --------------------------------------------------------------------------
# 8. HSTS 8.5.2: umbrales de Mozilla/MDN y opcionalidad de las directivas
# --------------------------------------------------------------------------


def hsts(value: str | None, *, url: str = "https://cliente.example/") -> swh.Finding:
    headers = {"content-type": ["text/html"]}
    if value is not None:
        headers["strict-transport-security"] = [value]
    snap = swh.ResponseSnapshot(
        url=url, status_code=200, reason="OK", headers=headers, display_names={}
    )
    findings = swh.analyze_hsts(snap, set())
    assert len(findings) == 1
    return findings[0]


@pytest.mark.parametrize("seconds", [1, 300, 604800, 2592000, 15767999])
def test_max_age_below_six_months_is_incorrect(seconds: int) -> None:
    item = hsts(f"max-age={seconds}")
    assert item.status == "incorrecta"
    assert "no alcanza el mínimo" in item.title
    assert "15768000" in item.recommendation


@pytest.mark.parametrize(
    "value",
    [
        "max-age=15768000",
        "max-age=15768000; includeSubDomains",
        "max-age=31536000",
        "max-age=63072000",
        "max-age=63072000; includeSubDomains",
        "max-age=63072000; includeSubDomains; preload",
        "max-age=94608000",
    ],
)
def test_max_age_at_or_above_six_months_is_correct(value: str) -> None:
    assert hsts(value).status == "correcta"


def test_include_subdomains_is_optional_and_never_downgrades() -> None:
    item = hsts("max-age=63072000")
    assert item.status == "correcta"
    # Se comunica como opción, con su condición, no como una carencia.
    assert "includeSubDomains no está presente" in item.evidence
    assert "opcional" in item.evidence
    assert "subdominios" in item.evidence


def test_preload_is_never_required() -> None:
    item = hsts("max-age=63072000; includeSubDomains")
    assert item.status == "correcta"
    # La herramienta no puede empujar hacia la lista de precarga: la propia
    # hstspreload.org pide que no se recomiende por defecto.
    assert "preload son opcionales" in item.recommendation


def test_below_recommended_two_years_is_only_an_observation() -> None:
    item = hsts("max-age=15768000")
    assert item.status == "correcta"
    assert "63072000" in item.evidence
    assert "recomendada" in item.evidence


def test_preload_without_include_subdomains_is_incorrect() -> None:
    item = hsts("max-age=63072000; preload")
    assert item.status == "incorrecta"
    assert "preload" in item.title
    assert "includeSubDomains" in item.evidence


def test_preload_below_one_year_is_incorrect() -> None:
    item = hsts("max-age=15768000; includeSubDomains; preload")
    assert item.status == "incorrecta"
    assert "31536000" in item.evidence


def test_zero_max_age_still_disables_the_policy() -> None:
    item = hsts("max-age=0")
    assert item.status == "incorrecta"
    assert "max-age=0" in item.title


def test_hsts_references_cite_the_three_sources() -> None:
    for value in ("max-age=300", "max-age=63072000", "max-age=63072000; preload"):
        references = hsts(value).references
        assert "https://wiki.mozilla.org/Security/Guidelines/Web_Security" in references
        assert any("Practical_implementation_guides/TLS" in ref for ref in references)
        assert "https://hstspreload.org/" in references


def test_duration_is_reported_in_readable_units() -> None:
    assert "meses" in hsts("max-age=15768000").evidence
    assert "años" in hsts("max-age=63072000").evidence
    assert "días" in hsts("max-age=604800").evidence


# --------------------------------------------------------------------------
# 9. Campos repetidos (8.5.3): RFC 9110 §5.3
# --------------------------------------------------------------------------


def xfo(*values: str) -> swh.Finding:
    snap = swh.ResponseSnapshot(
        url="https://cliente.example/",
        status_code=200,
        reason="OK",
        headers={"content-type": ["text/html"], "x-frame-options": list(values)},
        display_names={},
    )
    return swh.analyze_x_frame_options(snap, set(), "web")[0]


def test_repeated_fields_are_listed_one_per_line() -> None:
    item = xfo("SAMEORIGIN", "SAMEORIGIN")
    # El defecto original: "SAMEORIGIN | SAMEORIGIN" se leía como un solo valor.
    assert "|" not in item.evidence.split("Recombinación")[0]
    assert "[campo 1] SAMEORIGIN" in item.evidence
    assert "[campo 2] SAMEORIGIN" in item.evidence
    assert "2 campos recibidos" in item.evidence


def test_identical_repetition_is_reported_as_such() -> None:
    item = xfo("SAMEORIGIN", "SAMEORIGIN")
    assert item.status == "incorrecta"
    assert "mismo valor" in item.title
    assert item.severity == "media"
    # Explica la causa más probable, no solo que está duplicada.
    assert "proxy inverso" in item.risk or "capa intermedia" in item.risk


def test_conflicting_repetition_is_more_severe() -> None:
    item = xfo("SAMEORIGIN", "DENY")
    assert item.status == "incorrecta"
    assert "contradictorios" in item.title
    assert item.severity == "alta"


@pytest.mark.parametrize(
    "pair",
    [("SAMEORIGIN", "sameorigin"), ("DENY", "deny"), ("SameOrigin", "SAMEORIGIN")],
)
def test_case_differences_are_not_treated_as_a_conflict(pair: tuple[str, str]) -> None:
    item = xfo(*pair)
    # Para el navegador son el mismo token; el hallazgo lo refleja.
    assert "mismo valor" in item.title
    assert "mayúsculas" in item.risk


def test_whitespace_differences_are_not_treated_as_a_conflict() -> None:
    item = xfo("SAMEORIGIN", "  SAMEORIGIN  ")
    assert "mismo valor" in item.title
    assert "espacios" in item.risk


def test_repeated_field_finding_cites_rfc9110_first() -> None:
    for values in [("SAMEORIGIN", "SAMEORIGIN"), ("SAMEORIGIN", "DENY")]:
        item = xfo(*values)
        assert item.references[0] == (
            "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3"
        )


def test_evidence_shows_what_a_recipient_would_combine() -> None:
    item = xfo("SAMEORIGIN", "DENY")
    # RFC 9110 §5.3 permite recombinar; el resultado no es válido para XFO.
    assert "SAMEORIGIN, DENY" in item.evidence


def test_repetition_applies_to_other_non_list_headers() -> None:
    from safewebheaders.rules_basic import analyze_hsts, analyze_x_content_type_options

    base = {"content-type": ["text/html"]}
    hsts_snap = swh.ResponseSnapshot(
        url="https://cliente.example/",
        status_code=200,
        reason="OK",
        headers={**base, "strict-transport-security": ["max-age=63072000"] * 2},
        display_names={},
    )
    item = analyze_hsts(hsts_snap, set())[0]
    assert "repetida" in item.title and "[campo 2]" in item.evidence

    xcto_snap = swh.ResponseSnapshot(
        url="https://cliente.example/",
        status_code=200,
        reason="OK",
        headers={**base, "x-content-type-options": ["nosniff", "nosniff"]},
        display_names={},
    )
    item = analyze_x_content_type_options(xcto_snap, set())[0]
    assert "repetida" in item.title and "[campo 2]" in item.evidence


def test_single_field_display_is_unchanged() -> None:
    from safewebheaders.utils import format_repeated_field

    assert format_repeated_field(["SAMEORIGIN"]) == "SAMEORIGIN"
    assert format_repeated_field([]) == ""


def test_multiple_csp_policies_are_not_flagged_as_repetition() -> None:
    # CSP sí admite varias políticas: todas se aplican simultáneamente.
    from safewebheaders.constants import NON_LIST_SECURITY_FIELDS

    assert "content-security-policy" not in NON_LIST_SECURITY_FIELDS


def test_repeated_fields_reach_both_surfaces() -> None:
    raw = "\n".join(
        [
            "HTTP/1.1 200 OK",
            "Content-Type: text/html; charset=utf-8",
            "X-Frame-Options: SAMEORIGIN",
            "X-Frame-Options: SAMEORIGIN",
        ]
    )
    report = swh.create_manual_headers_report(
        raw, "https://cliente.example/", essential_only=True
    )

    # CLI: un campo por línea, sin barra separadora.
    console = swh.render_console(
        report, color=False, reveal_sensitive=False, include_banner=False
    )
    assert "[campo 1] SAMEORIGIN" in console
    assert "[campo 2] SAMEORIGIN" in console
    assert "SAMEORIGIN | SAMEORIGIN" not in console

    # GUI: el mismo texto, que la hoja de estilos respeta con pre-wrap.
    data = swh.analyze_web_payload(
        {
            "mode": "headers",
            "evidence_url": "https://cliente.example/",
            "raw_headers": raw,
            "options": {},
        }
    )
    values = [
        item["current_value"]
        for category in data["results"][0]["categories"]
        for item in category["findings"]
        if item["header"] == "X-Frame-Options"
    ]
    assert values and values[0] == "[campo 1] SAMEORIGIN\n[campo 2] SAMEORIGIN"

    # La vista RAW conserva la respuesta tal cual llegó.
    block = data["results"][0]["raw_header_blocks"][0]["text"]
    assert block.count("X-Frame-Options: SAMEORIGIN") == 2
