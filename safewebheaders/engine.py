"""Engine de SafeWebHeaders."""

from __future__ import annotations

from collections.abc import Sequence

from .models import (
    Finding,
    ResponseSnapshot,
)
from .rules_basic import (
    analyze_content_type,
    analyze_hsts,
    analyze_referrer_policy,
    analyze_x_content_type_options,
)
from .rules_context import (
    analyze_contextual_response_headers,
    analyze_cookies,
    analyze_cors,
    analyze_cross_origin_headers,
    analyze_disclosure,
    analyze_integrity_policy,
    analyze_legacy_and_deprecated,
    analyze_permissions_policy,
    analyze_redirects,
)
from .rules_csp import (
    analyze_csp_headers,
    analyze_x_frame_options,
)
from .utils import (
    normalize_header_name,
)


#: Cabeceras del alcance esencial cuyas observaciones contextuales nunca deben
#: desaparecer del informe. Sin esta excepción, un objetivo HTTP que redirige a
#: HTTPS o un host evaluado por dirección IP producían un reporte vacío en el
#: que HSTS simplemente no figuraba y el analista no sabía por qué.
ESSENTIAL_CONTEXT_HEADERS = {
    "strict-transport-security",
    "x-frame-options",
    "location",
}


def _run_essential_analysis(
    snapshot: ResponseSnapshot,
    *,
    snapshots: Sequence[ResponseSnapshot],
    excluded: set[str],
    profile: str,
    follow_redirects: bool,
    reused_nonces: set[str] | None,
) -> list[Finding]:
    findings = analyze_hsts(snapshot, excluded)
    csp_findings = analyze_csp_headers(
        snapshot,
        excluded,
        profile,
        reused_nonces=reused_nonces,
    )
    findings.extend(
        item
        for item in csp_findings
        if normalize_header_name(item.header) != "content-security-policy-report-only"
        and not item.policy.lower().startswith("csp report-only")
        and item.status != "informativa"
    )
    findings.extend(analyze_x_frame_options(snapshot, excluded, profile))

    # Estas dos familias siguen siendo accionables con independencia de la
    # línea base elegida por el operador.
    findings.extend(analyze_legacy_and_deprecated(snapshot, excluded))
    findings.extend(analyze_disclosure(snapshot, excluded))
    # Una degradación HTTPS -> HTTP es un hallazgo de transporte, no un extra
    # del informe completo: debe verse también en el alcance esencial.
    findings.extend(analyze_redirects(snapshots, follow_redirects))
    visible = [
        item
        for item in findings
        if item.category in {"obsoletas", "divulgacion"}
        or item.status != "informativa"
        or normalize_header_name(item.header) in ESSENTIAL_CONTEXT_HEADERS
    ]
    return deduplicate_exclusions(visible)


def run_analysis(
    snapshot: ResponseSnapshot,
    *,
    snapshots: Sequence[ResponseSnapshot],
    excluded: set[str],
    profile: str,
    follow_redirects: bool,
    reused_nonces: set[str] | None = None,
    cors_probe: ResponseSnapshot | None = None,
    cors_probe_origin: str = "",
    csp_only: bool = False,
    sensitive_response: bool = False,
    evaluate_cookies: bool = False,
    essential_only: bool = True,
) -> list[Finding]:
    if csp_only:
        return analyze_csp_headers(
            snapshot,
            excluded,
            "web",
            reused_nonces=reused_nonces,
            csp_only=True,
        )

    findings: list[Finding] = []
    if essential_only:
        findings = _run_essential_analysis(
            snapshot,
            snapshots=snapshots,
            excluded=excluded,
            profile=profile,
            follow_redirects=follow_redirects,
            reused_nonces=reused_nonces,
        )
        # Las comprobaciones solicitadas expresamente conservan su utilidad aun
        # cuando la línea base predeterminada sea esencial. No se incorporan al
        # informe por mera presencia: solo aparecen cuando el operador activó
        # su opción específica.
        if evaluate_cookies:
            findings.extend(analyze_cookies(snapshot, excluded))
        if cors_probe is not None:
            findings.extend(
                analyze_cors(snapshot, excluded, cors_probe, cors_probe_origin)
            )
        if sensitive_response:
            findings.extend(
                item
                for item in analyze_contextual_response_headers(
                    snapshot,
                    excluded,
                    sensitive_response=True,
                )
                if normalize_header_name(item.header) == "cache-control"
            )
        return deduplicate_exclusions(findings)

    findings.extend(analyze_hsts(snapshot, excluded))
    findings.extend(analyze_x_content_type_options(snapshot, excluded))
    findings.extend(analyze_content_type(snapshot, excluded))
    findings.extend(analyze_referrer_policy(snapshot, excluded, profile))
    findings.extend(
        analyze_csp_headers(
            snapshot,
            excluded,
            profile,
            reused_nonces=reused_nonces,
        )
    )
    findings.extend(analyze_x_frame_options(snapshot, excluded, profile))

    # Permissions-Policy es contextual: su ausencia no genera un hallazgo y, si
    # el servidor la envía, se comprueban su sintaxis y aperturas globales.
    findings.extend(analyze_permissions_policy(snapshot, excluded, profile))
    if any(
        snapshot.has(name)
        for name in (
            "cross-origin-opener-policy",
            "cross-origin-embedder-policy",
            "cross-origin-resource-policy",
        )
    ):
        findings.extend(analyze_cross_origin_headers(snapshot, excluded, profile))
    if snapshot.has("integrity-policy") or snapshot.has("integrity-policy-report-only"):
        findings.extend(analyze_integrity_policy(snapshot, excluded, profile))

    contextual_names = {
        name
        for name in (
            "content-disposition",
            "x-permitted-cross-domain-policies",
            "clear-site-data",
            "x-dns-prefetch-control",
        )
        if snapshot.has(name)
    }
    if sensitive_response or snapshot.has("cache-control"):
        contextual_names.add("cache-control")
    if contextual_names:
        contextual = analyze_contextual_response_headers(
            snapshot,
            excluded,
            sensitive_response=sensitive_response,
        )
        findings.extend(
            item
            for item in contextual
            if normalize_header_name(item.header) in contextual_names
        )

    findings.extend(analyze_legacy_and_deprecated(snapshot, excluded))
    findings.extend(analyze_disclosure(snapshot, excluded))
    if evaluate_cookies:
        findings.extend(analyze_cookies(snapshot, excluded))
    if cors_probe is not None or snapshot.has("access-control-allow-origin"):
        findings.extend(analyze_cors(snapshot, excluded, cors_probe, cors_probe_origin))
    findings.extend(analyze_redirects(snapshots, follow_redirects))
    return deduplicate_exclusions(findings)


def deduplicate_exclusions(findings: Sequence[Finding]) -> list[Finding]:
    seen_excluded: set[str] = set()
    output: list[Finding] = []
    for item in findings:
        if item.status == "excluida":
            key = normalize_header_name(item.header)
            if key in seen_excluded:
                continue
            seen_excluded.add(key)
        output.append(item)
    return output


def summarize_findings(findings: Sequence[Finding]) -> dict[str, int]:
    """Resumen interno conservado para compatibilidad con integraciones 4.x."""
    summary = {
        "correctas": 0,
        "ausentes": 0,
        "incorrectas": 0,
        "advertencias": 0,
        "informativas": 0,
        "excluidas": 0,
    }
    mapping = {
        "correcta": "correctas",
        "ausente": "ausentes",
        "incorrecta": "incorrectas",
        "advertencia": "advertencias",
        "informativa": "informativas",
        "excluida": "excluidas",
    }
    for item in findings:
        summary[mapping[item.status]] += 1
    return summary
