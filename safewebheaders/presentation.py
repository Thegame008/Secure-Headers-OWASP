"""Presentation de SafeWebHeaders."""

from __future__ import annotations

import html
import json
import re
import os
import time
import textwrap
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from typing import Any, ClassVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .constants import (
    CATEGORY_COLOR,
    CATEGORY_LABELS,
    DISPLAY_CATEGORY_COLOR,
    DISPLAY_CATEGORY_LABELS,
    DISPLAY_CATEGORY_SYMBOL,
    MDN_CSP,
    OWASP_CSP,
    STATUS_SYMBOL,
)
from .models import (
    BatchReport,
    DisplayEntry,
    Finding,
    RedirectHop,
    ScanReport,
)
from .profiles import (
    finding,
)
from .rules_csp import (
    CSP_KNOWN_DIRECTIVES,
    HASH_RE,
    NONCE_RE,
    decode_base64_value,
    frame_ancestors_is_restrictive,
    parse_csp_header_values,
    redact_csp_crypto_sources,
)
from .utils import (
    canonical_header,
    display_timestamp,
    normalize_header_name,
)


def empty_display_summary() -> dict[str, int]:
    return {
        "correctas": 0,
        "ausentes": 0,
        "incorrectas": 0,
        "cookies": 0,
        "obsoletas": 0,
        "divulgaciones": 0,
        "informativas": 0,
        "excluidas": 0,
    }


def display_category_for_finding(report: ScanReport, item: Finding) -> str:
    """Traduce una categoría técnica a un bloque visible y estable."""
    if item.category == "cookies":
        return "cookies"
    if item.category == "obsoletas":
        return "obsoletas"
    if item.category == "divulgacion":
        return "divulgacion"
    if item.status == "correcta":
        return "correctas"
    if item.status == "ausente":
        return "ausentes"
    if item.status in {"incorrecta", "advertencia"}:
        return "incorrectas"
    return "informativas"


def clone_display_finding(
    source: Finding,
    *,
    category: str,
    status: str,
    title: str | None = None,
) -> Finding:
    return Finding(
        category=category,
        status=status,
        severity=source.severity,
        header=source.header,
        title=title or source.title,
        evidence=source.evidence,
        risk=source.risk,
        recommendation=source.recommendation,
        references=list(source.references),
        policy=source.policy,
    )


def _has_actionable_csp_details(details: Sequence[Finding]) -> bool:
    return any(
        item.status in {"ausente", "incorrecta", "advertencia"} for item in details
    )


def _csp_policy_payload(
    values: Sequence[str],
    internal_findings: Sequence[Finding],
    *,
    label: str,
) -> tuple[list[str], list[list[tuple[str, str]]]]:
    policies = [redact_csp_crypto_sources(value) for value in values]
    policy_spans: list[list[tuple[str, str]]] = []
    for index, value in enumerate(values, start=1):
        finding_label = f"{label} #{index}".lower()
        policy_findings = [
            item for item in internal_findings if item.policy.lower() == finding_label
        ]
        policy_spans.append(csp_policy_spans(value, policy_findings))
    return policies, policy_spans


def _csp_policy_context(count: int, *, report_only: bool) -> str:
    if count <= 1:
        return ""
    if report_only:
        return (
            f"Se detectaron {count} políticas Content-Security-Policy-Report-Only; "
            "todas observan la respuesta, pero ninguna bloquea recursos por sí sola."
        )
    return (
        f"Se detectaron {count} políticas Content-Security-Policy aplicadas "
        "simultáneamente; el navegador exige cumplirlas todas y combina sus "
        "restricciones como una intersección efectiva."
    )


def _enforced_csp_display_entry(
    report: ScanReport,
    main: Finding | None,
    values: Sequence[str],
    internal_findings: Sequence[Finding],
    details: list[Finding],
) -> tuple[str, DisplayEntry] | None:
    if main is None:
        return None
    needs_correction = bool(values) and (
        _has_actionable_csp_details(details)
        or main.status in {"incorrecta", "advertencia"}
    )
    if needs_correction:
        bucket = "incorrectas"
        displayed = clone_display_finding(
            main,
            category=bucket,
            status="incorrecta",
            title="La CSP está aplicada, pero contiene configuraciones que requieren corrección",
        )
    else:
        bucket = display_category_for_finding(report, main)
        displayed = clone_display_finding(main, category=bucket, status=main.status)

    policies, policy_spans = _csp_policy_payload(
        values,
        internal_findings,
        label="CSP aplicada",
    )
    return (
        bucket,
        DisplayEntry(
            displayed,
            "\n".join(policies) if policies else "No encontrada",
            details,
            policies=policies,
            policy_spans=policy_spans,
            policy_context=_csp_policy_context(len(policies), report_only=False),
        ),
    )


def _report_only_main(internal_findings: Sequence[Finding]) -> Finding:
    observed = next(
        (
            item
            for item in internal_findings
            if normalize_header_name(item.header)
            == "content-security-policy-report-only"
            and not item.policy
        ),
        None,
    )
    if observed is not None:
        return observed
    return finding(
        "informativas",
        "informativa",
        "informativa",
        "Content-Security-Policy-Report-Only",
        "Se detectó una política CSP de monitoreo",
        risk="La política registra violaciones, pero no bloquea recursos por sí sola.",
        references=[OWASP_CSP, MDN_CSP],
    )


def _report_only_csp_display_entry(
    values: Sequence[str],
    internal_findings: Sequence[Finding],
    details: list[Finding],
) -> tuple[str, DisplayEntry] | None:
    if not values:
        return None
    main = _report_only_main(internal_findings)
    details = [item for item in details if item is not main]
    actionable = _has_actionable_csp_details(details)
    bucket = "incorrectas" if actionable else "informativas"
    displayed = clone_display_finding(
        main,
        category=bucket,
        status="incorrecta" if actionable else "informativa",
        title=(
            "La CSP Report-Only contiene configuraciones que requieren corrección"
            if actionable
            else main.title
        ),
    )
    policies, policy_spans = _csp_policy_payload(
        values,
        internal_findings,
        label="CSP Report-Only",
    )
    return (
        bucket,
        DisplayEntry(
            displayed,
            "\n".join(policies),
            details,
            policies=policies,
            policy_spans=policy_spans,
            policy_context=_csp_policy_context(len(policies), report_only=True),
        ),
    )


def _csp_display_entries(report: ScanReport) -> list[tuple[str, DisplayEntry]]:
    """Consolida CSP para mostrar la cabecera una vez y anidar sus problemas."""

    enforced_values = parse_csp_header_values(
        report.response_headers.get("content-security-policy", [])
    )
    report_only_values = parse_csp_header_values(
        report.response_headers.get("content-security-policy-report-only", [])
    )
    main = next(
        (
            item
            for item in report.findings
            if normalize_header_name(item.header) == "content-security-policy"
            and item.category != "csp"
            and not item.policy
            and item.status != "excluida"
        ),
        None,
    )
    if not enforced_values and not report_only_values and main is None:
        return []

    internal = [item for item in report.findings if item.category == "csp"]
    visible_details = csp_console_findings(internal)
    enforced_details = [
        item
        for item in visible_details
        if not item.policy.lower().startswith("csp report-only")
        and normalize_header_name(item.header) != "content-security-policy-report-only"
    ]
    report_only_details = [
        item for item in visible_details if item not in enforced_details
    ]
    entries = [
        _enforced_csp_display_entry(
            report,
            main,
            enforced_values,
            internal,
            enforced_details,
        ),
        _report_only_csp_display_entry(
            report_only_values,
            internal,
            report_only_details,
        ),
    ]
    return [entry for entry in entries if entry is not None]


def build_display_groups(report: ScanReport) -> dict[str, list[DisplayEntry]]:
    groups: dict[str, list[DisplayEntry]] = {key: [] for key in DISPLAY_CATEGORY_LABELS}
    csp_main_ids = {
        id(item)
        for item in report.findings
        if normalize_header_name(item.header) == "content-security-policy"
        and item.category != "csp"
        and not item.policy
    }
    for item in report.findings:
        if (
            item.status == "excluida"
            or item.category == "csp"
            or id(item) in csp_main_ids
        ):
            continue
        bucket = display_category_for_finding(report, item)
        groups[bucket].append(DisplayEntry(item, finding_value(report, item)))
    for bucket, entry in _csp_display_entries(report):
        groups[bucket].append(entry)
    return groups


def summarize_report(report: ScanReport) -> dict[str, int]:
    """Cuenta controles visibles; los subproblemas CSP no inflan el resumen."""
    summary = empty_display_summary()
    groups = build_display_groups(report)
    summary_key = {"divulgacion": "divulgaciones"}
    for category, entries in groups.items():
        key = summary_key.get(category, category)
        if category == "cookies":
            summary[key] = len(entries)
        else:
            unique_controls = {
                normalize_header_name(entry.finding.header) for entry in entries
            }
            summary[key] = len(unique_controls)
    summary["excluidas"] = len(report.excluded_headers)
    return summary


def serialize_display_entry(
    entry: DisplayEntry, reveal_sensitive: bool = False
) -> dict[str, Any]:
    item = entry.finding
    symbol = (
        "+"
        if item.category == "cookies" and item.status == "correcta"
        else "!"
        if item.category == "cookies"
        else DISPLAY_CATEGORY_SYMBOL.get(item.category, finding_symbol(item))
    )
    data = {
        "symbol": symbol,
        "header": item.header,
        "current_value": entry.current_value,
        "criterion": finding_criterion(item),
        "observation": item.title,
        "evidence": finding_evidence(item, reveal_sensitive),
        "risk": item.risk,
        "recommendation": item.recommendation,
        "references": list(dict.fromkeys(item.references)),
        "details": [
            {**detail.to_dict(), "purpose": csp_protection_purpose(detail)}
            for detail in entry.details
        ],
    }
    if entry.policies:
        data["policies"] = [
            {"index": index, "value": value}
            for index, value in enumerate(entry.policies, start=1)
        ]
        data["policy_spans"] = [
            {
                "index": index,
                "spans": [
                    {"text": text, "tone": tone}
                    for text, tone in csp_policy_spans(value, entry.details)
                ],
            }
            for index, value in enumerate(entry.policies, start=1)
        ]
        data["policy_context"] = entry.policy_context
    return data


def serialize_report_categories(
    report: ScanReport, reveal_sensitive: bool = False
) -> list[dict[str, Any]]:
    groups = build_display_groups(report)
    return [
        {
            "key": category,
            "label": label,
            "symbol": DISPLAY_CATEGORY_SYMBOL[category],
            "findings": [
                serialize_display_entry(entry, reveal_sensitive)
                for entry in groups[category]
            ],
        }
        for category, label in DISPLAY_CATEGORY_LABELS.items()
        if groups[category]
    ]


def redact_set_cookie(raw: str) -> str:
    if ";" in raw:
        first, rest = raw.split(";", 1)
        name = first.split("=", 1)[0]
        return f"{name}=<redactado>;{rest}"
    name = raw.split("=", 1)[0]
    return f"{name}=<redactado>"


SENSITIVE_RESPONSE_HEADERS = {
    "authentication-info",
    "authorization",
    "proxy-authentication-info",
    "proxy-authorization",
    "x-api-key",
    "x-client-secret",
    "x-jwt",
    "x-secret",
    "x-session-id",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-debug-token",
    "x-debug-token-link",
}


NEVER_REDACTED_RESPONSE_HEADERS = {
    # Estas cabeceras terminan en sufijos que el heurístico considera secretos,
    # pero su valor es la evidencia principal del análisis CORS y ocultarlo
    # impide revisar el hallazgo que la propia herramienta reporta.
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "access-control-request-headers",
}


def _is_sensitive_response_header(name: str) -> bool:
    if name in NEVER_REDACTED_RESPONSE_HEADERS:
        return False
    return name in SENSITIVE_RESPONSE_HEADERS or name.endswith(
        (
            "-api-key",
            "-auth-token",
            "-access-token",
            "-client-secret",
            "-credential",
            "-credentials",
            "-jwt",
            "-password",
            "-secret",
            "-session-id",
            "-token",
        )
    )


SENSITIVE_QUERY_NAMES = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "code",
    "id_token",
    "jwt",
    "key",
    "password",
    "secret",
    "session",
    "sig",
    "signature",
    "token",
    "x-amz-credential",
    "x-amz-security-token",
    "x-amz-signature",
}
SENSITIVE_QUERY_NAME_RE = re.compile(
    r"(?:^|[_\-.])(?:access[-_]?token|api[-_]?key|auth|authorization|"
    r"credential|id[-_]?token|jwt|nonce|pass(?:word|wd)?|secret|session|"
    r"sig(?:nature)?|token)(?:$|[_\-.])",
    re.IGNORECASE,
)


def redact_url_secrets(value: str, reveal_sensitive: bool = False) -> str:
    if reveal_sensitive or not value:
        return value
    try:
        parts = urlsplit(value)
        query = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        return value
    if not query:
        return value
    redacted = [
        (
            name,
            "<redactado>"
            if name.lower() in SENSITIVE_QUERY_NAMES
            or SENSITIVE_QUERY_NAME_RE.search(name)
            else item,
        )
        for name, item in query
    ]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(redacted), parts.fragment)
    )


URL_IN_TEXT_RE = re.compile(r"https?://[^\s|]+", re.IGNORECASE)
QUERY_PARAMETER_IN_TEXT_RE = re.compile(
    r"(?P<prefix>[?&](?P<name>[A-Za-z0-9_.-]{1,100})=)"
    r"(?P<value>[^&\s'\"<>)]*)"
)


def redact_text_urls(value: str, reveal_sensitive: bool = False) -> str:
    if reveal_sensitive or not value:
        return value
    redacted_urls = URL_IN_TEXT_RE.sub(
        lambda match: redact_url_secrets(match.group(0)), value
    )

    def redact_query_parameter(match: re.Match[str]) -> str:
        name = match.group("name")
        if name.lower() in SENSITIVE_QUERY_NAMES or SENSITIVE_QUERY_NAME_RE.search(
            name
        ):
            return f"{match.group('prefix')}%3Credactado%3E"
        return match.group(0)

    # Algunas bibliotecas muestran únicamente la ruta relativa dentro de sus
    # excepciones (por ejemplo, ``/?token=...``), después de haber omitido el
    # origen. Esa segunda pasada evita que el contenedor de error vuelva a
    # exponer el secreto que ya se ocultó en la URL solicitada.
    return QUERY_PARAMETER_IN_TEXT_RE.sub(redact_query_parameter, redacted_urls)


def finding_evidence(item: Finding, reveal_sensitive: bool = False) -> str:
    if reveal_sensitive or not item.evidence:
        return item.evidence
    key = normalize_header_name(item.header)
    if _is_sensitive_response_header(key):
        return "<redactado>"
    if key == "set-cookie":
        return (
            item.evidence
            if item.category == "cookies"
            else redact_set_cookie(item.evidence)
        )
    if key.startswith("content-security-policy"):
        return redact_csp_crypto_sources(item.evidence)
    if key in {"location", "content-location"}:
        return redact_text_urls(item.evidence)
    return item.evidence


def sanitize_terminal_text(value: Any) -> str:
    """Hace visibles los controles sin permitir ANSI/OSC desde datos remotos."""

    output: list[str] = []
    for char in str(value):
        code = ord(char)
        if code < 32 or 0x7F <= code <= 0x9F:
            output.append(f"\\x{code:02x}")
        else:
            output.append(char)
    return "".join(output)


def serializable_headers(
    headers: Mapping[str, Sequence[str]],
    display_names: Mapping[str, str],
    reveal_sensitive: bool,
) -> dict[str, list[str]]:
    output: dict[str, list[str]] = OrderedDict()
    for key in sorted(headers):
        display = display_names.get(key, canonical_header(key))
        values = list(headers[key])
        if not reveal_sensitive:
            if key == "set-cookie":
                values = [redact_set_cookie(value) for value in values]
            elif _is_sensitive_response_header(key):
                values = ["<redactado>" for _value in values]
            elif key.startswith("content-security-policy"):
                from .rules_csp import redact_csp_crypto_sources

                values = [redact_csp_crypto_sources(value) for value in values]
            elif key in {"location", "content-location"}:
                values = [redact_url_secrets(value) for value in values]
        output[display] = values
    return output


def response_header_blocks(
    report: ScanReport, reveal_sensitive: bool
) -> list[tuple[str, str]]:
    """Reconstruye bloques de respuesta legibles al estilo ``curl -i``.

    Requests no expone los bytes originales de la línea de estado ni conserva
    necesariamente el orden físico de campos duplicados. Por eso la salida se
    presenta explícitamente como una vista reconstruida, conservando valores
    duplicados y el casing observado cuando está disponible.
    """

    hops = list(report.redirects)
    if not hops:
        hops = [
            RedirectHop(
                url=report.final_url,
                status_code=report.status_code,
                reason=report.reason,
                location="",
                elapsed_ms=report.elapsed_ms,
                headers=report.response_headers,
                display_names=report.display_names,
            )
        ]

    blocks: list[tuple[str, str]] = []
    for index, hop in enumerate(hops):
        headers = hop.headers
        names = hop.display_names
        if not headers and index == len(hops) - 1:
            headers = report.response_headers
            names = report.display_names
        status_line = (
            f"{hop.http_version or 'HTTP/?'} {hop.status_code or 'N/A'} {hop.reason}"
        ).rstrip()
        lines = [status_line]
        for name, values in serializable_headers(
            headers, names, reveal_sensitive
        ).items():
            lines.extend(f"{name}: {value}" for value in values)
        blocks.append(
            (
                redact_url_secrets(hop.url, reveal_sensitive),
                "\n".join(lines),
            )
        )
    return blocks


class Palette:
    CODES: ClassVar[dict[str, str]] = {
        "green": "\033[92m",
        "yellow": "\033[93m",
        "orange": "\033[38;5;208m",
        "red": "\033[91m",
        "cyan": "\033[96m",
        "magenta": "\033[95m",
        "blue": "\033[94m",
        "white": "\033[97m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "reset": "\033[0m",
    }

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, text: str, color: str, *, bold: bool = False) -> str:
        text = sanitize_terminal_text(text)
        if not self.enabled:
            return text
        prefix = self.CODES.get(color, "")
        if bold:
            prefix += self.CODES["bold"]
        return f"{prefix}{text}{self.CODES['reset']}"

    def bold(self, text: str) -> str:
        text = sanitize_terminal_text(text)
        if not self.enabled:
            return text
        return f"{self.CODES['bold']}{text}{self.CODES['reset']}"

    def url_badge(self, value: str) -> str:
        # El fondo cubre exactamente el texto: el relleno lateral hacía que el
        # resaltado pareciera más largo que la propia URL.
        value = sanitize_terminal_text(value)
        if not self.enabled:
            return value
        return f"\033[48;5;24m\033[97m\033[1m{value}{self.CODES['reset']}"

    def value_badge(self, value: str) -> str:
        """Resalta el valor de una cabecera sin desbordar la línea.

        Se aplica por fragmento ya recortado, de modo que el fondo termina
        donde termina el texto y nunca se extiende hasta el borde del terminal.
        """

        value = sanitize_terminal_text(value)
        if not self.enabled or not value.strip():
            return value
        return f"\033[48;5;236m\033[97m{value}{self.CODES['reset']}"

    def heading(self, text: str) -> str:
        text = sanitize_terminal_text(text)
        if not self.enabled:
            return text
        return f"{self.CODES['cyan']}{self.CODES['bold']}{text}{self.CODES['reset']}"


def report_ips_text(report: ScanReport) -> str:
    return ", ".join(report.resolved_ips) if report.resolved_ips else "No disponible"


def append_section_context(
    lines: list[str], palette: Palette, report: ScanReport, color: str
) -> None:
    """Añade fecha e IP inmediatamente antes de cada bloque del reporte."""

    lines.append(
        f"{palette.paint('Date:', color, bold=True)} "
        f"{display_timestamp(report.timestamp)}"
    )
    lines.append(
        f"{palette.paint('IP(s):', color, bold=True)} {report_ips_text(report)}"
    )


def status_color(status: str) -> str:
    return {
        "correcta": "green",
        "ausente": "red",
        "incorrecta": "orange",
        "advertencia": "orange",
        "informativa": "cyan",
        "excluida": "magenta",
    }[status]


def wrap_text(value: str, width: int = 104, indent: str = "      ") -> list[str]:
    if not value:
        return []
    lines: list[str] = []
    for paragraph in value.splitlines() or [value]:
        lines.extend(
            textwrap.wrap(
                paragraph,
                width=max(20, width - len(indent)),
                initial_indent=indent,
                subsequent_indent=indent,
                replace_whitespace=False,
            )
            or [indent]
        )
    return lines


def finding_symbol(item: Finding) -> str:
    """Devuelve el símbolo visual sin confundir categoría con criticidad."""
    if item.category == "obsoletas":
        return "~"
    if item.category == "divulgacion":
        return "*"
    return STATUS_SYMBOL[item.status]


def finding_color(item: Finding) -> str:
    if item.category in {"obsoletas", "divulgacion"}:
        return CATEGORY_COLOR[item.category]
    return status_color(item.status)


def finding_value(report: ScanReport, item: Finding) -> str:
    """Obtiene el valor recibido sin inventar una configuración recomendada."""
    if item.category == "cookies":
        # Cada hallazgo representa una cookie concreta. Mostrar todos los
        # Set-Cookie en cada tarjeta duplicaría evidencia y podría confundir
        # atributos pertenecientes a cookies distintas.
        return item.evidence or "Valor ocultado"
    key = normalize_header_name(item.header)
    source_headers = (
        report.cors_probe_headers
        if item.category == "cors" and key in report.cors_probe_headers
        else report.response_headers
    )
    if key in source_headers:
        values = source_headers[key]
        if key == "set-cookie":
            return " | ".join(redact_set_cookie(value) for value in values)
        if _is_sensitive_response_header(key):
            return "<redactado>"
        if key.startswith("content-security-policy"):
            from .rules_csp import redact_csp_crypto_sources

            return " | ".join(redact_csp_crypto_sources(value) for value in values)
        if key in {"location", "content-location"}:
            return " | ".join(redact_url_secrets(value) for value in values)
        return " | ".join(values)
    if item.status == "ausente":
        return "No encontrada"
    return item.evidence or "Sin valor"


def finding_criterion(item: Finding) -> str:
    """Explica el nivel normativo sin convertir recomendaciones en mandatos."""

    key = normalize_header_name(item.header)
    if key == "strict-transport-security":
        return (
            "OWASP recomienda HSTS para hosts servidos por HTTPS. Los navegadores "
            "ignoran la cabecera recibida por HTTP y su uso sobre direcciones IP no "
            "equivale al caso normal de un nombre de dominio."
        )
    if key == "x-content-type-options":
        return (
            "OWASP recomienda X-Content-Type-Options: nosniff junto con un "
            "Content-Type correcto. La guía práctica de MDN no clasifica la "
            "verificación MIME como obligatoria; SafeWebHeaders solo la valida si existe."
        )
    if key == "content-type":
        return (
            "Content-Type describe la representación y debe ser correcto cuando se envía, "
            "pero SafeWebHeaders no lo trata como una cabecera de seguridad universalmente "
            "obligatoria. Una omisión no genera por sí sola un hallazgo."
        )
    if key == "referrer-policy":
        return (
            "OWASP recomienda enviarla en todas las respuestas y la guía práctica de "
            "MDN la marca como requerida. No es obligatoria para que HTTP funcione y "
            "los navegadores modernos suelen aplicar strict-origin-when-cross-origin "
            "cuando falta."
        )
    if key == "x-frame-options":
        return (
            "El estándar HTML vigente reconoce DENY y SAMEORIGIN, e IANA registra la "
            "cabecera con estado permanent. CSP frame-ancestors la reemplaza en navegadores "
            "compatibles; ALLOW-FROM sí es una directiva obsoleta."
        )
    if key == "content-security-policy":
        return (
            "OWASP recomienda CSP para documentos capaces de cargar o ejecutar contenido. "
            "Puede carecer de utilidad en una respuesta REST que no será renderizada."
        )
    if key == "permissions-policy":
        return (
            "OWASP recomienda restringir las funciones que el sitio no necesita. "
            "SafeWebHeaders no exige la presencia de la cabecera: si existe, valida su "
            "sintaxis y aperturas globales; la política exacta depende de la aplicación. "
            "MDN la clasifica como tecnología experimental y de disponibilidad limitada."
        )
    if key in {
        "cross-origin-opener-policy",
        "cross-origin-embedder-policy",
        "cross-origin-resource-policy",
    }:
        return (
            "OWASP documenta esta cabecera de aislamiento, pero su adopción requiere probar "
            "compatibilidad con recursos, ventanas e integraciones cross-origin."
        )
    if key == "access-control-allow-origin":
        return (
            "Su ausencia conserva la Same-Origin Policy. Si CORS se habilita, la seguridad "
            "depende del Origin autorizado, las credenciales y la sensibilidad de la respuesta."
        )
    if key == "cache-control":
        return (
            "OWASP recomienda no-store para datos sensibles. La política correcta de una "
            "respuesta pública puede permitir caché; la ausencia solo es un fallo de línea "
            "base cuando el contexto exige impedir almacenamiento."
        )
    if key == "clear-site-data":
        return (
            "OWASP Secure Headers la incluye como control de limpieza. No corresponde a "
            "todas las respuestas: suele aplicarse a cierres de sesión o flujos equivalentes."
        )
    if key == "x-dns-prefetch-control":
        return (
            "OWASP documenta el valor off para limitar DNS prefetch. Es una decisión de "
            "privacidad y rendimiento, no una defensa crítica universal."
        )
    if key == "x-permitted-cross-domain-policies":
        return (
            "OWASP Secure Headers publica el valor none para clientes heredados. Su ausencia "
            "no habilita CORS ni demuestra una lectura cross-origin en navegadores modernos."
        )
    return ""


def append_field(
    lines: list[str],
    palette: Palette,
    label: str,
    value: str,
    *,
    width: int = 118,
    highlight: bool = False,
) -> None:
    label = sanitize_terminal_text(label)
    value = sanitize_terminal_text(value)
    if not value:
        return
    plain_label = f"{label}:"
    first_prefix = "|  "
    continuation = "|  " + " " * (len(plain_label) + 1)
    paragraphs = value.splitlines() or [value]
    first_line = True
    for paragraph in paragraphs:
        available = max(24, width - len(first_prefix) - len(plain_label) - 1)
        chunks = textwrap.wrap(
            paragraph,
            width=available,
            replace_whitespace=False,
            break_long_words=False,
            break_on_hyphens=False,
        ) or [""]
        for chunk in chunks:
            # El realce se aplica al fragmento ya recortado para que el fondo
            # no se extienda más allá del texto en ninguna línea envuelta.
            painted = palette.value_badge(chunk.rstrip()) if highlight else chunk
            if first_line:
                body = f"{first_prefix}{palette.bold(plain_label)} {painted}"
                lines.append(body if highlight else body.rstrip())
                first_line = False
            else:
                body = f"{continuation}{painted}"
                lines.append(body if highlight else body.rstrip())


def append_references(
    lines: list[str], palette: Palette, references: Sequence[str]
) -> None:
    unique = list(dict.fromkeys(reference for reference in references if reference))
    if not unique:
        return
    lines.append(f"|  {palette.bold('Referencias:')}")
    lines.extend(f"|  - {sanitize_terminal_text(reference)}" for reference in unique)


CSP_CONSOLE_RISK_RE = re.compile(
    r"'unsafe-(?:inline|eval|hashes)'|"
    r"(?<![A-Za-z0-9_-])unsafe-(?:inline|eval|hashes)(?![A-Za-z0-9_-])|"
    r"(?<!\S)\*(?=\s|;|$)|"
    r"(?<![A-Za-z0-9+.-])http:(?=//|\s|$)",
    re.IGNORECASE,
)

CSP_ACTIONABLE_STATUSES = {"incorrecta", "advertencia"}


def _merge_csp_spans(spans: Sequence[tuple[str, str]]) -> list[tuple[str, str]]:
    merged: list[tuple[str, str]] = []
    for text, tone in spans:
        if not text:
            continue
        if merged and merged[-1][1] == tone:
            previous, _ = merged[-1]
            merged[-1] = (previous + text, tone)
        else:
            merged.append((text, tone))
    return merged


CSP_DIRECTIVE_TOKEN_RE = re.compile(r"[a-z][a-z0-9-]*")


def _csp_directive_tokens(text: str) -> set[str]:
    """Extrae nombres de directiva completos, no coincidencias parciales.

    Una comparación por substring hacía que un hallazgo exclusivo de
    ``script-src-elem`` marcase también ``script-src``, o que el texto
    ``Referrer-Policy`` activase la directiva CSP ``referrer``.
    """

    return {
        token
        for token in CSP_DIRECTIVE_TOKEN_RE.findall(text.lower())
        if token in CSP_KNOWN_DIRECTIVES
    }


def _csp_finding_directives(findings: Sequence[Finding]) -> set[str]:
    directives: set[str] = set()
    for item in findings:
        title_matches = _csp_directive_tokens(item.title)
        if title_matches:
            directives.update(title_matches)
            continue
        directives.update(_csp_directive_tokens(item.evidence))
    return directives


def _csp_crypto_tone(token: str, bad_findings: Sequence[Finding]) -> str:
    nonce_match = NONCE_RE.fullmatch(token)
    if nonce_match:
        decoded = decode_base64_value(nonce_match.group(1))
        nonce_problem = any("nonce" in item.title.lower() for item in bad_findings)
        return (
            "bad" if decoded is None or len(decoded) < 16 or nonce_problem else "good"
        )

    hash_match = HASH_RE.fullmatch(token)
    if hash_match:
        algorithm, raw_hash = hash_match.group(1).lower(), hash_match.group(2)
        decoded = decode_base64_value(raw_hash)
        expected = {"sha256": 32, "sha384": 48, "sha512": 64}[algorithm]
        hash_problem = any("hash" in item.title.lower() for item in bad_findings)
        return (
            "bad"
            if decoded is None or len(decoded) != expected or hash_problem
            else "good"
        )

    if re.match(r"^['\"]?(?:nonce|sha(?:256|384|512))-", token, re.IGNORECASE):
        return "bad"
    return ""


def _csp_directive_is_restrictive(directive: str, values: Sequence[str]) -> bool:
    normalized = {value.lower() for value in values}
    if directive == "object-src":
        return not values or normalized == {"'none'"}
    if directive == "base-uri":
        return normalized.issubset({"'none'", "'self'"})
    if directive == "frame-ancestors":
        return frame_ancestors_is_restrictive(values)
    if directive == "form-action":
        return "*" not in normalized
    if directive == "default-src":
        return bool(values) and normalized.issubset({"'none'", "'self'"})
    if directive in {"script-src", "script-src-elem", "script-src-attr"}:
        return normalized == {"'none'"}
    return False


def _csp_directive_tone(
    directive: str,
    *,
    bad_directives: set[str],
    good_directives: set[str],
    restrictive: bool,
) -> str:
    if directive in bad_directives:
        return "bad"
    if directive in good_directives or restrictive:
        return "good"
    return ""


def _csp_value_tone(
    token: str,
    *,
    bad_findings: Sequence[Finding],
    bad_tokens: set[str],
    good_context: str,
    valid_crypto: bool,
    restrictive: bool,
) -> str:
    crypto_tone = _csp_crypto_tone(token, bad_findings)
    if crypto_tone:
        return crypto_tone

    normalized = token.lower()
    unquoted = normalized.strip("'\"")
    if normalized == "'strict-dynamic'":
        return "good" if valid_crypto else ""
    if (
        normalized in bad_tokens
        or unquoted in bad_tokens
        or ("http:" in bad_tokens and normalized.startswith("http:"))
    ):
        return "bad"
    mentioned_good = normalized in good_context or (
        len(unquoted) > 1 and unquoted in good_context
    )
    return "good" if mentioned_good or restrictive else ""


def _csp_segment_spans(
    segment: str,
    *,
    bad_findings: Sequence[Finding],
    bad_tokens: set[str],
    bad_directives: set[str],
    good_directives: set[str],
    good_context: str,
) -> list[tuple[str, str]]:
    if not segment:
        return []
    if segment == ";":
        return [(segment, "")]

    pieces = re.split(r"(\s+)", segment)
    significant = [piece for piece in pieces if piece and not piece.isspace()]
    directive = significant[0].lower() if significant else ""
    values = significant[1:]
    valid_crypto = any(_csp_crypto_tone(token, []) == "good" for token in values)
    restrictive = _csp_directive_is_restrictive(directive, values)
    directive_tone = _csp_directive_tone(
        directive,
        bad_directives=bad_directives,
        good_directives=good_directives,
        restrictive=restrictive,
    )

    spans: list[tuple[str, str]] = []
    seen_directive = False
    for piece in pieces:
        if not piece or piece.isspace():
            spans.append((piece, ""))
            continue
        tone = (
            directive_tone
            if not seen_directive
            else _csp_value_tone(
                piece,
                bad_findings=bad_findings,
                bad_tokens=bad_tokens,
                good_context=good_context,
                valid_crypto=valid_crypto,
                restrictive=restrictive,
            )
        )
        seen_directive = True
        spans.append((redact_csp_crypto_sources(piece), tone))
    return spans


def csp_policy_spans(
    raw_policy: str, findings: Sequence[Finding]
) -> list[tuple[str, str]]:
    """Clasifica tramos CSP sin alterar ni divulgar el valor recibido."""

    bad_findings = [item for item in findings if item.status in CSP_ACTIONABLE_STATUSES]
    good_findings = [item for item in findings if item.status == "correcta"]
    good_context = " ".join(
        f"{item.title} {item.evidence}".lower() for item in good_findings
    )
    bad_tokens = csp_console_risky_tokens(bad_findings)
    bad_directives = _csp_finding_directives(bad_findings)
    good_directives = _csp_finding_directives(good_findings)

    spans: list[tuple[str, str]] = []
    for segment in re.split(r"(;)", raw_policy):
        spans.extend(
            _csp_segment_spans(
                segment,
                bad_findings=bad_findings,
                bad_tokens=bad_tokens,
                bad_directives=bad_directives,
                good_directives=good_directives,
                good_context=good_context,
            )
        )
    return _merge_csp_spans(spans)


def render_csp_spans_console(spans: Sequence[tuple[str, str]], palette: Palette) -> str:
    rendered: list[str] = []
    for text, tone in spans:
        if tone == "bad":
            rendered.append(palette.paint(text, "red", bold=True))
        elif tone == "good":
            rendered.append(palette.paint(text, "green", bold=True))
        else:
            rendered.append(sanitize_terminal_text(text))
    return "".join(rendered)


def render_csp_spans_html(spans: Sequence[tuple[str, str]]) -> str:
    rendered: list[str] = []
    for text, tone in spans:
        escaped = html_escape(text)
        if tone == "bad":
            rendered.append(f'<span class="csp-bad">{escaped}</span>')
        elif tone == "good":
            rendered.append(f'<span class="csp-good">{escaped}</span>')
        else:
            rendered.append(escaped)
    return "".join(rendered)


def csp_protection_purpose(item: Finding) -> str:
    """Explica la protección asociada a un subhallazgo CSP."""

    context = f"{item.title} {item.evidence}".lower()
    if "form-action" in context:
        return (
            "form-action limita los destinos a los que un formulario puede enviar "
            "datos y reduce exfiltración mediante formularios inyectados."
        )
    if "default-src" in context:
        return (
            "default-src funciona como respaldo para los tipos de recurso sin una "
            "directiva específica y evita que queden sin restricción por omisión."
        )
    if "frame-ancestors" in context:
        return (
            "frame-ancestors controla qué orígenes pueden embeber la página y ayuda "
            "a prevenir clickjacking."
        )
    if "base-uri" in context:
        return (
            "base-uri restringe etiquetas <base> inyectadas que podrían cambiar el "
            "destino de enlaces, formularios y recursos relativos."
        )
    if "object-src" in context:
        return (
            "object-src bloquea objetos y plugins embebidos que amplían superficies "
            "de carga o ejecución innecesarias."
        )
    if any(
        token in context
        for token in ("script-src", "nonce", "hash", "strict-dynamic", "unsafe-")
    ):
        return (
            "Las restricciones de scripts determinan qué código puede ejecutarse y "
            "aportan una capa de mitigación frente a JavaScript inyectado y XSS."
        )
    if "style-src" in context:
        return "style-src limita las fuentes de CSS y reduce la capacidad de una inyección de estilos."
    if "connect-src" in context:
        return (
            "connect-src limita destinos de fetch, XHR, WebSocket y APIs similares, "
            "reduciendo canales de conexión o exfiltración no previstos."
        )
    if "report" in context:
        return "El reporte CSP permite observar violaciones y corregir la política antes de aplicarla en bloqueo."
    if "trusted types" in context or "trusted-types" in context:
        return "Trusted Types reduce el uso inseguro de sinks DOM asociados con DOM XSS en navegadores compatibles."
    return (
        "Una CSP válida y restrictiva limita las fuentes y acciones permitidas al "
        "documento, reduciendo el impacto de inyecciones de contenido."
    )


def highlight_csp_value(
    value: str, palette: Palette, risky_tokens: set[str] | None = None
) -> str:
    """Resalta solo expresiones respaldadas por una observación accionable."""
    value = sanitize_terminal_text(value)
    if not palette.enabled:
        return value

    normalized_risks = {token.lower().strip("'") for token in (risky_tokens or set())}

    def replacement(match: re.Match[str]) -> str:
        normalized = match.group(0).lower().strip("'")
        if risky_tokens is not None and normalized not in normalized_risks:
            return match.group(0)
        return palette.paint(match.group(0), "red", bold=True)

    return CSP_CONSOLE_RISK_RE.sub(
        replacement,
        value,
    )


def csp_console_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Conserva problemas accionables y elimina duplicados informativos de CSP."""
    output: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for item in findings:
        actionable = item.status in {"ausente", "incorrecta", "advertencia"}
        important_info = (
            "report-only" in f"{item.header} {item.title}".lower()
            or "varias políticas" in item.title.lower()
        )
        if not actionable and not important_info:
            continue
        key = (item.policy, item.title, item.evidence)
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def csp_console_risky_tokens(findings: Sequence[Finding]) -> set[str]:
    tokens: set[str] = set()
    for item in findings:
        context = f"{item.title} {item.evidence}".lower()
        for token in ("unsafe-inline", "unsafe-eval", "unsafe-hashes"):
            if token in context:
                tokens.add(token)
        if "*" in item.evidence or "comodín global" in item.title.lower():
            tokens.add("*")
        if "http:" in context or "fuentes http" in context:
            tokens.add("http:")
    return tokens


def _csp_detail_marker(item: Finding) -> tuple[str, str]:
    actionable = item.status in {"ausente", "incorrecta", "advertencia"}
    return ("!", "orange") if actionable else ("*", "blue")


def _append_csp_policy_values(
    lines: list[str], palette: Palette, entry: DisplayEntry
) -> None:
    if entry.policy_context:
        append_field(lines, palette, "Contexto CSP", entry.policy_context)
    if not entry.policies:
        append_field(
            lines,
            palette,
            "Configuración actual en la URL",
            entry.current_value,
            highlight=True,
        )
        return

    report_only = normalize_header_name(entry.finding.header).endswith("report-only")
    base_label = "Política Report-Only" if report_only else "Política aplicada"
    if len(entry.policies) == 1:
        rendered = render_csp_spans_console(entry.policy_spans[0], palette)
        lines.append(
            f"|  {palette.bold('Configuración actual en la URL:')} {rendered}".rstrip()
        )
        return

    for index, spans in enumerate(entry.policy_spans, start=1):
        lines.append(f"|  {palette.bold(f'{base_label} #{index}:')}")
        lines.append(f"|    {render_csp_spans_console(spans, palette)}")


def _append_csp_block_title(
    lines: list[str], palette: Palette, title: str
) -> None:
    """Separa y realza los encabezados internos del bloque CSP.

    Sin la línea en blanco previa, el título quedaba pegado a la política y a
    los hallazgos anteriores, que es justo donde la vista se vuelve ilegible en
    políticas largas.
    """

    lines.append("|")
    lines.append(f"|  {palette.heading(title)}")
    lines.append(f"|  {palette.paint('─' * (len(title) + 2), 'cyan')}")


def _append_csp_issue_summary(
    lines: list[str], palette: Palette, details: Sequence[Finding]
) -> None:
    if not details:
        return
    _append_csp_block_title(lines, palette, "RESUMEN DE HALLAZGOS CSP")
    for detail in details:
        marker, color = _csp_detail_marker(detail)
        lines.append(palette.paint(f"|  [{marker}] {detail.title}", color, bold=True))


def _append_csp_issue_details(
    lines: list[str],
    palette: Palette,
    details: Sequence[Finding],
    *,
    reveal_sensitive: bool,
) -> None:
    if not details:
        return
    _append_csp_block_title(lines, palette, "ANÁLISIS DETALLADO DE CSP")
    for detail in details:
        marker, color = _csp_detail_marker(detail)
        lines.append(palette.paint(f"|  [{marker}] {detail.title}", color, bold=True))
        append_field(
            lines,
            palette,
            "Protección",
            csp_protection_purpose(detail),
        )
        append_field(lines, palette, "Política", detail.policy)
        append_field(
            lines,
            palette,
            "Evidencia",
            finding_evidence(detail, reveal_sensitive),
        )
        append_field(lines, palette, "Riesgo", detail.risk)
        append_field(lines, palette, "Recomendación", detail.recommendation)
        append_references(lines, palette, detail.references)


def _append_csp_console_entry(
    lines: list[str],
    palette: Palette,
    entry: DisplayEntry,
    *,
    symbol: str,
    color: str,
    reveal_sensitive: bool,
) -> None:
    item = entry.finding
    lines.append(palette.paint(f"[{symbol}] {item.header}", color, bold=True))
    _append_csp_policy_values(lines, palette, entry)
    _append_csp_issue_summary(lines, palette, entry.details)
    _append_csp_issue_details(
        lines,
        palette,
        entry.details,
        reveal_sensitive=reveal_sensitive,
    )
    append_field(lines, palette, "Criterio", finding_criterion(item))
    append_field(lines, palette, "Observación", item.title)
    evidence = finding_evidence(item, reveal_sensitive)
    if evidence and evidence not in {entry.current_value, "Cabecera no encontrada."}:
        append_field(lines, palette, "Evidencia", evidence)
    append_field(lines, palette, "Riesgo", item.risk)
    append_field(lines, palette, "Recomendación", item.recommendation)
    append_references(lines, palette, item.references)


def render_csp_section(
    lines: list[str], report: ScanReport, items: Sequence[Finding], palette: Palette
) -> None:
    """Compatibilidad: usa el mismo renderer CSP que el flujo normal."""

    del items
    heading = CATEGORY_LABELS["csp"]
    lines.append(
        f"{palette.paint(heading + ':', CATEGORY_COLOR['csp'], bold=True)} "
        f"{palette.url_badge(report.final_url)}"
    )
    groups = build_display_groups(report)
    for category, entries in groups.items():
        for entry in entries:
            if not normalize_header_name(entry.finding.header).startswith(
                "content-security-policy"
            ):
                continue
            lines.append("")
            _append_csp_console_entry(
                lines,
                palette,
                entry,
                symbol=DISPLAY_CATEGORY_SYMBOL[category],
                color=DISPLAY_CATEGORY_COLOR[category],
                reveal_sensitive=False,
            )


#: Escudo del logo rasterizado a bloques de media altura. Cada fila es una
#: secuencia de segmentos ``(tono, texto)``: ``body`` es el cuerpo del escudo y
#: ``ink`` la pila de cabeceras HTTP que aparece dentro, igual que en el SVG.
BRAND_SHIELD: tuple[tuple[tuple[str, str], ...], ...] = (
    (("body", " \u2584\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2584"),),
    (("body", "\u2584\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2584"),),
    (("body", "\u2588\u2588\u2588\u2588\u2588\u2588"), ("ink", "\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588"), ("body", "\u2588\u2588\u2588\u2588\u2588\u2588")),
    (("body", "\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588"),),
    (("body", "\u2588\u2588\u2588\u2588\u2588\u2588"), ("ink", "\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588"), ("body", "\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588")),
    (("body", " \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588"),),
    (("body", "  \u2580\u2588\u2588\u2588"), ("ink", "\u2588\u2588\u2588\u2588\u2588\u2588\u2588"), ("body", "\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2580")),
    (("body", "     \u2580\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2580"),),
    (("body", "        \u2580\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2580"),),
    (("body", "           \u2580\u2580\u2580\u2580"),),
)

#: Filas del escudo en las que se ancla el texto de marca, a la derecha.
_BRAND_TEXT_ROWS = {3: "wordmark", 5: "subtitle"}
_BRAND_GUTTER = 30


def _render_shield_row(
    palette: Palette, row: tuple[tuple[str, str], ...]
) -> str:
    return "".join(
        palette.paint(text, "white", bold=True)
        if tone == "ink"
        else palette.paint(text, "blue", bold=True)
        for tone, text in row
    )


def console_brand_banner(
    palette: Palette,
    version: str,
    *,
    subtitle: str = "HTTP SECURITY AUDITOR",
) -> list[str]:
    """Escudo del logo en bloques, con la marca alineada a su derecha."""

    texts = {
        "wordmark": palette.paint(f"SafeWebHeaders {version}", "blue", bold=True),
        "subtitle": palette.paint(subtitle, "white", bold=True),
    }
    lines: list[str] = []
    for index, row in enumerate(BRAND_SHIELD):
        plain_width = sum(len(text) for _tone, text in row)
        rendered = _render_shield_row(palette, row)
        slot = _BRAND_TEXT_ROWS.get(index)
        if slot is not None:
            padding = " " * max(2, _BRAND_GUTTER - plain_width)
            rendered = f"{rendered}{padding}{texts[slot]}"
        lines.append(rendered)
    lines.append("")
    return lines


def animate_brand_banner(
    stream: TextIO,
    palette: Palette,
    version: str,
    *,
    subtitle: str = "HTTP SECURITY AUDITOR",
) -> None:
    """Escribe el banner con una entrada progresiva fila a fila.

    Solo se anima en un terminal interactivo y con color habilitado: cuando la
    salida se redirige a un archivo o a una tubería, el texto resultante es
    idéntico al de ``console_brand_banner`` y no se emite ninguna secuencia de
    control adicional que ensucie la evidencia.
    """

    lines = console_brand_banner(palette, version, subtitle=subtitle)
    animated = (
        palette.enabled
        and getattr(stream, "isatty", lambda: False)()
        and not os.environ.get("SAFEWEBHEADERS_NO_ANIMATION")
    )
    if not animated:
        stream.write("\n".join(lines) + "\n")
        return
    for line in lines:
        stream.write(line + "\n")
        stream.flush()
        time.sleep(0.045)


def render_console(
    report: ScanReport,
    *,
    color: bool,
    reveal_sensitive: bool,
    include_banner: bool = True,
    position: tuple[int, int] | None = None,
) -> str:
    p = Palette(color)
    lines: list[str] = []

    if include_banner:
        lines.extend(console_brand_banner(p, report.version))
    if position:
        lines.append(
            p.paint(f"Evaluación {position[0]} de {position[1]}", "white", bold=True)
        )

    metadata = [
        (
            "URL solicitada",
            redact_url_secrets(report.requested_url, reveal_sensitive),
        ),
        ("URL evaluada", redact_url_secrets(report.final_url, reveal_sensitive)),
        ("Fecha y hora", display_timestamp(report.timestamp)),
        ("IP(s) resueltas", report_ips_text(report)),
        ("Respuesta", f"{report.status_code or 'N/A'} {report.reason}".strip()),
        ("Perfil", report.profile),
        ("Método", report.method),
        ("Validación TLS", report.tls_verification),
        ("Duración", f"{report.elapsed_ms} ms"),
        (
            "Redirecciones",
            (
                f"HTTP: {report.redirect_count}; HTML: {report.client_redirect_count} "
                f"(seguimiento: {'sí' if report.redirect_following else 'no'})"
            ),
        ),
        ("Exclusiones", ", ".join(report.excluded_headers) or "ninguna"),
    ]
    width = max(len(label) for label, _ in metadata)
    for label, value in metadata:
        lines.append(f"{p.bold(label.ljust(width))} : {sanitize_terminal_text(value)}")

    summary = summarize_report(report)
    lines.append("")
    lines.append(p.paint("Resumen por URL", "blue", bold=True))
    summary_parts = [
        p.paint(f"Correctas: {summary['correctas']}", "green", bold=True),
        p.paint(f"Ausentes: {summary['ausentes']}", "red", bold=True),
        p.paint(f"Incorrectas: {summary['incorrectas']}", "orange", bold=True),
    ]
    if summary["cookies"]:
        summary_parts.append(
            p.paint(f"Cookies evaluadas: {summary['cookies']}", "cyan", bold=True)
        )
    summary_parts.extend(
        [
            p.paint(f"Obsoletas: {summary['obsoletas']}", "cyan", bold=True),
            p.paint(f"Divulgaciones: {summary['divulgaciones']}", "magenta", bold=True),
            p.paint(f"Informativas: {summary['informativas']}", "blue", bold=True),
            p.paint(f"Excluidas: {summary['excluidas']}", "white", bold=True),
        ]
    )
    lines.append("  " + " | ".join(summary_parts))

    if report.show_headers:
        lines.append("")
        append_section_context(lines, p, report, "cyan")
        lines.append(
            p.paint(
                "Vista de respuestas tipo curl (reconstruida, no bytes RAW):",
                "cyan",
                bold=True,
            )
        )
        blocks = response_header_blocks(report, reveal_sensitive)
        for index, (url, block) in enumerate(blocks, start=1):
            lines.append(
                f"{p.bold(f'Respuesta {index}/{len(blocks)}')} {p.url_badge(url)}"
            )
            lines.extend(
                f"|  {sanitize_terminal_text(line)}" for line in block.splitlines()
            )
            lines.append("|")

    if report.navigation_count:
        lines.append("")
        append_section_context(lines, p, report, "blue")
        lines.append(
            f"{p.paint('Cadena de redirecciones desde la URL:', 'cyan', bold=True)} "
            f"{p.url_badge(redact_url_secrets(report.requested_url, reveal_sensitive))}"
        )
        for hop in report.redirects:
            hop_url = redact_url_secrets(hop.url, reveal_sensitive)
            kind = (
                "META REFRESH"
                if hop.redirect_kind == "meta-refresh"
                else "HTTP"
                if hop.redirect_kind == "http" or hop.location
                else "FINAL"
            )
            lines.append(
                sanitize_terminal_text(f"[*] {kind} {hop.status_code} {hop_url}")
            )
            announced = hop.redirect_target or hop.location
            if announced:
                visible_announced = redact_url_secrets(announced, reveal_sensitive)
                lines.append(
                    sanitize_terminal_text(
                        f"    Destino anunciado : {visible_announced}"
                    )
                )
            if hop.redirect_followed and hop.effective_redirect_target:
                visible_effective = redact_url_secrets(
                    hop.effective_redirect_target, reveal_sensitive
                )
                lines.append(
                    sanitize_terminal_text(
                        f"    Destino solicitado: {visible_effective}"
                    )
                )
        if any(
            (hop.redirect_target or hop.location) and not hop.redirect_followed
            for hop in report.redirects
        ):
            lines.append(
                "[*] El destino anunciado no fue solicitado en uno o más saltos; usa "
                "--follow-redirects para completar la navegación."
            )

    groups = build_display_groups(report)
    for category, label in DISPLAY_CATEGORY_LABELS.items():
        entries = groups[category]
        if not entries:
            continue
        lines.append("")
        color_name = DISPLAY_CATEGORY_COLOR[category]
        append_section_context(lines, p, report, color_name)
        lines.append(
            f"{p.paint(label + ':', color_name, bold=True)} "
            f"{p.url_badge(redact_url_secrets(report.final_url, reveal_sensitive))}"
        )
        for entry in entries:
            item = entry.finding
            lines.append("")
            symbol = (
                "+"
                if category == "cookies" and item.status == "correcta"
                else "!"
                if category == "cookies"
                else DISPLAY_CATEGORY_SYMBOL[category]
            )
            entry_color = (
                "green"
                if category == "cookies" and item.status == "correcta"
                else "orange"
                if category == "cookies"
                else color_name
            )
            if normalize_header_name(item.header).startswith("content-security-policy"):
                _append_csp_console_entry(
                    lines,
                    p,
                    entry,
                    symbol=symbol,
                    color=entry_color,
                    reveal_sensitive=reveal_sensitive,
                )
                continue

            prefix = f"[{symbol}] {item.header}"
            lines.append(p.paint(prefix, entry_color, bold=True))
            append_field(
                lines,
                p,
                "Configuración actual en la URL",
                entry.current_value,
                highlight=True,
            )
            append_field(lines, p, "Criterio", finding_criterion(item))
            append_field(lines, p, "Observación", item.title)
            evidence = finding_evidence(item, reveal_sensitive)
            if evidence and evidence not in {
                entry.current_value,
                "Cabecera no encontrada.",
            }:
                append_field(lines, p, "Evidencia", evidence)
            append_field(lines, p, "Riesgo", item.risk)
            append_field(lines, p, "Recomendación", item.recommendation)
            append_references(lines, p, item.references)

    if report.notes:
        # Marco de una sola regla horizontal: la banda de signos de admiración
        # gritaba sin aportar información y ensuciaba la captura de evidencia.
        lines.extend(["", ""])
        rule = "─" * 72
        lines.append(p.paint(rule, "orange", bold=True))
        lines.append(p.paint("NOTAS DE LA EVALUACIÓN", "orange", bold=True))
        lines.append(
            f"URL: {p.url_badge(redact_url_secrets(report.final_url, reveal_sensitive))}"
        )
        lines.append(p.paint(rule, "orange"))
        for index, note in enumerate(report.notes, start=1):
            visible_note = redact_text_urls(note, reveal_sensitive)
            marker = f"{index:>2}. "
            wrapped_note = wrap_text(
                sanitize_terminal_text(visible_note), width=86, indent=""
            )
            for position, part in enumerate(wrapped_note):
                prefix = p.paint(marker, "orange") if position == 0 else " " * len(marker)
                lines.append(f"{prefix}{part}")
        lines.append(p.paint(rule, "orange", bold=True))
    return "\n".join(lines).rstrip() + "\n"


def render_batch_console(
    batch: BatchReport,
    *,
    color: bool,
    reveal_sensitive: bool,
    include_banner: bool = True,
) -> str:
    if (
        len(batch.requested_targets) == 1
        and len(batch.reports) == 1
        and not batch.errors
    ):
        return render_console(
            batch.reports[0],
            color=color,
            reveal_sensitive=reveal_sensitive,
            include_banner=include_banner,
        )

    p = Palette(color)
    summary = batch.summary()
    lines = [
        *(
            console_brand_banner(p, batch.version, subtitle="RESUMEN GENERAL DEL LOTE")
            if include_banner
            else []
        ),
        f"{p.bold('Fecha y hora')}      : {display_timestamp(batch.timestamp)}",
        f"{p.bold('URLs solicitadas')} : {summary['urls_solicitadas']}",
        f"{p.bold('URLs evaluadas')}   : {summary['urls_evaluadas']}",
        f"{p.bold('URLs con error')}   : {summary['urls_con_error']}",
        "",
        p.paint("Resumen acumulado", "blue", bold=True),
        "  "
        + " | ".join(
            [
                p.paint(f"Correctas: {summary['correctas']}", "green", bold=True),
                p.paint(f"Ausentes: {summary['ausentes']}", "red", bold=True),
                p.paint(f"Incorrectas: {summary['incorrectas']}", "orange", bold=True),
                *(
                    [
                        p.paint(
                            f"Cookies evaluadas: {summary['cookies']}",
                            "cyan",
                            bold=True,
                        )
                    ]
                    if summary["cookies"]
                    else []
                ),
                p.paint(f"Obsoletas: {summary['obsoletas']}", "cyan", bold=True),
                p.paint(
                    f"Divulgaciones: {summary['divulgaciones']}",
                    "magenta",
                    bold=True,
                ),
                p.paint(f"Informativas: {summary['informativas']}", "blue", bold=True),
                p.paint(f"Excluidas: {summary['excluidas']}", "white", bold=True),
            ]
        ),
    ]
    total = len(batch.reports)
    for index, report in enumerate(batch.reports, start=1):
        lines.extend(["", p.paint("-" * 72, "blue", bold=True), ""])
        lines.append(
            render_console(
                report,
                color=color,
                reveal_sensitive=reveal_sensitive,
                include_banner=False,
                position=(index, total),
            ).rstrip()
        )
    if batch.errors:
        lines.extend(["", p.paint("-" * 72, "red", bold=True), ""])
        lines.append(p.paint("URLs que no pudieron evaluarse", "red", bold=True))
        for error in batch.errors:
            lines.append(
                f"{p.paint('Date:', 'red', bold=True)} {display_timestamp(error.timestamp)}"
            )
            requested = redact_url_secrets(error.requested_url, reveal_sensitive)
            message = redact_text_urls(error.error, reveal_sensitive)
            lines.append(p.paint(f"[!] {requested}", "red", bold=True))
            lines.append(f"|  {p.bold('Error:')} {sanitize_terminal_text(message)}")
    return "\n".join(lines).rstrip() + "\n"


def html_escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _csp_policy_values_html(entry: DisplayEntry) -> str:
    if not entry.policies:
        return (
            "<dl><dt>Configuración actual en la URL</dt>"
            f"<dd><code>{html_escape(entry.current_value)}</code></dd></dl>"
        )

    context = (
        f'<p class="csp-context">{html_escape(entry.policy_context)}</p>'
        if entry.policy_context
        else ""
    )
    report_only = normalize_header_name(entry.finding.header).endswith("report-only")
    base_label = "Política Report-Only" if report_only else "Política aplicada"
    policies: list[str] = []
    for index, value in enumerate(entry.policies, start=1):
        spans = (
            entry.policy_spans[index - 1]
            if index <= len(entry.policy_spans)
            else [(value, "")]
        )
        label = (
            "Configuración actual en la URL"
            if len(entry.policies) == 1
            else f"{base_label} #{index}"
        )
        policies.append(
            '<div class="csp-policy">'
            f"<h4>{html_escape(label)}</h4>"
            f"<code>{render_csp_spans_html(spans)}</code>"
            "</div>"
        )
    return context + '<div class="csp-policies">' + "".join(policies) + "</div>"


def _csp_issue_summary_html(details: Sequence[Finding]) -> str:
    if not details:
        return ""
    items = "".join(
        f"<li>[{_csp_detail_marker(item)[0]}] {html_escape(item.title)}</li>"
        for item in details
    )
    return (
        '<div class="csp-summary"><h4>Resumen de hallazgos CSP</h4>'
        f"<ul>{items}</ul></div>"
    )


def _csp_issue_details_html(
    details: Sequence[Finding], *, reveal_sensitive: bool
) -> str:
    rendered: list[str] = []
    for detail in details:
        refs = "".join(
            f'<li><a href="{html_escape(ref)}" target="_blank" '
            f'rel="noopener noreferrer">{html_escape(ref)}</a></li>'
            for ref in detail.references
        )
        rendered.append(
            '<div class="csp-detail">'
            f"<h4>[{_csp_detail_marker(detail)[0]}] {html_escape(detail.title)}</h4>"
            "<dl>"
            f"<dt>Protección</dt><dd>{html_escape(csp_protection_purpose(detail))}</dd>"
            f"<dt>Política</dt><dd>{html_escape(detail.policy)}</dd>"
            f"<dt>Evidencia</dt><dd><code>{html_escape(finding_evidence(detail, reveal_sensitive))}</code></dd>"
            f"<dt>Riesgo</dt><dd>{html_escape(detail.risk)}</dd>"
            f"<dt>Recomendación</dt><dd>{html_escape(detail.recommendation)}</dd>"
            + (f"<dt>Referencias</dt><dd><ul>{refs}</ul></dd>" if refs else "")
            + "</dl></div>"
        )
    if not rendered:
        return ""
    return (
        '<div class="csp-details"><h4>Análisis detallado de CSP</h4>'
        + "".join(rendered)
        + "</div>"
    )


def _render_csp_finding_card_html(
    entry: DisplayEntry,
    *,
    category: str,
    symbol: str,
    reveal_sensitive: bool,
) -> str:
    item = entry.finding
    refs = "".join(
        f'<li><a href="{html_escape(ref)}" target="_blank" '
        f'rel="noopener noreferrer">{html_escape(ref)}</a></li>'
        for ref in item.references
    )
    parent_details: list[str] = []
    criterion = finding_criterion(item)
    if criterion:
        parent_details.append(f"<dt>Criterio</dt><dd>{html_escape(criterion)}</dd>")
    evidence = finding_evidence(item, reveal_sensitive)
    if evidence and evidence not in {entry.current_value, "Cabecera no encontrada."}:
        parent_details.append(
            f"<dt>Evidencia</dt><dd><code>{html_escape(evidence)}</code></dd>"
        )
    if item.risk:
        parent_details.append(
            f"<dt>Riesgo/alcance</dt><dd>{html_escape(item.risk)}</dd>"
        )
    if item.recommendation:
        parent_details.append(
            f"<dt>Recomendación</dt><dd>{html_escape(item.recommendation)}</dd>"
        )
    if refs:
        parent_details.append(f"<dt>Referencias</dt><dd><ul>{refs}</ul></dd>")
    parent = f"<dl>{''.join(parent_details)}</dl>" if parent_details else ""
    return (
        f'<article class="finding {html_escape(category)}">'
        f'<div class="finding-head"><span class="badge">[{html_escape(symbol)}]</span></div>'
        f"<h3>{html_escape(item.header)}</h3>"
        f'<p class="finding-title">{html_escape(item.title)}</p>'
        f"{_csp_policy_values_html(entry)}"
        f"{_csp_issue_summary_html(entry.details)}"
        f"{_csp_issue_details_html(entry.details, reveal_sensitive=reveal_sensitive)}"
        f"{parent}"
        "</article>"
    )


def render_html(report: ScanReport, reveal_sensitive: bool) -> str:
    requested_url = redact_url_secrets(report.requested_url, reveal_sensitive)
    final_url = redact_url_secrets(report.final_url, reveal_sensitive)
    summary = summarize_report(report)
    groups = build_display_groups(report)

    metric_values = [
        ("Correctas", summary["correctas"], "ok"),
        ("Ausentes", summary["ausentes"], "bad"),
        ("Incorrectas", summary["incorrectas"], "warn"),
    ]
    if summary["cookies"]:
        metric_values.append(("Cookies", summary["cookies"], "info"))
    metric_values.extend(
        [
            ("Obsoletas", summary["obsoletas"], "info"),
            ("Divulgaciones", summary["divulgaciones"], "skip"),
            ("Informativas", summary["informativas"], "info"),
            ("Excluidas", summary["excluidas"], "skip"),
        ]
    )
    cards = "".join(
        f'<div class="metric {html_escape(css)}"><span>{html_escape(label)}</span><strong>{count}</strong></div>'
        for label, count, css in metric_values
    )

    redirect_rows = "".join(
        "<tr>"
        f"<td>{index}</td>"
        f"<td>{html_escape('Meta refresh' if hop.redirect_kind == 'meta-refresh' else 'HTTP' if hop.redirect_kind == 'http' or hop.location else 'Final')}</td>"
        f"<td>{hop.status_code}</td>"
        f"<td><code>{html_escape(redact_url_secrets(hop.url, reveal_sensitive))}</code></td>"
        f"<td><code>{html_escape(redact_url_secrets(hop.redirect_target or hop.location, reveal_sensitive))}</code></td>"
        f"<td><code>{html_escape(redact_url_secrets(hop.effective_redirect_target, reveal_sensitive))}</code></td>"
        f"<td>{'Sí' if hop.redirect_followed else 'No' if hop.redirect_target or hop.location else '—'}</td>"
        f"<td>{hop.elapsed_ms} ms</td>"
        "</tr>"
        for index, hop in enumerate(report.redirects, start=1)
    )

    raw_headers = ""
    if report.show_headers:
        blocks = response_header_blocks(report, reveal_sensitive)
        rendered_blocks = "".join(
            '<article class="csp-detail">'
            f"<h3>Respuesta {index}/{len(blocks)}</h3>"
            f"<p><code>{html_escape(url)}</code></p>"
            f"<pre>{html_escape(block)}</pre>"
            "</article>"
            for index, (url, block) in enumerate(blocks, start=1)
        )
        raw_headers = (
            "<section><h2>Vista de respuestas tipo curl</h2>"
            '<p class="notice">Vista reconstruida; no representa los bytes RAW exactos recibidos en la red.</p>'
            + rendered_blocks
            + "</section>"
        )

    notes_html = ""
    if report.notes:
        note_items = "".join(
            f"<li>{html_escape(redact_text_urls(note, reveal_sensitive))}</li>"
            for note in report.notes
        )
        notes_html = (
            '<section class="important-notes"><p class="important-label">'
            "[!] IMPORTANTE</p><h2>Notas de la evaluación</h2>"
            f"<ul>{note_items}</ul></section>"
        )

    sections = []
    for category, label in DISPLAY_CATEGORY_LABELS.items():
        entries = groups[category]
        if not entries:
            continue
        finding_cards = []
        for entry in entries:
            item = entry.finding
            entry_symbol = (
                "+"
                if category == "cookies" and item.status == "correcta"
                else "!"
                if category == "cookies"
                else DISPLAY_CATEGORY_SYMBOL[category]
            )
            if normalize_header_name(item.header).startswith("content-security-policy"):
                finding_cards.append(
                    _render_csp_finding_card_html(
                        entry,
                        category=category,
                        symbol=entry_symbol,
                        reveal_sensitive=reveal_sensitive,
                    )
                )
                continue
            refs = "".join(
                f'<li><a href="{html_escape(ref)}" target="_blank" rel="noopener noreferrer">{html_escape(ref)}</a></li>'
                for ref in item.references
            )
            detail = [
                (
                    "<dt>Configuración actual en la URL</dt>"
                    f"<dd><code>{html_escape(entry.current_value)}</code></dd>"
                )
            ]
            criterion = finding_criterion(item)
            if criterion:
                detail.append(f"<dt>Criterio</dt><dd>{html_escape(criterion)}</dd>")
            evidence = finding_evidence(item, reveal_sensitive)
            if evidence:
                detail.append(
                    f"<dt>Evidencia</dt><dd><code>{html_escape(evidence)}</code></dd>"
                )
            if item.risk:
                detail.append(
                    f"<dt>Riesgo/alcance</dt><dd>{html_escape(item.risk)}</dd>"
                )
            if item.recommendation:
                detail.append(
                    f"<dt>Recomendación</dt><dd>{html_escape(item.recommendation)}</dd>"
                )
            if refs:
                detail.append(f"<dt>Referencias</dt><dd><ul>{refs}</ul></dd>")
            nested = []
            for csp_detail in entry.details:
                nested_refs = "".join(
                    f'<li><a href="{html_escape(ref)}" target="_blank" rel="noopener noreferrer">{html_escape(ref)}</a></li>'
                    for ref in csp_detail.references
                )
                nested.append(
                    '<div class="csp-detail">'
                    f"<h4>[!] {html_escape(csp_detail.title)}</h4>"
                    "<dl>"
                    f"<dt>Política</dt><dd>{html_escape(csp_detail.policy)}</dd>"
                    f"<dt>Evidencia</dt><dd><code>{html_escape(csp_detail.evidence)}</code></dd>"
                    f"<dt>Riesgo</dt><dd>{html_escape(csp_detail.risk)}</dd>"
                    f"<dt>Recomendación</dt><dd>{html_escape(csp_detail.recommendation)}</dd>"
                    + (
                        f"<dt>Referencias</dt><dd><ul>{nested_refs}</ul></dd>"
                        if nested_refs
                        else ""
                    )
                    + "</dl></div>"
                )
            finding_cards.append(
                f'<article class="finding {html_escape(category)}">'
                f'<div class="finding-head"><span class="badge">[{html_escape(entry_symbol)}]</span></div>'
                f'<h3>{html_escape(item.header)}</h3><p class="finding-title">{html_escape(item.title)}</p>'
                f"<dl>{''.join(detail)}</dl>{''.join(nested)}</article>"
            )
        sections.append(
            f'<section><div class="section-heading"><div><time datetime="{html_escape(report.timestamp)}"><strong>Date:</strong> {html_escape(display_timestamp(report.timestamp))}</time>'
            f"<p><strong>IP(s):</strong> {html_escape(report_ips_text(report))}</p>"
            f"<h2>{html_escape(label)}</h2><p>{html_escape(final_url)}</p></div></div>"
            f'<div class="findings">{"".join(finding_cards)}</div></section>'
        )

    metadata = [
        ("URL solicitada", requested_url),
        ("URL evaluada", final_url),
        ("Fecha y hora", display_timestamp(report.timestamp)),
        ("IP(s) resueltas", report_ips_text(report)),
        ("Respuesta", f"{report.status_code or 'N/A'} {report.reason}".strip()),
        ("Perfil", report.profile),
        ("Método", report.method),
        ("Validación TLS", report.tls_verification),
        ("Duración", f"{report.elapsed_ms} ms"),
        (
            "Redirecciones",
            f"HTTP: {report.redirect_count}; HTML: {report.client_redirect_count} "
            + f"(seguimiento: {'sí' if report.redirect_following else 'no'})",
        ),
        ("Exclusiones", ", ".join(report.excluded_headers) or "ninguna"),
    ]
    metadata_rows = "".join(
        f"<tr><th>{html_escape(key)}</th><td>{html_escape(value)}</td></tr>"
        for key, value in metadata
    )

    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SafeWebHeaders — {html_escape(final_url)}</title>
  <style>
    :root {{ color-scheme: dark; --bg:#071018; --panel:#0d1822; --panel2:#101f2b; --line:#263746;
      --text:#e8f0f5; --muted:#91a5b4; --ok:#39d98a; --bad:#ff5d73; --warn:#ffc857;
      --info:#58c7f3; --skip:#c792ea; --accent:#36f1cd; }}
    * {{ box-sizing:border-box; }} body {{ margin:0; background:radial-gradient(circle at top right,#123042 0,#071018 42%);
      color:var(--text); font:15px/1.55 Inter,Segoe UI,Arial,sans-serif; }}
    a {{ color:#7ddcff; word-break:break-all; }} code {{ font-family:Consolas,Monaco,monospace; color:#d8f7ee; white-space:pre-wrap; word-break:break-word; }}
    .wrap {{ width:min(1180px,calc(100% - 36px)); margin:0 auto; padding:40px 0 70px; }}
    header {{ padding:30px; border:1px solid var(--line); background:linear-gradient(135deg,rgba(16,31,43,.96),rgba(8,20,29,.94)); border-radius:18px; box-shadow:0 18px 50px #0007; }}
    .eyebrow {{ color:var(--accent); text-transform:uppercase; letter-spacing:.18em; font-size:12px; font-weight:800; }}
    h1 {{ margin:.25rem 0 .4rem; font-size:clamp(30px,5vw,58px); line-height:1; }}
    .subtitle {{ color:var(--muted); margin:0; }} .metrics {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(125px,1fr)); gap:12px; margin:22px 0; }}
    .metric {{ padding:15px; border-radius:13px; background:var(--panel); border:1px solid var(--line); }}
    .metric span {{ color:var(--muted); display:block; font-size:12px; }} .metric strong {{ font-size:26px; }}
    .metric.ok strong {{ color:var(--ok); }} .metric.bad strong {{ color:var(--bad); }} .metric.warn strong {{ color:var(--warn); }}
    .metric.info strong {{ color:var(--info); }} .metric.skip strong {{ color:var(--skip); }}
    section {{ margin-top:28px; padding:24px; border:1px solid var(--line); background:rgba(13,24,34,.92); border-radius:16px; }}
    h2 {{ margin:0; font-size:22px; }} .section-heading {{ display:flex; align-items:flex-start; justify-content:space-between; gap:18px; margin-bottom:18px; }}
    .section-heading p,.section-heading time {{ color:var(--muted); margin:.3rem 0 0; font-size:13px; word-break:break-all; }}
    table {{ width:100%; border-collapse:collapse; }} th,td {{ padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }}
    th {{ color:#b6c6d2; width:210px; }} .table-wrap {{ overflow-x:auto; }}
    .findings {{ display:grid; gap:14px; }} .finding {{ border:1px solid var(--line); border-left:5px solid var(--info); background:var(--panel2); border-radius:12px; padding:18px; }}
    .finding.correctas {{ border-left-color:var(--ok); }} .finding.ausentes {{ border-left-color:var(--bad); }}
    .finding.incorrectas {{ border-left-color:var(--warn); }} .finding.cookies {{ border-left-color:var(--info); }} .finding.obsoletas {{ border-left-color:var(--info); }}
    .finding.divulgacion {{ border-left-color:var(--skip); }} .finding.informativas {{ border-left-color:#6aa9ff; }}
    .finding-head {{ display:flex; gap:8px; }} .badge {{ border:1px solid var(--line); border-radius:999px; padding:3px 9px; font-size:11px; text-transform:uppercase; letter-spacing:.08em; }}
    .finding h3 {{ margin:12px 0 2px; }} .finding-title {{ margin:0 0 14px; color:#d3dee6; font-size:16px; }}
    .csp-detail {{ margin-top:18px; padding:15px; border:1px solid var(--line); border-radius:10px; background:#0a151e; }}
    .csp-detail h4 {{ margin:0 0 12px; color:var(--warn); }}
    .csp-policies {{ display:grid; gap:10px; margin:12px 0; }} .csp-policy {{ padding:12px; border:1px solid var(--line); border-radius:8px; background:#07131c; }}
    .csp-policy h4 {{ margin:0 0 7px; color:var(--muted); }} .csp-context {{ color:var(--muted); border-left:3px solid var(--info); padding-left:12px; }}
    .csp-bad {{ color:var(--bad); font-weight:800; }} .csp-good {{ color:var(--ok); font-weight:800; }}
    .csp-summary {{ margin:14px 0; padding:12px; border:1px solid var(--warn); border-radius:8px; background:#1d190d; }}
    .csp-summary h4,.csp-details>h4 {{ margin:0 0 8px; }} .csp-summary li {{ margin:4px 0; }}
    dl {{ margin:0; display:grid; grid-template-columns:155px 1fr; gap:8px 14px; }} dt {{ color:var(--muted); font-weight:700; }} dd {{ margin:0; }} ul {{ margin:.2rem 0; padding-left:20px; }}
    .notice {{ color:var(--muted); border-left:3px solid var(--accent); padding-left:14px; margin-top:24px; }}
    .important-notes {{ margin-top:42px; border:2px solid var(--warn); background:#211b0b;
      box-shadow:0 0 0 4px #ffc85718,0 16px 36px #0006; }}
    .important-notes h2 {{ color:var(--warn); }} .important-notes li {{ margin:.55rem 0; }}
    .important-label {{ display:inline-block; margin:0 0 8px; padding:5px 10px; border-radius:999px;
      color:#17130a; background:var(--warn); font-weight:900; letter-spacing:.08em; }}
    footer {{ color:var(--muted); text-align:center; margin-top:28px; font-size:13px; }}
    @media (max-width:900px) {{ .metrics {{ grid-template-columns:repeat(3,1fr); }} }}
    @media (max-width:620px) {{ .wrap {{ width:min(100% - 20px,1180px); }} header,section {{ padding:17px; }}
      .metrics {{ grid-template-columns:repeat(2,1fr); }} dl {{ grid-template-columns:1fr; }} .section-heading {{ display:block; }} }}
  </style>
</head>
<body><main class="wrap">
  <header><div class="eyebrow">HTTP security headers audit</div><h1>SafeWebHeaders</h1>
    <p class="subtitle">Análisis estático, contextual y reproducible de cabeceras de seguridad.</p></header>
  <div class="metrics">{cards}</div>
  <section><h2>Datos de la evaluación</h2><div class="table-wrap"><table><tbody>{metadata_rows}</tbody></table></div></section>
  {('<section><h2>Cadena de navegación</h2><div class="table-wrap"><table><thead><tr><th>#</th><th>Tipo</th><th>Estado</th><th>URL</th><th>Destino anunciado</th><th>Destino solicitado</th><th>Seguido</th><th>Tiempo</th></tr></thead><tbody>' + redirect_rows + "</tbody></table></div></section>") if redirect_rows else ""}
  {raw_headers}
  {"".join(sections)}
  {notes_html}
  <p class="notice">El resultado describe una respuesta puntual. No reemplaza pruebas en navegador, revisión de código, análisis de TLS ni validación de todos los endpoints.</p>
  <footer data-generated-at="{html_escape(report.timestamp)}">SafeWebHeaders {html_escape(report.version)} · generado {html_escape(display_timestamp(report.timestamp))}</footer>
</main></body></html>"""


def javascript_literal(value: str) -> str:
    """Serializa texto para un <script> sin permitir cerrar el elemento."""
    return (
        json.dumps(value, ensure_ascii=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
