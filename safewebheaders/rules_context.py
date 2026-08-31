"""Rules context de SafeWebHeaders."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from itertools import pairwise
from urllib.parse import urlsplit

from .constants import (
    IANA_HTTP_FIELDS,
    MDN_CACHE_CONTROL,
    MDN_CLEAR_SITE_DATA,
    MDN_COEP,
    MDN_COOKIES,
    MDN_COOP,
    MDN_CORP,
    MDN_CORS,
    MDN_DNS_PREFETCH,
    MDN_INTEGRITY_POLICY,
    MDN_PERMISSIONS,
    MDN_XPCDP,
    MDN_XXSSP,
    OWASP_HEADERS,
    OWASP_HSTS,
    OWASP_SECURE_HEADERS,
    OWASP_WSTG_HEADERS,
)
from .models import (
    Finding,
    ResponseSnapshot,
)
from .profiles import (
    excluded_finding,
    finding,
)
from .utils import (
    HTTP_FIELD_NAME_PATTERN,
    parse_http_parameter_value,
    split_http_parameters,
)


def split_permissions_policy(value: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    quoted = False
    for char in value:
        if char == '"':
            quoted = not quoted
        elif not quoted and char == "(":
            depth += 1
        elif not quoted and char == ")" and depth:
            depth -= 1
        if char == "," and depth == 0 and not quoted:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
        else:
            current.append(char)
    part = "".join(current).strip()
    if part:
        parts.append(part)
    return parts


def parse_permissions_policy(value: str) -> tuple[dict[str, str], list[str]]:
    directives: dict[str, str] = {}
    invalid: list[str] = []
    allow_item = re.compile(r'"[^"\r\n]*"|self|src|\*')
    endpoint = r'(?:[!#$%&\'*+\-.^_`|~0-9A-Za-z]+|"[^"\r\n]+")'
    for part in split_permissions_policy(value):
        match = re.fullmatch(
            rf"([a-zA-Z][a-zA-Z0-9-]*)\s*=\s*(\*|\(([^()]*)\))"
            rf"(?:\s*;\s*report-to\s*=\s*{endpoint})?",
            part,
        )
        if not match:
            invalid.append(part)
            continue
        feature = match.group(1).lower()
        allowlist = match.group(2)
        inner = match.group(3)
        if feature in directives:
            invalid.append(f"{part} (directiva duplicada)")
            continue
        if inner is not None:
            tokens = re.findall(r'"[^"\r\n]*"|\S+', inner)
            if " ".join(tokens) != " ".join(inner.split()) or any(
                not allow_item.fullmatch(token) for token in tokens
            ):
                invalid.append(part)
                continue
        directives[feature] = allowlist
    return directives, invalid


def analyze_permissions_policy(
    snapshot: ResponseSnapshot, excluded: set[str], profile: str
) -> list[Finding]:
    name = "permissions-policy"
    if name in excluded:
        return [excluded_finding(name)]
    values = snapshot.all(name)
    if not values:
        return []
    combined = ",".join(values)
    directives, invalid = parse_permissions_policy(combined)
    if invalid:
        return [
            finding(
                "incorrectas",
                "incorrecta",
                "media",
                "Permissions-Policy",
                "La política contiene sintaxis no reconocida",
                evidence="; ".join(invalid),
                risk="El navegador puede ignorar las directivas inválidas.",
                recommendation="Usa la sintaxis actual feature=(allowlist), separada por comas.",
                references=[MDN_PERMISSIONS, OWASP_WSTG_HEADERS],
            )
        ]
    broad = [
        directive
        for directive in ("geolocation", "camera", "microphone")
        if directives.get(directive) in {"*", "(*)"}
    ]
    if broad:
        return [
            finding(
                "incorrectas",
                "advertencia",
                "media",
                "Permissions-Policy",
                "Funciones sensibles están permitidas globalmente",
                evidence=", ".join(f"{item}={directives[item]}" for item in broad),
                risk="Documentos embebidos de cualquier origen podrían solicitar esas capacidades.",
                recommendation="Usa allowlists mínimas o () cuando la función no sea necesaria.",
                references=[OWASP_HEADERS, MDN_PERMISSIONS],
            )
        ]
    return [
        finding(
            "correctas",
            "correcta",
            "informativa",
            "Permissions-Policy",
            "La política tiene sintaxis válida y no abre globalmente cámara, micrófono o geolocalización",
            evidence=combined,
            recommendation=(
                "Confirma que cada allowlist corresponde al funcionamiento real del sitio "
                "y deshabilita explícitamente las funciones que no necesite."
            ),
            references=[OWASP_HEADERS, MDN_PERMISSIONS],
        )
    ]


def analyze_cross_origin_headers(
    snapshot: ResponseSnapshot, excluded: set[str], profile: str
) -> list[Finding]:
    results: list[Finding] = []
    specs = [
        (
            "cross-origin-opener-policy",
            "Cross-Origin-Opener-Policy",
            {"same-origin", "same-origin-allow-popups", "noopener-allow-popups"},
            {"unsafe-none"},
            "same-origin",
            MDN_COOP,
            True,
        ),
        (
            "cross-origin-embedder-policy",
            "Cross-Origin-Embedder-Policy",
            {"require-corp", "credentialless"},
            {"unsafe-none"},
            "require-corp",
            MDN_COEP,
            True,
        ),
        (
            "cross-origin-resource-policy",
            "Cross-Origin-Resource-Policy",
            {"same-origin", "same-site"},
            {"cross-origin"},
            "same-site",
            MDN_CORP,
            False,
        ),
    ]
    for key, display, strong, weak, recommended, reference, allows_report_to in specs:
        if key in excluded:
            results.append(excluded_finding(key))
            continue
        values = snapshot.all(key)
        if not values:
            continue
        raw_value = values[0].strip()
        if allows_report_to:
            match = re.fullmatch(
                r"([A-Za-z-]+)(?:\s*;\s*report-to=(?:[!#$%&'*+\-.^_`|~0-9A-Za-z]+|\"[^\"\r\n]+\"))?",
                raw_value,
            )
            value = match.group(1).lower() if match else ""
        else:
            value = raw_value.lower() if re.fullmatch(r"[A-Za-z-]+", raw_value) else ""
        if len(values) > 1 or value not in strong | weak:
            results.append(
                finding(
                    "incorrectas",
                    "incorrecta",
                    "media",
                    display,
                    "La cabecera tiene un valor inválido o está duplicada",
                    evidence=" | ".join(values),
                    risk="El navegador puede aplicar el valor predeterminado menos restrictivo.",
                    recommendation=f"Revisa compatibilidad y usa {recommended} cuando corresponda.",
                    references=[OWASP_HEADERS, reference],
                )
            )
        elif value in weak:
            results.append(
                finding(
                    "contextuales",
                    "advertencia",
                    "baja",
                    display,
                    "La cabecera conserva una política permisiva",
                    evidence=values[0],
                    risk="No se obtiene el aislamiento cross-origin esperado.",
                    recommendation=f"Evalúa {recommended}; puede romper OAuth, pagos o recursos de terceros.",
                    references=[OWASP_HEADERS, reference],
                )
            )
        else:
            results.append(
                finding(
                    "correctas",
                    "correcta",
                    "informativa",
                    display,
                    "La cabecera tiene un valor reconocido y restrictivo",
                    evidence=values[0],
                    recommendation="Prueba integraciones cross-origin y flujos de ventanas emergentes.",
                    references=[OWASP_HEADERS, reference],
                )
            )
    return results


def analyze_integrity_policy(
    snapshot: ResponseSnapshot, excluded: set[str], profile: str
) -> list[Finding]:
    name = "integrity-policy"
    report_name = "integrity-policy-report-only"
    results: list[Finding] = []
    if name in excluded:
        results.append(excluded_finding(name))
    if report_name in excluded:
        results.append(excluded_finding(report_name))
    values = [] if name in excluded else snapshot.all(name)
    report_values = [] if report_name in excluded else snapshot.all(report_name)
    if not values and not report_values:
        return results
    for header, raw_values, report_only in (
        ("Integrity-Policy", values, False),
        ("Integrity-Policy-Report-Only", report_values, True),
    ):
        for value in raw_values:
            members: dict[str, list[str]] = {}
            malformed: list[str] = []
            for member in split_permissions_policy(value):
                match = re.fullmatch(
                    r"([a-z][a-z0-9-]*)\s*=\s*\(([^()]*)\)",
                    member,
                    re.IGNORECASE,
                )
                if not match or match.group(1).lower() in members:
                    malformed.append(member)
                    continue
                members[match.group(1).lower()] = match.group(2).split()
            blocked = members.get("blocked-destinations")
            invalid_destinations = set(blocked or []) - {"script", "style"}
            invalid_sources = set(members.get("sources", [])) - {"inline"}
            unknown_members = set(members) - {
                "blocked-destinations",
                "sources",
                "endpoints",
            }
            if (
                not blocked
                or malformed
                or invalid_destinations
                or invalid_sources
                or unknown_members
            ):
                details: list[str] = []
                if not blocked:
                    details.append("falta blocked-destinations")
                if malformed:
                    details.append("miembros malformados: " + "; ".join(malformed))
                if invalid_destinations:
                    details.append(
                        "destinos no reconocidos: "
                        + ", ".join(sorted(invalid_destinations))
                    )
                if invalid_sources:
                    details.append(
                        "sources no reconocidos: " + ", ".join(sorted(invalid_sources))
                    )
                if unknown_members:
                    details.append(
                        "miembros no reconocidos: " + ", ".join(sorted(unknown_members))
                    )
                results.append(
                    finding(
                        "incorrectas",
                        "incorrecta",
                        "media",
                        header,
                        "La política de integridad contiene sintaxis o destinos inválidos",
                        evidence=f"{value}; {'; '.join(details)}",
                        risk="La política puede no bloquear o reportar los destinos previstos.",
                        recommendation="Usa la sintaxis de Structured Fields definida por SRI 2.",
                        references=[
                            MDN_INTEGRITY_POLICY,
                            "https://www.w3.org/TR/sri-2/",
                        ],
                    )
                )
            else:
                results.append(
                    finding(
                        "contextuales" if report_only else "correctas",
                        "informativa" if report_only else "correcta",
                        "baja" if report_only else "informativa",
                        header,
                        (
                            "La política de integridad está en observación"
                            if report_only
                            else "La política exige metadatos de integridad"
                        ),
                        evidence=value,
                        risk="",
                        recommendation="Monitorea bloqueos y mantén hashes SRI actualizados.",
                        references=[
                            MDN_INTEGRITY_POLICY,
                            "https://www.w3.org/TR/sri-2/",
                        ],
                    )
                )
    return results


def analyze_content_disposition(
    snapshot: ResponseSnapshot, excluded: set[str]
) -> list[Finding]:
    name = "content-disposition"
    if name in excluded:
        return [excluded_finding(name)]
    values = snapshot.all(name)
    if not values:
        return []
    observed = " | ".join(values)
    if len(values) != 1:
        return [
            finding(
                "incorrectas",
                "incorrecta",
                "media",
                "Content-Disposition",
                "Se recibieron varios campos Content-Disposition",
                evidence=observed,
                risk="Los clientes pueden seleccionar parámetros distintos o ignorar la cabecera.",
                recommendation="Emite una sola cabecera Content-Disposition.",
                references=[IANA_HTTP_FIELDS],
            )
        ]

    parts, syntax_error = split_http_parameters(values[0])
    disposition = parts[0].lower() if parts else ""
    errors: list[str] = []
    warnings: list[str] = []
    if syntax_error:
        errors.append(syntax_error)
    if not disposition or not re.fullmatch(HTTP_FIELD_NAME_PATTERN, disposition):
        errors.append("tipo de disposición inválido")
    elif disposition not in {"inline", "attachment"}:
        warnings.append(f"tipo de extensión no habitual: {disposition}")

    parameters: dict[str, str] = {}
    for part in parts[1:]:
        if "=" not in part:
            errors.append(f"parámetro sin valor: {part or '<vacío>'}")
            continue
        raw_name, raw_value = part.split("=", 1)
        parameter = raw_name.strip().lower()
        raw_value = raw_value.strip()
        if not re.fullmatch(HTTP_FIELD_NAME_PATTERN, parameter) or not raw_value:
            errors.append(f"parámetro inválido: {part}")
            continue
        if parameter in parameters:
            errors.append(f"parámetro duplicado: {parameter}")
            continue
        decoded_value, value_error = parse_http_parameter_value(raw_value)
        if value_error:
            errors.append(f"valor inválido: {parameter} ({value_error})")
            continue
        parameters[parameter] = decoded_value

    filename = parameters.get("filename", "")
    extended_filename = parameters.get("filename*", "")
    if extended_filename:
        if not re.fullmatch(
            r"[A-Za-z0-9!#$%&+\-.^_`{}~]+\x27[^\x27]*\x27(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9!#$&+\-.^_`|~])*",
            extended_filename,
        ):
            errors.append("filename* no cumple la sintaxis RFC 5987")
        if re.search(r"%(?:00|0a|0d|2f|5c)", extended_filename, re.IGNORECASE):
            warnings.append("filename* codifica controles o separadores de ruta")
    if filename and (
        any(ord(char) < 32 or ord(char) == 127 for char in filename)
        or "/" in filename
        or "\\" in filename
        or filename in {".", ".."}
    ):
        warnings.append("filename contiene controles o componentes de ruta")

    if errors:
        return [
            finding(
                "incorrectas",
                "incorrecta",
                "media",
                "Content-Disposition",
                "La cabecera tiene sintaxis inválida o parámetros ambiguos",
                evidence=f"{observed}; observaciones: {', '.join(errors)}",
                risk="Los clientes pueden ignorar la disposición o interpretar de forma distinta el nombre sugerido.",
                recommendation="Usa inline o attachment y parámetros únicos correctamente citados.",
                references=[IANA_HTTP_FIELDS],
            )
        ]
    if warnings:
        return [
            finding(
                "contextuales",
                "advertencia",
                "media",
                "Content-Disposition",
                "La cabecera requiere revisión antes de usar el nombre de archivo",
                evidence=f"{observed}; observaciones: {', '.join(warnings)}",
                risk="Un cliente que no normalice el nombre podría escribir fuera del destino previsto o mostrar un nombre engañoso.",
                recommendation="Trata filename como dato no confiable y conserva únicamente el nombre base seguro.",
                references=[IANA_HTTP_FIELDS],
            )
        ]
    return [
        finding(
            "contextuales",
            "correcta",
            "informativa",
            "Content-Disposition",
            "La cabecera tiene una disposición y parámetros sintácticamente válidos",
            evidence=observed,
            recommendation="El consumidor debe seguir tratando filename como una sugerencia no confiable.",
            references=[IANA_HTTP_FIELDS],
        )
    ]


def analyze_cache_control(
    snapshot: ResponseSnapshot, excluded: set[str], *, sensitive_response: bool = False
) -> list[Finding]:
    results: list[Finding] = []
    cache_name = "cache-control"
    if cache_name in excluded:
        results.append(excluded_finding(cache_name))
    else:
        cache_values = snapshot.all(cache_name)
        if not cache_values and sensitive_response:
            results.append(
                finding(
                    "ausentes",
                    "ausente",
                    "media",
                    "Cache-Control",
                    "La respuesta marcada como sensible no declara una política de caché",
                    evidence="Cabecera no encontrada; se usó --sensitive-response.",
                    risk="Navegadores o cachés intermedias podrían almacenar la respuesta según sus reglas predeterminadas.",
                    recommendation="Usa Cache-Control: no-store para contenido que no deba almacenarse.",
                    references=[OWASP_HEADERS, MDN_CACHE_CONTROL],
                )
            )
        elif not cache_values:
            # Sin --sensitive-response no existe base para exigir no-store.
            # La ausencia de Cache-Control en contenido público no se muestra.
            pass
        elif cache_values:
            combined = ", ".join(cache_values)
            directives = {
                part.split("=", 1)[0].strip().lower()
                for value in cache_values
                for part in value.split(",")
                if part.strip()
            }
            problems: list[str] = []
            severity = "baja"
            if sensitive_response and "no-store" not in directives:
                problems.append(
                    "falta no-store para la respuesta marcada como sensible"
                )
                severity = "media"
            if "public" in directives and snapshot.has("set-cookie"):
                problems.append("public aparece en una respuesta que establece cookies")
                severity = "media"
            if "public" in directives and "private" in directives:
                problems.append("public y private son contradictorios")
                severity = "media"
            if problems:
                results.append(
                    finding(
                        "incorrectas",
                        "advertencia",
                        severity,
                        "Cache-Control",
                        "La política de caché requiere revisión contextual",
                        evidence=f"{combined}; observaciones: {', '.join(problems)}",
                        risk="Contenido sensible podría almacenarse o la política podría interpretarse de forma distinta a la intención.",
                        recommendation="Usa no-store para datos sensibles; usa private solo cuando el caché del usuario sea aceptable.",
                        references=[OWASP_HEADERS, MDN_CACHE_CONTROL],
                    )
                )
            else:
                results.append(
                    finding(
                        "correctas"
                        if sensitive_response and "no-store" in directives
                        else "contextuales",
                        "correcta"
                        if sensitive_response and "no-store" in directives
                        else "informativa",
                        "informativa",
                        "Cache-Control",
                        (
                            "La respuesta sensible impide almacenamiento con no-store"
                            if sensitive_response and "no-store" in directives
                            else "Se detectó una política explícita de caché"
                        ),
                        evidence=combined,
                        recommendation="Confirma que la política corresponda a la sensibilidad y al modelo de caché del endpoint.",
                        references=[OWASP_HEADERS, MDN_CACHE_CONTROL],
                    )
                )
    return results


def analyze_x_permitted_cross_domain_policies(
    snapshot: ResponseSnapshot, excluded: set[str]
) -> list[Finding]:
    results: list[Finding] = []
    xpcdp_name = "x-permitted-cross-domain-policies"
    if xpcdp_name in excluded:
        results.append(excluded_finding(xpcdp_name))
    else:
        values = snapshot.all(xpcdp_name)
        if values:
            allowed = {
                "none",
                "master-only",
                "by-content-type",
                "by-ftp-filename",
                "all",
                "none-this-response",
            }
            normalized = values[0].strip().lower()
            if len(values) > 1 or normalized not in allowed:
                results.append(
                    finding(
                        "incorrectas",
                        "incorrecta",
                        "media",
                        "X-Permitted-Cross-Domain-Policies",
                        "La meta-policy heredada tiene un valor inválido o está duplicada",
                        evidence=" | ".join(values),
                        risk="El cliente puede ignorar el control.",
                        recommendation="Usa none si no necesitas policy files heredados.",
                        references=[OWASP_SECURE_HEADERS, MDN_XPCDP],
                    )
                )
            elif normalized == "all":
                results.append(
                    finding(
                        "incorrectas",
                        "advertencia",
                        "media",
                        "X-Permitted-Cross-Domain-Policies",
                        "La meta-policy permite archivos de política en todo el sitio",
                        evidence=values[0],
                        risk="Clientes heredados podrían aceptar una política cross-domain más amplia de lo previsto.",
                        recommendation="Usa none salvo que exista una necesidad documentada.",
                        references=[OWASP_SECURE_HEADERS, MDN_XPCDP],
                    )
                )
            else:
                results.append(
                    finding(
                        "correctas" if normalized == "none" else "contextuales",
                        "correcta" if normalized == "none" else "informativa",
                        "informativa",
                        "X-Permitted-Cross-Domain-Policies",
                        "La meta-policy heredada tiene un valor reconocido",
                        evidence=values[0],
                        recommendation="Mantén el valor más restrictivo compatible con el servicio.",
                        references=[OWASP_SECURE_HEADERS, MDN_XPCDP],
                    )
                )
    return results


def analyze_clear_site_data(
    snapshot: ResponseSnapshot, excluded: set[str]
) -> list[Finding]:
    results: list[Finding] = []
    clear_name = "clear-site-data"
    if clear_name in excluded:
        results.append(excluded_finding(clear_name))
    elif snapshot.has(clear_name):
        values = snapshot.all(clear_name)
        tokens = [
            part.strip()
            for value in values
            for part in value.split(",")
            if part.strip()
        ]
        allowed_tokens = {
            '"cache"',
            '"clientHints"',
            '"cookies"',
            '"executionContexts"',
            '"prefetchCache"',
            '"prerenderCache"',
            '"storage"',
            '"*"',
        }
        invalid = [token for token in tokens if token not in allowed_tokens]
        if urlsplit(snapshot.url).scheme.lower() != "https":
            results.append(
                finding(
                    "incorrectas",
                    "advertencia",
                    "media",
                    "Clear-Site-Data",
                    "Clear-Site-Data se recibió fuera de un contexto HTTPS",
                    evidence=" | ".join(values),
                    risk="Los navegadores aplican este control únicamente en contextos seguros.",
                    recommendation="Emite la cabecera desde HTTPS.",
                    references=[MDN_CLEAR_SITE_DATA],
                )
            )
        elif invalid or not tokens:
            results.append(
                finding(
                    "incorrectas",
                    "incorrecta",
                    "media",
                    "Clear-Site-Data",
                    "La cabecera contiene directivas inválidas o sin comillas",
                    evidence=f"{' | '.join(values)}; inválidas: {', '.join(invalid) or '<sin tokens>'}",
                    risk="El navegador puede ignorar los tipos de datos que se pretendía limpiar.",
                    recommendation='Usa tokens entre comillas, por ejemplo "cookies", "storage".',
                    references=[MDN_CLEAR_SITE_DATA, OWASP_SECURE_HEADERS],
                )
            )
        else:
            results.append(
                finding(
                    "contextuales",
                    "correcta",
                    "informativa",
                    "Clear-Site-Data",
                    "La cabecera usa directivas reconocidas en un contexto seguro",
                    evidence=" | ".join(values),
                    recommendation="Confirma el alcance: cookies puede afectar el dominio registrable y sus subdominios.",
                    references=[MDN_CLEAR_SITE_DATA, OWASP_SECURE_HEADERS],
                )
            )
    return results


def analyze_dns_prefetch_control(
    snapshot: ResponseSnapshot, excluded: set[str]
) -> list[Finding]:
    results: list[Finding] = []
    dns_name = "x-dns-prefetch-control"
    if dns_name in excluded:
        results.append(excluded_finding(dns_name))
    elif snapshot.has(dns_name):
        values = snapshot.all(dns_name)
        normalized = values[0].strip().lower()
        if len(values) > 1 or normalized not in {"on", "off"}:
            results.append(
                finding(
                    "incorrectas",
                    "advertencia",
                    "baja",
                    "X-DNS-Prefetch-Control",
                    "La cabecera tiene un valor no reconocido o está duplicada",
                    evidence=" | ".join(values),
                    risk="El navegador puede conservar su comportamiento predeterminado.",
                    recommendation="Usa on u off; no dependas de esta cabecera para un control crítico.",
                    references=[OWASP_HEADERS, MDN_DNS_PREFETCH],
                )
            )
        else:
            results.append(
                finding(
                    "contextuales",
                    "informativa",
                    "informativa",
                    "X-DNS-Prefetch-Control",
                    "La configuración de DNS prefetch tiene un valor reconocido",
                    evidence=values[0],
                    recommendation="Usa off si no controlas los enlaces y la privacidad prima sobre la latencia.",
                    references=[OWASP_HEADERS, MDN_DNS_PREFETCH],
                )
            )
    return results


def analyze_contextual_response_headers(
    snapshot: ResponseSnapshot,
    excluded: set[str],
    *,
    sensitive_response: bool = False,
) -> list[Finding]:
    return [
        *analyze_content_disposition(snapshot, excluded),
        *analyze_cache_control(
            snapshot, excluded, sensitive_response=sensitive_response
        ),
        *analyze_x_permitted_cross_domain_policies(snapshot, excluded),
        *analyze_clear_site_data(snapshot, excluded),
        *analyze_dns_prefetch_control(snapshot, excluded),
    ]


def analyze_legacy_and_deprecated(
    snapshot: ResponseSnapshot, excluded: set[str]
) -> list[Finding]:
    results: list[Finding] = []
    deprecated = {
        "expect-ct": (
            "Expect-CT",
            "Los navegadores principales ya exigen Certificate Transparency y esta cabecera está retirada.",
            "Elimínala.",
            "baja",
        ),
        "public-key-pins": (
            "Public-Key-Pins",
            "HPKP fue retirado y una configuración histórica incorrecta podía causar denegación de servicio.",
            "Elimínala; usa Certificate Transparency y registros DNS CAA.",
            "media",
        ),
        "public-key-pins-report-only": (
            "Public-Key-Pins-Report-Only",
            "HPKP está retirado de los navegadores modernos.",
            "Elimínala.",
            "baja",
        ),
        "feature-policy": (
            "Feature-Policy",
            "Fue reemplazada por Permissions-Policy.",
            "Migra a Permissions-Policy con la sintaxis actual.",
            "baja",
        ),
        "x-content-security-policy": (
            "X-Content-Security-Policy",
            "Es una variante CSP obsoleta e inconsistente.",
            "Usa Content-Security-Policy.",
            "media",
        ),
        "x-webkit-csp": (
            "X-WebKit-CSP",
            "Es una variante CSP obsoleta e inconsistente.",
            "Usa Content-Security-Policy.",
            "media",
        ),
    }
    for key, (display, risk, recommendation, severity) in deprecated.items():
        if key in excluded:
            results.append(excluded_finding(key))
            continue
        values = snapshot.all(key)
        if values:
            results.append(
                finding(
                    "obsoletas",
                    "advertencia",
                    severity,
                    display,
                    "Se detectó una cabecera retirada u obsoleta",
                    evidence=" | ".join(values),
                    risk=risk,
                    recommendation=recommendation,
                    references=[OWASP_HEADERS, OWASP_SECURE_HEADERS],
                )
            )

    xss_name = "x-xss-protection"
    if xss_name in excluded:
        results.append(excluded_finding(xss_name))
    elif snapshot.has(xss_name):
        values = snapshot.all(xss_name)
        if len(values) == 1 and values[0].strip() == "0":
            results.append(
                finding(
                    "obsoletas",
                    "informativa",
                    "informativa",
                    "X-XSS-Protection",
                    "El filtro XSS heredado está desactivado explícitamente",
                    evidence=values[0],
                    recommendation="Puedes retirar la cabecera cuando no necesites documentar la desactivación.",
                    references=[OWASP_HEADERS, MDN_XXSSP],
                )
            )
        else:
            results.append(
                finding(
                    "obsoletas",
                    "incorrecta",
                    "media",
                    "X-XSS-Protection",
                    "El filtro XSS heredado está habilitado o mal configurado",
                    evidence=" | ".join(values),
                    risk="En navegadores antiguos el filtro puede introducir comportamientos inseguros; los modernos lo ignoran.",
                    recommendation="Elimina la cabecera o usa X-XSS-Protection: 0; basa la defensa en CSP y codificación segura.",
                    references=[OWASP_HEADERS, MDN_XXSSP],
                )
            )
    return results


DISCLOSURE_HEADERS: dict[str, tuple[str, str]] = {
    "server": ("Server", "Identifica o ayuda a perfilar el servidor web."),
    "x-powered-by": ("X-Powered-By", "Expone tecnologías o frameworks del backend."),
    "x-aspnet-version": ("X-AspNet-Version", "Expone la versión de ASP.NET."),
    "x-aspnetmvc-version": ("X-AspNetMvc-Version", "Expone la versión de ASP.NET MVC."),
    "x-generator": ("X-Generator", "Puede identificar el CMS o generador."),
    "x-runtime": ("X-Runtime", "Puede revelar el framework y tiempos internos."),
    "x-backend-server": (
        "X-Backend-Server",
        "Puede revelar nombres de infraestructura interna.",
    ),
    "x-served-by": (
        "X-Served-By",
        "Puede revelar nodos o detalles de infraestructura.",
    ),
    "x-debug-token": ("X-Debug-Token", "Expone un token de depuración."),
    "x-debug-token-link": (
        "X-Debug-Token-Link",
        "Expone una interfaz o vínculo de depuración.",
    ),
    "x-source-map": (
        "X-SourceMap",
        "Puede publicar la ubicación de código fuente mapeado.",
    ),
    "sourcemap": ("SourceMap", "Puede publicar la ubicación de código fuente mapeado."),
}


def analyze_disclosure(snapshot: ResponseSnapshot, excluded: set[str]) -> list[Finding]:
    results: list[Finding] = []
    for key, (display, risk) in DISCLOSURE_HEADERS.items():
        if key in excluded:
            results.append(excluded_finding(key))
            continue
        values = snapshot.all(key)
        if not values:
            continue
        value = " | ".join(values)
        severity = "media" if key.startswith("x-debug") else "baja"
        if key == "server" and not re.search(r"[/\s]\d+(?:\.\d+)+", value):
            severity = "informativa"
        results.append(
            finding(
                "divulgacion",
                "advertencia" if severity != "informativa" else "informativa",
                severity,
                display,
                "La respuesta expone información tecnológica o interna",
                evidence=value or "Valor vacío.",
                risk=risk + " No constituye por sí sola una vulnerabilidad explotable.",
                recommendation="Elimina el campo o usa un valor genérico cuando no sea necesario operacionalmente.",
                references=[OWASP_HEADERS],
            )
        )
    return results


def parse_set_cookie(raw: str) -> tuple[str, dict[str, str | None]]:
    parts = [part.strip() for part in raw.split(";") if part.strip()]
    if not parts or "=" not in parts[0]:
        return "<sin nombre>", {}
    name, _ = parts[0].split("=", 1)
    attributes: dict[str, str | None] = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            attributes[key.strip().lower()] = value.strip()
        else:
            attributes[part.lower()] = None
    return name.strip(), attributes


def duplicate_cookie_attributes(raw: str) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for part in [item.strip() for item in raw.split(";")][1:]:
        if not part:
            continue
        attribute = part.split("=", 1)[0].strip().lower()
        if attribute in seen:
            duplicates.add(attribute)
        seen.add(attribute)
    return duplicates


def cookie_evidence(name: str, attrs: Mapping[str, str | None]) -> str:
    flags = []
    display_names = {
        "secure": "Secure",
        "httponly": "HttpOnly",
        "samesite": "SameSite",
        "partitioned": "Partitioned",
        "path": "Path",
        "domain": "Domain",
        "max-age": "Max-Age",
        "expires": "Expires",
    }
    for key in (
        "secure",
        "httponly",
        "samesite",
        "partitioned",
        "path",
        "domain",
        "max-age",
        "expires",
    ):
        if key in attrs:
            value = attrs[key]
            flags.append(
                display_names[key] + (f"={value}" if value is not None else "")
            )
    return f"Cookie {name}; atributos: {', '.join(flags) if flags else 'ninguno'}; valor ocultado"


def analyze_cookies(snapshot: ResponseSnapshot, excluded: set[str]) -> list[Finding]:
    name = "set-cookie"
    if name in excluded:
        return [excluded_finding(name)]
    raw_cookies = snapshot.all(name)
    if not raw_cookies:
        return []
    results: list[Finding] = []
    secure_transport = urlsplit(snapshot.url).scheme.lower() == "https"
    session_name_re = re.compile(r"session|sess|auth|token|jwt|sid", re.IGNORECASE)

    for raw in raw_cookies:
        cookie_name, attrs = parse_set_cookie(raw)
        evidence = cookie_evidence(cookie_name, attrs)
        is_session_like = bool(session_name_re.search(cookie_name))
        issues: list[str] = []
        severity = "baja"
        duplicates = duplicate_cookie_attributes(raw)
        if duplicates:
            issues.append("atributos duplicados: " + ", ".join(sorted(duplicates)))
            severity = "media"
        for boolean_attribute in ("secure", "httponly", "partitioned"):
            if boolean_attribute in attrs and attrs[boolean_attribute] is not None:
                issues.append(f"{boolean_attribute} no debe llevar valor")
                severity = "media"
        if "secure" not in attrs:
            issues.append("falta Secure")
            severity = "media" if is_session_like else severity
        if not secure_transport:
            issues.append("la cookie fue emitida desde HTTP")
            severity = "media" if is_session_like else severity
        if is_session_like and "httponly" not in attrs:
            issues.append("falta HttpOnly")
            severity = "media"
        same_site = (attrs.get("samesite") or "").lower()
        if not same_site:
            issues.append("falta SameSite")
        elif same_site not in {"strict", "lax", "none"}:
            issues.append("SameSite no reconocido")
            severity = "media"
        elif same_site == "none" and "secure" not in attrs:
            issues.append("SameSite=None sin Secure")
            severity = "media"

        if "partitioned" in attrs and "secure" not in attrs:
            issues.append("Partitioned sin Secure")
            severity = "media"

        prefix_issue_count = len(issues)
        # RFC 6265bis compara los prefijos sin distinguir mayúsculas: un
        # ``__HOST-sesion`` recibe las mismas restricciones del navegador y no
        # debe escapar a la comprobación.
        lowered_name = cookie_name.lower()
        is_host_http = lowered_name.startswith(("__host-http-", "__hosthttp-"))
        if lowered_name.startswith("__secure-") and "secure" not in attrs:
            issues.append("prefijo __Secure- sin Secure")
        if lowered_name.startswith("__host-") or is_host_http:
            if "secure" not in attrs:
                issues.append("prefijo __Host- sin Secure")
            if attrs.get("path") != "/":
                issues.append("prefijo __Host- sin Path=/")
            if "domain" in attrs:
                issues.append("prefijo __Host- con Domain")
        if is_host_http:
            if "httponly" not in attrs:
                issues.append("prefijo __Host-Http- sin HttpOnly")
        elif lowered_name.startswith("__http-"):
            if "secure" not in attrs:
                issues.append("prefijo __Http- sin Secure")
            if "httponly" not in attrs:
                issues.append("prefijo __Http- sin HttpOnly")
        if len(issues) > prefix_issue_count:
            severity = "media"

        if issues:
            results.append(
                finding(
                    "cookies",
                    "advertencia",
                    severity,
                    "Set-Cookie",
                    f"La cookie {cookie_name} requiere revisión",
                    evidence=f"{evidence}; observaciones: {', '.join(issues)}",
                    risk=(
                        "Según el propósito de la cookie, puede aumentar la exposición a robo por script, "
                        "envío por canal no cifrado o solicitudes cross-site."
                    ),
                    recommendation="Confirma el propósito y aplica Secure, HttpOnly y SameSite con el valor funcional mínimo.",
                    references=[OWASP_HEADERS, MDN_COOKIES],
                )
            )
        else:
            results.append(
                finding(
                    "cookies",
                    "correcta",
                    "informativa",
                    "Set-Cookie",
                    f"La cookie {cookie_name} contiene los atributos de línea base",
                    evidence=evidence,
                    recommendation="Valida que SameSite corresponda a los flujos legítimos de la aplicación.",
                    references=[OWASP_HEADERS, MDN_COOKIES],
                )
            )
    return results


def is_serialized_cors_origin(value: str) -> bool:
    if value in {"*", "null"}:
        return True
    if "," in value or any(char.isspace() for char in value):
        return False
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc or parsed.username or parsed.password:
        return False
    return parsed.path in {"", "/"} and not parsed.query and not parsed.fragment


def analyze_cors(
    snapshot: ResponseSnapshot,
    excluded: set[str],
    probe: ResponseSnapshot | None = None,
    probe_origin: str = "",
) -> list[Finding]:
    name = "access-control-allow-origin"
    if name in excluded:
        return [excluded_finding(name)]
    observed = probe if probe is not None else snapshot
    values = observed.all(name)
    results: list[Finding] = []
    acao = values[0].strip() if values else ""
    credential_values = observed.all("access-control-allow-credentials")
    credentials_raw = credential_values[0].strip() if credential_values else ""
    credentials = len(credential_values) == 1 and credentials_raw == "true"
    refs = [OWASP_HEADERS, MDN_CORS]

    if len(values) > 1:
        results.append(
            finding(
                "cors",
                "incorrecta",
                "media",
                "Access-Control-Allow-Origin",
                "Se recibieron múltiples campos Access-Control-Allow-Origin",
                evidence=" | ".join(values),
                risk="Los navegadores rechazan respuestas con más de un origen permitido en ACAO.",
                recommendation="Devuelve un único origen o * solo para recursos realmente públicos y sin credenciales.",
                references=refs,
            )
        )
        return results

    if len(credential_values) > 1:
        results.append(
            finding(
                "cors",
                "incorrecta",
                "media",
                "Access-Control-Allow-Credentials",
                "Se recibieron múltiples campos Access-Control-Allow-Credentials",
                evidence=" | ".join(credential_values),
                risk="La respuesta CORS queda inválida o se interpreta de forma inconsistente.",
                recommendation="Emite como máximo un campo con el valor exacto true.",
                references=[MDN_CORS],
            )
        )
    elif credentials_raw and credentials_raw != "true":
        results.append(
            finding(
                "cors",
                "incorrecta",
                "media",
                "Access-Control-Allow-Credentials",
                "Access-Control-Allow-Credentials usa un valor no reconocido",
                evidence=f"Access-Control-Allow-Credentials: {credentials_raw}",
                risk="El único valor válido es true y distingue mayúsculas de minúsculas.",
                recommendation="Emite exactamente true cuando necesites credenciales; en caso contrario elimina la cabecera.",
                references=[MDN_CORS],
            )
        )

    if acao and not is_serialized_cors_origin(acao):
        results.insert(
            0,
            finding(
                "cors",
                "incorrecta",
                "media",
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Origin no contiene un único origen serializado válido",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                risk="Los navegadores rechazan listas separadas por comas y valores que no sean *, null o un origen exacto.",
                recommendation="Devuelve un solo origen exacto por respuesta y usa Vary: Origin si cambia dinámicamente.",
                references=refs,
            ),
        )
        return results

    if probe is not None and acao == probe_origin:
        results.insert(
            0,
            finding(
                "cors",
                "incorrecta",
                "alta" if credentials else "media",
                "Access-Control-Allow-Origin",
                "El servidor reflejó el origen no confiable utilizado por la prueba",
                evidence=(
                    f"Origin enviado: {probe_origin}; ACAO recibido: {acao}; "
                    f"credenciales: {credentials_raw or 'no declaradas'}"
                ),
                risk=(
                    "Un origen atacante podría leer la respuesta. Con credenciales válidas, el "
                    "navegador también puede incluir cookies permitidas por SameSite y por sus "
                    "controles de cookies de terceros."
                ),
                recommendation="Compara Origin contra una allowlist exacta y devuelve Vary: Origin.",
                references=refs,
            ),
        )
        vary_raw = ", ".join(probe.all("vary"))
        vary = {token.strip().lower() for token in vary_raw.split(",")}
        if "origin" not in vary:
            results.append(
                finding(
                    "cors",
                    "advertencia",
                    "media",
                    "Vary",
                    "La respuesta CORS dinámica no declara Vary: Origin",
                    evidence=f"Vary: {vary_raw or '<ausente>'}",
                    risk="Una caché compartida podría reutilizar una respuesta asociada a otro Origin.",
                    recommendation="Añade Vary: Origin cuando ACAO cambia según la solicitud.",
                    references=[MDN_CORS],
                )
            )
        return results

    if acao == "*" and credentials:
        results.insert(
            0,
            finding(
                "cors",
                "incorrecta",
                "media",
                "Access-Control-Allow-Origin",
                "ACAO=* se combina con credenciales",
                evidence="Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
                risk="Los navegadores bloquean esta combinación; indica una configuración defectuosa, no un bypass autenticado directo.",
                recommendation="Usa orígenes explícitos si necesitas credenciales.",
                references=refs,
            ),
        )
    elif acao == "*":
        results.insert(
            0,
            finding(
                "cors",
                "informativa",
                "baja",
                "Access-Control-Allow-Origin",
                "CORS permite lectura desde cualquier origen sin credenciales",
                evidence="Access-Control-Allow-Origin: *",
                risk="Es válido para recursos públicos, pero inapropiado para respuestas que deban ser privadas.",
                recommendation="Confirma que el recurso sea realmente público.",
                references=refs,
            ),
        )
    elif acao.lower() == "null":
        results.insert(
            0,
            finding(
                "cors",
                "incorrecta",
                "media",
                "Access-Control-Allow-Origin",
                "CORS confía en el origen null",
                evidence="Access-Control-Allow-Origin: null",
                risk="Documentos sandboxed y algunos esquemas locales pueden enviar Origin: null.",
                recommendation="Evita null y usa orígenes HTTPS explícitos.",
                references=refs,
            ),
        )
    elif probe is not None:
        results.insert(
            0,
            finding(
                "cors",
                "correcta",
                "informativa",
                "Access-Control-Allow-Origin",
                "La respuesta no autorizó el origen no confiable utilizado por la prueba",
                evidence=f"Origin enviado: {probe_origin}; ACAO recibido: {acao or '<ausente>'}",
                recommendation="La prueba cubre un único origen y no sustituye una revisión completa de la lógica CORS.",
                references=refs,
            ),
        )
    elif acao:
        results.insert(
            0,
            finding(
                "cors",
                "informativa",
                "informativa",
                "Access-Control-Allow-Origin",
                "CORS declara un origen específico",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                recommendation="Valida activamente que el servidor no refleje orígenes arbitrarios.",
                references=refs,
            ),
        )
    return results


def analyze_redirects(
    snapshots: Sequence[ResponseSnapshot], follow_redirects: bool
) -> list[Finding]:
    results: list[Finding] = []
    if len(snapshots) == 1:
        only = snapshots[0]
        if (
            300 <= only.status_code < 400
            and only.first("location")
            and not follow_redirects
        ):
            results.append(
                finding(
                    "redirecciones",
                    "informativa",
                    "baja",
                    "Location",
                    "La respuesta redirige, pero el seguimiento está desactivado",
                    evidence=f"{only.status_code} -> {only.first('location')}",
                    recommendation="Repite con --follow-redirects para analizar el destino final.",
                    references=[],
                )
            )
        return results

    for current, nxt in pairwise(snapshots):
        current_scheme = urlsplit(current.url).scheme.lower()
        next_scheme = urlsplit(nxt.url).scheme.lower()
        current_host = (urlsplit(current.url).hostname or "").lower()
        next_host = (urlsplit(nxt.url).hostname or "").lower()
        if current_scheme == "https" and next_scheme == "http":
            results.append(
                finding(
                    "redirecciones",
                    "incorrecta",
                    "alta",
                    "Location",
                    "La cadena degrada de HTTPS a HTTP",
                    evidence=f"{current.url} -> {nxt.url}",
                    risk="La navegación abandona el transporte cifrado.",
                    recommendation="Redirige únicamente hacia HTTPS.",
                    references=[OWASP_HSTS],
                )
            )
        if current_host != next_host:
            results.append(
                finding(
                    "redirecciones",
                    "informativa",
                    "baja",
                    "Location",
                    "La redirección cambia de host",
                    evidence=f"{current_host} -> {next_host}",
                    risk="Puede ser legítimo; confirma que el dominio de destino sea controlado y esperado.",
                    recommendation="Documenta redirecciones cross-origin y evita destinos construidos con datos no confiables.",
                    references=[],
                )
            )
    return results
