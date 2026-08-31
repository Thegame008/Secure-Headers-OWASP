"""Rules basic de SafeWebHeaders."""

from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .constants import (
    MDN_HSTS,
    MDN_REFERRER,
    MDN_XCTO,
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
    effective_response_kind,
    excluded_finding,
    finding,
)
from .utils import (
    HTTP_FIELD_NAME_PATTERN,
    parse_http_parameter_value,
    split_http_parameters,
)

HTTP_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
META_REFRESH_URL_RE = re.compile(
    r"(?:^|;)\s*url\s*=\s*(?P<target>.+?)\s*$", re.IGNORECASE | re.DOTALL
)


def extract_meta_refresh_url(content: str) -> str:
    """Extrae el destino ``url=`` de un atributo content de meta refresh."""

    match = META_REFRESH_URL_RE.search(content)
    if match is None:
        return ""
    target = match.group("target").strip()
    if len(target) >= 2 and target[0] == target[-1] and target[0] in {"'", '"'}:
        target = target[1:-1].strip()
    return target


class MetaRefreshParser(HTMLParser):
    """Parser mínimo que evita confundir texto o JavaScript con una etiqueta meta."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.target = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.target or tag.lower() != "meta":
            return
        normalized = {
            name.lower(): value.strip() if value is not None else ""
            for name, value in attrs
        }
        if normalized.get("http-equiv", "").lower() != "refresh":
            return
        self.target = extract_meta_refresh_url(normalized.get("content", ""))


def detect_meta_refresh_target(snapshot: ResponseSnapshot) -> str:
    """Detecta una navegación HTML del lado del cliente sin ejecutar el documento."""

    if 300 <= snapshot.status_code < 400 or not snapshot.body_preview:
        return ""
    content_type = snapshot.first("content-type").split(";", 1)[0].strip().lower()
    if content_type not in {"text/html", "application/xhtml+xml"}:
        return ""
    parser = MetaRefreshParser()
    try:
        parser.feed(snapshot.body_preview)
        parser.close()
    except (ValueError, AssertionError):
        return ""
    return urljoin(snapshot.url, parser.target) if parser.target else ""


def response_diagnostic_notes(
    snapshot: ResponseSnapshot, *, include_meta_refresh: bool = True
) -> list[str]:
    """Explica navegaciones no HTTP y barreras de autenticación observables."""

    notes: list[str] = []
    target = detect_meta_refresh_target(snapshot)
    if target and include_meta_refresh:
        notes.append(
            "Se detectó una redirección del lado del cliente (meta refresh) hacia "
            f"{target}. SafeWebHeaders no ejecuta JavaScript y no puede seguirla "
            "automáticamente sin --follow-redirects; usa ese parámetro para seguir "
            "esta navegación HTML o analiza la URL directamente."
        )

    if snapshot.status_code in {401, 403}:
        advertised = " ".join(snapshot.all("www-authenticate"))
        schemes = list(
            dict.fromkeys(
                match.group(0)
                for match in re.finditer(
                    r"\b(?:NTLM|Negotiate)\b", advertised, re.IGNORECASE
                )
            )
        )
        if schemes:
            notes.append(
                f"La respuesta {snapshot.status_code} anuncia autenticación "
                f"{'/'.join(schemes)} mediante WWW-Authenticate. Un flujo SSO/NTLM "
                "está bloqueando el acceso al contenido; configura una autenticación "
                "autorizada y vuelve a analizar el endpoint. No se trata de una "
                "redirección HTTP fallida."
            )
    return notes


def split_hsts_directives(value: str) -> tuple[list[str], str]:
    """Separa por punto y coma sin romper quoted-string de RFC 6797."""
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if quoted and char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            current.append(char)
            continue
        if char == ";" and not quoted:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    parts.append("".join(current).strip())
    if quoted or escaped:
        return parts, "quoted-string sin cierre o con escape incompleto"
    return parts, ""


def decode_hsts_directive_value(raw: str) -> tuple[str | None, str]:
    """Valida token/quoted-string y devuelve su valor sin escapes."""
    value = raw.strip()
    if not value:
        return None, "valor vacío después de ="
    if HTTP_TOKEN_RE.fullmatch(value):
        return value, ""
    if not value.startswith('"'):
        return None, f"valor no válido: {value}"

    decoded: list[str] = []
    index = 1
    while index < len(value):
        char = value[index]
        if char == '"':
            if index != len(value) - 1:
                return None, "texto adicional después de quoted-string"
            return "".join(decoded), ""
        if char == "\\":
            index += 1
            if index >= len(value):
                return None, "escape incompleto en quoted-string"
            char = value[index]
        if char in {"\r", "\n", "\x7f"} or (ord(char) < 32 and char != "\t"):
            return None, "carácter de control no permitido en quoted-string"
        decoded.append(char)
        index += 1
    return None, "quoted-string sin cierre"


def parse_hsts_directives(
    value: str,
) -> tuple[dict[str, str | None], list[str], list[str]]:
    directives: dict[str, str | None] = {}
    duplicates: list[str] = []
    invalid: list[str] = []
    parts, split_error = split_hsts_directives(value)
    if split_error:
        invalid.append(split_error)

    for part in parts:
        if not part:
            continue
        key, separator, raw_value = part.partition("=")
        normalized_key = key.strip().lower()
        if not HTTP_TOKEN_RE.fullmatch(normalized_key):
            invalid.append(f"nombre de directiva no válido: {key.strip() or '<vacío>'}")
            continue
        if normalized_key in directives:
            duplicates.append(normalized_key)
        if separator:
            decoded, value_error = decode_hsts_directive_value(raw_value)
            if value_error:
                invalid.append(f"{normalized_key}: {value_error}")
            directives[normalized_key] = decoded
        else:
            directives[normalized_key] = None
    return directives, duplicates, invalid


def analyze_hsts(snapshot: ResponseSnapshot, excluded: set[str]) -> list[Finding]:
    name = "strict-transport-security"
    if name in excluded:
        return [excluded_finding(name)]

    values = snapshot.all(name)
    scheme = urlsplit(snapshot.url).scheme.lower()
    refs = [OWASP_HSTS, MDN_HSTS]
    if scheme != "https":
        location = snapshot.first("location")
        redirect_target = urljoin(snapshot.url, location) if location else ""
        redirects_to_https = (
            300 <= snapshot.status_code < 400
            and urlsplit(redirect_target).scheme.lower() == "https"
        )
        if redirects_to_https:
            return [
                finding(
                    "contextuales",
                    "informativa",
                    "baja",
                    "Strict-Transport-Security",
                    "HSTS debe evaluarse en el destino HTTPS de la redirección",
                    evidence=(
                        f"{snapshot.status_code} {snapshot.url} -> {redirect_target}; "
                        + (
                            f"HSTS recibido por HTTP e ignorado: {values[0]}"
                            if values
                            else "HSTS no evaluable en este salto HTTP."
                        )
                    ),
                    risk="La respuesta HTTP no permite concluir si el destino HTTPS implementa HSTS.",
                    recommendation="Repite el análisis con --follow-redirects y revisa la respuesta HTTPS final.",
                    references=refs,
                )
            ]
        return [
            finding(
                "incorrectas" if values else "ausentes",
                "incorrecta" if values else "ausente",
                "alta",
                "Strict-Transport-Security",
                "HSTS no puede proteger una respuesta entregada por HTTP",
                evidence=values[0] if values else f"URL final: {snapshot.url}",
                risk=(
                    "El navegador ignora HSTS recibido por HTTP. La primera conexión puede quedar "
                    "expuesta a degradación de protocolo o SSL stripping."
                ),
                recommendation=(
                    "Publica el sitio únicamente por HTTPS y envía HSTS desde la respuesta HTTPS."
                ),
                references=refs,
            )
        ]

    hostname = urlsplit(snapshot.url).hostname or ""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        is_ip_address = False
    else:
        is_ip_address = True
    if is_ip_address:
        return [
            finding(
                "contextuales",
                "informativa" if not values else "advertencia",
                "baja",
                "Strict-Transport-Security",
                "HSTS no se almacena para direcciones IP",
                evidence=(
                    f"Host evaluado: {hostname}; valor recibido: {values[0]}"
                    if values
                    else f"Host evaluado: {hostname}; cabecera no encontrada."
                ),
                risk="Los navegadores identifican hosts HSTS por nombre de dominio, no por dirección IP.",
                recommendation="Evalúa el nombre DNS de producción que usarán los usuarios.",
                references=refs,
            )
        ]

    if not values:
        return [
            finding(
                "ausentes",
                "ausente",
                "media",
                "Strict-Transport-Security",
                "La respuesta HTTPS no implementa HSTS",
                evidence="Cabecera no encontrada.",
                risk=(
                    "Un usuario que aún no tenga una política HSTS almacenada puede ser inducido a "
                    "iniciar la navegación por HTTP."
                ),
                recommendation=(
                    "Tras confirmar HTTPS en el dominio y sus subdominios, usa la línea base de "
                    "OWASP: max-age=63072000; includeSubDomains. Activa preload solo de forma deliberada."
                ),
                references=refs,
            )
        ]

    if len(values) > 1:
        return [
            finding(
                "incorrectas",
                "incorrecta",
                "media",
                "Strict-Transport-Security",
                "Se recibieron múltiples campos HSTS y el resultado es ambiguo",
                evidence=" | ".join(values),
                risk=(
                    "RFC 6797 indica que el navegador procesa únicamente el primer campo; "
                    "intermediarios y herramientas pueden presentar el conjunto de forma diferente."
                ),
                recommendation="Emite una sola cabecera HSTS canónica.",
                references=[OWASP_WSTG_HEADERS, MDN_HSTS],
            )
        ]

    value = values[0]
    directives, duplicate_directives, invalid_parts = parse_hsts_directives(value)

    if duplicate_directives:
        invalid_parts.append(
            "directivas duplicadas: " + ", ".join(sorted(set(duplicate_directives)))
        )
    for flag in ("includesubdomains", "preload"):
        if flag in directives and directives[flag] is not None:
            invalid_parts.append(f"{flag} no admite valor")

    raw_max_age = directives.get("max-age")
    if raw_max_age is None or not re.fullmatch(r"[0-9]+", str(raw_max_age)):
        invalid_parts.append("max-age ausente o no numérico")
        max_age = -1
        oversized_max_age = False
    else:
        normalized_age = str(raw_max_age).lstrip("0") or "0"
        oversized_max_age = len(normalized_age) > 18
        # RFC 6797 no fija un máximo. Acotar la conversión evita que una
        # cabecera controlada por el servidor agote el límite de int() de
        # Python; para las comparaciones de línea base basta tratarla como un
        # valor superior a cualquier umbral usado aquí.
        max_age = 10**18 if oversized_max_age else int(normalized_age)

    known = {"max-age", "includesubdomains", "preload"}
    unknown = sorted(set(directives) - known)

    if invalid_parts:
        return [
            finding(
                "incorrectas",
                "incorrecta",
                "media",
                "Strict-Transport-Security",
                "La política HSTS tiene una sintaxis inválida o ambigua",
                evidence=f"{value} ({'; '.join(invalid_parts)})",
                risk="El navegador puede ignorar la política o aplicar una duración no prevista.",
                recommendation=(
                    "Usa una sola directiva max-age numérica con sintaxis RFC 6797; "
                    "includeSubDomains y preload son flags sin valor."
                ),
                references=refs,
            )
        ]

    if max_age == 0:
        return [
            finding(
                "incorrectas",
                "incorrecta",
                "alta",
                "Strict-Transport-Security",
                "HSTS está deshabilitado con max-age=0",
                evidence=value,
                risk="La política HSTS almacenada será eliminada por el navegador.",
                recommendation="Configura una duración positiva; OWASP propone 63072000 segundos.",
                references=refs,
            )
        ]

    # SafeWebHeaders usa como línea base la propuesta vigente del proyecto
    # OWASP Secure Headers: dos años e includeSubDomains. RFC 6797 permite una
    # política válida solo para el host, pero OWASP advierte que omitir la
    # cobertura de subdominios deja una superficie relevante. El resultado se
    # consolida para que HSTS nunca aparezca a la vez como correcta e
    # informativa/incorrecta.
    baseline_gaps: list[str] = []
    if max_age < 63_072_000:
        baseline_gaps.append(
            f"max-age={max_age} es inferior a los 63072000 segundos propuestos por OWASP"
        )
    if "includesubdomains" not in directives:
        baseline_gaps.append("falta includeSubDomains")
    if "preload" in directives and (
        max_age < 31_536_000 or "includesubdomains" not in directives
    ):
        baseline_gaps.append(
            "preload no cumple sus precondiciones mínimas (un año e includeSubDomains)"
        )

    policy_notes: list[str] = []
    if unknown:
        policy_notes.append(
            "directivas no reconocidas que un navegador conforme debe ignorar: "
            + ", ".join(unknown)
        )
    if oversized_max_age:
        policy_notes.append(
            "max-age es extremadamente grande; los clientes pueden limitar su duración efectiva"
        )
    ignored_note = "; " + "; ".join(policy_notes) if policy_notes else ""
    if baseline_gaps:
        return [
            finding(
                "incorrectas",
                "incorrecta",
                "media",
                "Strict-Transport-Security",
                "HSTS es válida para el host, pero no cumple la línea base reforzada de OWASP",
                evidence=f"{value}; brechas: {'; '.join(baseline_gaps)}{ignored_note}",
                risk=(
                    "La protección puede caducar antes de la referencia adoptada o no cubrir "
                    "subdominios, que conservan políticas HSTS independientes."
                ),
                recommendation=(
                    "Después de verificar HTTPS en todo el árbol necesario, usa "
                    "max-age=63072000; includeSubDomains. Añade preload únicamente tras una "
                    "decisión operativa y una validación específica."
                ),
                references=[OWASP_SECURE_HEADERS, *refs],
            )
        ]

    return [
        finding(
            "correctas",
            "correcta",
            "informativa",
            "Strict-Transport-Security",
            "HSTS cumple la línea base reforzada de OWASP",
            evidence=f"{value}{ignored_note}",
            recommendation=(
                "Mantén HTTPS operativo en el dominio y todos los subdominios cubiertos. "
                "No añadas preload sin revisar antes sus consecuencias."
            ),
            references=[OWASP_SECURE_HEADERS, *refs],
        )
    ]


def analyze_x_content_type_options(
    snapshot: ResponseSnapshot, excluded: set[str]
) -> list[Finding]:
    name = "x-content-type-options"
    if name in excluded:
        return [excluded_finding(name)]
    values = snapshot.all(name)
    refs = [OWASP_HEADERS, MDN_XCTO]
    if not values:
        return []
    normalized = [value.strip().lower() for value in values]
    if len(values) == 1 and normalized[0] == "nosniff":
        return [
            finding(
                "correctas",
                "correcta",
                "informativa",
                "X-Content-Type-Options",
                "La protección contra MIME sniffing está activa",
                evidence=values[0],
                references=refs,
            )
        ]
    return [
        finding(
            "incorrectas",
            "incorrecta",
            "media",
            "X-Content-Type-Options",
            "La cabecera tiene un valor no reconocido o está duplicada",
            evidence=" | ".join(values),
            risk="Los navegadores pueden ignorar una configuración diferente de nosniff.",
            recommendation="Emite una sola cabecera con el valor exacto nosniff.",
            references=[OWASP_WSTG_HEADERS, *refs],
        )
    ]


def parse_media_type(value: str) -> tuple[str, dict[str, str], str]:
    """Parsea Content-Type sin aceptar las recuperaciones permisivas de email."""

    parts, split_error = split_http_parameters(value)
    if split_error:
        return "", {}, split_error
    media_type = parts[0].lower() if parts else ""
    if not re.fullmatch(
        rf"{HTTP_FIELD_NAME_PATTERN}/{HTTP_FIELD_NAME_PATTERN}", media_type
    ):
        return "", {}, "El tipo MIME no tiene una sintaxis válida tipo/subtipo."

    parameters: dict[str, str] = {}
    for raw_parameter in parts[1:]:
        if "=" not in raw_parameter:
            return "", {}, f"El parámetro {raw_parameter!r} no tiene valor."
        parameter, raw_value = raw_parameter.split("=", 1)
        normalized = parameter.strip().lower()
        raw_value = raw_value.strip()
        if not re.fullmatch(HTTP_FIELD_NAME_PATTERN, normalized):
            return "", {}, f"El parámetro {parameter!r} no es válido."
        if normalized in parameters:
            return "", {}, f"El parámetro {normalized!r} está duplicado."
        decoded_value, value_error = parse_http_parameter_value(raw_value)
        if value_error:
            return "", {}, f"El valor de {normalized!r} {value_error}."
        parameters[normalized] = decoded_value
    return media_type, parameters, ""


def analyze_content_type(
    snapshot: ResponseSnapshot, excluded: set[str]
) -> list[Finding]:
    name = "content-type"
    if name in excluded:
        return [excluded_finding(name)]
    values = snapshot.all(name)
    if not values:
        return []
    if len(values) != 1 or not values[0].strip():
        return [
            finding(
                "incorrectas",
                "incorrecta",
                "media",
                "Content-Type",
                "La respuesta contiene un Content-Type vacío o duplicado",
                evidence=" | ".join(values) or "Valor vacío.",
                risk="Los clientes pueden interpretar de forma distinta el tipo del recurso.",
                recommendation="Emite un solo Content-Type con el MIME type correcto.",
                references=[OWASP_HEADERS],
            )
        ]
    value = values[0]
    media_type, parameters, syntax_error = parse_media_type(value)
    if syntax_error:
        return [
            finding(
                "incorrectas",
                "incorrecta",
                "media",
                "Content-Type",
                "La respuesta declara un Content-Type con sintaxis inválida",
                evidence=f"{value} — {syntax_error}",
                risk="Los clientes pueden interpretar de forma distinta un tipo de recurso mal formado.",
                recommendation="Emite un único tipo MIME válido y parámetros bien formados.",
                references=[OWASP_HEADERS],
            )
        ]
    if (
        media_type in {"text/html", "application/xhtml+xml"}
        and "charset" not in parameters
    ):
        return [
            finding(
                "incorrectas",
                "advertencia",
                "baja",
                "Content-Type",
                "La respuesta HTML no declara charset",
                evidence=value,
                risk="Una interpretación ambigua de caracteres puede facilitar errores de codificación.",
                recommendation="Declara, por ejemplo, text/html; charset=UTF-8.",
                references=[OWASP_HEADERS],
            )
        ]
    if "charset" in parameters and not parameters["charset"]:
        return [
            finding(
                "incorrectas",
                "incorrecta",
                "media",
                "Content-Type",
                "La respuesta declara un charset vacío",
                evidence=value,
                risk="La codificación queda ambigua pese a declarar el parámetro charset.",
                recommendation="Declara un charset válido, por ejemplo UTF-8.",
                references=[OWASP_HEADERS],
            )
        ]
    return [
        finding(
            "correctas",
            "correcta",
            "informativa",
            "Content-Type",
            "La respuesta declara explícitamente su tipo de contenido",
            evidence=value,
            recommendation="Conserva el MIME type y charset acordes con el recurso real.",
            references=[OWASP_HEADERS],
        )
    ]


def analyze_referrer_policy(
    snapshot: ResponseSnapshot, excluded: set[str], profile: str
) -> list[Finding]:
    name = "referrer-policy"
    if name in excluded:
        return [excluded_finding(name)]
    values = snapshot.all(name)
    refs = [OWASP_HEADERS, MDN_REFERRER]
    if not values:
        if effective_response_kind(snapshot, profile) != "document":
            return []
        category = "ausentes" if profile == "web" else "contextuales"
        status = "ausente" if profile == "web" else "informativa"
        severity = "media" if profile == "web" else "baja"
        return [
            finding(
                category,
                status,
                severity,
                "Referrer-Policy",
                (
                    "No se declaró Referrer-Policy: OWASP la recomienda, "
                    "pero no es una obligación del protocolo HTTP"
                ),
                evidence=(
                    "Cabecera no encontrada. Los navegadores modernos suelen aplicar "
                    "strict-origin-when-cross-origin como valor predeterminado."
                ),
                risk=(
                    "La ausencia no demuestra por sí sola una fuga en navegadores modernos. "
                    "Clientes antiguos o cambios del valor predeterminado pueden compartir más "
                    "información de navegación de la prevista."
                ),
                recommendation=(
                    "Para cumplir explícitamente la recomendación de OWASP y MDN, usa "
                    "strict-origin-when-cross-origin o una política más restrictiva."
                ),
                references=refs,
            )
        ]

    known = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }
    tokens: list[str] = []
    for value in values:
        tokens.extend(
            token.strip().lower() for token in value.split(",") if token.strip()
        )
    effective = next((token for token in reversed(tokens) if token in known), "")
    if not effective:
        return [
            finding(
                "incorrectas",
                "incorrecta",
                "media",
                "Referrer-Policy",
                "La política no contiene un valor reconocido",
                evidence=" | ".join(values),
                risk="El navegador usará su comportamiento por defecto.",
                recommendation="Configura strict-origin-when-cross-origin o no-referrer.",
                references=refs,
            )
        ]
    if effective == "unsafe-url":
        return [
            finding(
                "incorrectas",
                "incorrecta",
                "media",
                "Referrer-Policy",
                "La política puede divulgar la URL completa a otros orígenes",
                evidence=f"Valor efectivo: {effective}; recibido: {' | '.join(values)}",
                risk="Rutas y parámetros de consulta pueden enviarse mediante Referer.",
                recommendation="Sustituye unsafe-url por strict-origin-when-cross-origin o no-referrer.",
                references=refs,
            )
        ]
    if effective in {
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
    }:
        return [
            finding(
                "incorrectas",
                "advertencia",
                "baja",
                "Referrer-Policy",
                "La política es válida, pero menos restrictiva que la línea base recomendada",
                evidence=f"Valor efectivo: {effective}; recibido: {' | '.join(values)}",
                risk="Puede compartirse más contexto de navegación del necesario.",
                recommendation="Valora strict-origin-when-cross-origin.",
                references=refs,
            )
        ]
    return [
        finding(
            "correctas",
            "correcta",
            "informativa",
            "Referrer-Policy",
            "La política de Referer es restrictiva",
            evidence=f"Valor efectivo: {effective}; recibido: {' | '.join(values)}",
            references=refs,
        )
    ]
