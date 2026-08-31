"""Rules csp de SafeWebHeaders."""

from __future__ import annotations

import base64
import re
from collections import OrderedDict
from collections.abc import Callable, Sequence
from urllib.parse import urlsplit

from .constants import (
    GOOGLE_CSP_EVALUATOR,
    GOOGLE_STRICT_CSP,
    HTML_XFO,
    IANA_HTTP_FIELDS,
    MDN_CSP,
    MDN_CSP_FRAME_ANCESTORS,
    MDN_XFO,
    OWASP_CLICKJACKING,
    OWASP_CSP,
    OWASP_HEADERS,
    OWASP_SECURE_HEADERS,
    OWASP_WSTG_HEADERS,
    SEVERITY_RANK,
    W3C_CSP3,
    W3C_TRUSTED_TYPES,
)
from .models import (
    CSPPolicy,
    Finding,
    ResponseSnapshot,
)
from .profiles import (
    effective_response_kind,
    excluded_finding,
    finding,
)

CSP_KNOWN_DIRECTIVES = {
    "base-uri",
    "block-all-mixed-content",
    "child-src",
    "connect-src",
    "default-src",
    "fenced-frame-src",
    "font-src",
    "form-action",
    "frame-ancestors",
    "frame-src",
    "img-src",
    "manifest-src",
    "media-src",
    "navigate-to",
    "object-src",
    "plugin-types",
    "prefetch-src",
    "referrer",
    "reflected-xss",
    "report-to",
    "report-uri",
    "require-sri-for",
    "require-trusted-types-for",
    "sandbox",
    "script-src",
    "script-src-attr",
    "script-src-elem",
    "style-src",
    "style-src-attr",
    "style-src-elem",
    "trusted-types",
    "upgrade-insecure-requests",
    "webrtc",
    "worker-src",
}

CSP_VALUE_REQUIRED_DIRECTIVES = {
    "plugin-types",
    "referrer",
    "report-to",
    "report-uri",
    "require-sri-for",
    "require-trusted-types-for",
    "webrtc",
}
CSP_DEPRECATED_DIRECTIVES = {
    "block-all-mixed-content": "Los navegadores modernos bloquean o actualizan contenido mixto; la directiva fue retirada.",
    "plugin-types": "La directiva está obsoleta junto con los plugins heredados.",
    "referrer": "Usa la cabecera Referrer-Policy.",
    "reflected-xss": "La directiva está obsoleta; usa una CSP moderna y codificación de salida.",
    "navigate-to": "La propuesta fue retirada de CSP Level 3 y no debe usarse como control de navegación.",
    "prefetch-src": "La directiva es no estándar, está obsoleta y tiene soporte limitado.",
    "report-uri": "CSP3 la reemplaza por report-to; puede mantenerse temporalmente por compatibilidad.",
    "require-sri-for": "La directiva experimental fue retirada; considera Integrity-Policy.",
}


def split_csp_policy_list(raw: str) -> list[str]:
    """Separa una lista CSP serializada sin confundir comas entre comillas."""

    policies: list[str] = []
    current: list[str] = []
    quote = ""
    for char in raw:
        if char in {"'", '"'}:
            quote = "" if quote == char else char if not quote else quote
        if char == "," and not quote:
            policy = "".join(current).strip()
            if policy:
                policies.append(policy)
            current = []
            continue
        current.append(char)
    policy = "".join(current).strip()
    if policy:
        policies.append(policy)
    return policies


def parse_csp_header_values(values: Sequence[str]) -> list[str]:
    """Expande múltiples campos y políticas combinadas en una lista uniforme."""

    return [policy for value in values for policy in split_csp_policy_list(value)]


def parse_csp(raw: str) -> CSPPolicy:
    directives: OrderedDict[str, list[str]] = OrderedDict()
    duplicates: list[str] = []
    invalid: list[str] = []
    unknown: list[str] = []

    for segment in raw.split(";"):
        segment = segment.strip()
        if not segment:
            continue
        parts = segment.split()
        if not parts:
            continue
        name = parts[0].lower()
        if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
            invalid.append(segment)
            continue
        if name in directives:
            duplicates.append(name)
            continue  # El primer valor es el que conserva el parser CSP.
        values = parts[1:]
        directives[name] = values
        if name not in CSP_KNOWN_DIRECTIVES:
            unknown.append(name)
        if not values and name in CSP_VALUE_REQUIRED_DIRECTIVES:
            invalid.append(segment)

    return CSPPolicy(raw, directives, duplicates, invalid, unknown)


def csp_effective_values(
    policy: CSPPolicy, directive: str
) -> tuple[list[str] | None, str]:
    directive = directive.lower()
    fallbacks: dict[str, list[str]] = {
        "script-src": ["script-src", "default-src"],
        "script-src-elem": ["script-src-elem", "script-src", "default-src"],
        "script-src-attr": ["script-src-attr", "script-src", "default-src"],
        "style-src": ["style-src", "default-src"],
        "style-src-elem": ["style-src-elem", "style-src", "default-src"],
        "style-src-attr": ["style-src-attr", "style-src", "default-src"],
        "worker-src": ["worker-src", "child-src", "script-src", "default-src"],
        "frame-src": ["frame-src", "child-src", "default-src"],
        "object-src": ["object-src", "default-src"],
    }
    for candidate in fallbacks.get(directive, [directive, "default-src"]):
        values = policy.values(candidate)
        if values is not None:
            return values, candidate
    return None, ""


def csp_token_lower(token: str) -> str:
    return token.strip().lower()


CSP_GLOBAL_SCHEMES = {"http:", "https:", "ws:", "wss:"}
# ``https://*`` autoriza exactamente el mismo conjunto de hosts que ``https:``.
# Lo mismo ocurre con ``*://*`` y ``*:*``. Tratarlos como allowlist concreta
# ocultaba por completo el hallazgo correspondiente.
CSP_GLOBAL_HOST_RE = re.compile(
    r"(?:\*|(?:[a-z][a-z0-9+.\-]*|\*)://\*)(?::(?:\*|\d+))?",
    re.IGNORECASE,
)
CSP_BROAD_SCHEMES = {"data:"}


def csp_source_is_global(token: str) -> bool:
    """Indica si una source expression equivale a «cualquier origen»."""

    normalized = csp_token_lower(token)
    if normalized in CSP_GLOBAL_SCHEMES:
        return True
    return bool(CSP_GLOBAL_HOST_RE.fullmatch(normalized))


def csp_has_keyword(values: Sequence[str] | None, keyword: str) -> bool:
    if values is None:
        return False
    return keyword.lower() in {csp_token_lower(value) for value in values}


CSP_BASE64_VALUE = r"[A-Za-z0-9+/_-]+={0,2}"
NONCE_RE = re.compile(rf"^'nonce-({CSP_BASE64_VALUE})'$", re.IGNORECASE)
HASH_RE = re.compile(rf"^'(sha256|sha384|sha512)-({CSP_BASE64_VALUE})'$", re.IGNORECASE)
CSP_CRYPTO_SOURCE_RE = re.compile(
    r"(?P<open>['\"]?)(?P<kind>nonce|sha256|sha384|sha512)-"
    r"(?P<value>[^\s;'\"]+)(?P<close>['\"]?)",
    re.IGNORECASE,
)


def redact_csp_crypto_sources(value: str) -> str:
    """Oculta material nonce/hash en evidencias y reportes de hallazgos."""

    def replace(match: re.Match[str]) -> str:
        return (
            f"{match.group('open')}{match.group('kind')}-<oculto>{match.group('close')}"
        )

    return CSP_CRYPTO_SOURCE_RE.sub(replace, value)


def decode_base64_value(value: str) -> bytes | None:
    try:
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError):
        return None


def csp_nonces(values: Sequence[str] | None) -> list[tuple[str, bytes | None]]:
    nonces: list[tuple[str, bytes | None]] = []
    for value in values or []:
        match = NONCE_RE.match(value)
        if match:
            raw_nonce = match.group(1)
            nonces.append((raw_nonce, decode_base64_value(raw_nonce)))
    return nonces


def csp_hashes(values: Sequence[str] | None) -> list[tuple[str, str, bytes | None]]:
    hashes: list[tuple[str, str, bytes | None]] = []
    for value in values or []:
        match = HASH_RE.match(value)
        if match:
            algorithm, raw_hash = match.group(1).lower(), match.group(2)
            hashes.append((algorithm, raw_hash, decode_base64_value(raw_hash)))
    return hashes


def extract_csp_nonce_strings(snapshot: ResponseSnapshot) -> set[str]:
    result: set[str] = set()
    for raw in parse_csp_header_values(snapshot.all("content-security-policy")):
        policy = parse_csp(raw)
        for directive in ("script-src", "script-src-elem", "default-src"):
            values = policy.values(directive)
            if values is not None:
                result.update(nonce for nonce, _ in csp_nonces(values))
    return result


def downgrade_report_only(item: Finding) -> Finding:
    severity = item.severity
    if severity == "alta":
        severity = "media"
    status = item.status
    if status in {"incorrecta", "ausente"}:
        status = "advertencia"
    item.severity = severity
    item.status = status
    item.title = f"[Report-Only] {item.title}"
    item.risk = (
        "La política analizada no se aplica en modo de bloqueo. " + item.risk
    ).strip()
    return item


CSPFindingSink = Callable[[Finding], None]


def _analyze_csp_syntax(
    policy: CSPPolicy, *, report_only: bool, add: CSPFindingSink
) -> None:
    refs = [OWASP_CSP, MDN_CSP, GOOGLE_STRICT_CSP, GOOGLE_CSP_EVALUATOR]
    if policy.invalid_segments:
        add(
            finding(
                "csp",
                "incorrecta",
                "alta",
                "Content-Security-Policy",
                "La política contiene directivas sin valor o segmentos inválidos",
                evidence="; ".join(policy.invalid_segments),
                risk="Los segmentos inválidos se ignoran y pueden dejar recursos sin restricción.",
                recommendation="Corrige la sintaxis y valida nuevamente en navegador y CSP Evaluator.",
                references=refs,
            )
        )

    if policy.duplicates:
        add(
            finding(
                "csp",
                "advertencia",
                "media",
                "Content-Security-Policy",
                "La política repite directivas; las apariciones posteriores se ignoran",
                evidence=", ".join(sorted(set(policy.duplicates))),
                risk="Un valor aparentemente restrictivo puede no ser el que aplica el navegador.",
                recommendation="Declara cada directiva una sola vez dentro de cada política.",
                references=[W3C_CSP3, OWASP_WSTG_HEADERS],
            )
        )

    if policy.unknown_directives:
        add(
            finding(
                "csp",
                "advertencia",
                "baja",
                "Content-Security-Policy",
                "Se detectaron nombres de directiva no reconocidos por este analizador",
                evidence=", ".join(sorted(set(policy.unknown_directives))),
                risk="Un navegador puede ignorar una directiva desconocida o con un error tipográfico.",
                recommendation="Contrasta cada nombre con CSP Level 3 y la compatibilidad del navegador.",
                references=[W3C_CSP3, MDN_CSP],
            )
        )

    if report_only and "sandbox" in policy.directives:
        add(
            finding(
                "csp",
                "informativa",
                "baja",
                "Content-Security-Policy-Report-Only",
                "sandbox se ignora dentro de una política Report-Only",
                evidence="sandbox " + " ".join(policy.directives["sandbox"]),
                risk="Las restricciones sandbox no se aplican ni pueden probarse con esta cabecera de monitoreo.",
                recommendation="Prueba sandbox en un entorno controlado antes de moverlo a una CSP aplicada.",
                references=[MDN_CSP, W3C_CSP3],
            )
        )

    if report_only and not ({"report-to", "report-uri"} & policy.directives.keys()):
        add(
            finding(
                "csp",
                "advertencia",
                "media",
                "Content-Security-Policy-Report-Only",
                "La política de monitoreo no declara un destino de reportes",
                evidence="No se encontró report-to ni el fallback heredado report-uri.",
                risk="No se enviarán reportes de violación a un colector remoto.",
                recommendation="Añade report-to y Reporting-Endpoints; conserva report-uri temporalmente si necesitas compatibilidad.",
                references=[MDN_CSP, W3C_CSP3],
            )
        )

    for directive, values in policy.directives.items():
        lowered = [csp_token_lower(value) for value in values]
        if "'none'" in lowered and len(values) > 1:
            add(
                finding(
                    "csp",
                    "advertencia",
                    "media",
                    "Content-Security-Policy",
                    f"{directive} combina 'none' con otras fuentes",
                    evidence=f"{directive} {' '.join(values)}",
                    risk="El valor 'none' no aporta la restricción esperada cuando comparte la lista.",
                    recommendation="Usa 'none' como único valor o elimina ese token.",
                    references=[W3C_CSP3, MDN_CSP],
                )
            )
        for keyword in (
            "self",
            "none",
            "unsafe-inline",
            "unsafe-eval",
            "strict-dynamic",
        ):
            if keyword in lowered:
                add(
                    finding(
                        "csp",
                        "incorrecta",
                        "media",
                        "Content-Security-Policy",
                        f"La palabra clave {keyword} no está entre comillas simples",
                        evidence=f"{directive} {' '.join(values)}",
                        risk="El token no será interpretado como la palabra clave CSP prevista.",
                        recommendation=f"Usa '{keyword}'.",
                        references=[W3C_CSP3, MDN_CSP],
                    )
                )
        for token in values:
            if re.match(r"^(?:nonce-|sha(?:256|384|512)-)", token, re.IGNORECASE):
                add(
                    finding(
                        "csp",
                        "incorrecta",
                        "alta",
                        "Content-Security-Policy",
                        "Una expresión nonce/hash no está entre comillas simples",
                        evidence=f"{directive} {token}",
                        risk="El navegador no la interpretará como una source expression criptográfica válida.",
                        recommendation="Usa el formato 'nonce-BASE64' o 'sha256-BASE64'.",
                        references=[W3C_CSP3, MDN_CSP],
                    )
                )
            quoted_crypto = token.lower().startswith("'nonce-") or bool(
                re.match(r"^'sha(?:256|384|512)-", token, re.IGNORECASE)
            )
            if quoted_crypto and not (
                NONCE_RE.fullmatch(token) or HASH_RE.fullmatch(token)
            ):
                add(
                    finding(
                        "csp",
                        "incorrecta",
                        "alta",
                        "Content-Security-Policy",
                        "Una expresión nonce/hash tiene sintaxis no válida",
                        evidence=f"{directive} {token}",
                        risk="El navegador ignorará la source expression mal formada.",
                        recommendation="Usa comillas simples y caracteres Base64/Base64URL en el token.",
                        references=[W3C_CSP3, MDN_CSP],
                    )
                )

    trusted_types_required = policy.values("require-trusted-types-for")
    if trusted_types_required is not None and [
        csp_token_lower(value) for value in trusted_types_required
    ] != ["'script'"]:
        add(
            finding(
                "csp",
                "incorrecta",
                "media",
                "Content-Security-Policy",
                "require-trusted-types-for no contiene el único valor válido",
                evidence=(
                    "require-trusted-types-for " + " ".join(trusted_types_required)
                ).rstrip(),
                risk="El navegador ignorará valores distintos de 'script' y no exigirá Trusted Types en los sinks DOM XSS.",
                recommendation="Usa require-trusted-types-for 'script' y prueba compatibilidad antes de aplicar.",
                references=[W3C_TRUSTED_TYPES, MDN_CSP],
            )
        )

    webrtc_values = policy.values("webrtc")
    if webrtc_values is not None:
        normalized_webrtc = [csp_token_lower(value) for value in webrtc_values]
        if normalized_webrtc not in [["'allow'"], ["'block'"]]:
            add(
                finding(
                    "csp",
                    "incorrecta",
                    "media",
                    "Content-Security-Policy",
                    "La directiva webrtc tiene un valor inválido",
                    evidence=("webrtc " + " ".join(webrtc_values)).rstrip(),
                    risk="CSP Level 3 solo define 'allow' y 'block' para esta directiva.",
                    recommendation="Usa webrtc 'block' si la aplicación no necesita conexiones WebRTC.",
                    references=[W3C_CSP3],
                )
            )
        else:
            add(
                finding(
                    "csp",
                    "informativa",
                    "baja",
                    "Content-Security-Policy",
                    "La política declara explícitamente el control WebRTC",
                    evidence=f"webrtc {webrtc_values[0]}",
                    risk="El soporte puede variar; 'allow' conserva las conexiones WebRTC y 'block' las restringe.",
                    recommendation="Elige el valor según la funcionalidad y valida navegadores objetivo.",
                    references=[W3C_CSP3],
                )
            )

    sandbox_values = policy.values("sandbox")
    if sandbox_values is not None:
        sandbox_flags = {
            "allow-downloads",
            "allow-forms",
            "allow-modals",
            "allow-orientation-lock",
            "allow-pointer-lock",
            "allow-popups",
            "allow-popups-to-escape-sandbox",
            "allow-presentation",
            "allow-same-origin",
            "allow-scripts",
            "allow-storage-access-by-user-activation",
            "allow-top-navigation",
            "allow-top-navigation-by-user-activation",
            "allow-top-navigation-to-custom-protocols",
        }
        invalid_sandbox_flags = sorted(
            value for value in sandbox_values if value.lower() not in sandbox_flags
        )
        if invalid_sandbox_flags:
            add(
                finding(
                    "csp",
                    "advertencia",
                    "media",
                    "Content-Security-Policy",
                    "sandbox contiene flags no reconocidos",
                    evidence="sandbox " + " ".join(invalid_sandbox_flags),
                    risk="Los flags desconocidos se ignoran y pueden ocultar un error de configuración.",
                    recommendation="Conserva únicamente tokens sandbox definidos por HTML.",
                    references=[W3C_CSP3, MDN_CSP],
                )
            )


def _analyze_script_execution_tokens(
    policy: CSPPolicy,
    *,
    script_values: list[str],
    script_source: str,
    lowered_scripts: list[str],
    has_nonce_or_hash: bool,
    add: CSPFindingSink,
) -> None:
    refs = [OWASP_CSP, MDN_CSP, GOOGLE_STRICT_CSP, GOOGLE_CSP_EVALUATOR]
    if "'unsafe-inline'" in lowered_scripts:
        if has_nonce_or_hash:
            add(
                finding(
                    "csp",
                    "informativa",
                    "baja",
                    "Content-Security-Policy",
                    "'unsafe-inline' actúa como fallback y se ignora en navegadores con nonce/hash",
                    evidence=f"Directiva efectiva: {script_source} {' '.join(script_values)}",
                    risk="Navegadores CSP antiguos pueden aplicar el fallback permisivo.",
                    recommendation="Conserva el fallback solo si necesitas compatibilidad heredada y está probado.",
                    references=[MDN_CSP, GOOGLE_STRICT_CSP],
                )
            )
        else:
            granular_overrides = all(
                policy.values(directive) is not None
                and not csp_has_keyword(policy.values(directive), "'unsafe-inline'")
                for directive in ("script-src-elem", "script-src-attr")
            )
            add(
                finding(
                    "csp",
                    "advertencia" if granular_overrides else "incorrecta",
                    "media" if granular_overrides else "alta",
                    "Content-Security-Policy",
                    (
                        "script-src contiene 'unsafe-inline', pero las directivas granulares lo restringen"
                        if granular_overrides
                        else "La fuente efectiva de scripts permite 'unsafe-inline'"
                    ),
                    evidence=f"Directiva efectiva: {script_source} {' '.join(script_values)}",
                    risk=(
                        "script-src-elem y script-src-attr reducen el alcance, pero conviene comprobar "
                        "javascript: URLs y navegadores sin soporte granular."
                        if granular_overrides
                        else "Se permite JavaScript inline y manejadores de evento, reduciendo fuertemente la mitigación XSS."
                    ),
                    recommendation=(
                        "Elimina el fallback cuando la compatibilidad lo permita."
                        if granular_overrides
                        else "Migra a nonces o hashes y elimina el inline no confiable."
                    ),
                    references=refs,
                )
            )
    if "'unsafe-eval'" in lowered_scripts:
        add(
            finding(
                "csp",
                "incorrecta",
                "media",
                "Content-Security-Policy",
                "La fuente efectiva de scripts permite 'unsafe-eval'",
                evidence=f"Directiva efectiva: {script_source} {' '.join(script_values)}",
                risk="APIs como eval() pueden ejecutar cadenas como código y amplificar una inyección.",
                recommendation="Elimina unsafe-eval y refactoriza las dependencias que lo requieren.",
                references=refs,
            )
        )
    if "'wasm-unsafe-eval'" in lowered_scripts:
        add(
            finding(
                "csp",
                "advertencia",
                "baja",
                "Content-Security-Policy",
                "La política permite compilación dinámica de WebAssembly",
                evidence=f"Directiva efectiva: {script_source} {' '.join(script_values)}",
                risk="Amplía las capacidades de ejecución disponibles al código de la página.",
                recommendation="Mantén wasm-unsafe-eval solo si la aplicación lo necesita.",
                references=[MDN_CSP, W3C_CSP3],
            )
        )


def _analyze_script_source_scope(
    *,
    script_values: list[str],
    script_source: str,
    strict_dynamic_effective: bool,
    has_strict_dynamic: bool,
    has_nonce_or_hash: bool,
    add: CSPFindingSink,
) -> None:
    dangerous_schemes = [
        value
        for value in script_values
        if csp_token_lower(value) != "*"
        and (
            csp_token_lower(value) in CSP_BROAD_SCHEMES or csp_source_is_global(value)
        )
    ]
    if dangerous_schemes:
        add(
            finding(
                "csp",
                "incorrecta" if not strict_dynamic_effective else "advertencia",
                "alta" if not strict_dynamic_effective else "baja",
                "Content-Security-Policy",
                "La fuente de scripts contiene esquemas demasiado amplios",
                evidence=f"{script_source}: {', '.join(dangerous_schemes)}",
                risk=(
                    "Permitir un esquema completo puede autorizar scripts desde una cantidad no controlada de orígenes. "
                    "Con strict-dynamic y nonce/hash, estos fallbacks se ignoran en navegadores compatibles."
                ),
                recommendation="Usa una CSP strict y limita los fallbacks a la compatibilidad realmente necesaria.",
                references=[GOOGLE_CSP_EVALUATOR, GOOGLE_STRICT_CSP],
            )
        )
    if "*" in script_values:
        add(
            finding(
                "csp",
                "advertencia" if strict_dynamic_effective else "incorrecta",
                "baja" if strict_dynamic_effective else "alta",
                "Content-Security-Policy",
                (
                    "El comodín global actúa como fallback y strict-dynamic lo ignora en navegadores compatibles"
                    if strict_dynamic_effective
                    else "La fuente efectiva de scripts permite el comodín global"
                ),
                evidence=f"Directiva efectiva: {script_source} {' '.join(script_values)}",
                risk="Scripts de orígenes no confiables pueden quedar autorizados.",
                recommendation="Elimina * y adopta nonce/hash con strict-dynamic.",
                references=[GOOGLE_CSP_EVALUATOR, GOOGLE_STRICT_CSP],
            )
        )
    wildcard_hosts = [
        value
        for value in script_values
        if "*" in value
        and csp_token_lower(value) != "*"
        and not csp_source_is_global(value)
        and not value.startswith("'nonce-")
    ]
    if wildcard_hosts:
        add(
            finding(
                "csp",
                "advertencia",
                "baja" if strict_dynamic_effective else "media",
                "Content-Security-Policy",
                "La lista de scripts confía en hosts con comodín",
                evidence=", ".join(wildcard_hosts),
                risk="Un subdominio comprometido o controlable puede convertirse en una fuente de script permitida.",
                recommendation="Enumera orígenes indispensables o migra a una CSP strict.",
                references=[GOOGLE_STRICT_CSP, GOOGLE_CSP_EVALUATOR],
            )
        )

    if has_strict_dynamic and not has_nonce_or_hash:
        add(
            finding(
                "csp",
                "incorrecta",
                "alta",
                "Content-Security-Policy",
                "'strict-dynamic' no tiene un nonce o hash que establezca confianza",
                evidence=f"Directiva efectiva: {script_source} {' '.join(script_values)}",
                risk="La directiva no aporta el modelo de confianza esperado.",
                recommendation="Añade un nonce criptográfico por respuesta o hashes válidos.",
                references=[W3C_CSP3, GOOGLE_STRICT_CSP],
            )
        )


def _analyze_script_crypto_sources(
    *,
    script_values: list[str],
    script_source: str,
    nonces: list[tuple[str, bytes | None]],
    hashes: list[tuple[str, str, bytes | None]],
    has_nonce_or_hash: bool,
    has_strict_dynamic: bool,
    reused_nonces: set[str] | None,
    add: CSPFindingSink,
) -> None:
    for nonce, decoded in nonces:
        if decoded is None:
            add(
                finding(
                    "csp",
                    "advertencia",
                    "media",
                    "Content-Security-Policy",
                    "No fue posible confirmar que el nonce contiene 128 bits",
                    evidence="El token usa caracteres permitidos, pero no tiene una codificación Base64 canónica; valor ocultado.",
                    risk="La sintaxis puede ser aceptada por CSP, pero el análisis estático no puede confirmar entropía suficiente.",
                    recommendation="Genera 128 bits aleatorios y usa una codificación Base64 canónica en cada respuesta.",
                    references=[GOOGLE_STRICT_CSP, W3C_CSP3],
                )
            )
        elif len(decoded) < 16:
            add(
                finding(
                    "csp",
                    "advertencia",
                    "media",
                    "Content-Security-Policy",
                    "El nonce contiene menos de 128 bits",
                    evidence=f"Longitud decodificada: {len(decoded) * 8} bits",
                    risk="Un nonce corto puede ser más predecible o vulnerable a colisiones.",
                    recommendation="Usa al menos 128 bits aleatorios por respuesta.",
                    references=[GOOGLE_STRICT_CSP],
                )
            )
        if re.search(r"\{.*\}|random|nonce|replace|example", nonce, re.IGNORECASE):
            add(
                finding(
                    "csp",
                    "advertencia",
                    "alta",
                    "Content-Security-Policy",
                    "El nonce parece ser un marcador estático o de ejemplo",
                    evidence="Se detectó un patrón textual de marcador; valor ocultado.",
                    risk="Un nonce conocido o reutilizado no impide que un atacante autorice su propio script.",
                    recommendation="Genera un valor criptográfico nuevo para cada respuesta.",
                    references=[GOOGLE_STRICT_CSP],
                )
            )
        if reused_nonces and nonce in reused_nonces:
            add(
                finding(
                    "csp",
                    "incorrecta",
                    "alta",
                    "Content-Security-Policy",
                    "El nonce se repitió en dos respuestas independientes",
                    evidence="El mismo nonce apareció en ambas solicitudes; su valor fue ocultado.",
                    risk="La reutilización elimina la propiedad de uso único y debilita la mitigación XSS.",
                    recommendation="Genera el nonce de forma criptográfica en cada respuesta HTTP.",
                    references=[GOOGLE_STRICT_CSP],
                )
            )

    expected_hash_lengths = {"sha256": 32, "sha384": 48, "sha512": 64}
    for algorithm, _, decoded in hashes:
        if decoded is None or len(decoded) != expected_hash_lengths[algorithm]:
            add(
                finding(
                    "csp",
                    "incorrecta",
                    "alta",
                    "Content-Security-Policy",
                    f"Se detectó un hash {algorithm} inválido",
                    evidence="El valor del hash fue ocultado; longitud o Base64 no válidos.",
                    risk="La expresión no autorizará el script previsto y puede generar una falsa sensación de protección.",
                    recommendation="Calcula el digest correcto y codifícalo en Base64.",
                    references=[MDN_CSP, W3C_CSP3],
                )
            )

    if has_nonce_or_hash:
        add(
            finding(
                "csp",
                "correcta",
                "informativa",
                "Content-Security-Policy",
                "La autorización de scripts usa nonce o hash",
                evidence=(
                    f"Directiva efectiva: {script_source}; nonces: {len(nonces)}; hashes: {len(hashes)}; "
                    f"strict-dynamic: {'sí' if has_strict_dynamic else 'no'}"
                ),
                recommendation=(
                    "Verifica que los nonces roten por respuesta y que cada etiqueta autorizada tenga el valor correcto."
                ),
                references=[GOOGLE_STRICT_CSP, MDN_CSP],
            )
        )
    elif not script_values or (
        len(script_values) == 1 and csp_has_keyword(script_values, "'none'")
    ):
        explicit_none = bool(script_values)
        add(
            finding(
                "csp",
                "correcta",
                "informativa",
                "Content-Security-Policy",
                (
                    "La política bloquea toda carga y ejecución de scripts"
                    if explicit_none
                    else "La lista vacía bloquea toda carga y ejecución de scripts"
                ),
                evidence=(
                    f"Directiva efectiva: {script_source} 'none'"
                    if explicit_none
                    else f"Directiva efectiva: {script_source} (lista vacía)"
                ),
                risk=(
                    "La lista de fuentes bloquea scripts de todos los orígenes."
                    if explicit_none
                    else "CSP Level 3 trata una lista de fuentes vacía como equivalente a 'none'."
                ),
                recommendation=(
                    "Mantén 'none' mientras el documento no deba ejecutar JavaScript."
                    if explicit_none
                    else "Usa 'none' de forma explícita si quieres que la intención sea más legible."
                ),
                references=[W3C_CSP3],
            )
        )
    else:
        add(
            finding(
                "csp",
                "advertencia",
                "media",
                "Content-Security-Policy",
                "La política de scripts está basada en allowlists y no es una CSP strict",
                evidence=f"Directiva efectiva: {script_source} {' '.join(script_values)}",
                risk="Las allowlists son difíciles de mantener y un origen permitido puede contener endpoints aprovechables.",
                recommendation="Evalúa una migración progresiva a nonce/hash y strict-dynamic.",
                references=[OWASP_CSP, GOOGLE_STRICT_CSP],
            )
        )


def _analyze_granular_script_sources(policy: CSPPolicy, *, add: CSPFindingSink) -> None:
    for granular_directive in ("script-src-elem", "script-src-attr"):
        granular_values = policy.values(granular_directive)
        if granular_values is None:
            continue
        lowered_granular = [csp_token_lower(value) for value in granular_values]
        granular_crypto = bool(
            csp_nonces(granular_values) or csp_hashes(granular_values)
        )
        if "'unsafe-inline'" in lowered_granular and not granular_crypto:
            add(
                finding(
                    "csp",
                    "incorrecta",
                    "alta",
                    "Content-Security-Policy",
                    f"{granular_directive} permite contenido JavaScript inline",
                    evidence=f"{granular_directive} {' '.join(granular_values)}",
                    risk="La directiva granular autoriza el tipo de JavaScript inline que controla.",
                    recommendation="Usa 'none', nonces/hashes compatibles o elimina los manejadores inline.",
                    references=[MDN_CSP, GOOGLE_CSP_EVALUATOR],
                )
            )
        if "'unsafe-hashes'" in lowered_granular:
            add(
                finding(
                    "csp",
                    "advertencia",
                    "media",
                    "Content-Security-Policy",
                    f"{granular_directive} permite 'unsafe-hashes'",
                    evidence=f"{granular_directive} {' '.join(granular_values)}",
                    risk="Hashes concretos pueden autorizar manejadores inline reutilizables en contextos no previstos.",
                    recommendation="Prefiere addEventListener y elimina manejadores inline cuando sea posible.",
                    references=[GOOGLE_CSP_EVALUATOR, MDN_CSP],
                )
            )
        broad = [
            value
            for value in granular_values
            if csp_token_lower(value) in CSP_BROAD_SCHEMES
            or csp_source_is_global(value)
        ]
        if broad:
            add(
                finding(
                    "csp",
                    "incorrecta",
                    "alta",
                    "Content-Security-Policy",
                    f"{granular_directive} contiene fuentes globales o esquemas amplios",
                    evidence=f"{granular_directive}: {', '.join(broad)}",
                    risk="La directiva granular puede autorizar scripts desde orígenes no controlados.",
                    recommendation="Reduce las fuentes y adopta una política criptográfica.",
                    references=[GOOGLE_CSP_EVALUATOR, GOOGLE_STRICT_CSP],
                )
            )


def _analyze_csp_script_sources(
    policy: CSPPolicy,
    *,
    reused_nonces: set[str] | None,
    add: CSPFindingSink,
) -> None:
    refs = [OWASP_CSP, MDN_CSP, GOOGLE_STRICT_CSP, GOOGLE_CSP_EVALUATOR]
    script_values, script_source = csp_effective_values(policy, "script-src")
    if script_values is None:
        add(
            finding(
                "csp",
                "ausente",
                "alta",
                "Content-Security-Policy",
                "No existe script-src ni default-src como respaldo",
                evidence="Las fuentes de script no quedan restringidas por esta política.",
                risk="La política no aporta una mitigación efectiva frente a ejecución de scripts inyectados.",
                recommendation="Define una política strict basada en nonce o hash.",
                references=refs,
            )
        )
    else:
        lowered_scripts = [csp_token_lower(value) for value in script_values]
        nonces = csp_nonces(script_values)
        hashes = csp_hashes(script_values)
        has_nonce_or_hash = bool(nonces or hashes)
        has_strict_dynamic = "'strict-dynamic'" in lowered_scripts
        strict_dynamic_effective = has_strict_dynamic and has_nonce_or_hash
        _analyze_script_execution_tokens(
            policy,
            script_values=script_values,
            script_source=script_source,
            lowered_scripts=lowered_scripts,
            has_nonce_or_hash=has_nonce_or_hash,
            add=add,
        )
        _analyze_script_source_scope(
            script_values=script_values,
            script_source=script_source,
            strict_dynamic_effective=strict_dynamic_effective,
            has_strict_dynamic=has_strict_dynamic,
            has_nonce_or_hash=has_nonce_or_hash,
            add=add,
        )
        _analyze_script_crypto_sources(
            script_values=script_values,
            script_source=script_source,
            nonces=nonces,
            hashes=hashes,
            has_nonce_or_hash=has_nonce_or_hash,
            has_strict_dynamic=has_strict_dynamic,
            reused_nonces=reused_nonces,
            add=add,
        )
    _analyze_granular_script_sources(policy, add=add)


def _analyze_csp_resource_sources(policy: CSPPolicy, *, add: CSPFindingSink) -> None:
    refs = [OWASP_CSP, MDN_CSP, GOOGLE_STRICT_CSP, GOOGLE_CSP_EVALUATOR]
    style_values, style_source = csp_effective_values(policy, "style-src")
    if style_values is not None:
        style_lower = [csp_token_lower(value) for value in style_values]
        if "'unsafe-inline'" in style_lower and not (
            csp_nonces(style_values) or csp_hashes(style_values)
        ):
            add(
                finding(
                    "csp",
                    "advertencia",
                    "media",
                    "Content-Security-Policy",
                    "La fuente efectiva de estilos permite 'unsafe-inline'",
                    evidence=f"Directiva efectiva: {style_source} {' '.join(style_values)}",
                    risk="Las inyecciones CSS conservan mayor capacidad; el impacto depende del DOM y del navegador.",
                    recommendation="Migra estilos inline a hojas autorizadas o usa nonces/hashes cuando sea viable.",
                    references=[MDN_CSP, OWASP_CSP],
                )
            )

    connect_values, connect_source = csp_effective_values(policy, "connect-src")
    if connect_values is not None and "*" in connect_values:
        add(
            finding(
                "csp",
                "advertencia",
                "media",
                "Content-Security-Policy",
                "connect-src permite conexiones a cualquier origen",
                evidence=f"Directiva efectiva: {connect_source} {' '.join(connect_values)}",
                risk="Si un script malicioso llega a ejecutarse, la política no limita sus destinos de exfiltración.",
                recommendation="Restringe connect-src a APIs, WebSockets y endpoints realmente necesarios.",
                references=[MDN_CSP, OWASP_CSP],
            )
        )

    object_values, object_source = csp_effective_values(policy, "object-src")
    object_blocks_all = object_values is not None and (
        not object_values
        or (len(object_values) == 1 and csp_has_keyword(object_values, "'none'"))
    )
    if not object_blocks_all:
        add(
            finding(
                "csp",
                "incorrecta",
                "alta",
                "Content-Security-Policy",
                "object-src no está restringido efectivamente a 'none'",
                evidence=(
                    f"{object_source or 'sin fallback'}: {' '.join(object_values or []) or 'sin valor'}"
                ),
                risk="Contenido de plugins u objetos embebidos puede conservar superficies de ejecución innecesarias.",
                recommendation="Configura object-src 'none'.",
                references=refs,
            )
        )
    else:
        object_evidence = (
            f"Directiva efectiva: {object_source} (lista vacía, equivalente a 'none')"
            if not object_values
            else f"Directiva efectiva: {object_source} 'none'"
        )
        add(
            finding(
                "csp",
                "correcta",
                "informativa",
                "Content-Security-Policy",
                "object-src bloquea objetos embebidos",
                evidence=object_evidence,
                references=refs,
            )
        )


def _analyze_csp_navigation_controls(policy: CSPPolicy, *, add: CSPFindingSink) -> None:
    base_values = policy.values("base-uri")
    if base_values is None:
        add(
            finding(
                "csp",
                "ausente",
                "alta",
                "Content-Security-Policy",
                "La política no define base-uri",
                evidence="base-uri no hereda de default-src.",
                risk="Una etiqueta <base> inyectada puede cambiar el destino de URL relativas.",
                recommendation="Configura base-uri 'none' o, si es necesario, 'self'.",
                references=[GOOGLE_CSP_EVALUATOR, GOOGLE_STRICT_CSP, MDN_CSP],
            )
        )
    elif set(map(csp_token_lower, base_values)).issubset({"'none'", "'self'"}):
        add(
            finding(
                "csp",
                "correcta",
                "informativa",
                "Content-Security-Policy",
                "base-uri limita la modificación de la URL base",
                evidence=f"base-uri {' '.join(base_values)}",
                references=[GOOGLE_STRICT_CSP, MDN_CSP],
            )
        )
    else:
        add(
            finding(
                "csp",
                "advertencia",
                "media",
                "Content-Security-Policy",
                "base-uri permite orígenes adicionales",
                evidence=f"base-uri {' '.join(base_values)}",
                risk="Una inyección de <base> puede redirigir recursos relativos a un origen permitido.",
                recommendation="Reduce base-uri a 'none' o 'self'.",
                references=[GOOGLE_CSP_EVALUATOR, MDN_CSP],
            )
        )

    frame_values = policy.values("frame-ancestors")
    if frame_values is None:
        add(
            finding(
                "csp",
                "ausente",
                "media",
                "Content-Security-Policy",
                "La política Content-Security-Policy no define frame-ancestors",
                evidence="frame-ancestors no hereda de default-src.",
                risk=(
                    "Esta CSP no limita qué sitios pueden embeber la página. "
                    "X-Frame-Options se evalúa por separado como otra cabecera."
                ),
                recommendation="Usa frame-ancestors 'none', 'self' o una allowlist justificada.",
                references=[
                    OWASP_CLICKJACKING,
                    MDN_CSP_FRAME_ANCESTORS,
                    MDN_CSP,
                ],
            )
        )
    elif not frame_ancestors_is_restrictive(frame_values):
        add(
            finding(
                "csp",
                "incorrecta",
                "alta",
                "Content-Security-Policy",
                "frame-ancestors permite un conjunto global de orígenes",
                evidence=f"frame-ancestors {' '.join(frame_values)}",
                risk=(
                    "Un comodín global o un esquema amplio como https: permite que sitios no "
                    "confiables embeban la página."
                ),
                recommendation="Restringe frame-ancestors según la necesidad real.",
                references=[OWASP_CLICKJACKING, MDN_XFO, OWASP_HEADERS],
            )
        )
    else:
        add(
            finding(
                "csp",
                "correcta",
                "informativa",
                "Content-Security-Policy",
                "frame-ancestors restringe el framing",
                evidence=f"frame-ancestors {' '.join(frame_values)}",
                references=[MDN_XFO, MDN_CSP],
            )
        )

    form_values = policy.values("form-action")
    if form_values is None:
        add(
            finding(
                "csp",
                "advertencia",
                "media",
                "Content-Security-Policy",
                "La política no limita destinos de formularios con form-action",
                evidence="form-action no hereda de default-src.",
                risk="Una inyección HTML podría enviar formularios a un destino no previsto.",
                recommendation="Define form-action 'self' o los destinos explícitamente necesarios.",
                references=[OWASP_CSP, MDN_CSP],
            )
        )
    elif "*" in form_values:
        add(
            finding(
                "csp",
                "incorrecta",
                "alta",
                "Content-Security-Policy",
                "form-action permite cualquier destino",
                evidence=f"form-action {' '.join(form_values)}",
                risk="Los formularios pueden enviar información a orígenes no confiables.",
                recommendation="Limita form-action a 'self' y destinos indispensables.",
                references=[OWASP_CSP, MDN_CSP],
            )
        )
    else:
        add(
            finding(
                "csp",
                "correcta",
                "informativa",
                "Content-Security-Policy",
                "form-action limita los destinos de formularios",
                evidence=f"form-action {' '.join(form_values)}",
                references=[OWASP_CSP, MDN_CSP],
            )
        )

    if policy.values("default-src") is None:
        add(
            finding(
                "csp",
                "advertencia",
                "media",
                "Content-Security-Policy",
                "La política no define default-src como fallback general",
                evidence="Cada tipo de recurso no declarado queda sin el fallback de default-src.",
                risk="Es fácil omitir una directiva de carga y dejar ese tipo de recurso sin restricción.",
                recommendation="Empieza con default-src 'none' o 'self' y abre solo lo necesario.",
                references=[MDN_CSP, OWASP_CSP],
            )
        )


def _analyze_csp_transport_and_reporting(
    policy: CSPPolicy,
    *,
    snapshot: ResponseSnapshot,
    add: CSPFindingSink,
) -> None:
    insecure_sources: list[str] = []
    if urlsplit(snapshot.url).scheme.lower() == "https":
        for directive, values in policy.directives.items():
            for value in values:
                if value.lower() == "http:" or value.lower().startswith("http://"):
                    insecure_sources.append(f"{directive} {value}")
    if insecure_sources:
        upgraded = "upgrade-insecure-requests" in policy.directives
        add(
            finding(
                "csp",
                "advertencia",
                "media" if not upgraded else "baja",
                "Content-Security-Policy",
                "La política contiene fuentes HTTP en una página HTTPS",
                evidence="; ".join(insecure_sources[:10]),
                risk=(
                    "Los recursos podrían depender de transporte no cifrado. "
                    + (
                        "upgrade-insecure-requests intentará actualizarlos."
                        if upgraded
                        else ""
                    )
                ),
                recommendation="Usa orígenes HTTPS explícitos y elimina dependencias HTTP.",
                references=[MDN_CSP, OWASP_CSP],
            )
        )

    for directive, message in CSP_DEPRECATED_DIRECTIVES.items():
        if directive in policy.directives:
            add(
                finding(
                    "csp",
                    "advertencia",
                    "baja",
                    "Content-Security-Policy",
                    f"La política usa la directiva heredada {directive}",
                    evidence=f"{directive} {' '.join(policy.directives[directive])}".strip(),
                    risk=message,
                    recommendation=(
                        "Verifica compatibilidad y migra al mecanismo actual; si usas report-to, "
                        "report-uri puede mantenerse temporalmente como fallback."
                    ),
                    references=[OWASP_CSP, W3C_CSP3],
                )
            )

    if "report-to" in policy.directives and not snapshot.has("reporting-endpoints"):
        add(
            finding(
                "csp",
                "advertencia",
                "baja",
                "Content-Security-Policy",
                "report-to no tiene una cabecera Reporting-Endpoints asociada",
                evidence=f"report-to {' '.join(policy.directives['report-to'])}",
                risk="Los reportes CSP pueden no tener un destino resoluble.",
                recommendation="Define el grupo en Reporting-Endpoints.",
                references=[OWASP_CSP, MDN_CSP],
            )
        )

    if "require-trusted-types-for" not in policy.directives:
        add(
            finding(
                "csp",
                "informativa",
                "baja",
                "Content-Security-Policy",
                "Trusted Types no está exigido",
                evidence="No se encontró require-trusted-types-for 'script'.",
                risk="No se aplica esta capa adicional frente a sinks DOM XSS en navegadores compatibles.",
                recommendation="Evalúa Trusted Types progresivamente; no lo actives sin probar compatibilidad.",
                references=[MDN_CSP, OWASP_SECURE_HEADERS],
            )
        )


def analyze_single_csp(
    policy: CSPPolicy,
    *,
    label: str,
    snapshot: ResponseSnapshot,
    report_only: bool = False,
    reused_nonces: set[str] | None = None,
) -> list[Finding]:
    results: list[Finding] = []

    def add(item: Finding) -> None:
        item.category = "csp"
        item.policy = label
        results.append(downgrade_report_only(item) if report_only else item)

    _analyze_csp_syntax(policy, report_only=report_only, add=add)
    _analyze_csp_script_sources(policy, reused_nonces=reused_nonces, add=add)
    _analyze_csp_resource_sources(policy, add=add)
    _analyze_csp_navigation_controls(policy, add=add)
    _analyze_csp_transport_and_reporting(policy, snapshot=snapshot, add=add)
    return results


def csp_frame_ancestor_policies(snapshot: ResponseSnapshot) -> list[list[str]]:
    """Devuelve cada frame-ancestors aplicada; varias CSP se intersectan."""
    policies: list[list[str]] = []
    for raw in parse_csp_header_values(snapshot.all("content-security-policy")):
        values = parse_csp(raw).values("frame-ancestors")
        if values is not None:
            policies.append(values)
    return policies


def csp_frame_ancestors(snapshot: ResponseSnapshot) -> list[str] | None:
    """Compatibilidad 5.x: devuelve la primera directiva aplicada."""
    policies = csp_frame_ancestor_policies(snapshot)
    return policies[0] if policies else None


def valid_xfo(snapshot: ResponseSnapshot) -> tuple[bool, str]:
    values = snapshot.all("x-frame-options")
    if len(values) != 1:
        return False, " | ".join(values)
    normalized = values[0].strip().upper()
    return normalized in {"DENY", "SAMEORIGIN"}, normalized


def frame_ancestors_is_restrictive(values: Sequence[str]) -> bool:
    """Indica si una policy limita a algún conjunto menor que todo Internet."""
    normalized = {csp_token_lower(value) for value in values}
    if not normalized or normalized == {"'none'"}:
        return True
    # Las expresiones se unen dentro de una source-list. Por eso añadir una
    # allowlist junto a * o a un esquema web global no vuelve restrictiva la
    # política. 'none' solo tiene efecto cuando aparece sola.
    effective = normalized - {"'none'"}
    return not any(csp_source_is_global(value) for value in effective)


def describe_frame_ancestor_policies(policies: Sequence[Sequence[str]]) -> str:
    if not policies:
        return "No encontrada"
    rendered = []
    for index, values in enumerate(policies, start=1):
        value = " ".join(values) if values else "<lista vacía: bloquea todo>"
        rendered.append(f"policy #{index}: {value}")
    return " | ".join(rendered)


def qualify_multi_policy_finding(item: Finding) -> Finding:
    """Evita presentar una policy individual como la política CSP efectiva.

    Varias cabeceras CSP se aplican simultáneamente. Una policy permisiva no
    debilita otra más restrictiva, por lo que una conclusión individual debe
    revisarse en la intersección de todas ellas.
    """
    if item.status in {"incorrecta", "ausente", "advertencia"}:
        if SEVERITY_RANK[item.severity] > SEVERITY_RANK["media"]:
            item.severity = "media"
        if item.status in {"incorrecta", "ausente"}:
            item.status = "advertencia"
        item.title = f"[Policy individual] {item.title}"
        item.risk = (
            "Esta observación aplica a la policy indicada por separado; otra policy aplicada "
            "puede imponer la restricción faltante porque el navegador exige cumplirlas todas. "
            + item.risk
        ).strip()
    return item


def analyze_csp_headers(
    snapshot: ResponseSnapshot,
    excluded: set[str],
    profile: str,
    reused_nonces: set[str] | None = None,
    csp_only: bool = False,
) -> list[Finding]:
    enforced_name = "content-security-policy"
    report_name = "content-security-policy-report-only"
    results: list[Finding] = []
    enforced_excluded = enforced_name in excluded
    report_excluded = report_name in excluded
    if enforced_excluded:
        results.append(excluded_finding(enforced_name))
    if report_excluded:
        results.append(excluded_finding(report_name))

    enforced = (
        []
        if enforced_excluded
        else parse_csp_header_values(snapshot.all(enforced_name))
    )
    report_only = (
        [] if report_excluded else parse_csp_header_values(snapshot.all(report_name))
    )

    if not enforced and not enforced_excluded:
        if csp_only or effective_response_kind(snapshot, profile) == "document":
            results.append(
                finding(
                    "ausentes",
                    "ausente",
                    "media",
                    "Content-Security-Policy",
                    "No existe una CSP aplicada en modo de bloqueo",
                    evidence=(
                        "Solo se encontró Content-Security-Policy-Report-Only."
                        if report_only
                        else "Cabecera no encontrada."
                    ),
                    risk=(
                        "La aplicación pierde una capa de defensa en profundidad frente a XSS, "
                        "inyecciones de contenido y clickjacking. Esto no demuestra por sí solo que exista XSS."
                    ),
                    recommendation="Despliega primero Report-Only, corrige violaciones y luego aplica una CSP strict.",
                    references=[OWASP_CSP, MDN_CSP, GOOGLE_STRICT_CSP],
                )
            )
    elif enforced:
        multiple_enforced = len(enforced) > 1
        if multiple_enforced:
            results.append(
                finding(
                    "csp",
                    "informativa",
                    "baja",
                    "Content-Security-Policy",
                    "Se recibieron varias políticas CSP aplicadas",
                    evidence=f"Cantidad: {len(enforced)}",
                    risk="Los navegadores aplican todas las políticas; el resultado efectivo es acumulativo y más restrictivo.",
                    recommendation="Revisa cada política y documenta por qué se mantienen separadas.",
                    references=[W3C_CSP3],
                )
            )
        detail: list[Finding] = []
        for index, raw in enumerate(enforced, start=1):
            policy_detail = analyze_single_csp(
                parse_csp(raw),
                label=f"CSP aplicada #{index}",
                snapshot=snapshot,
                reused_nonces=reused_nonces,
            )
            if multiple_enforced:
                detail.extend(
                    qualify_multi_policy_finding(item) for item in policy_detail
                )
            else:
                detail.extend(policy_detail)
        definite_weakness = any(
            item.status in {"incorrecta", "ausente"}
            and SEVERITY_RANK[item.severity] >= SEVERITY_RANK["media"]
            for item in detail
        )
        relevant_warning = any(
            item.status == "advertencia"
            and SEVERITY_RANK[item.severity] >= SEVERITY_RANK["media"]
            for item in detail
        )
        multi_requires_review = multiple_enforced and any(
            item.status == "advertencia" for item in detail
        )
        needs_review = definite_weakness or relevant_warning or multi_requires_review
        results.insert(
            0,
            finding(
                "contextuales"
                if (relevant_warning or multi_requires_review) and not definite_weakness
                else "incorrectas"
                if definite_weakness
                else "correctas",
                "incorrecta"
                if definite_weakness
                else "advertencia"
                if needs_review
                else "correcta",
                "media" if needs_review else "informativa",
                "Content-Security-Policy",
                (
                    "Hay varias policies CSP; las observaciones individuales requieren revisión combinada"
                    if multi_requires_review
                    else "La CSP está aplicada, pero contiene debilidades relevantes"
                    if definite_weakness
                    else "La CSP está aplicada y contiene advertencias que deben revisarse"
                    if relevant_warning
                    else "La CSP está aplicada y no se detectaron debilidades de línea base"
                ),
                evidence=f"Políticas aplicadas: {len(enforced)}",
                risk=(
                    "Consulta el análisis por directiva; una revisión estática no demuestra que la política funcione con toda la aplicación."
                ),
                recommendation="Prueba la política en navegador, monitorea reportes y valida todos los endpoints HTML.",
                references=[OWASP_CSP, MDN_CSP, GOOGLE_CSP_EVALUATOR],
            ),
        )
        results.extend(detail)

    if report_only:
        results.append(
            finding(
                "csp",
                "informativa",
                "baja",
                "Content-Security-Policy-Report-Only",
                "Se detectó una política de monitoreo que no bloquea recursos",
                evidence=f"Políticas Report-Only: {len(report_only)}",
                risk="Sirve para despliegue y observación, pero no mitiga por sí sola en producción.",
                recommendation="Revisa reportes antes de promoverla a Content-Security-Policy.",
                references=[OWASP_CSP, MDN_CSP],
            )
        )
        for index, raw in enumerate(report_only, start=1):
            results.extend(
                analyze_single_csp(
                    parse_csp(raw),
                    label=f"CSP Report-Only #{index}",
                    snapshot=snapshot,
                    report_only=True,
                    reused_nonces=None,
                )
            )
    return results


def analyze_x_frame_options(
    snapshot: ResponseSnapshot, excluded: set[str], profile: str
) -> list[Finding]:
    """Evalúa exclusivamente la cabecera HTTP X-Frame-Options.

    Content-Security-Policy y su directiva frame-ancestors se analizan en el
    módulo CSP. No se crea un control sintético ni se sustituye el nombre de la
    cabecera por el nombre de una vulnerabilidad.
    """

    name = "x-frame-options"
    if name in excluded:
        return [excluded_finding(name)]

    values = snapshot.all(name)
    if not values:
        if effective_response_kind(snapshot, profile) != "document":
            return []
        return [
            finding(
                "ausentes",
                "ausente",
                "media",
                "X-Frame-Options",
                "No se encontró la cabecera X-Frame-Options",
                evidence="Cabecera no encontrada.",
                risk=(
                    "La respuesta no aporta esta capa de compatibilidad contra framing. "
                    "Content-Security-Policy se evalúa por separado y puede incluir "
                    "frame-ancestors, pero no cambia el estado de esta cabecera."
                ),
                recommendation=(
                    "Para respuestas HTML que no deban embeberse, OWASP recomienda "
                    "X-Frame-Options: DENY. Usa SAMEORIGIN solo si el sitio necesita "
                    "framing desde su mismo origen."
                ),
                references=[
                    OWASP_HEADERS,
                    OWASP_CLICKJACKING,
                    MDN_XFO,
                    HTML_XFO,
                    IANA_HTTP_FIELDS,
                ],
            )
        ]

    observed = " | ".join(values)
    if len(values) != 1:
        return [
            finding(
                "incorrectas",
                "incorrecta",
                "media",
                "X-Frame-Options",
                "Se recibieron varios campos X-Frame-Options",
                evidence=observed,
                risk=(
                    "Los navegadores no procesan de forma uniforme valores duplicados; "
                    "la protección puede quedar sin efecto."
                ),
                recommendation="Emite una sola cabecera con DENY o SAMEORIGIN.",
                references=[OWASP_CLICKJACKING, MDN_XFO, HTML_XFO],
            )
        ]

    value = values[0].strip()
    normalized = value.upper()
    if normalized == "DENY":
        return [
            finding(
                "correctas",
                "correcta",
                "informativa",
                "X-Frame-Options",
                "La cabecera impide que la respuesta se cargue dentro de un frame",
                evidence=value,
                references=[
                    OWASP_HEADERS,
                    OWASP_CLICKJACKING,
                    MDN_XFO,
                    HTML_XFO,
                    IANA_HTTP_FIELDS,
                ],
            )
        ]
    if normalized == "SAMEORIGIN":
        return [
            finding(
                "correctas",
                "correcta",
                "informativa",
                "X-Frame-Options",
                "La cabecera solo permite framing desde el mismo origen",
                evidence=value,
                risk=(
                    "SAMEORIGIN es un valor válido, pero permite que páginas del mismo "
                    "origen embeban la respuesta."
                ),
                recommendation=(
                    "Conserva SAMEORIGIN si existe una necesidad funcional; usa DENY "
                    "cuando la respuesta no deba cargarse en ningún frame."
                ),
                references=[
                    OWASP_CLICKJACKING,
                    MDN_XFO,
                    HTML_XFO,
                    IANA_HTTP_FIELDS,
                ],
            )
        ]
    if re.match(r"^ALLOW-FROM(?:$|\s+|=)", normalized):
        return [
            finding(
                "obsoletas",
                "informativa",
                "media",
                "X-Frame-Options",
                "La cabecera usa la directiva obsoleta ALLOW-FROM",
                evidence=value,
                risk=(
                    "Los navegadores modernos ignoran ALLOW-FROM por completo, por lo que "
                    "la respuesta puede quedar abierta al framing."
                ),
                recommendation=(
                    "Sustituye ALLOW-FROM por Content-Security-Policy con una directiva "
                    "frame-ancestors y usa DENY o SAMEORIGIN como compatibilidad."
                ),
                references=[
                    OWASP_CLICKJACKING,
                    MDN_XFO,
                    MDN_CSP_FRAME_ANCESTORS,
                    HTML_XFO,
                ],
            )
        ]

    return [
        finding(
            "incorrectas",
            "incorrecta",
            "media",
            "X-Frame-Options",
            "La cabecera tiene un valor no reconocido",
            evidence=value or "Valor vacío.",
            risk="Los navegadores pueden ignorar completamente la cabecera.",
            recommendation="Configura exactamente DENY o SAMEORIGIN.",
            references=[OWASP_HEADERS, OWASP_CLICKJACKING, MDN_XFO, HTML_XFO],
        )
    ]


def analyze_clickjacking(
    snapshot: ResponseSnapshot, excluded: set[str], profile: str
) -> list[Finding]:
    """Alias de compatibilidad 6.x; devuelve hallazgos de X-Frame-Options."""

    return analyze_x_frame_options(snapshot, excluded, profile)
