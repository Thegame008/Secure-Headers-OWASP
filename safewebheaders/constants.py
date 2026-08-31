"""Constants de SafeWebHeaders."""

from __future__ import annotations

from collections import OrderedDict

try:  # Mejora el soporte ANSI en Windows, pero el programa funciona sin ella.
    from colorama import just_fix_windows_console  # type: ignore[import-untyped]

    just_fix_windows_console()
except ImportError:  # pragma: no cover - dependencia opcional en ejecución
    pass


VERSION = "8.5.1"
DEFAULT_USER_AGENT = f"SafeWebHeaders/{VERSION} (+security-header-audit)"

ESSENTIAL_ONLY_NOTE = (
    "Modo esencial predeterminado activo: se omiten Referrer-Policy, "
    "X-Content-Type-Options, "
    "Content-Type, Permissions-Policy, COOP/COEP/CORP, Cache-Control, cookies, "
    "CORS e informativos ajenos al alcance esencial. Se conservan siempre las "
    "observaciones de HSTS, CSP y X-Frame-Options, incluidas las contextuales, "
    "y la cadena de navegación. Ejecuta con --all-headers para el informe completo."
)

ALL_HEADERS_NOTE = (
    "Modo completo activo mediante --all-headers: se analizaron también controles "
    "contextuales, cookies solicitadas, CORS e informativos aplicables."
)

OWASP_HEADERS = (
    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
)
OWASP_SECURE_HEADERS = "https://owasp.org/www-project-secure-headers/"
OWASP_CSP = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Content_Security_Policy_Cheat_Sheet.html"
)
OWASP_HSTS = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "HTTP_Strict_Transport_Security_Cheat_Sheet.html"
)
OWASP_WSTG_HEADERS = (
    "https://owasp.org/www-project-web-security-testing-guide/latest/"
    "4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"
    "14-Test_Other_HTTP_Security_Header_Misconfigurations"
)
OWASP_CLICKJACKING = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Clickjacking_Defense_Cheat_Sheet.html"
)
MDN_CSP = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP"
MDN_HSTS = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
    "Strict-Transport-Security"
)
MDN_XCTO = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
    "X-Content-Type-Options"
)
MDN_XFO = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
    "X-Frame-Options"
)
MDN_CSP_FRAME_ANCESTORS = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
    "Content-Security-Policy/frame-ancestors"
)
HTML_XFO = "https://html.spec.whatwg.org/multipage/browsing-the-web.html#the-x-frame-options-header"
IANA_HTTP_FIELDS = "https://www.iana.org/assignments/http-fields/"
MDN_XXSSP = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
    "X-XSS-Protection"
)
MDN_REFERRER = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
    "Referrer-Policy"
)
MDN_PERMISSIONS = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
    "Permissions-Policy"
)
MDN_COOP = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
    "Cross-Origin-Opener-Policy"
)
MDN_COEP = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
    "Cross-Origin-Embedder-Policy"
)
MDN_CORP = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
    "Cross-Origin-Resource-Policy"
)
MDN_COOKIES = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie"
)
MDN_CORS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS"
MDN_INTEGRITY_POLICY = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
    "Integrity-Policy"
)
MDN_CACHE_CONTROL = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control"
)
MDN_CLEAR_SITE_DATA = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Clear-Site-Data"
MDN_XPCDP = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
    "X-Permitted-Cross-Domain-Policies"
)
MDN_DNS_PREFETCH = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
    "X-DNS-Prefetch-Control"
)
GOOGLE_STRICT_CSP = "https://web.dev/articles/strict-csp"
GOOGLE_CSP_EVALUATOR = "https://csp-evaluator.withgoogle.com/"
W3C_CSP3 = "https://www.w3.org/TR/CSP3/"
W3C_TRUSTED_TYPES = "https://www.w3.org/TR/trusted-types/"


SEVERITY_RANK = {
    "informativa": 0,
    "baja": 1,
    "media": 2,
    "alta": 3,
    "crítica": 4,
}

STATUS_SYMBOL = {
    "correcta": "+",
    "ausente": "-",
    "incorrecta": "!",
    "advertencia": "!",
    "informativa": "*",
    "excluida": "~",
}

CATEGORY_LABELS = OrderedDict(
    [
        ("ausentes", "Ausencia de cabeceras de seguridad en la URL"),
        ("correctas", "Cabeceras de seguridad correctamente implementadas en la URL"),
        (
            "incorrectas",
            "Cabeceras de seguridad incorrectamente configuradas en la URL",
        ),
        ("obsoletas", "Cabeceras heredadas u obsoletas en la URL"),
        ("divulgacion", "Divulgación de información en cabecera para la URL"),
        ("csp", "Análisis de Content-Security-Policy en la URL"),
        ("cookies", "Atributos de seguridad de las cookies en la URL"),
        ("cors", "Configuración CORS observada en la URL"),
        ("redirecciones", "Redirecciones observadas desde la URL"),
        ("contextuales", "Observaciones dependientes del contexto para la URL"),
    ]
)

CATEGORY_COLOR = {
    "ausentes": "red",
    "correctas": "green",
    "incorrectas": "yellow",
    "obsoletas": "magenta",
    "divulgacion": "magenta",
    "csp": "cyan",
    "cookies": "cyan",
    "cors": "yellow",
    "redirecciones": "cyan",
    "contextuales": "cyan",
}

# Orden visible solicitado para la consola y los reportes. Las categorías
# internas (csp, cookies, cors, contextuales, etc.) se conservan para que el
# motor pueda razonar con precisión, pero se traducen a estos bloques finales.
DISPLAY_CATEGORY_LABELS = OrderedDict(
    [
        ("correctas", "Cabeceras de seguridad correctamente implementadas en la URL"),
        ("ausentes", "Ausencia de cabeceras de seguridad en la URL"),
        (
            "incorrectas",
            "Cabeceras de seguridad incorrectamente configuradas en la URL",
        ),
        ("cookies", "Atributos de seguridad de las cookies en la URL"),
        ("obsoletas", "Cabeceras heredadas u obsoletas en la URL"),
        ("divulgacion", "Divulgación de información en cabeceras para la URL"),
        ("informativas", "Observaciones informativas para la URL"),
    ]
)

DISPLAY_CATEGORY_COLOR = {
    "correctas": "green",
    "ausentes": "red",
    "incorrectas": "orange",
    "cookies": "cyan",
    # Amarillo exclusivo: en 8.4.1 las obsoletas compartían cian con cookies en
    # la CLI y naranja con incorrectas en la GUI. Ahora tienen tono propio y el
    # mismo en ambas superficies.
    "obsoletas": "yellow",
    "divulgacion": "magenta",
    "informativas": "blue",
}

DISPLAY_CATEGORY_SYMBOL = {
    "correctas": "+",
    "ausentes": "-",
    "incorrectas": "!",
    "cookies": "±",
    "obsoletas": "~",
    "divulgacion": "*",
    "informativas": "i",
}

HEADER_ALIASES = {
    "csp": "content-security-policy",
    "csp-report-only": "content-security-policy-report-only",
    "hsts": "strict-transport-security",
    "xcto": "x-content-type-options",
    "xfo": "x-frame-options",
    "referrer": "referrer-policy",
    "permissions": "permissions-policy",
    "coop": "cross-origin-opener-policy",
    "coep": "cross-origin-embedder-policy",
    "corp": "cross-origin-resource-policy",
    "cookies": "set-cookie",
    "cors": "access-control-allow-origin",
}

LEGACY_HEADER_NAMES = {
    "expect-ct",
    "public-key-pins",
    "public-key-pins-report-only",
    "feature-policy",
    "x-content-security-policy",
    "x-webkit-csp",
    "x-xss-protection",
}

DISCLOSURE_HEADER_NAMES = {
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "x-backend-server",
    "x-served-by",
    "x-debug-token",
    "x-debug-token-link",
    "x-source-map",
    "sourcemap",
}

EXCLUDABLE_HEADERS = {
    "strict-transport-security",
    "x-content-type-options",
    "content-type",
    "referrer-policy",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "integrity-policy",
    "integrity-policy-report-only",
    "cache-control",
    "content-disposition",
    "x-permitted-cross-domain-policies",
    "clear-site-data",
    "x-dns-prefetch-control",
    "set-cookie",
    "access-control-allow-origin",
    *LEGACY_HEADER_NAMES,
    *DISCLOSURE_HEADER_NAMES,
}

EXCLUSION_GROUPS = {
    "obsolete": LEGACY_HEADER_NAMES,
    "obsoletas": LEGACY_HEADER_NAMES,
    "legacy": LEGACY_HEADER_NAMES,
    "disclosure": DISCLOSURE_HEADER_NAMES,
    "divulgacion": DISCLOSURE_HEADER_NAMES,
    "divulgación": DISCLOSURE_HEADER_NAMES,
}
