"""Cli de SafeWebHeaders."""

from __future__ import annotations

import argparse
import sys
import textwrap
import time
import uuid
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlsplit

from requests import Response, Session

from .constants import (
    ALL_HEADERS_NOTE,
    DEFAULT_USER_AGENT,
    ESSENTIAL_ONLY_NOTE,
    VERSION,
)
from .engine import (
    run_analysis,
)
from .models import (
    BatchReport,
    RedirectHop,
    ResponseSnapshot,
    ScanError,
    ScanFailure,
    ScanReport,
)
from .navigation import collect_navigation
from .output import (
    write_batch_output,
)
from .pocs import (
    generate_requested_pocs,
)
from .profiles import (
    detect_profile,
)
from .rules_csp import (
    extract_csp_nonce_strings,
)
from .transport import (
    build_session,
    request_target,
    snapshot_response,
)
from .utils import (
    canonical_header,
    format_excludable_headers,
    machine_timestamp,
    normalize_url,
    parse_exclusions,
    resolve_url_ips,
    sanitize_url,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safewebheaders",
        add_help=False,
        description=(
            "Audita cabeceras HTTP de seguridad en una o varias URL y genera "
            "evidencia legible o exportable."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent(
            """
            ALCANCE PREDETERMINADO Y NOMBRES REALES
              El modo predeterminado analiza las tres cabeceras esenciales:
              X-Frame-Options, Strict-Transport-Security y Content-Security-Policy.
              Las cabeceras obsoletas y de divulgación siempre se conservan.
              Usa --all-headers para añadir Referrer-Policy y todos los controles
              contextuales aplicables.
              X-Content-Type-Options, Content-Type y Permissions-Policy son
              recomendaciones contextuales: solo se validan cuando están presentes.
              En API, recursos, descargas, redirecciones o respuestas vacías aplica
              únicamente los controles que tienen efecto en ese tipo de respuesta.

            EJEMPLOS RÁPIDOS
              Iniciar la interfaz web local:
                safewebheaders --web
                safewebheaders --gui
                python safewebheaders.py --web --web-port 9090

              Escaneo normal:
                safewebheaders https://example.com
                python safewebheaders.py https://example.com

              Informe completo con todas las cabeceras aplicables:
                safewebheaders https://example.com --all-headers

              Varias URL separadas por espacios o desde archivo:
                safewebheaders https://uno.example https://dos.example
                safewebheaders --url-file urls.txt

              Ver cada respuesta y seguir redirecciones, similar a curl -L -D -:
                safewebheaders https://example.com --follow-redirects --show-headers

              Página autenticada o API con una cabecera propia:
                safewebheaders https://example.com/panel -H "Authorization: Bearer TOKEN"

              Consultar capacidades con OPTIONS:
                safewebheaders https://api.example.com/recurso --method OPTIONS

              Auditar una respuesta POST con un cuerpo JSON controlado:
                safewebheaders https://api.example.com/consulta --method POST --content-type application/json --data '{"prueba":true}'

              Ajustar cuánto esperar por una respuesta lenta:
                safewebheaders https://example.com --timeout 30

              Analizar solo una cadena CSP, sin conectarse a una web:
                safewebheaders --analyze-csp "default-src 'self'; object-src 'none'"

              Probar CORS y generar una página de confirmación local:
                safewebheaders https://api.example.com/me --poc-cors

              Exportar un reporte:
                safewebheaders https://example.com -o reporte.html
                safewebheaders https://example.com --output reporte.csv
                PANTALLA + ARCHIVO: --output conserva el resumen en pantalla salvo --quiet.

            NOTA
              La salida de --show-headers reconstruye la línea de estado y los campos
              recibidos; no representa los bytes RAW exactos del socket. Los secretos se
              ocultan salvo que se solicite expresamente --reveal-sensitive.
            """
        ),
    )
    parser._positionals.title = "objetivos"
    parser._optionals.title = "opciones generales"
    parser.add_argument(
        "-h", "--help", action="help", help="Muestra esta ayuda detallada y termina"
    )
    parser.add_argument(
        "urls",
        nargs="*",
        metavar="URL",
        help=(
            "Una o varias URL HTTP(S). Varias URL separadas por espacios.\n"
            "Si omites http:// o https:// se utiliza https://."
        ),
    )
    targets = parser.add_argument_group("entrada y alcance")
    targets.add_argument(
        "--url-file",
        "--input-file",
        action="append",
        default=[],
        metavar="ARCHIVO",
        help=(
            "Lee objetivos desde un archivo de texto, una URL por línea.\n"
            "Puede repetirse y combinarse con URL posicionales."
        ),
    )
    targets.add_argument(
        "--analyze-csp",
        dest="csp_policy",
        metavar="POLÍTICA",
        help=(
            "Analiza una cadena Content-Security-Policy sin realizar peticiones.\n"
            "Sirve para revisar una política antes de desplegarla o desde CI."
        ),
    )
    targets.add_argument(
        "--response-type",
        choices=("auto", "web", "api"),
        default="auto",
        dest="profile",
        help=(
            "Cómo interpretar la respuesta: auto usa Content-Type; web fuerza la\n"
            "línea base HTML y api evita ausencias que solo aplican al navegador.\n"
            "Usa web/api únicamente si el servidor declara un Content-Type erróneo."
        ),
    )
    targets.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
        help="Muestra la versión instalada y termina",
    )
    web = parser.add_argument_group("interfaz web local")
    web.add_argument(
        "--web",
        "--gui",
        action="store_true",
        help=(
            "Inicia la GUI en 127.0.0.1 y abre el navegador. Si el puerto 8080\n"
            "no está disponible, selecciona automáticamente otro puerto local."
        ),
    )
    web.add_argument(
        "--web-port",
        type=int,
        default=8080,
        metavar="PUERTO",
        help=(
            "Puerto preferido de la GUI (predeterminado: 8080). Usa 0 para que\n"
            "el sistema elija directamente un puerto local libre."
        ),
    )
    web.add_argument(
        "--no-browser",
        action="store_true",
        help="Con --web, no abre automáticamente el navegador",
    )

    scan = parser.add_argument_group("comportamiento del escaneo")
    scan.add_argument(
        "--exclude-header",
        "--exclude-headers",
        action="append",
        default=[],
        metavar="NOMBRE[,NOMBRE...]",
        help=(
            "Omite una comprobación por nombre HTTP o alias HSTS/CSP/XFO.\n"
            "Puede repetirse o recibir varios valores separados por coma.\n"
            "Ejemplos: --exclude-header Strict-Transport-Security; "
            "--exclude-header X-Frame-Options."
        ),
    )
    scope = scan.add_mutually_exclusive_group()
    scope.add_argument(
        "--all-headers",
        action="store_false",
        dest="essential_only",
        default=True,
        help=(
            "Amplía el informe predeterminado: analiza también Referrer-Policy,\n"
            "XCTO, Content-Type, Permissions-Policy, controles cross-origin, caché,\n"
            "cookies solicitadas, CORS e informativos aplicables."
        ),
    )
    scope.add_argument(
        "--essential-only",
        action="store_true",
        dest="essential_only",
        help=argparse.SUPPRESS,
    )
    scan.add_argument(
        "--follow-redirects",
        "--follow-redirect",
        action="store_true",
        dest="follow_redirects",
        help=(
            "Sigue 3xx y meta refresh HTML hasta la respuesta final. Muestra el\n"
            "destino anunciado, el solicitado y la URL auditada. Si un salto HTTP\n"
            "anunciado desde HTTPS falla, prueba su variante segura. No ejecuta JS."
        ),
    )
    scan.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        metavar="SEGUNDOS",
        help=(
            "Tiempo máximo para conectar y para esperar datos en cada fase.\n"
            "Predeterminado: 15 segundos. Ejemplo para una web lenta: --timeout 30."
        ),
    )
    scan.add_argument(
        "--method",
        choices=("GET", "HEAD", "OPTIONS", "POST"),
        default="GET",
        help=(
            "Método HTTP de la comprobación (predeterminado: GET).\n"
            "HEAD evita descargar el cuerpo; OPTIONS consulta capacidades; POST\n"
            "puede ejecutar lógica del servidor y solo debe usarse conscientemente."
        ),
    )

    request_body = parser.add_argument_group("cuerpo opcional para POST")
    body_source = request_body.add_mutually_exclusive_group()
    body_source.add_argument(
        "--data",
        "--request-body",
        dest="request_body",
        metavar="TEXTO",
        help=(
            "Cuerpo enviado cuando --method POST está activo. Para secretos o\n"
            "cuerpos extensos usa --data-file y evita el historial de la terminal."
        ),
    )
    body_source.add_argument(
        "--data-file",
        "--request-body-file",
        dest="request_body_file",
        metavar="ARCHIVO",
        help="Lee el cuerpo POST desde un archivo de hasta 1 MiB.",
    )
    request_body.add_argument(
        "--content-type",
        dest="request_content_type",
        metavar="TIPO",
        help=(
            "Content-Type del cuerpo POST, por ejemplo application/json.\n"
            "Si también usas -H Content-Type, la cabecera personalizada prevalece."
        ),
    )

    access = parser.add_argument_group("acceso, autenticación y TLS")
    access.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        dest="request_header",
        metavar="NOMBRE:VALOR",
        help=(
            "Añade una cabecera a la petición; puede repetirse. Útil para tokens,\n"
            "cookies de laboratorio, Origin, Referer o cabeceras de un WAF."
        ),
    )
    access.add_argument(
        "--header-file",
        action="append",
        default=[],
        dest="request_header_file",
        metavar="ARCHIVO",
        help=(
            "Lee cabeceras desde un archivo UTF-8, una por línea. Recomendado para\n"
            "no dejar tokens o cookies en el historial de la terminal."
        ),
    )
    access.add_argument(
        "--forward-custom-secrets",
        action="store_true",
        dest="keep_sensitive_headers_on_redirect",
        help=(
            "Permite reenviar a otro origen secretos personalizados agregados con -H,\n"
            "como X-API-Key. Es peligroso: úsalo solo si confías en el destino.\n"
            "Authorization y Cookie conservan las protecciones propias de Requests."
        ),
    )
    access.add_argument(
        "--use-environment",
        action="store_true",
        dest="trust_env",
        help=(
            "Usa HTTP_PROXY/HTTPS_PROXY/NO_PROXY, REQUESTS_CA_BUNDLE y credenciales\n"
            ".netrc del entorno. Déjalo apagado si no confías en esa configuración."
        ),
    )
    access.add_argument(
        "--no-resolve",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    access.add_argument(
        "--insecure",
        action="store_true",
        help="Desactiva validación TLS; solo para pruebas autorizadas con certificados no confiables",
    )
    access.add_argument("--ca-bundle", help="Ruta a una CA o bundle PEM privado")
    access.add_argument(
        "--proxy", help="Proxy HTTP(S), por ejemplo http://127.0.0.1:8080"
    )
    access.add_argument(
        "--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent de la solicitud"
    )
    access.add_argument("--cert", help="Certificado cliente PEM o PKCS#12 (.p12/.pfx)")
    access.add_argument(
        "--cert-key", help="Clave privada PEM cuando --cert usa PEM separado"
    )
    access.add_argument(
        "--certpass",
        help="Contraseña P12/PFX; es preferible SAFEWEBHEADERS_CERT_PASSWORD",
    )
    access.add_argument(
        "--certpass-file",
        help="Lee la contraseña P12/PFX desde la primera línea de un archivo",
    )

    evidence = parser.add_argument_group("evidencia y validaciones adicionales")
    evidence.add_argument(
        "--show-headers",
        action="store_true",
        help=(
            "Muestra línea de estado y cabeceras de cada respuesta en formato tipo\n"
            "curl -D -. Con --follow-redirects incluye todos los saltos. Es una\n"
            "vista reconstruida, no los bytes exactos del socket."
        ),
    )
    evidence.add_argument(
        "--value-cookie",
        action="store_true",
        dest="value_cookie",
        help=(
            "Evalúa los atributos Secure, HttpOnly y SameSite de Set-Cookie.\n"
            "Funciona también en modo esencial porque es una comprobación explícita.\n"
            "Sin esta opción no se generan hallazgos de cookies; sus valores se ocultan."
        ),
    )
    evidence.add_argument(
        "--reveal-sensitive",
        action="store_true",
        dest="show_sensitive",
        help=(
            "Muestra valores que normalmente se ocultan: cookies, tokens, parámetros\n"
            "sensibles y nonces. Puede dejar secretos en consola o reportes."
        ),
    )
    evidence.add_argument(
        "--check-nonce-reuse",
        action="store_true",
        help=(
            "Realiza una segunda petición y compara los nonces de CSP. Reutilizar el\n"
            "mismo nonce puede debilitar una CSP si un atacante llega a conocerlo."
        ),
    )
    evidence.add_argument(
        "--test-cors",
        action="store_true",
        help=(
            "Envía una segunda petición con un Origin aleatorio y detecta reflexión,\n"
            "comodines y credenciales. No genera HTML; para eso usa --poc-cors."
        ),
    )
    evidence.add_argument(
        "--sensitive-response",
        action="store_true",
        help="Marca el endpoint como sensible y exige Cache-Control: no-store",
    )

    pocs = parser.add_argument_group("pruebas de concepto locales")
    pocs.add_argument(
        "--poc-frame",
        action="store_true",
        help=(
            "Genera una PoC HTML básica que intenta cargar la URL en un iframe.\n"
            "El navegador confirma si X-Frame-Options o CSP frame-ancestors bloquean"
        ),
    )
    pocs.add_argument(
        "--poc-frame-overlay",
        action="store_true",
        help=(
            "Superpone un formulario ficticio sobre el iframe real. Permite ajustar\n"
            "opacidad/posición del overlay y refleja los valores solo localmente;\n"
            "no transmite datos y debe usarse con valores de prueba"
        ),
    )
    pocs.add_argument(
        "--poc-cors",
        action="store_true",
        help=(
            "Envía una sonda con --poc-origin y genera un HTML explicativo con\n"
            "fetch() sin/con credenciales desde ese Origin exacto. Separa lectura\n"
            "pública de autenticada; solo datos sensibles legibles prueban impacto"
        ),
    )
    pocs.add_argument(
        "--poc-csp",
        action="store_true",
        help=(
            "Genera un kit HTML de validación CSP con política, observaciones y\n"
            "payloads inocuos; no afirma XSS sin un punto de inyección"
        ),
    )
    pocs.add_argument(
        "--poc-origin",
        default="http://127.0.0.1:8000",
        metavar="ORIGIN",
        help=(
            "Origin exacto usado por --poc-cors (predeterminado:\n"
            "http://127.0.0.1:8000). Sirve el HTML desde ese mismo Origin"
        ),
    )
    pocs.add_argument(
        "--poc-dir",
        default="safewebheaders-pocs",
        metavar="DIRECTORIO",
        help="Directorio donde se guardan las PoC HTML (predeterminado: safewebheaders-pocs)",
    )

    output = parser.add_argument_group("salida y automatización")
    output.add_argument(
        "--format",
        "--export-format",
        choices=("console", "txt", "html", "json", "csv"),
        default="console",
        help=(
            "Formato de salida cuando no puede inferirse por la extensión.\n"
            "Valores: console/txt, json, csv o html (predeterminado: console)."
        ),
    )
    output.add_argument(
        "--output",
        "--export",
        "-o",
        metavar="ARCHIVO",
        help=(
            "Guarda una copia del resultado y mantiene la salida normal en pantalla.\n"
            "La extensión elige TXT/JSON/CSV/HTML; usa - para stdout."
        ),
    )
    output.add_argument(
        "--force",
        action="store_true",
        help="Permite reemplazar un archivo de salida existente",
    )
    output.add_argument(
        "--fail-on",
        choices=("none", "incorrect", "absent", "warning", "any"),
        default="none",
        help="Devuelve código 3 si existe el tipo de hallazgo indicado",
    )
    output.add_argument(
        "--quiet",
        "--no-console",
        action="store_true",
        dest="quiet",
        help="Con --output, guarda el archivo sin repetir el análisis completo en pantalla",
    )
    output.add_argument(
        "--no-color", action="store_true", help="Desactiva colores ANSI"
    )

    # Compatibilidad con automatizaciones 8.0. Estas opciones siguen siendo
    # aceptadas, pero no se muestran en la interfaz pública de producción.
    parser.add_argument("--csp-policy", dest="csp_policy", help=argparse.SUPPRESS)
    parser.add_argument(
        "--list-excludable-headers",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--max-redirects",
        type=int,
        default=20,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--keep-sensitive-headers-on-redirect",
        action="store_true",
        dest="keep_sensitive_headers_on_redirect",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--profile",
        choices=("auto", "web", "api"),
        dest="profile",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--connect-timeout", type=float, help=argparse.SUPPRESS)
    parser.add_argument("--read-timeout", type=float, help=argparse.SUPPRESS)
    parser.add_argument("--resolve-timeout", type=float, help=argparse.SUPPRESS)
    parser.add_argument(
        "--trust-env", action="store_true", dest="trust_env", help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--request-header",
        action="append",
        dest="request_header",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--request-header-file",
        action="append",
        dest="request_header_file",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--show-sensitive",
        action="store_true",
        dest="show_sensitive",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--value-cookies",
        "--check-cookies",
        action="store_true",
        dest="value_cookie",
        help=argparse.SUPPRESS,
    )
    return parser


def _validate_target_args(args: argparse.Namespace) -> None:
    has_targets = bool(args.urls or args.url_file)
    if args.csp_policy and has_targets:
        raise ScanError(
            "--analyze-csp no puede combinarse con URL posicionales ni --url-file."
        )
    if not args.csp_policy and not has_targets:
        raise ScanError(
            "Proporciona una URL, usa --url-file ARCHIVO o indica --analyze-csp."
        )
    if args.csp_policy and any(
        (
            args.check_nonce_reuse,
            args.test_cors,
            args.poc_frame,
            args.poc_frame_overlay,
            args.poc_cors,
            args.sensitive_response,
            args.value_cookie,
        )
    ):
        raise ScanError(
            "Las opciones contextuales de red no se pueden usar con --analyze-csp."
        )


def _validate_transport_args(args: argparse.Namespace) -> None:
    if args.max_redirects < 0:
        raise ScanError("--max-redirects no puede ser negativo.")
    if args.timeout <= 0:
        raise ScanError("--timeout debe ser mayor que cero.")
    request_body = getattr(args, "request_body", None)
    request_body_file = getattr(args, "request_body_file", None)
    request_content_type = getattr(args, "request_content_type", None)
    if request_body is not None and request_body_file:
        raise ScanError("--data y --data-file son opciones incompatibles.")
    if args.method != "POST" and any(
        value is not None and value != ""
        for value in (request_body, request_body_file, request_content_type)
    ):
        raise ScanError(
            "--data, --data-file y --content-type solo se usan con --method POST."
        )
    # Los tres nombres 8.0 siguen funcionando de forma oculta. Cuando no se
    # usan, la única opción pública controla conexión, lectura y resolución.
    args.connect_timeout = (
        args.timeout if args.connect_timeout is None else args.connect_timeout
    )
    args.read_timeout = args.timeout if args.read_timeout is None else args.read_timeout
    args.resolve_timeout = (
        args.timeout if args.resolve_timeout is None else args.resolve_timeout
    )
    if any(
        value <= 0
        for value in (
            args.connect_timeout,
            args.read_timeout,
            args.resolve_timeout,
        )
    ):
        raise ScanError("Los tiempos de espera deben ser mayores que cero.")
    if args.insecure and args.ca_bundle:
        raise ScanError("--insecure y --ca-bundle son opciones incompatibles.")
    if args.cert_key and not args.cert:
        raise ScanError("--cert-key requiere --cert.")
    if (args.certpass or args.certpass_file) and not args.cert:
        raise ScanError("--certpass/--certpass-file requiere --cert.")
    if args.certpass and args.certpass_file:
        raise ScanError("Usa --certpass o --certpass-file, no ambos.")
    if args.keep_sensitive_headers_on_redirect and not args.follow_redirects:
        raise ScanError("--forward-custom-secrets requiere --follow-redirects.")


def _validate_output_args(args: argparse.Namespace) -> None:
    if args.quiet and not args.output:
        raise ScanError("--quiet/--no-console requiere --output/--export.")
    if args.force and (not args.output or args.output == "-"):
        raise ScanError("--force requiere un archivo real en --output.")


def _normalize_poc_origin(value: str) -> str:
    try:
        origin = urlsplit(value)
        _ = origin.port
    except ValueError as exc:
        raise ScanError(
            f"--poc-origin contiene un host o puerto inválido: {exc}"
        ) from exc
    if (
        origin.scheme.lower() not in {"http", "https"}
        or not origin.hostname
        or origin.path not in {"", "/"}
        or origin.query
        or origin.fragment
        or origin.username
        or origin.password
    ):
        raise ScanError(
            "--poc-origin debe ser un Origin HTTP(S) sin ruta, consulta, fragmento "
            "ni credenciales; ejemplo: http://127.0.0.1:8000."
        )
    origin_scheme = origin.scheme.lower()
    origin_host = origin.hostname.lower()
    if ":" in origin_host:
        origin_host = f"[{origin_host}]"
    origin_port = origin.port
    if (origin_scheme, origin_port) in {("http", 80), ("https", 443)}:
        origin_port = None
    origin_authority = (
        f"{origin_host}:{origin_port}" if origin_port is not None else origin_host
    )
    return f"{origin_scheme}://{origin_authority}"


def _validate_poc_args(args: argparse.Namespace) -> None:
    if args.poc_origin != "http://127.0.0.1:8000" and not args.poc_cors:
        raise ScanError("--poc-origin solo tiene efecto junto con --poc-cors.")
    if args.method != "GET" and (
        args.poc_frame or args.poc_frame_overlay or args.poc_csp
    ):
        raise ScanError(
            "Las PoC de navegador requieren --method GET para ser comparables."
        )
    if args.poc_cors:
        args.poc_origin = _normalize_poc_origin(args.poc_origin)
        if args.method != "GET":
            raise ScanError(
                "--poc-cors requiere --method GET para que la PoC y la sonda sean comparables."
            )


def validate_args(args: argparse.Namespace) -> None:
    _validate_target_args(args)
    _validate_transport_args(args)
    _validate_output_args(args)
    _validate_poc_args(args)
    # Valida nombres y errores tipográficos antes de iniciar cualquier
    # solicitud del lote.
    parse_exclusions(args.exclude_header)


def read_url_file(path_value: str) -> list[str]:
    path = Path(path_value).expanduser()
    if not path.exists():
        raise ScanError(f"No se encontró el archivo de URL: {path}")
    if not path.is_file():
        raise ScanError(f"La ruta de --url-file no es un archivo: {path}")
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except UnicodeDecodeError as exc:
        raise ScanError(
            f"No se pudo leer {path} como UTF-8. Guarda el listado como texto UTF-8."
        ) from exc
    return [
        line.strip()
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    ]


def collect_targets(args: argparse.Namespace) -> list[str]:
    values = list(args.urls)
    for file_name in args.url_file:
        values.extend(read_url_file(file_name))
    if not values:
        raise ScanError("No se encontraron URL válidas en los argumentos o archivos.")

    # Conserva el orden y elimina repeticiones literales. La normalización de
    # cada URL ocurre al evaluarla para que un objetivo inválido quede
    # registrado como error individual sin detener el resto del lote.
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        candidate = value.strip()
        if candidate and candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique


def make_offline_csp_snapshot(policy: str) -> ResponseSnapshot:
    return ResponseSnapshot(
        url="csp://politica-local",
        status_code=0,
        reason="Análisis local",
        headers={
            "content-security-policy": [policy],
            "content-type": ["text/html; charset=UTF-8"],
        },
        display_names={
            "content-security-policy": "Content-Security-Policy",
            "content-type": "Content-Type",
        },
    )


def create_report(
    args: argparse.Namespace, target_url: str | None = None
) -> ScanReport:
    validate_args(args)
    timestamp = machine_timestamp()
    excluded = parse_exclusions(args.exclude_header)
    notes: list[str] = []
    if args.essential_only:
        notes.append(ESSENTIAL_ONLY_NOTE)
    else:
        notes.append(ALL_HEADERS_NOTE)

    if args.csp_policy:
        snapshot = make_offline_csp_snapshot(args.csp_policy)
        findings = run_analysis(
            snapshot,
            snapshots=[snapshot],
            excluded=excluded,
            profile="web",
            follow_redirects=False,
            csp_only=True,
            evaluate_cookies=False,
            essential_only=args.essential_only,
        )
        return ScanReport(
            tool="SafeWebHeaders",
            version=VERSION,
            timestamp=timestamp,
            requested_url="Análisis CSP local",
            final_url=snapshot.url,
            method="N/A",
            status_code=0,
            reason=snapshot.reason,
            profile="csp-only",
            tls_verification="N/A",
            elapsed_ms=0,
            redirect_following=False,
            redirects=[],
            excluded_headers=sorted(canonical_header(item) for item in excluded),
            findings=findings,
            response_headers=snapshot.headers,
            display_names=snapshot.display_names,
            show_headers=args.show_headers,
            essential_only=args.essential_only,
            notes=[*notes, "No se realizó ninguna solicitud de red."],
            resolved_ips=[],
        )

    if target_url is None:
        if not args.urls:
            raise ScanError("No se indicó la URL que debe evaluarse.")
        target_url = args.urls[0]
    target = normalize_url(target_url)
    session: Session | None = None
    opened_responses: list[Response] = []
    try:
        session = build_session(args)
        started = time.monotonic()
        navigation = collect_navigation(session, target, args)
        opened_responses.extend(navigation.responses)
        response = navigation.final_response
        snapshots = navigation.snapshots
        snapshot = navigation.final_snapshot
        notes.extend(navigation.notes)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        profile = detect_profile(args.profile, snapshot)

        reused_nonces: set[str] = set()
        if args.check_nonce_reuse:
            first_nonces = extract_csp_nonce_strings(snapshot)
            if first_nonces:
                second_response = request_target(session, snapshot.url, args)
                opened_responses.extend([*second_response.history, second_response])
                second_snapshot = snapshot_response(second_response)
                reused_nonces = first_nonces & extract_csp_nonce_strings(
                    second_snapshot
                )
                notes.append(
                    "Se realizó una segunda solicitud para comprobar rotación de nonces CSP."
                )
            else:
                notes.append(
                    "No se encontraron nonces CSP que permitieran comprobar reutilización."
                )

        cors_probe: ResponseSnapshot | None = None
        probe_origin = ""
        if args.test_cors or args.poc_cors:
            probe_origin = (
                args.poc_origin
                if args.poc_cors
                else f"https://{uuid.uuid4().hex}.invalid"
            )
            probe_response = request_target(
                session, snapshot.url, args, extra_headers={"Origin": probe_origin}
            )
            opened_responses.extend([*probe_response.history, probe_response])
            cors_probe = snapshot_response(probe_response)
            notes.append(
                f"Se realizó una solicitud adicional con Origin {probe_origin} para comprobar CORS."
            )

        findings = run_analysis(
            snapshot,
            snapshots=snapshots,
            excluded=excluded,
            profile=profile,
            follow_redirects=args.follow_redirects,
            reused_nonces=reused_nonces,
            cors_probe=cors_probe,
            cors_probe_origin=probe_origin,
            sensitive_response=args.sensitive_response,
            # La revisión de atributos de Set-Cookie es deliberadamente opt-in;
            # sus valores continúan ocultos salvo --reveal-sensitive.
            evaluate_cookies=args.value_cookie,
            essential_only=args.essential_only,
        )

        redirects = [
            RedirectHop(
                url=item.url,
                status_code=item.status_code,
                location=item.first("location"),
                elapsed_ms=item.elapsed_ms,
                reason=item.reason,
                http_version=item.http_version,
                headers=item.headers,
                display_names=item.display_names,
                redirect_kind=item.redirect_kind,
                redirect_target=item.redirect_target,
                effective_redirect_target=item.effective_redirect_target,
                redirect_followed=item.redirect_followed,
            )
            for item in snapshots
        ]
        uses_https = any(
            urlsplit(item.url).scheme.lower() == "https" for item in snapshots
        )
        tls_verification = (
            "desactivada"
            if args.insecure and uses_https
            else "activa"
            if uses_https
            else "no aplica (solo HTTP)"
        )

        if args.insecure:
            notes.append(
                "La validación TLS se desactivó con --insecure; el resultado no valida la identidad del servidor."
            )
        if args.trust_env:
            notes.append(
                "Se habilitó la configuración de red y credenciales .netrc del entorno con --use-environment."
            )
        if getattr(args, "keep_sensitive_headers_on_redirect", False):
            notes.append(
                "Se permitió reenviar secretos personalizados a otros orígenes con --forward-custom-secrets."
            )
        if response.status_code >= 400:
            notes.append(
                "La respuesta HTTP es de error; las cabeceras pueden diferir de una página funcional."
            )
        final_request_method = str(
            getattr(getattr(response, "request", None), "method", args.method)
            or args.method
        ).upper()
        visible_method = (
            args.method
            if final_request_method == args.method
            else f"{args.method} → {final_request_method}"
        )
        if args.method == "POST":
            notes.append(
                "Se utilizó POST por solicitud expresa. Este método puede ejecutar "
                "lógica o cambios en el servidor; SafeWebHeaders no guarda ni muestra "
                "el cuerpo enviado."
            )
        elif args.method == "OPTIONS":
            notes.append(
                "Se utilizó OPTIONS; las cabeceras observadas pertenecen a esa "
                "respuesta y pueden diferir de las entregadas por GET."
            )
        if final_request_method != args.method:
            notes.append(
                f"La navegación cambió el método {args.method} a "
                f"{final_request_method} en la solicitud final."
            )

        resolved_ips = (
            []
            if getattr(args, "no_resolve", False)
            else resolve_url_ips(
                snapshot.url, timeout=getattr(args, "resolve_timeout", 2.0)
            )
        )
        return ScanReport(
            tool="SafeWebHeaders",
            version=VERSION,
            timestamp=timestamp,
            requested_url=sanitize_url(target),
            final_url=snapshot.url,
            method=visible_method,
            status_code=snapshot.status_code,
            reason=snapshot.reason,
            profile=profile,
            tls_verification=tls_verification,
            elapsed_ms=elapsed_ms,
            redirect_following=args.follow_redirects,
            redirects=redirects,
            excluded_headers=sorted(canonical_header(item) for item in excluded),
            findings=findings,
            response_headers=snapshot.headers,
            display_names=snapshot.display_names,
            show_headers=args.show_headers,
            essential_only=args.essential_only,
            notes=notes,
            resolved_ips=resolved_ips,
            document_preview=snapshot.body_preview,
            cors_probe_origin=probe_origin,
            cors_probe_status_code=(
                cors_probe.status_code if cors_probe is not None else None
            ),
            cors_probe_headers=(
                dict(cors_probe.headers) if cors_probe is not None else {}
            ),
            cookie_analysis_enabled=args.value_cookie,
        )
    finally:
        for opened in reversed(opened_responses):
            with suppress(Exception):
                opened.close()
        if session is not None:
            session.close()


def batch_triggers_fail_on(batch: BatchReport, mode: str) -> bool:
    if mode == "none":
        return False
    accepted = {
        "incorrect": {"incorrecta"},
        "absent": {"ausente"},
        "warning": {"advertencia"},
        "any": {"incorrecta", "ausente", "advertencia"},
    }[mode]
    return any(
        finding.status in accepted
        for report in batch.reports
        for finding in report.findings
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.list_excludable_headers:
            print(format_excludable_headers(), end="")
            return 0

        if args.web:
            if args.urls or args.url_file or args.csp_policy:
                raise ScanError(
                    "--web inicia la interfaz local y no se combina con URL, "
                    "--url-file ni --analyze-csp."
                )
            from .web.server import run_server

            return run_server(args.web_port, open_browser=not args.no_browser)

        validate_args(args)
        batch_timestamp = machine_timestamp()
        if args.csp_policy:
            report = create_report(args)
            generate_requested_pocs(report, args)
            batch = BatchReport(
                tool="SafeWebHeaders",
                version=VERSION,
                timestamp=batch_timestamp,
                requested_targets=["Análisis CSP local"],
                reports=[report],
                errors=[],
            )
        else:
            targets = collect_targets(args)
            reports: list[ScanReport] = []
            errors: list[ScanFailure] = []
            for target in targets:
                try:
                    report = create_report(args, target)
                    generate_requested_pocs(report, args)
                    reports.append(report)
                except ScanError as exc:
                    errors.append(
                        ScanFailure(
                            requested_url=target,
                            timestamp=machine_timestamp(),
                            error=str(exc),
                        )
                    )
            batch = BatchReport(
                tool="SafeWebHeaders",
                version=VERSION,
                timestamp=batch_timestamp,
                requested_targets=targets,
                reports=reports,
                errors=errors,
            )

        write_batch_output(batch, args)
        if batch.errors and batch.reports:
            return 1
        if batch.errors:
            return 2
        return 3 if batch_triggers_fail_on(batch, args.fail_on) else 0
    except ScanError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[ERROR] Análisis cancelado por el usuario.", file=sys.stderr)
        return 130
