"""Utils de SafeWebHeaders."""

from __future__ import annotations

import difflib
import ipaddress
import queue
import re
import socket
import threading
from collections.abc import Sequence
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .constants import (
    EXCLUDABLE_HEADERS,
    EXCLUSION_GROUPS,
    HEADER_ALIASES,
)
from .models import (
    ScanError,
)

HTTP_FIELD_NAME_PATTERN = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"


def split_http_parameters(value: str) -> tuple[list[str], str]:
    """Separa parámetros HTTP respetando quoted-string y rechaza controles."""

    parts: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in value:
        if char in "\r\n\x00":
            return [], "contiene caracteres de control"
        if escaped:
            escaped = False
        elif char == "\\" and quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
        if char == ";" and not quoted:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if quoted or escaped:
        return [], "contiene una cadena entre comillas sin cerrar"
    parts.append("".join(current).strip())
    return parts, ""


def parse_http_parameter_value(value: str) -> tuple[str, str]:
    """Valida token/quoted-string y devuelve el contenido decodificado."""

    if re.fullmatch(HTTP_FIELD_NAME_PATTERN, value):
        return value, ""
    if len(value) < 2 or not value.startswith('"') or not value.endswith('"'):
        return "", "no es token ni quoted-string"
    decoded: list[str] = []
    escaped = False
    for char in value[1:-1]:
        if escaped:
            if ord(char) < 32 and char != "\t":
                return "", "quoted-string contiene un control inválido"
            decoded.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            return "", "quoted-string contiene comillas sin escape"
        elif ord(char) < 32 and char != "\t":
            return "", "quoted-string contiene un control inválido"
        else:
            decoded.append(char)
    if escaped:
        return "", "quoted-string termina con un escape incompleto"
    return "".join(decoded), ""


def normalize_header_name(name: str) -> str:
    """Normaliza nombres internos y entradas de CLI, incluidos alias cómodos."""

    normalized = name.strip().lower().replace("_", "-")
    return HEADER_ALIASES.get(normalized, normalized)


def normalize_observed_header_name(name: str) -> str:
    """Normaliza un nombre recibido por HTTP sin convertir alias ni guiones bajos.

    RFC 9110 indica que los nombres no distinguen mayúsculas y minúsculas, pero
    ``XFO`` no es un alias de protocolo de ``X-Frame-Options`` y ``_`` no
    equivale a ``-``. Estas comodidades se reservan a la CLI y a las pruebas.
    """

    return name.strip().lower()


def machine_timestamp() -> str:
    """Fecha ISO 8601 con zona para JSON/CSV y correlación entre sistemas."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def display_timestamp(value: str) -> str:
    """Fecha legible sin el offset UTC, que se conserva en datos estructurados."""
    rendered = value.strip().replace("T", " ", 1)
    return re.sub(r"\s?(?:Z|[+-]\d{2}:?\d{2})$", "", rendered).strip()


def canonical_header(name: str) -> str:
    normalized = name.strip().lower()
    special = {
        "content-security-policy": "Content-Security-Policy",
        "content-security-policy-report-only": "Content-Security-Policy-Report-Only",
        "strict-transport-security": "Strict-Transport-Security",
        "x-content-type-options": "X-Content-Type-Options",
        "x-frame-options": "X-Frame-Options",
        "x-xss-protection": "X-XSS-Protection",
        "x-aspnet-version": "X-AspNet-Version",
        "x-aspnetmvc-version": "X-AspNetMvc-Version",
        "x-dns-prefetch-control": "X-DNS-Prefetch-Control",
        "x-webkit-csp": "X-WebKit-CSP",
        "x-content-security-policy": "X-Content-Security-Policy",
        "x-source-map": "X-SourceMap",
        "sourcemap": "SourceMap",
        "expect-ct": "Expect-CT",
    }
    return special.get(
        normalized, "-".join(part.capitalize() for part in normalized.split("-"))
    )


def sanitize_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise ScanError(f"La URL contiene un host o puerto inválido: {exc}") from exc
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port:
        host = f"{host}:{port}"
    # Los fragmentos no se envían en HTTP y con frecuencia contienen estado o
    # tokens de flujos OAuth. No deben terminar en reportes ni PoC.
    return urlunsplit((parts.scheme, host, parts.path, parts.query, ""))


def normalize_url(url: str) -> str:
    candidate = url.strip()
    if not candidate:
        raise ScanError("La URL no puede estar vacía.")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        parts = urlsplit(candidate)
        _ = parts.port
    except ValueError as exc:
        raise ScanError(f"La URL contiene un host o puerto inválido: {exc}") from exc
    if parts.scheme.lower() not in {"http", "https"}:
        raise ScanError("Solo se admiten URL con esquema http:// o https://.")
    if not parts.hostname:
        raise ScanError("La URL no contiene un nombre de host válido.")
    if parts.username or parts.password:
        raise ScanError(
            "No incluyas credenciales dentro de la URL. Usa -H/--header "
            "o un mecanismo de autenticación controlado."
        )
    # Un fragmento pertenece al cliente, nunca a la petición HTTP auditada.
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def resolve_url_ips(url: str, timeout: float = 2.0) -> list[str]:
    """Resuelve todas las direcciones A/AAAA visibles para el host final.

    Estas son direcciones obtenidas del resolvedor DNS local. Cuando se usa un
    proxy o una CDN no deben interpretarse automáticamente como la dirección
    exacta del servidor que terminó la conexión HTTP.
    """

    try:
        parts = urlsplit(url)
        host = parts.hostname
        if not host:
            return []
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            return [literal.compressed]

        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except (OSError, ValueError):
        return []

    results_queue: queue.Queue[list[Any] | None] = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            records = socket.getaddrinfo(
                host,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except (OSError, ValueError):
            records = None
        try:
            results_queue.put_nowait(records)
        except queue.Full:
            pass

    worker = threading.Thread(target=resolve, daemon=True, name="swh-dns")
    worker.start()
    worker.join(max(0.01, timeout))
    if worker.is_alive():
        return []
    try:
        records = results_queue.get_nowait()
    except queue.Empty:
        return []
    if records is None:
        return []

    addresses: set[str] = set()
    for _family, _socktype, _proto, _canonname, sockaddr in records:
        if not sockaddr:
            continue
        address = str(sockaddr[0]).split("%", 1)[0]
        try:
            addresses.add(ipaddress.ip_address(address).compressed)
        except ValueError:
            continue

    return sorted(
        addresses,
        key=lambda value: (
            ipaddress.ip_address(value).version,
            int(ipaddress.ip_address(value)),
        ),
    )


def parse_exclusions(values: Sequence[str]) -> set[str]:
    excluded: set[str] = set()
    for value in values:
        for item in value.split(","):
            raw = item.strip()
            if not raw:
                continue
            lookup = raw.lower().replace("_", "-")
            if lookup in EXCLUSION_GROUPS:
                excluded.update(EXCLUSION_GROUPS[lookup])
                continue
            normalized = normalize_header_name(raw)
            if normalized not in EXCLUDABLE_HEADERS:
                candidates = sorted(
                    EXCLUDABLE_HEADERS | set(HEADER_ALIASES) | set(EXCLUSION_GROUPS)
                )
                close = difflib.get_close_matches(lookup, candidates, n=3, cutoff=0.55)
                hint = f" Quizá quisiste: {', '.join(close)}." if close else ""
                raise ScanError(
                    f"No se reconoce {raw!r} en --exclude-header.{hint} "
                    "Consulta la sección Exclusiones de README.md o usa el nombre HTTP "
                    "que aparece en el reporte."
                )
            excluded.add(normalized)
    return excluded


def format_excludable_headers() -> str:
    lines = [
        "Cabeceras que pueden excluirse (no distingue mayúsculas/minúsculas):",
        "",
    ]
    lines.extend(f"  - {canonical_header(name)}" for name in sorted(EXCLUDABLE_HEADERS))
    lines.extend(
        [
            "",
            "Alias cortos:",
            "  CSP, CSP-Report-Only, HSTS, XCTO, XFO, Referrer, Permissions,",
            "  COOP, COEP, CORP, Cookies y CORS.",
            "",
            "Grupos:",
            "  obsolete / obsoletas  Todas las cabeceras retiradas o heredadas.",
            "  disclosure / divulgacion  Todas las cabeceras de divulgación.",
            "",
            "Ejemplos:",
            "  --exclude-header Strict-Transport-Security",
            "  --exclude-header X-Frame-Options",
            "  --exclude-header Referrer-Policy",
            "  --exclude-headers Referrer-Policy",
            "  --exclude-header CSP --exclude-header Server",
            '  --exclude-header "HSTS,X-Frame-Options,X-XSS-Protection"',
            '  --exclude-headers "HSTS,CSP,Referrer-Policy"',
            "  --exclude-header obsoletas",
            "",
            "Con una sola opción, separa nombres con comas. Si prefieres espacios,",
            "repite --exclude-header antes de cada nombre.",
        ]
    )
    return "\n".join(lines) + "\n"


def parse_request_headers(values: Sequence[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    observed_names: set[str] = set()
    for item in values:
        if "\n" in item or "\r" in item:
            raise ScanError("Se rechazó una cabecera de solicitud con saltos de línea.")
        if ":" not in item:
            raise ScanError(
                f"Cabecera de solicitud inválida: {item!r}. Usa 'Nombre: valor'."
            )
        name, value = item.split(":", 1)
        name = name.strip()
        if not name:
            raise ScanError("La cabecera de solicitud debe tener nombre.")
        if not re.fullmatch(HTTP_FIELD_NAME_PATTERN, name):
            raise ScanError(
                f"Nombre de cabecera HTTP inválido: {name!r}. Usa un field-name RFC válido."
            )
        normalized = name.lower()
        if normalized in observed_names:
            raise ScanError(f"La cabecera de solicitud {name!r} está duplicada.")
        observed_names.add(normalized)
        headers[name] = value.strip()
    return headers
