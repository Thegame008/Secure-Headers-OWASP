"""Transport de SafeWebHeaders."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from requests import Response, Session
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import (
    InvalidURL,
    ProxyError,
    RequestException,
    SSLError,
    Timeout,
    TooManyRedirects,
)
from urllib3.exceptions import HTTPError as Urllib3HTTPError

from .models import (
    ResponseSnapshot,
    ScanError,
)
from .utils import (
    normalize_observed_header_name,
    parse_request_headers,
    sanitize_url,
)

SENSITIVE_REQUEST_HEADERS = {
    "api-key",
    "authorization",
    "cookie",
    "jwt",
    "proxy-authorization",
    "secret",
    "token",
    "x-access-token",
    "x-api-key",
    "x-auth-token",
    "x-client-secret",
    "x-csrf-token",
    "x-jwt",
    "x-secret",
    "x-session-id",
    "x-token",
}

BODY_PREVIEW_LIMIT = 256 * 1024
REQUEST_BODY_LIMIT = 1024 * 1024


def normalized_origin(url: str) -> tuple[str, str, int | None]:
    """Devuelve el origen efectivo, normalizando puertos predeterminados."""

    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    port = parts.port
    if port is None:
        port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, host, port


def is_sensitive_request_header(name: str) -> bool:
    normalized = name.strip().lower()
    return normalized in SENSITIVE_REQUEST_HEADERS or normalized.endswith(
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


class SafeRedirectSession(requests.Session):
    """Session que no propaga secretos personalizados a otro origen."""

    def __init__(self, *, keep_sensitive_headers_on_redirect: bool = False) -> None:
        super().__init__()
        self.keep_sensitive_headers_on_redirect = keep_sensitive_headers_on_redirect

    def rebuild_auth(self, prepared_request: Any, response: Response) -> None:
        super().rebuild_auth(prepared_request, response)
        if self.keep_sensitive_headers_on_redirect:
            return
        try:
            changed_origin = normalized_origin(
                response.request.url or ""
            ) != normalized_origin(prepared_request.url)
        except (TypeError, ValueError):
            changed_origin = True
        if changed_origin:
            for name in list(prepared_request.headers):
                if is_sensitive_request_header(name):
                    prepared_request.headers.pop(name, None)


def read_request_header_files(paths: Sequence[str]) -> list[str]:
    values: list[str] = []
    for path_value in paths:
        path = Path(path_value).expanduser()
        try:
            lines = path.read_text(encoding="utf-8-sig").splitlines()
        except (OSError, UnicodeError) as exc:
            raise ScanError(
                f"No se pudo leer el archivo de cabeceras {path}: {exc}"
            ) from exc
        values.extend(
            line.strip()
            for line in lines
            if line.strip() and not line.lstrip().startswith("#")
        )
    return values


def read_secret_file(path_value: str) -> str:
    path = Path(path_value).expanduser()
    try:
        value = path.read_text(encoding="utf-8-sig").splitlines()[0]
    except IndexError as exc:
        raise ScanError(f"El archivo de secreto está vacío: {path}") from exc
    except (OSError, UnicodeError) as exc:
        raise ScanError(f"No se pudo leer el archivo de secreto {path}: {exc}") from exc
    return value


def request_body_data(args: argparse.Namespace) -> str | bytes | None:
    """Carga de forma acotada el cuerpo POST solicitado por el operador."""

    inline = getattr(args, "request_body", None)
    path_value = getattr(args, "request_body_file", None)
    if inline is not None:
        if len(inline.encode("utf-8")) > REQUEST_BODY_LIMIT:
            raise ScanError("El cuerpo indicado con --data supera 1 MiB.")
        return inline
    if not path_value:
        return None
    path = Path(path_value).expanduser()
    try:
        if not path.is_file():
            raise ScanError(f"No se encontró el archivo de cuerpo POST: {path}")
        if path.stat().st_size > REQUEST_BODY_LIMIT:
            raise ScanError("El archivo de cuerpo POST supera 1 MiB.")
        return path.read_bytes()
    except ScanError:
        raise
    except OSError as exc:
        raise ScanError(f"No se pudo leer el cuerpo POST {path}: {exc}") from exc


def extract_response_headers(
    response: Response,
) -> tuple[dict[str, list[str]], dict[str, str]]:
    collected: dict[str, list[str]] = {}
    display_names: dict[str, str] = {}
    raw_headers = getattr(response.raw, "headers", None)

    if raw_headers is not None and hasattr(raw_headers, "keys"):
        for raw_name in raw_headers:
            name = str(raw_name)
            key = normalize_observed_header_name(name)
            display_names.setdefault(key, name)
            try:
                values = [str(value) for value in raw_headers.getlist(raw_name)]
            except (AttributeError, TypeError):
                value = raw_headers.get(raw_name)
                values = [str(value)] if value is not None else []
            if values:
                # RFC 9110 define los nombres de campo como case-insensitive.
                # Si un servidor/intermediario envía el mismo nombre con otra
                # combinación de mayúsculas, debe conservarse como otro valor
                # del mismo campo y no sobrescribir la evidencia anterior.
                collected.setdefault(key, []).extend(values)

    if not collected:
        for name, value in response.headers.items():
            key = normalize_observed_header_name(name)
            display_names[key] = name
            collected.setdefault(key, []).append(str(value))

    return collected, display_names


def response_http_version(response: Response) -> str:
    """Convierte la versión expuesta por urllib3 a una etiqueta legible."""

    version = getattr(response.raw, "version", None)
    known = {
        9: "HTTP/0.9",
        10: "HTTP/1.0",
        11: "HTTP/1.1",
        20: "HTTP/2",
        30: "HTTP/3",
    }
    if version in known:
        return known[version]
    if isinstance(version, str) and version.upper().startswith("HTTP/"):
        return version.upper()
    return "HTTP/?"


def response_body_preview(
    response: Response,
    headers: Mapping[str, Sequence[str]],
    *,
    limit: int = BODY_PREVIEW_LIMIT,
) -> str:
    """Lee una muestra acotada de HTML para diagnósticos del lado del cliente."""

    content_types = headers.get("content-type", [])
    media_type = (
        content_types[0].split(";", 1)[0].strip().lower() if content_types else ""
    )
    method = getattr(getattr(response, "request", None), "method", "GET")
    if media_type not in {"text/html", "application/xhtml+xml"} or method == "HEAD":
        return ""
    try:
        raw = response.raw.read(limit, decode_content=True)
    except (OSError, ValueError, Urllib3HTTPError):
        # La muestra es diagnóstica y no debe invalidar un análisis de
        # cabeceras si el cuerpo está truncado o usa una codificación rota.
        return ""
    if not raw:
        return ""
    if isinstance(raw, str):
        return raw[:limit]
    encoding = response.encoding or "utf-8"
    try:
        return raw.decode(encoding, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def snapshot_response(
    response: Response, *, include_body_preview: bool = False
) -> ResponseSnapshot:
    headers, names = extract_response_headers(response)
    elapsed_ms = int(response.elapsed.total_seconds() * 1000) if response.elapsed else 0
    location = headers.get("location", [""])[0]
    is_http_redirect = 300 <= response.status_code < 400 and bool(location)
    redirect_target = (
        sanitize_url(urljoin(response.url, location)) if is_http_redirect else ""
    )
    return ResponseSnapshot(
        url=sanitize_url(response.url),
        status_code=response.status_code,
        reason=response.reason or "",
        headers=headers,
        display_names=names,
        elapsed_ms=elapsed_ms,
        http_version=response_http_version(response),
        body_preview=(
            response_body_preview(response, headers) if include_body_preview else ""
        ),
        redirect_kind="http" if is_http_redirect else "",
        redirect_target=redirect_target,
        effective_redirect_target=sanitize_url(
            str(getattr(response, "_safewebheaders_effective_redirect_target", ""))
        ),
    )


def build_session(args: argparse.Namespace) -> Session:
    header_values = list(args.request_header)
    header_values.extend(
        read_request_header_files(getattr(args, "request_header_file", []))
    )
    custom_headers = parse_request_headers(header_values)

    cert_path: Path | None = None
    key_path: Path | None = None
    pkcs12_adapter: Any | None = None
    if args.cert:
        cert_path = Path(args.cert).expanduser()
        if not cert_path.is_file():
            raise ScanError(f"No se encontró el certificado: {cert_path}")
        if cert_path.suffix.lower() in {".p12", ".pfx"}:
            password = args.certpass
            if getattr(args, "certpass_file", None):
                password = read_secret_file(args.certpass_file)
            password = password or os.getenv("SAFEWEBHEADERS_CERT_PASSWORD")
            if password is None and sys.stdin.isatty():
                password = getpass.getpass("Contraseña del certificado PKCS#12: ")
            try:
                from requests_pkcs12 import (  # type: ignore[import-untyped]
                    Pkcs12Adapter,
                )
            except ImportError as exc:
                raise ScanError(
                    "Para usar certificados P12/PFX instala requests-pkcs12: "
                    "python -m pip install requests-pkcs12"
                ) from exc
            try:
                pkcs12_adapter = Pkcs12Adapter(
                    pkcs12_filename=str(cert_path),
                    pkcs12_password=password,
                )
            except (OSError, TypeError, ValueError) as exc:
                raise ScanError(
                    f"No se pudo abrir el certificado PKCS#12: {exc}"
                ) from exc
        elif args.cert_key:
            key_path = Path(args.cert_key).expanduser()
            if not key_path.is_file():
                raise ScanError(f"No se encontró la clave privada: {key_path}")

    session = SafeRedirectSession(
        keep_sensitive_headers_on_redirect=getattr(
            args, "keep_sensitive_headers_on_redirect", False
        )
    )
    # Evita que Requests envíe credenciales de .netrc o use proxies del entorno
    # sin una decisión explícita del operador.
    session.trust_env = args.trust_env
    session.max_redirects = args.max_redirects
    session.headers.update({"User-Agent": args.user_agent})
    session.headers.update(custom_headers)
    request_content_type = getattr(args, "request_content_type", None)
    if request_content_type and "Content-Type" not in session.headers:
        session.headers["Content-Type"] = request_content_type
    session_any: Any = session
    session_any._safewebheaders_request_body = request_body_data(args)

    if args.proxy:
        session.proxies.update({"http": args.proxy, "https": args.proxy})

    if pkcs12_adapter is not None:
        session.mount("https://", pkcs12_adapter)
    elif cert_path is not None and key_path is not None:
        session.cert = (str(cert_path), str(key_path))
    elif cert_path is not None:
        session.cert = str(cert_path)

    return session


def request_target(
    session: Session,
    url: str,
    args: argparse.Namespace,
    *,
    extra_headers: Mapping[str, str] | None = None,
) -> Response:
    verify: bool | str
    if args.insecure:
        verify = False
        try:
            from urllib3 import disable_warnings
            from urllib3.exceptions import InsecureRequestWarning

            disable_warnings(category=InsecureRequestWarning)
        except ImportError:
            pass
    elif args.ca_bundle:
        verify = args.ca_bundle
    else:
        verify = True

    prefix: list[Response] = []
    request_url = url

    def close_prefix(items: Sequence[Response]) -> None:
        for item in reversed(items):
            try:
                item.close()
            except RequestException:
                pass

    def secure_retry_for_failed_downgrade(
        observed: Sequence[Response], exc: RequestException
    ) -> tuple[Response | None, str]:
        failed_request = getattr(exc, "request", None)
        failed_url = str(getattr(failed_request, "url", "") or "")

        def same_request_url(left: str, right: str) -> bool:
            try:
                left_parts = urlsplit(left)
                right_parts = urlsplit(right)
                left_origin = normalized_origin(left)
                right_origin = normalized_origin(right)
            except (TypeError, ValueError):
                return False
            return (
                left_origin == right_origin
                and (left_parts.path or "/") == (right_parts.path or "/")
                and left_parts.query == right_parts.query
            )

        for candidate in reversed(observed):
            location = candidate.headers.get("Location", "")
            if not (300 <= candidate.status_code < 400 and location):
                continue
            try:
                announced = urljoin(candidate.url, location)
                source_is_https = urlsplit(candidate.url).scheme.lower() == "https"
            except ValueError:
                continue
            candidate_failed_url = failed_url or announced
            try:
                failed_parts = urlsplit(candidate_failed_url)
            except ValueError:
                continue
            if (
                not source_is_https
                or failed_parts.scheme.lower() != "http"
                or not same_request_url(announced, candidate_failed_url)
            ):
                continue
            try:
                hostname = failed_parts.hostname or ""
                port = failed_parts.port
            except ValueError:
                continue
            if not hostname:
                return None, ""
            netloc = hostname
            if ":" in hostname and not hostname.startswith("["):
                netloc = f"[{hostname}]"
            if port not in {None, 80}:
                netloc = f"{netloc}:{port}"
            if failed_parts.username or failed_parts.password:
                return None, ""
            secure_url = urlunsplit(
                (
                    "https",
                    netloc,
                    failed_parts.path,
                    failed_parts.query,
                    failed_parts.fragment,
                )
            )
            return candidate, secure_url
        return None, ""

    try:
        while True:
            observed: list[Response] = []

            def remember_response(
                response: Response,
                *_args: Any,
                _observed: list[Response] = observed,
                **_kwargs: Any,
            ) -> None:
                _observed.append(response)

            try:
                response = session.request(
                    method=args.method,
                    url=request_url,
                    headers=dict(extra_headers or {}),
                    data=(
                        getattr(session, "_safewebheaders_request_body", None)
                        if args.method == "POST"
                        else None
                    ),
                    timeout=(args.connect_timeout, args.read_timeout),
                    allow_redirects=args.follow_redirects,
                    verify=verify,
                    stream=True,
                    hooks={"response": remember_response},
                )
            except (Timeout, RequestsConnectionError) as exc:
                source, secure_url = secure_retry_for_failed_downgrade(observed, exc)
                may_retry = (
                    bool(args.follow_redirects)
                    and source is not None
                    and bool(secure_url)
                    and len(prefix) + len(observed) < args.max_redirects
                )
                if not may_retry:
                    close_prefix([*prefix, *observed])
                    raise
                source_any: Any = source
                source_any._safewebheaders_effective_redirect_target = secure_url
                prefix.extend(observed)
                request_url = secure_url
                continue
            if prefix:
                response.history = [*prefix, *response.history]
            return response
    except SSLError as exc:
        close_prefix(prefix)
        raise ScanError(
            "Falló la validación TLS. Corrige el certificado, usa --ca-bundle "
            "para una CA privada o, solo para pruebas autorizadas, --insecure. "
            f"Detalle: {exc}"
        ) from exc
    except TooManyRedirects as exc:
        close_prefix(prefix)
        raise ScanError(
            f"Se alcanzó el límite interno de {args.max_redirects} redirecciones; "
            "puede existir un bucle o una cadena anormalmente larga."
        ) from exc
    except Timeout as exc:
        close_prefix(prefix)
        raise ScanError(
            f"La URL no respondió dentro del tiempo configurado "
            f"({args.timeout:g} s por fase). Detalle: {exc}"
        ) from exc
    except ProxyError as exc:
        close_prefix(prefix)
        raise ScanError(f"No fue posible usar el proxy configurado: {exc}") from exc
    except (InvalidURL, RequestsConnectionError) as exc:
        close_prefix(prefix)
        raise ScanError(f"No fue posible conectar con la URL: {exc}") from exc
    except RequestException as exc:
        close_prefix(prefix)
        raise ScanError(f"La solicitud HTTP falló: {exc}") from exc
