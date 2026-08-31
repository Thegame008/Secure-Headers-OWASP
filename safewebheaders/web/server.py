"""Servidor HTTP local, sin dependencias externas, para la GUI."""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import re
import secrets
import sys
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import Any, cast
from urllib.parse import urlsplit

from ..constants import VERSION
from ..models import ScanError
from . import assets as web_assets
from .evidence import POC_LABELS
from .service import POC_STORE, analyze_web_payload, excludable_header_catalog

#: Los identificadores de PoC son tokens urlsafe generados por ``PocStore``.
_POC_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{16,64}")

MAX_REQUEST_BODY = 1024 * 1024
ASSET_CONTENT_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
}


def _is_loopback_host(value: str) -> bool:
    if value.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


class SafeWebHeadersServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int]) -> None:
        super().__init__(server_address, SafeWebHeadersHandler)
        self.api_token = secrets.token_urlsafe(32)


class SafeWebHeadersHandler(BaseHTTPRequestHandler):
    server_version = "SafeWebHeadersWeb"
    sys_version = ""

    @property
    def app_server(self) -> SafeWebHeadersServer:
        return cast(SafeWebHeadersServer, self.server)

    def log_message(self, format_string: str, *args: Any) -> None:
        sys.stderr.write(
            f"[SafeWebHeaders Web] {self.address_string()} {format_string % args}\n"
        )

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        )
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def _send_bytes(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: HTTPStatus, payload: MappingLike) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8")

    def _local_origin(self) -> str:
        host = self.headers.get("Host", "").strip()
        return f"http://{host}" if host else "http://127.0.0.1"

    def _valid_local_host_header(self) -> bool:
        host = self.headers.get("Host", "")
        try:
            parsed = urlsplit(f"http://{host}")
            hostname = parsed.hostname or ""
            port = parsed.port
        except ValueError:
            return False
        return _is_loopback_host(hostname) and port in {
            None,
            self.app_server.server_port,
        }

    def _valid_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        try:
            parsed = urlsplit(origin)
            port = parsed.port
        except ValueError:
            return False
        return (
            parsed.scheme == "http"
            and _is_loopback_host(parsed.hostname or "")
            and port == self.app_server.server_port
            and not parsed.username
            and not parsed.password
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
        )

    def _asset_bytes(self, name: str) -> bytes:
        asset = files(web_assets).joinpath(name)
        data = asset.read_bytes()
        if name == "index.html":
            text = data.decode("utf-8")
            text = text.replace("__SWH_TOKEN__", self.app_server.api_token)
            text = text.replace("__SWH_VERSION__", VERSION)
            return text.encode("utf-8")
        return data

    def do_GET(self) -> None:
        if not self._valid_local_host_header():
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Host local inválido."})
            return
        path = urlsplit(self.path).path
        assets = {
            "/": "index.html",
            "/index.html": "index.html",
            "/styles.css": "styles.css",
            "/app.js": "app.js",
            "/logo.svg": "logo.svg",
        }
        if path == "/api/health":
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "tool": "SafeWebHeaders",
                    "version": VERSION,
                    "excludable_headers": excludable_header_catalog(),
                },
            )
            return
        if path.startswith("/poc/"):
            self._send_poc(path)
            return
        name = assets.get(path)
        if name is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Recurso no encontrado."})
            return
        suffix = "." + name.rsplit(".", 1)[-1]
        self._send_bytes(
            HTTPStatus.OK,
            self._asset_bytes(name),
            ASSET_CONTENT_TYPES[suffix],
        )

    def _build_poc(self, payload: Any) -> MappingLike:
        if not isinstance(payload, dict):
            raise ScanError("El cuerpo JSON debe ser un objeto.")
        token = payload.get("poc_id", "")
        kind = payload.get("kind", "")
        if not isinstance(token, str) or not isinstance(kind, str):
            raise ScanError("poc_id y kind deben ser texto.")
        if not _POC_TOKEN_RE.fullmatch(token):
            raise ScanError("Identificador de prueba de concepto inválido.")
        origin = self._local_origin()
        POC_STORE.build(token, kind, local_origin=origin)
        return {
            "poc_id": token,
            "kind": kind,
            "label": POC_LABELS[kind],
            "url": f"{origin}/poc/{token}/{kind}",
            "filename": f"safewebheaders-poc-{kind}.html",
        }

    def _send_poc(self, path: str) -> None:
        parts = path.strip("/").split("/")
        if len(parts) != 3 or not _POC_TOKEN_RE.fullmatch(parts[1]):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "PoC no encontrada."})
            return
        content = POC_STORE.rendered(parts[1], parts[2])
        if content is None:
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"error": "La PoC no ha sido generada o ya expiró."},
            )
            return
        body = content.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        # La PoC define su propia CSP en un meta y necesita enmarcar el objetivo,
        # de modo que no se le aplica la CSP restrictiva de la interfaz.
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        route = urlsplit(self.path).path
        if route not in {"/api/analyze", "/api/poc"}:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Recurso no encontrado."})
            return
        if not self._valid_local_host_header() or not self._valid_origin():
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Origen local inválido."})
            return
        token = self.headers.get("X-SafeWebHeaders-Token", "")
        if not hmac.compare_digest(token, self.app_server.api_token):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Token local inválido."})
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if content_type != "application/json":
            self._send_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {"error": "El cuerpo debe usar Content-Type: application/json."},
            )
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = -1
        if not 0 < content_length <= MAX_REQUEST_BODY:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": "El cuerpo JSON está vacío o supera 1 MiB."},
            )
            return
        try:
            payload = json.loads(self.rfile.read(content_length))
            if route == "/api/poc":
                result = self._build_poc(payload)
            else:
                result = analyze_web_payload(
                    payload, local_origin=self._local_origin()
                )
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "JSON inválido."})
            return
        except ScanError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        except Exception:  # noqa: BLE001 - última frontera del servidor HTTP local
            self.log_error("Error interno durante el análisis")
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "No fue posible completar el análisis."},
            )
            return
        self._send_json(HTTPStatus.OK, result)


MappingLike = dict[str, Any]


def create_server(port: int = 8080) -> SafeWebHeadersServer:
    if not 0 <= port <= 65_535:
        raise ScanError("El puerto web debe estar entre 0 y 65535.")
    return SafeWebHeadersServer(("127.0.0.1", port))


def _create_server_with_fallback(
    port: int,
) -> tuple[SafeWebHeadersServer, OSError | None]:
    """Usa el puerto preferido y recurre a uno efímero si el SO lo rechaza."""

    try:
        return create_server(port), None
    except OSError as preferred_error:
        if port == 0:
            raise ScanError(
                "El sistema operativo no permitió abrir un socket local en "
                f"127.0.0.1: {preferred_error}"
            ) from preferred_error
        try:
            return create_server(0), preferred_error
        except OSError as fallback_error:
            raise ScanError(
                f"El puerto local {port} fue rechazado ({preferred_error}) y tampoco "
                f"se pudo reservar un puerto libre ({fallback_error}). Revisa el "
                "Firewall de Windows, el antivirus y los rangos de puertos reservados."
            ) from fallback_error


def run_server(port: int = 8080, *, open_browser: bool = True) -> int:
    server, preferred_error = _create_server_with_fallback(port)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"SafeWebHeaders Web {VERSION}")
    if preferred_error is not None:
        print(
            f"[AVISO] El puerto {port} no estaba disponible ({preferred_error}).\n"
            "Se seleccionó automáticamente un puerto local libre."
        )
    print(f"Servidor local: {url}")
    print("Presiona Ctrl+C para detenerlo.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inicia la GUI local de SafeWebHeaders"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Puerto preferido (8080); usa 0 para elegir uno libre",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="No abre automáticamente el navegador",
    )
    args = parser.parse_args(argv)
    try:
        return run_server(args.port, open_browser=not args.no_browser)
    except (OSError, ScanError) as exc:
        print(f"[ERROR] No se pudo iniciar la GUI: {exc}", file=sys.stderr)
        return 2
