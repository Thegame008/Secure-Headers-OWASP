"""Apoyo de evidencia visual para la GUI local.

Reúne tres capacidades que solo tienen sentido en la interfaz web:

* el inventario compacto de cabeceras por categoría, para encabezar el informe;
* el favicon del objetivo, recuperado por el servidor y embebido como ``data:``
  para que el navegador no emita ninguna petición hacia el sitio auditado;
* el almacén de pruebas de concepto, que permite servirlas desde el propio
  servidor local en vez de escribirlas en disco como hace la CLI.
"""

from __future__ import annotations

import argparse
import base64
import re
import secrets
import threading
from collections import OrderedDict
from typing import Any
from urllib.parse import urljoin, urlsplit

from ..models import ScanError, ScanReport
from ..pocs import build_cors_poc, build_csp_poc, build_frame_poc
from ..presentation import build_display_groups
from ..utils import normalize_header_name

#: Categorías que aparecen en el inventario compacto, en orden de lectura.
INVENTORY_CATEGORIES = (
    "ausentes",
    "incorrectas",
    "correctas",
    "obsoletas",
    "divulgacion",
    "cookies",
)

FAVICON_MAX_BYTES = 64 * 1024
FAVICON_MEDIA_TYPES = {
    "image/x-icon",
    "image/vnd.microsoft.icon",
    "image/png",
    "image/gif",
    "image/jpeg",
    "image/svg+xml",
    "image/webp",
}
_ICON_LINK_RE = re.compile(
    r"<link\b[^>]*\brel\s*=\s*[\"']([^\"']*icon[^\"']*)[\"'][^>]*>",
    re.IGNORECASE,
)
_HREF_RE = re.compile(r"\bhref\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)

POC_KINDS = {"frame", "frame-overlay", "cors", "csp"}
POC_LABELS = {
    "frame": "Framing en iframe",
    "frame-overlay": "Framing interactivo con superposición",
    "cors": "Lectura cross-origin (CORS)",
    "csp": "Resumen de Content-Security-Policy",
}


def header_inventory(report: ScanReport) -> dict[str, list[str]]:
    """Devuelve los nombres de cabecera agrupados por categoría visible.

    Solo nombres: el detalle completo ya vive en el cuerpo del informe. Sirve
    para que el analista vea de un vistazo qué falta, qué está mal, qué está
    bien y qué es heredado.
    """

    groups = build_display_groups(report)
    inventory: dict[str, list[str]] = {}
    for category in INVENTORY_CATEGORIES:
        seen: list[str] = []
        known: set[str] = set()
        for entry in groups.get(category, []):
            name = entry.finding.header
            key = normalize_header_name(name)
            if key and key not in known:
                known.add(key)
                seen.append(name)
        if seen:
            inventory[category] = seen
    return inventory


def _favicon_candidates(report: ScanReport) -> list[str]:
    base = report.final_url
    parts = urlsplit(base)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return []
    candidates: list[str] = []
    preview = getattr(report, "document_preview", "") or ""
    for match in _ICON_LINK_RE.finditer(preview):
        href = _HREF_RE.search(match.group(0))
        if href is None:
            continue
        try:
            resolved = urljoin(base, href.group(1).strip())
        except ValueError:
            continue
        if urlsplit(resolved).scheme in {"http", "https"}:
            candidates.append(resolved)
    origin = f"{parts.scheme}://{parts.netloc}"
    candidates.extend(
        [
            f"{origin}/favicon.ico",
            f"{origin}/favicon.png",
            f"{origin}/favicon.svg",
            f"{origin}/apple-touch-icon.png",
        ]
    )
    unique: list[str] = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    return unique[:5]


def fetch_favicon(report: ScanReport, args: argparse.Namespace) -> str | None:
    """Recupera el favicon del objetivo y lo devuelve como ``data:`` URI.

    Nunca interrumpe el análisis: cualquier fallo se traduce en ``None`` y la
    GUI muestra un marcador con la inicial del host.
    """

    candidates = _favicon_candidates(report)
    if not candidates:
        return None
    try:
        from ..transport import build_session
    except Exception:  # pragma: no cover - dependencia opcional ausente
        return None
    timeout = min(float(getattr(args, "timeout", 15) or 15), 6.0)
    try:
        session = build_session(args)
    except Exception:
        return None
    try:
        for candidate in candidates:
            try:
                response = session.get(
                    candidate,
                    timeout=timeout,
                    allow_redirects=True,
                    stream=True,
                    verify=not getattr(args, "insecure", False),
                )
            except Exception:
                continue
            try:
                if response.status_code != 200:
                    continue
                media_type = (
                    response.headers.get("Content-Type", "")
                    .split(";", 1)[0]
                    .strip()
                    .lower()
                )
                if media_type not in FAVICON_MEDIA_TYPES:
                    continue
                payload = response.raw.read(FAVICON_MAX_BYTES + 1, decode_content=True)
                if not payload or len(payload) > FAVICON_MAX_BYTES:
                    continue
                encoded = base64.b64encode(payload).decode("ascii")
                return f"data:{media_type};base64,{encoded}"
            finally:
                response.close()
    finally:
        session.close()
    return None


class PocStore:
    """Almacén acotado en memoria de informes y PoC generadas.

    Mantener el ``ScanReport`` permite construir una PoC después del análisis
    sin repetir el escaneo. El identificador es un token aleatorio: es lo único
    que protege la URL de la PoC, que por diseño no puede exigir una cabecera de
    token porque el navegador la abre como navegación de primer nivel.
    """

    def __init__(self, capacity: int = 48) -> None:
        self._capacity = capacity
        self._reports: OrderedDict[str, ScanReport] = OrderedDict()
        self._rendered: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()

    def register(self, report: ScanReport) -> str:
        token = secrets.token_urlsafe(18)
        with self._lock:
            self._reports[token] = report
            while len(self._reports) > self._capacity:
                evicted, _ = self._reports.popitem(last=False)
                for key in [key for key in self._rendered if key[0] == evicted]:
                    self._rendered.pop(key, None)
        return token

    def report(self, token: str) -> ScanReport | None:
        with self._lock:
            found = self._reports.get(token)
            if found is not None:
                self._reports.move_to_end(token)
            return found

    def build(self, token: str, kind: str, *, local_origin: str) -> str:
        if kind not in POC_KINDS:
            raise ScanError("Tipo de prueba de concepto no reconocido.")
        report = self.report(token)
        if report is None:
            raise ScanError(
                "El análisis asociado ya no está disponible. Vuelve a escanear la URL."
            )
        if urlsplit(report.final_url).scheme not in {"http", "https"}:
            raise ScanError(
                "Las pruebas de concepto requieren un objetivo HTTP analizado en vivo."
            )
        with self._lock:
            cached = self._rendered.get((token, kind))
        if cached is not None:
            return cached
        served_url = f"{local_origin}/poc/{token}/{kind}"
        if kind == "frame":
            content = build_frame_poc(report)
        elif kind == "frame-overlay":
            content = build_frame_poc(report, interactive=True)
        elif kind == "csp":
            content = build_csp_poc(report)
        else:
            probe_origin = report.cors_probe_origin or local_origin
            content = build_cors_poc(
                report, probe_origin, served_url=served_url, file_name="poc-cors.html"
            )
        with self._lock:
            self._rendered[(token, kind)] = content
        return content

    def rendered(self, token: str, kind: str) -> str | None:
        with self._lock:
            return self._rendered.get((token, kind))


def poc_availability(report: ScanReport) -> dict[str, Any]:
    """Describe qué PoC tienen sentido para este informe y por qué."""

    live = urlsplit(report.final_url).scheme in {"http", "https"}
    probed = bool(report.cors_probe_headers) or bool(report.cors_probe_origin)
    return {
        "available": live,
        "cors_probe_origin": report.cors_probe_origin,
        "cors_probe_ready": probed,
        "kinds": [
            {
                "kind": kind,
                "label": POC_LABELS[kind],
                "enabled": live and (kind != "cors" or probed),
            }
            for kind in ("frame", "frame-overlay", "cors", "csp")
        ],
    }
