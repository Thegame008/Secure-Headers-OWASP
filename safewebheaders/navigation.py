"""Navegación HTTP y diagnósticos de redirección del lado del cliente."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from requests import Response, Session

from .models import ResponseSnapshot
from .rules_basic import detect_meta_refresh_target, response_diagnostic_notes
from .transport import request_target, snapshot_response
from .utils import sanitize_url


@dataclass
class NavigationResult:
    """Respuestas abiertas y evidencia normalizada de una navegación."""

    responses: list[Response] = field(default_factory=list)
    snapshots: list[ResponseSnapshot] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def final_response(self) -> Response:
        return self.responses[-1]

    @property
    def final_snapshot(self) -> ResponseSnapshot:
        return self.snapshots[-1]


def _https_variant(url: str) -> str:
    """Crea la variante HTTPS de una URL HTTP sin propagar credenciales."""

    try:
        parts = urlsplit(url)
        hostname = parts.hostname or ""
        port = parts.port
    except ValueError:
        return ""
    if parts.scheme.lower() != "http" or not hostname:
        return url
    if parts.username or parts.password:
        return ""
    host = (
        f"[{hostname}]"
        if ":" in hostname and not hostname.startswith("[")
        else hostname
    )
    if port not in {None, 80}:
        host = f"{host}:{port}"
    return urlunsplit(("https", host, parts.path, parts.query, parts.fragment))


def _effective_meta_target(source_url: str, announced_target: str) -> str:
    try:
        source_scheme = urlsplit(source_url).scheme.lower()
        target_scheme = urlsplit(announced_target).scheme.lower()
    except ValueError:
        return announced_target
    if source_scheme == "https" and target_scheme == "http":
        return _https_variant(announced_target)
    return announced_target


def _mark_http_navigation(snapshots: list[ResponseSnapshot]) -> None:
    for index, snapshot in enumerate(snapshots[:-1]):
        if snapshot.redirect_kind != "http":
            continue
        snapshot.redirect_followed = True
        if not snapshot.effective_redirect_target:
            snapshot.effective_redirect_target = snapshots[index + 1].url


def _secure_recovery_note(snapshot: ResponseSnapshot) -> str:
    if (
        snapshot.redirect_kind != "http"
        or not snapshot.redirect_followed
        or not snapshot.redirect_target
        or not snapshot.effective_redirect_target
        or snapshot.redirect_target == snapshot.effective_redirect_target
    ):
        return ""
    return (
        "El servidor anunció la redirección hacia "
        f"{snapshot.redirect_target}, pero ese salto no pudo completarse. "
        "SafeWebHeaders reintentó de forma segura la misma dirección como "
        f"{snapshot.effective_redirect_target} y continuó la cadena."
    )


def collect_navigation(
    session: Session, target: str, args: argparse.Namespace
) -> NavigationResult:
    """Sigue 3xx y, de forma opt-in, meta refresh HTML sin ejecutar JavaScript."""

    result = NavigationResult()
    requested_urls: set[str] = set()
    request_url = target
    request_args = args
    try:
        while True:
            requested_urls.add(sanitize_url(request_url))
            response = request_target(session, request_url, request_args)
            segment_responses = [*response.history, response]
            segment_snapshots = [
                snapshot_response(
                    item,
                    include_body_preview=index == len(segment_responses) - 1,
                )
                for index, item in enumerate(segment_responses)
            ]
            _mark_http_navigation(segment_snapshots)
            result.responses.extend(segment_responses)
            result.snapshots.extend(segment_snapshots)

            for snapshot in segment_snapshots:
                note = _secure_recovery_note(snapshot)
                if note and note not in result.notes:
                    result.notes.append(note)

            final = segment_snapshots[-1]
            meta_target = detect_meta_refresh_target(final)
            result.notes.extend(
                response_diagnostic_notes(
                    final,
                    include_meta_refresh=not bool(
                        meta_target and args.follow_redirects
                    ),
                )
            )
            if not meta_target:
                return result

            final.redirect_kind = "meta-refresh"
            final.redirect_target = sanitize_url(meta_target)
            if not args.follow_redirects:
                return result

            effective_target = _effective_meta_target(final.url, meta_target)
            final.effective_redirect_target = sanitize_url(effective_target)
            redirect_total = sum(
                1 for snapshot in result.snapshots if snapshot.redirect_target
            )
            if redirect_total > args.max_redirects:
                result.notes.append(
                    "Se detuvo el seguimiento del meta refresh porque se alcanzó "
                    f"el límite interno de {args.max_redirects} redirecciones."
                )
                return result
            if final.effective_redirect_target in requested_urls:
                result.notes.append(
                    "Se detuvo el seguimiento porque el meta refresh regresaba a una "
                    f"URL ya solicitada: {final.effective_redirect_target}."
                )
                return result

            final.redirect_followed = True
            if final.redirect_target != final.effective_redirect_target:
                result.notes.append(
                    "El meta refresh anunció un destino HTTP desde una página HTTPS. "
                    "SafeWebHeaders priorizó su variante segura para continuar: "
                    f"{final.effective_redirect_target}."
                )
            else:
                result.notes.append(
                    "SafeWebHeaders siguió la redirección HTML meta refresh hacia "
                    f"{final.effective_redirect_target} porque se usó "
                    "--follow-redirects."
                )
            if request_args.method != "GET":
                request_args = argparse.Namespace(**vars(args))
                request_args.method = "GET"
                result.notes.append(
                    "El meta refresh representa una navegación del navegador; el "
                    "salto siguiente se solicitó con GET y no volvió a enviar el "
                    "cuerpo del método original."
                )
            request_url = effective_target
    except Exception:
        for response in reversed(result.responses):
            response.close()
        raise
