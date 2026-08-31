"""Adaptador entre la API web local y el motor de análisis."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from ..cli import build_parser, create_report
from ..constants import EXCLUDABLE_HEADERS, VERSION
from ..manual import create_manual_csp_report, create_manual_headers_report
from ..models import BatchReport, ScanError, ScanFailure, ScanReport
from ..presentation import (
    build_display_groups,
    redact_url_secrets,
    response_header_blocks,
)
from ..utils import canonical_header, machine_timestamp, normalize_header_name
from .evidence import PocStore, fetch_favicon, header_inventory, poc_availability

MAX_TARGET_TEXT_LENGTH = 900_000
MAX_URL_LENGTH = 4_096
MAX_REQUEST_BODY_LENGTH = 256 * 1024
MAX_EXCLUDED_HEADERS = 40
DEFAULT_LOCAL_ORIGIN = "http://127.0.0.1:8765"

#: Informes recientes disponibles para generar pruebas de concepto bajo demanda.
POC_STORE = PocStore()


def excludable_header_catalog() -> list[str]:
    """Nombres canónicos que ``--exclude-header`` acepta, para el autocompletado."""

    return sorted(canonical_header(name) for name in EXCLUDABLE_HEADERS)

CATEGORY_TONES = {
    "correctas": "success",
    "ausentes": "absent",
    "incorrectas": "incorrect",
    "cookies": "cookies",
    "obsoletas": "legacy",
    "divulgacion": "recon",
    "informativas": "info",
    "exclusiones": "info",
}
TONE_PRIORITY = {
    "info": 0,
    "success": 1,
    "recon": 2,
    "cookies": 3,
    "warning": 3,
    "legacy": 3,
    "incorrect": 4,
    "absent": 5,
}


def _option_bool(options: Mapping[str, Any], name: str, default: bool = False) -> bool:
    value = options.get(name, default)
    if not isinstance(value, bool):
        raise ScanError(f"La opción {name} debe ser true o false.")
    return value


def _option_choice(
    options: Mapping[str, Any], name: str, allowed: set[str], default: str
) -> str:
    value = options.get(name, default)
    if not isinstance(value, str) or value not in allowed:
        choices = ", ".join(sorted(allowed))
        raise ScanError(f"La opción {name} debe ser una de: {choices}.")
    return value


def _option_timeout(options: Mapping[str, Any]) -> float:
    value = options.get("timeout", 15)
    if isinstance(value, bool):
        raise ScanError("El timeout debe ser un número entre 1 y 120 segundos.")
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ScanError(
            "El timeout debe ser un número entre 1 y 120 segundos."
        ) from exc
    if not 1 <= timeout <= 120:
        raise ScanError("El timeout debe estar entre 1 y 120 segundos.")
    return timeout


def _option_text(
    options: Mapping[str, Any], name: str, *, default: str = "", limit: int
) -> str:
    value = options.get(name, default)
    if not isinstance(value, str):
        raise ScanError(f"La opción {name} debe ser texto.")
    if len(value.encode("utf-8")) > limit:
        raise ScanError(f"La opción {name} supera el tamaño permitido.")
    return value


def _option_all_headers(options: Mapping[str, Any]) -> bool:
    """Lee el alcance nuevo y conserva payloads GUI 8.2.0 ya guardados."""

    if "all_headers" in options:
        return _option_bool(options, "all_headers")
    if "essential_only" in options:
        return not _option_bool(options, "essential_only")
    return False


def _targets_from_payload(value: Any) -> list[str]:
    if isinstance(value, str):
        if len(value) > MAX_TARGET_TEXT_LENGTH:
            raise ScanError("El listado de URL es demasiado grande.")
        candidates = value.splitlines()
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        if sum(len(item) for item in value) > MAX_TARGET_TEXT_LENGTH:
            raise ScanError(
                "El listado de URL supera el tamaño admitido por la API local."
            )
        candidates = value
    else:
        raise ScanError("Las URL deben enviarse como texto o como una lista de texto.")
    targets: list[str] = []
    seen: set[str] = set()
    for raw in candidates:
        candidate = raw.strip()
        if not candidate or candidate.startswith("#"):
            continue
        if len(candidate) > MAX_URL_LENGTH:
            raise ScanError(f"Una URL supera el límite de {MAX_URL_LENGTH} caracteres.")
        if candidate not in seen:
            seen.add(candidate)
            targets.append(candidate)
    if not targets:
        raise ScanError("Escribe al menos una URL para analizar.")
    return targets


def _excluded_headers(options: Mapping[str, Any]) -> list[str]:
    """Lee la lista de cabeceras que el analista quiere ocultar del informe.

    Acepta texto separado por comas, espacios o saltos de línea, o una lista.
    Se traduce a ``--exclude-header``, de modo que la GUI y la CLI producen
    exactamente la misma evidencia y la misma sección de exclusiones.
    """

    raw = options.get("excluded_headers", "")
    if isinstance(raw, str):
        candidates = re.split(r"[\s,;]+", raw)
    elif isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        candidates = raw
    else:
        raise ScanError("excluded_headers debe ser texto o una lista de texto.")
    names: list[str] = []
    for candidate in candidates:
        name = candidate.strip().strip(":")
        if not name:
            continue
        if len(name) > 128 or not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", name):
            raise ScanError(f"Nombre de cabecera inválido para ocultar: {name}")
        if name.lower() not in {item.lower() for item in names}:
            names.append(name)
    if len(names) > MAX_EXCLUDED_HEADERS:
        raise ScanError(
            f"No se pueden ocultar más de {MAX_EXCLUDED_HEADERS} cabeceras a la vez."
        )
    return names


def _header_tones(report: ScanReport) -> dict[str, str]:
    tones: dict[str, str] = {}
    groups = build_display_groups(report)
    for category, entries in groups.items():
        for entry in entries:
            name = normalize_header_name(entry.finding.header)
            tone = CATEGORY_TONES[category]
            if category == "cookies" and entry.finding.status == "correcta":
                tone = "success"
            current = tones.get(name, "info")
            if TONE_PRIORITY[tone] >= TONE_PRIORITY[current]:
                tones[name] = tone
    return tones


def serialize_web_report(
    report: ScanReport,
    *,
    reveal_sensitive: bool = False,
    favicon: str | None = None,
    live: bool = False,
) -> dict[str, Any]:
    data = report.to_dict(reveal_sensitive)
    data["raw_header_blocks"] = [
        {"url": url, "text": block}
        for url, block in response_header_blocks(report, reveal_sensitive)
    ]
    data["header_tones"] = _header_tones(report)
    data["header_inventory"] = header_inventory(report)
    data["favicon"] = favicon
    if live:
        data["poc_id"] = POC_STORE.register(report)
        data["poc"] = poc_availability(report)
    else:
        data["poc_id"] = None
        data["poc"] = {"available": False, "kinds": [], "cors_probe_ready": False}
    return data


def _url_scan(
    payload: Mapping[str, Any],
    options: Mapping[str, Any],
    *,
    local_origin: str = DEFAULT_LOCAL_ORIGIN,
) -> dict[str, Any]:
    targets = _targets_from_payload(payload.get("targets", ""))
    reveal_sensitive = _option_bool(options, "reveal_sensitive")
    arguments = ["--show-headers", "--timeout", str(_option_timeout(options))]
    for name in _excluded_headers(options):
        arguments.extend(["--exclude-header", name])
    if _option_bool(options, "follow_redirects", True):
        arguments.append("--follow-redirects")
    if _option_all_headers(options):
        arguments.append("--all-headers")
    if _option_bool(options, "evaluate_cookies"):
        arguments.append("--value-cookie")
    if reveal_sensitive:
        arguments.append("--reveal-sensitive")
    if _option_bool(options, "use_environment"):
        arguments.append("--use-environment")
    if _option_bool(options, "insecure"):
        arguments.append("--insecure")
    method = _option_choice(
        options, "method", {"GET", "HEAD", "OPTIONS", "POST"}, "GET"
    )
    profile = _option_choice(options, "profile", {"auto", "api", "web"}, "auto")
    arguments.extend(["--method", method, "--response-type", profile])
    # La sonda CORS usa el origen real desde el que se servirá la PoC, para que
    # el veredicto estático y la comprobación en el navegador sean comparables.
    if _option_bool(options, "prepare_cors_poc"):
        if method != "GET":
            raise ScanError(
                "La PoC de CORS necesita el método GET para que la sonda y el "
                "navegador sean comparables."
            )
        arguments.extend(["--poc-cors", f"--poc-origin={local_origin}"])
    if method == "POST":
        body = _option_text(
            options,
            "request_body",
            limit=MAX_REQUEST_BODY_LENGTH,
        )
        content_type = _option_choice(
            options,
            "request_content_type",
            {
                "application/json",
                "application/xml",
                "application/x-www-form-urlencoded",
                "text/plain",
            },
            "application/json",
        )
        arguments.extend([f"--data={body}", f"--content-type={content_type}"])
    arguments.extend(["--", *targets])
    args = build_parser().parse_args(arguments)

    reports: list[ScanReport] = []
    errors: list[ScanFailure] = []
    for target in targets:
        try:
            reports.append(create_report(args, target))
        except ScanError as exc:
            errors.append(
                ScanFailure(
                    requested_url=target,
                    timestamp=machine_timestamp(),
                    error=str(exc),
                )
            )
    # El favicon exige una petición adicional al objetivo, así que es opt-in:
    # una auditoría no debe emitir tráfico que el analista no pidió, y la
    # evidencia deja constancia de la solicitud extra cuando se activa.
    favicons: dict[int, str | None] = {}
    if _option_bool(options, "show_favicon", False):
        for report in reports:
            favicons[id(report)] = fetch_favicon(report, args)
            report.notes.append(
                "Se realizó una solicitud adicional para recuperar el favicon "
                "del objetivo y mostrarlo en la interfaz."
            )
    timestamp = machine_timestamp()
    batch = BatchReport(
        tool="SafeWebHeaders",
        version=VERSION,
        timestamp=timestamp,
        requested_targets=targets,
        reports=reports,
        errors=errors,
    )
    serialized_batch = batch.to_dict(reveal_sensitive)
    return {
        "tool": "SafeWebHeaders",
        "version": VERSION,
        "generated_at": timestamp,
        "mode": "url",
        "summary_general": batch.summary(),
        "requested_targets": serialized_batch["requested_targets"],
        "results": [
            serialize_web_report(
                report,
                reveal_sensitive=reveal_sensitive,
                favicon=favicons.get(id(report)),
                live=True,
            )
            for report in reports
        ],
        "errors": serialized_batch["errors"],
    }


def _manual_headers(
    payload: Mapping[str, Any], options: Mapping[str, Any]
) -> dict[str, Any]:
    raw = payload.get("raw_headers", "")
    evidence_url = payload.get("evidence_url", "")
    if not isinstance(raw, str) or not isinstance(evidence_url, str):
        raise ScanError("Las cabeceras y la URL de evidencia deben ser texto.")
    reveal_sensitive = _option_bool(options, "reveal_sensitive")
    all_headers = _option_all_headers(options)
    evaluate_cookies = _option_bool(options, "evaluate_cookies")
    report = create_manual_headers_report(
        raw,
        evidence_url,
        essential_only=not all_headers,
        evaluate_cookies=evaluate_cookies,
        profile=_option_choice(options, "profile", {"auto", "api", "web"}, "auto"),
        excluded=_excluded_headers(options),
    )
    return _single_report_response("headers", report, reveal_sensitive)


def _manual_csp(
    payload: Mapping[str, Any], options: Mapping[str, Any]
) -> dict[str, Any]:
    policy = payload.get("csp_policy", "")
    evidence_url = payload.get("evidence_url", "")
    if not isinstance(policy, str) or not isinstance(evidence_url, str):
        raise ScanError("La política CSP y la URL de evidencia deben ser texto.")
    report = create_manual_csp_report(policy, evidence_url)
    return _single_report_response(
        "csp", report, _option_bool(options, "reveal_sensitive")
    )


def _single_report_response(
    mode: str, report: ScanReport, reveal_sensitive: bool
) -> dict[str, Any]:
    serialized_report = report.to_dict(reveal_sensitive)
    return {
        "tool": "SafeWebHeaders",
        "version": VERSION,
        "generated_at": report.timestamp,
        "mode": mode,
        "summary_general": {
            **serialized_report["summary"],
            "urls_solicitadas": 1,
            "urls_evaluadas": 1,
            "urls_con_error": 0,
        },
        "requested_targets": [
            redact_url_secrets(report.requested_url, reveal_sensitive)
        ],
        "results": [serialize_web_report(report, reveal_sensitive=reveal_sensitive)],
        "errors": [],
    }


def analyze_web_payload(
    payload: Any, *, local_origin: str = DEFAULT_LOCAL_ORIGIN
) -> dict[str, Any]:
    """Valida y ejecuta una solicitud de la GUI sin confiar en el navegador."""

    if not isinstance(payload, Mapping):
        raise ScanError("El cuerpo JSON debe ser un objeto.")
    mode = payload.get("mode")
    options = payload.get("options", {})
    if not isinstance(options, Mapping):
        raise ScanError("options debe ser un objeto JSON.")
    if mode == "url":
        return _url_scan(payload, options, local_origin=local_origin)
    if mode == "headers":
        return _manual_headers(payload, options)
    if mode == "csp":
        return _manual_csp(payload, options)
    raise ScanError("Modo inválido. Usa url, headers o csp.")
