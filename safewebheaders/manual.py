"""Análisis de cabeceras pegadas manualmente, sin realizar solicitudes de red."""

from __future__ import annotations

import re
from collections import OrderedDict
from collections.abc import Sequence
from urllib.parse import urljoin, urlsplit

from .constants import ALL_HEADERS_NOTE, ESSENTIAL_ONLY_NOTE, VERSION
from .engine import run_analysis
from .models import RedirectHop, ResponseSnapshot, ScanError, ScanReport
from .profiles import detect_profile
from .utils import (
    HTTP_FIELD_NAME_PATTERN,
    canonical_header,
    machine_timestamp,
    normalize_observed_header_name,
    normalize_url,
    parse_exclusions,
    sanitize_url,
)

MAX_MANUAL_HEADER_BYTES = 512 * 1024
MAX_MANUAL_HEADER_FIELDS = 500
MAX_MANUAL_LINE_LENGTH = 65_536
MAX_CSP_BYTES = 128 * 1024
STATUS_LINE_RE = re.compile(
    r"^HTTP/(?P<version>\d(?:\.\d)?)\s+(?P<status>\d{3})(?:\s+(?P<reason>.*))?$",
    re.IGNORECASE,
)


def _validated_evidence_url(value: str) -> str:
    if not value.strip():
        raise ScanError("La URL de evidencia es obligatoria.")
    return sanitize_url(normalize_url(value))


def _split_response_blocks(raw: str) -> list[list[str]]:
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if STATUS_LINE_RE.fullmatch(line.strip()) and current:
            blocks.append(current)
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append(current)
    return [block for block in blocks if any(line.strip() for line in block)]


def _parse_header_block(
    lines: list[str], evidence_url: str, *, block_index: int
) -> tuple[ResponseSnapshot, list[str]]:
    status_code = 200
    reason = "Evidencia manual"
    http_version = "HTTP/?"
    headers: OrderedDict[str, list[str]] = OrderedDict()
    display_names: dict[str, str] = {}
    warnings: list[str] = []
    previous_key = ""
    field_count = 0

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if len(line) > MAX_MANUAL_LINE_LENGTH:
            raise ScanError(
                f"La línea {line_number} del bloque {block_index} supera "
                f"{MAX_MANUAL_LINE_LENGTH} caracteres."
            )
        status_match = STATUS_LINE_RE.fullmatch(stripped)
        if status_match:
            status_code = int(status_match.group("status"))
            reason = (status_match.group("reason") or "").strip()
            http_version = f"HTTP/{status_match.group('version')}"
            previous_key = ""
            continue
        if line[:1].isspace() and previous_key:
            headers[previous_key][-1] += " " + stripped
            continue
        if ":" not in line:
            warnings.append(
                f"Se ignoró la línea {line_number} del bloque {block_index} porque "
                "no tiene el formato Nombre: valor."
            )
            previous_key = ""
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        if not re.fullmatch(HTTP_FIELD_NAME_PATTERN, name):
            raise ScanError(
                f"Nombre de cabecera inválido en el bloque {block_index}: {name!r}."
            )
        field_count += 1
        if field_count > MAX_MANUAL_HEADER_FIELDS:
            raise ScanError(
                f"El bloque {block_index} supera el límite de "
                f"{MAX_MANUAL_HEADER_FIELDS} campos."
            )
        key = normalize_observed_header_name(name)
        headers.setdefault(key, []).append(value.strip())
        display_names.setdefault(key, name)
        previous_key = key

    if not headers:
        raise ScanError(
            f"No se encontraron cabeceras válidas en el bloque {block_index}."
        )
    location = headers.get("location", [""])[0]
    is_redirect = 300 <= status_code < 400 and bool(location)
    return (
        ResponseSnapshot(
            url=evidence_url,
            status_code=status_code,
            reason=reason,
            headers=dict(headers),
            display_names=display_names,
            http_version=http_version,
            redirect_kind="http" if is_redirect else "",
            redirect_target=(
                sanitize_url(urljoin(evidence_url, location)) if is_redirect else ""
            ),
        ),
        warnings,
    )


def parse_manual_response_headers(
    raw: str, evidence_url: str
) -> tuple[list[ResponseSnapshot], list[str]]:
    """Convierte uno o varios bloques tipo Burp/curl en snapshots analizables."""

    if not raw.strip():
        raise ScanError("Pega al menos una cabecera HTTP de respuesta.")
    if len(raw.encode("utf-8")) > MAX_MANUAL_HEADER_BYTES:
        raise ScanError(
            f"La evidencia supera el límite de {MAX_MANUAL_HEADER_BYTES // 1024} KiB."
        )
    normalized_url = _validated_evidence_url(evidence_url)
    snapshots: list[ResponseSnapshot] = []
    warnings: list[str] = []
    for index, block in enumerate(_split_response_blocks(raw), start=1):
        snapshot, block_warnings = _parse_header_block(
            block, normalized_url, block_index=index
        )
        snapshots.append(snapshot)
        warnings.extend(block_warnings)
    for snapshot in snapshots[:-1]:
        if snapshot.redirect_kind == "http":
            snapshot.redirect_followed = True
            snapshot.effective_redirect_target = snapshot.redirect_target
    return snapshots, warnings


def _redirect_hops(snapshots: list[ResponseSnapshot]) -> list[RedirectHop]:
    return [
        RedirectHop(
            url=item.url,
            status_code=item.status_code,
            location=item.first("location"),
            elapsed_ms=0,
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


def create_manual_headers_report(
    raw: str,
    evidence_url: str,
    *,
    essential_only: bool = True,
    evaluate_cookies: bool = False,
    profile: str = "auto",
    excluded: Sequence[str] | None = None,
) -> ScanReport:
    """Analiza evidencia pegada y etiqueta sus conclusiones como no verificadas."""

    if profile not in {"auto", "web", "api"}:
        raise ScanError("El tipo de respuesta debe ser auto, web o api.")
    snapshots, warnings = parse_manual_response_headers(raw, evidence_url)
    final = snapshots[-1]
    effective_profile = detect_profile(profile, final)
    excluded_names = parse_exclusions(list(excluded or []))
    findings = run_analysis(
        final,
        snapshots=snapshots,
        excluded=excluded_names,
        profile=effective_profile,
        follow_redirects=len(snapshots) > 1,
        evaluate_cookies=evaluate_cookies,
        essential_only=essential_only,
    )
    notes = [
        "Análisis manual: no se realizó ninguna solicitud de red.",
        (
            "La URL de evidencia fue aportada por el analista y sirve para identificar "
            "el origen declarado; SafeWebHeaders no comprobó que las cabeceras provengan "
            "realmente de esa URL."
        ),
    ]
    if essential_only:
        notes.insert(0, ESSENTIAL_ONLY_NOTE)
    else:
        notes.insert(0, ALL_HEADERS_NOTE)
    notes.extend(warnings)
    return ScanReport(
        tool="SafeWebHeaders",
        version=VERSION,
        timestamp=machine_timestamp(),
        requested_url=final.url,
        final_url=final.url,
        method="EVIDENCIA MANUAL",
        status_code=final.status_code,
        reason=final.reason,
        profile=effective_profile,
        tls_verification="no comprobada (entrada manual)",
        elapsed_ms=0,
        redirect_following=len(snapshots) > 1,
        redirects=_redirect_hops(snapshots),
        excluded_headers=sorted(excluded_names),
        findings=findings,
        response_headers=final.headers,
        display_names=final.display_names,
        show_headers=True,
        notes=notes,
        essential_only=essential_only,
        cookie_analysis_enabled=evaluate_cookies,
    )


def _extract_csp_header_values(raw_policy: str) -> dict[str, list[str]]:
    if not raw_policy.strip():
        raise ScanError("Pega una política Content-Security-Policy para analizar.")
    if len(raw_policy.encode("utf-8")) > MAX_CSP_BYTES:
        raise ScanError(
            f"La política CSP supera el límite de {MAX_CSP_BYTES // 1024} KiB."
        )
    enforced: list[str] = []
    report_only: list[str] = []
    recognized_lines = False
    for line in raw_policy.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not line.strip():
            continue
        name, separator, value = line.partition(":")
        normalized = name.strip().lower()
        if separator and normalized in {
            "content-security-policy",
            "content-security-policy-report-only",
        }:
            recognized_lines = True
            destination = (
                enforced if normalized == "content-security-policy" else report_only
            )
            destination.append(value.strip())
    if not recognized_lines:
        enforced.append(" ".join(line.strip() for line in raw_policy.splitlines()))
    if not any(enforced) and not any(report_only):
        raise ScanError(
            "No se encontró un valor CSP después del nombre de la cabecera."
        )
    headers: dict[str, list[str]] = {"content-type": ["text/html; charset=UTF-8"]}
    if enforced:
        headers["content-security-policy"] = enforced
    if report_only:
        headers["content-security-policy-report-only"] = report_only
    return headers


def create_manual_csp_report(raw_policy: str, evidence_url: str) -> ScanReport:
    """Analiza CSP/CSP-Report-Only asociándola a una URL de evidencia."""

    normalized_url = _validated_evidence_url(evidence_url)
    headers = _extract_csp_header_values(raw_policy)
    display_names = {key: canonical_header(key) for key in headers}
    snapshot = ResponseSnapshot(
        url=normalized_url,
        status_code=0,
        reason="Análisis CSP manual",
        headers=headers,
        display_names=display_names,
        response_kind="document",
    )
    findings = run_analysis(
        snapshot,
        snapshots=[snapshot],
        excluded=set(),
        profile="web",
        follow_redirects=False,
        csp_only=True,
    )
    return ScanReport(
        tool="SafeWebHeaders",
        version=VERSION,
        timestamp=machine_timestamp(),
        requested_url=normalized_url,
        final_url=normalized_url,
        method="CSP MANUAL",
        status_code=0,
        reason=snapshot.reason,
        profile="csp-only",
        tls_verification=(
            "no comprobada (URL HTTPS aportada como evidencia)"
            if urlsplit(normalized_url).scheme == "https"
            else "no aplica (evidencia HTTP manual)"
        ),
        elapsed_ms=0,
        redirect_following=False,
        redirects=[],
        excluded_headers=[],
        findings=findings,
        response_headers=headers,
        display_names=display_names,
        show_headers=True,
        notes=[
            "Análisis CSP manual: no se realizó ninguna solicitud de red.",
            (
                "La URL identifica la evidencia aportada; no demuestra que el servidor "
                "entregue actualmente esta política."
            ),
        ],
    )
