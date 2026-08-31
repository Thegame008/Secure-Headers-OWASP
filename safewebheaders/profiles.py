"""Profiles de SafeWebHeaders."""

from __future__ import annotations

import re
from collections.abc import Iterable

from .models import (
    Finding,
    ResponseSnapshot,
)
from .utils import (
    canonical_header,
)


def detect_response_kind(snapshot: ResponseSnapshot) -> str:
    """Clasifica la representación para aplicar únicamente reglas pertinentes."""

    if snapshot.status_code in {204, 205, 304}:
        return "empty"
    if 300 <= snapshot.status_code < 400:
        return "redirect"
    disposition = snapshot.first("content-disposition").lower()
    if re.search(r"(?:^|;)\s*attachment(?:\s*;|$)", disposition):
        return "download"
    content_type = snapshot.first("content-type").split(";", 1)[0].strip().lower()
    if content_type in {"text/html", "application/xhtml+xml", "image/svg+xml"}:
        return "document"
    if content_type in {
        "application/json",
        "application/xml",
        "text/xml",
    } or content_type.endswith(("+json", "+xml")):
        return "api"
    if content_type == "application/pdf":
        return "download"
    if content_type.startswith(
        ("image/", "audio/", "video/", "font/")
    ) or content_type in {
        "application/javascript",
        "application/wasm",
        "application/x-font-ttf",
        "application/vnd.ms-fontobject",
        "text/css",
        "text/javascript",
    }:
        return "asset"
    if snapshot.status_code >= 400:
        return "error"
    return "unknown"


def effective_response_kind(snapshot: ResponseSnapshot, profile: str) -> str:
    detected = snapshot.response_kind
    if detected == "unknown":
        detected = detect_response_kind(snapshot)
    if detected in {"empty", "redirect"}:
        return detected
    if profile == "web":
        return "document"
    if profile == "api":
        return "api"
    return detected


def detect_profile(requested: str, snapshot: ResponseSnapshot) -> str:
    kind = detect_response_kind(snapshot)
    if requested == "web" and kind not in {"empty", "redirect"}:
        snapshot.response_kind = "document"
        return "web"
    if requested == "api" and kind not in {"empty", "redirect"}:
        snapshot.response_kind = "api"
        return "api"
    snapshot.response_kind = kind
    return "web" if kind == "document" else "api" if kind == "api" else kind


def finding(
    category: str,
    status: str,
    severity: str,
    header: str,
    title: str,
    evidence: str = "",
    risk: str = "",
    recommendation: str = "",
    references: Iterable[str] | None = None,
    policy: str = "",
) -> Finding:
    if header.lower().startswith("content-security-policy"):
        from .rules_csp import redact_csp_crypto_sources

        evidence = redact_csp_crypto_sources(evidence)
    return Finding(
        category=category,
        status=status,
        severity=severity,
        header=header,
        title=title,
        evidence=evidence,
        risk=risk,
        recommendation=recommendation,
        references=list(references or []),
        policy=policy,
    )


def excluded_finding(header: str) -> Finding:
    return finding(
        "exclusiones",
        "excluida",
        "informativa",
        canonical_header(header),
        "Comprobación omitida por --exclude-header",
        evidence=canonical_header(header),
        risk="No se emitieron conclusiones ni se contabilizaron resultados para esta cabecera.",
    )
