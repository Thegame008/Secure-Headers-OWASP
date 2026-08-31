"""Models de SafeWebHeaders."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from typing import Any


class ScanError(RuntimeError):
    """Error operativo o de validación de entrada."""


@dataclass
class Finding:
    category: str
    status: str
    severity: str
    header: str
    title: str
    evidence: str = ""
    risk: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    policy: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # La criticidad final pertenece al análisis humano y al contexto del
        # cliente. ``severity`` se conserva solo para resolver reglas internas
        # de CSP y nunca se publica en los reportes.
        data.pop("severity", None)
        return data


@dataclass
class RedirectHop:
    url: str
    status_code: int
    location: str
    elapsed_ms: int
    reason: str = ""
    http_version: str = "HTTP/?"
    headers: dict[str, list[str]] = field(default_factory=dict)
    display_names: dict[str, str] = field(default_factory=dict)
    redirect_kind: str = ""
    redirect_target: str = ""
    effective_redirect_target: str = ""
    redirect_followed: bool = False


@dataclass
class ResponseSnapshot:
    url: str
    status_code: int
    reason: str
    headers: dict[str, list[str]]
    display_names: dict[str, str]
    elapsed_ms: int = 0
    response_kind: str = "unknown"
    http_version: str = "HTTP/?"
    body_preview: str = ""
    redirect_kind: str = ""
    redirect_target: str = ""
    effective_redirect_target: str = ""
    redirect_followed: bool = False

    def all(self, name: str) -> list[str]:
        from .utils import normalize_header_name

        return list(self.headers.get(normalize_header_name(name), []))

    def first(self, name: str, default: str = "") -> str:
        values = self.all(name)
        return values[0] if values else default

    def joined(self, name: str, separator: str = ", ") -> str:
        return separator.join(self.all(name))

    def has(self, name: str) -> bool:
        from .utils import normalize_header_name

        return normalize_header_name(name) in self.headers


@dataclass
class CSPPolicy:
    raw: str
    directives: OrderedDict[str, list[str]]
    duplicates: list[str] = field(default_factory=list)
    invalid_segments: list[str] = field(default_factory=list)
    unknown_directives: list[str] = field(default_factory=list)

    def values(self, directive: str) -> list[str] | None:
        return self.directives.get(directive.lower())


@dataclass
class ScanReport:
    tool: str
    version: str
    timestamp: str
    requested_url: str
    final_url: str
    method: str
    status_code: int
    reason: str
    profile: str
    tls_verification: str
    elapsed_ms: int
    redirect_following: bool
    redirects: list[RedirectHop]
    excluded_headers: list[str]
    findings: list[Finding]
    response_headers: dict[str, list[str]]
    display_names: dict[str, str]
    show_headers: bool
    notes: list[str] = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)
    #: Fragmento del cuerpo ya descargado durante el análisis. Solo lo usa la
    #: GUI para localizar <link rel="icon"> sin emitir peticiones extra; nunca
    #: se publica en los reportes.
    document_preview: str = ""
    cors_probe_origin: str = ""
    cors_probe_status_code: int | None = None
    cors_probe_headers: dict[str, list[str]] = field(default_factory=dict)
    essential_only: bool = True
    cookie_analysis_enabled: bool = False

    @property
    def redirect_count(self) -> int:
        """Cantidad real de respuestas HTTP 3xx que anunciaron un destino."""

        return sum(
            1
            for hop in self.redirects
            if hop.redirect_kind == "http"
            or (
                not hop.redirect_kind
                and 300 <= hop.status_code < 400
                and bool(hop.location)
            )
        )

    @property
    def http_redirect_count(self) -> int:
        return sum(
            1
            for hop in self.redirects
            if hop.redirect_kind == "http"
            or (
                not hop.redirect_kind
                and 300 <= hop.status_code < 400
                and bool(hop.location)
            )
        )

    @property
    def client_redirect_count(self) -> int:
        return sum(1 for hop in self.redirects if hop.redirect_kind == "meta-refresh")

    @property
    def navigation_count(self) -> int:
        return self.redirect_count + self.client_redirect_count

    def to_dict(self, reveal_sensitive: bool = False) -> dict[str, Any]:
        from .presentation import (
            redact_text_urls,
            redact_url_secrets,
            serializable_headers,
            serialize_report_categories,
            summarize_report,
        )
        from .utils import canonical_header

        data = asdict(self)
        # La representación pública se organiza por los bloques visibles del
        # reporte. Se eliminan los hallazgos internos para no publicar la
        # severidad usada únicamente por el motor de reglas.
        data.pop("findings", None)
        data.pop("document_preview", None)
        data["requested_url"] = redact_url_secrets(self.requested_url, reveal_sensitive)
        data["final_url"] = redact_url_secrets(self.final_url, reveal_sensitive)
        data["notes"] = [
            redact_text_urls(note, reveal_sensitive) for note in self.notes
        ]
        data["redirects"] = []
        for hop in self.redirects:
            serialized_hop: dict[str, Any] = {
                "url": redact_url_secrets(hop.url, reveal_sensitive),
                "status_code": hop.status_code,
                "reason": hop.reason,
                "location": redact_url_secrets(hop.location, reveal_sensitive),
                "elapsed_ms": hop.elapsed_ms,
                "http_version": hop.http_version,
                "redirect_kind": hop.redirect_kind,
                "redirect_target": redact_url_secrets(
                    hop.redirect_target, reveal_sensitive
                ),
                "effective_redirect_target": redact_url_secrets(
                    hop.effective_redirect_target, reveal_sensitive
                ),
                "redirect_followed": hop.redirect_followed,
            }
            if self.show_headers and hop.headers:
                serialized_hop["response_headers"] = serializable_headers(
                    hop.headers,
                    hop.display_names,
                    reveal_sensitive,
                )
            data["redirects"].append(serialized_hop)
        data["summary"] = summarize_report(self)
        data["categories"] = serialize_report_categories(self, reveal_sensitive)
        data["redirect_count"] = self.redirect_count
        data["http_redirect_count"] = self.http_redirect_count
        data["client_redirect_count"] = self.client_redirect_count
        data["navigation_count"] = self.navigation_count
        data["response_headers"] = serializable_headers(
            self.response_headers, self.display_names, reveal_sensitive
        )
        data["cors_probe_headers"] = serializable_headers(
            self.cors_probe_headers,
            {key: canonical_header(key) for key in self.cors_probe_headers},
            reveal_sensitive,
        )
        return data


@dataclass
class DisplayEntry:
    """Hallazgo listo para mostrarse, con posibles detalles CSP anidados."""

    finding: Finding
    current_value: str
    details: list[Finding] = field(default_factory=list)
    policies: list[str] = field(default_factory=list)
    policy_spans: list[list[tuple[str, str]]] = field(default_factory=list)
    policy_context: str = ""


@dataclass
class ScanFailure:
    requested_url: str
    timestamp: str
    error: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class BatchReport:
    tool: str
    version: str
    timestamp: str
    requested_targets: list[str]
    reports: list[ScanReport]
    errors: list[ScanFailure]

    def summary(self) -> dict[str, int]:
        from .presentation import empty_display_summary, summarize_report

        totals = empty_display_summary()
        for report in self.reports:
            for key, value in summarize_report(report).items():
                totals[key] += value
        totals["urls_solicitadas"] = len(self.requested_targets)
        totals["urls_evaluadas"] = len(self.reports)
        totals["urls_con_error"] = len(self.errors)
        return totals

    def to_dict(self, reveal_sensitive: bool = False) -> dict[str, Any]:
        from .presentation import redact_text_urls, redact_url_secrets

        return {
            "tool": self.tool,
            "version": self.version,
            "generated_at": self.timestamp,
            "summary_general": self.summary(),
            "requested_targets": [
                redact_url_secrets(value, reveal_sensitive)
                for value in self.requested_targets
            ],
            "results": [report.to_dict(reveal_sensitive) for report in self.reports],
            "errors": [
                {
                    **error.to_dict(),
                    "requested_url": redact_url_secrets(
                        error.requested_url, reveal_sensitive
                    ),
                    "error": redact_text_urls(error.error, reveal_sensitive),
                }
                for error in self.errors
            ],
        }
