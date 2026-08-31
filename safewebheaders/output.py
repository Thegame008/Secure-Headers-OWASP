"""Output de SafeWebHeaders."""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .constants import (
    DISPLAY_CATEGORY_LABELS,
    DISPLAY_CATEGORY_SYMBOL,
)
from .models import (
    BatchReport,
    ScanError,
    ScanReport,
)
from .presentation import (
    Palette,
    animate_brand_banner,
    build_display_groups,
    csp_protection_purpose,
    finding_criterion,
    finding_evidence,
    redact_text_urls,
    redact_url_secrets,
    render_batch_console,
    render_html,
    sanitize_terminal_text,
    serializable_headers,
    summarize_report,
)


def determine_output_format(args: argparse.Namespace) -> str:
    if args.output:
        suffix = Path(args.output).suffix.lower()
        if suffix == ".html":
            return "html"
        if suffix == ".json":
            return "json"
        if suffix == ".csv":
            return "csv"
        if suffix in {".txt", ".log"}:
            return "console"
    return args.format


CSV_FIELDS = [
    "tipo_registro",
    "fecha_hora",
    "url_solicitada",
    "url_evaluada",
    "ips_resueltas",
    "codigo_http",
    "perfil",
    "metodo",
    "categoria",
    "simbolo",
    "cabecera",
    "configuracion_actual",
    "contexto",
    "criterio",
    "observacion",
    "evidencia",
    "riesgo",
    "recomendacion",
    "referencias",
    "correctas",
    "ausentes",
    "incorrectas",
    "cookies",
    "obsoletas",
    "divulgaciones",
    "informativas",
    "excluidas",
    "error",
]


def _csv_base_row() -> dict[str, Any]:
    return {field: "" for field in CSV_FIELDS}


CSV_FORMULA_RE = re.compile(r"^[\t\r\n ]*[=+\-@]")


def csv_safe_cell(value: Any) -> Any:
    """Neutraliza fórmulas sin alterar números ni valores vacíos."""

    if isinstance(value, str) and CSV_FORMULA_RE.match(value):
        return "'" + value
    return value


class FormulaSafeDictWriter(csv.DictWriter):
    def writerow(self, rowdict: Mapping[str, Any]) -> Any:
        return super().writerow(
            {name: csv_safe_cell(value) for name, value in rowdict.items()}
        )


def render_batch_csv(batch: BatchReport, reveal_sensitive: bool) -> str:
    buffer = io.StringIO(newline="")
    writer = FormulaSafeDictWriter(buffer, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()

    general = _csv_base_row()
    general.update(
        {
            "tipo_registro": "resumen_general",
            "fecha_hora": batch.timestamp,
            **{key: value for key, value in batch.summary().items() if key in general},
            "observacion": (
                f"URLs solicitadas: {len(batch.requested_targets)}; "
                f"evaluadas: {len(batch.reports)}; con error: {len(batch.errors)}"
            ),
        }
    )
    writer.writerow(general)

    for report in batch.reports:
        summary = summarize_report(report)
        summary_row = _csv_base_row()
        summary_row.update(
            {
                "tipo_registro": "resumen_url",
                "fecha_hora": report.timestamp,
                "url_solicitada": redact_url_secrets(
                    report.requested_url, reveal_sensitive
                ),
                "url_evaluada": redact_url_secrets(report.final_url, reveal_sensitive),
                "ips_resueltas": " | ".join(report.resolved_ips),
                "codigo_http": report.status_code,
                "perfil": report.profile,
                "metodo": report.method,
                **summary,
            }
        )
        writer.writerow(summary_row)

        for hop in report.redirects:
            if not (hop.redirect_target or hop.location):
                continue
            redirect_row = _csv_base_row()
            redirect_row.update(
                {
                    "tipo_registro": "redireccion",
                    "fecha_hora": report.timestamp,
                    "url_solicitada": redact_url_secrets(
                        report.requested_url, reveal_sensitive
                    ),
                    "url_evaluada": redact_url_secrets(hop.url, reveal_sensitive),
                    "codigo_http": hop.status_code,
                    "perfil": report.profile,
                    "metodo": report.method,
                    "categoria": (
                        "meta-refresh"
                        if hop.redirect_kind == "meta-refresh"
                        else "http"
                    ),
                    "configuracion_actual": redact_url_secrets(
                        hop.redirect_target or hop.location, reveal_sensitive
                    ),
                    "contexto": redact_url_secrets(
                        hop.effective_redirect_target, reveal_sensitive
                    ),
                    "observacion": (
                        "Destino solicitado"
                        if hop.redirect_followed
                        else "Destino no solicitado"
                    ),
                }
            )
            writer.writerow(redirect_row)

        for note in report.notes:
            note_row = _csv_base_row()
            note_row.update(
                {
                    "tipo_registro": "nota",
                    "fecha_hora": report.timestamp,
                    "url_solicitada": redact_url_secrets(
                        report.requested_url, reveal_sensitive
                    ),
                    "url_evaluada": redact_url_secrets(
                        report.final_url, reveal_sensitive
                    ),
                    "codigo_http": report.status_code,
                    "perfil": report.profile,
                    "metodo": report.method,
                    "observacion": redact_text_urls(note, reveal_sensitive),
                }
            )
            writer.writerow(note_row)

        groups = build_display_groups(report)
        for category, label in DISPLAY_CATEGORY_LABELS.items():
            for entry in groups[category]:
                item = entry.finding
                row = _csv_base_row()
                row.update(
                    {
                        "tipo_registro": "hallazgo",
                        "fecha_hora": report.timestamp,
                        "url_solicitada": redact_url_secrets(
                            report.requested_url, reveal_sensitive
                        ),
                        "url_evaluada": redact_url_secrets(
                            report.final_url, reveal_sensitive
                        ),
                        "ips_resueltas": " | ".join(report.resolved_ips),
                        "codigo_http": report.status_code,
                        "perfil": report.profile,
                        "metodo": report.method,
                        "categoria": label,
                        "simbolo": (
                            "+"
                            if category == "cookies" and item.status == "correcta"
                            else "!"
                            if category == "cookies"
                            else DISPLAY_CATEGORY_SYMBOL[category]
                        ),
                        "cabecera": item.header,
                        "configuracion_actual": entry.current_value,
                        "contexto": entry.policy_context,
                        "criterio": finding_criterion(item),
                        "observacion": item.title,
                        "evidencia": finding_evidence(item, reveal_sensitive),
                        "riesgo": item.risk,
                        "recomendacion": item.recommendation,
                        "referencias": " | ".join(dict.fromkeys(item.references)),
                    }
                )
                writer.writerow(row)
                for detail in entry.details:
                    detail_row = dict(row)
                    detail_row.update(
                        {
                            "tipo_registro": "detalle_csp",
                            "simbolo": (
                                "!"
                                if detail.status
                                in {"ausente", "incorrecta", "advertencia"}
                                else "*"
                            ),
                            "configuracion_actual": detail.policy,
                            "contexto": csp_protection_purpose(detail),
                            "observacion": detail.title,
                            "evidencia": detail.evidence,
                            "riesgo": detail.risk,
                            "recomendacion": detail.recommendation,
                            "referencias": " | ".join(dict.fromkeys(detail.references)),
                        }
                    )
                    writer.writerow(detail_row)

        if report.show_headers:
            for name, values in serializable_headers(
                report.response_headers,
                report.display_names,
                reveal_sensitive,
            ).items():
                for value in values:
                    header_row = _csv_base_row()
                    header_row.update(
                        {
                            "tipo_registro": "cabecera_http",
                            "fecha_hora": report.timestamp,
                            "url_solicitada": redact_url_secrets(
                                report.requested_url, reveal_sensitive
                            ),
                            "url_evaluada": redact_url_secrets(
                                report.final_url, reveal_sensitive
                            ),
                            "ips_resueltas": " | ".join(report.resolved_ips),
                            "codigo_http": report.status_code,
                            "perfil": report.profile,
                            "metodo": report.method,
                            "cabecera": name,
                            "configuracion_actual": value,
                        }
                    )
                    writer.writerow(header_row)

    for failure in batch.errors:
        row = _csv_base_row()
        row.update(
            {
                "tipo_registro": "error",
                "fecha_hora": failure.timestamp,
                "url_solicitada": redact_url_secrets(
                    failure.requested_url, reveal_sensitive
                ),
                "simbolo": "!",
                "error": redact_text_urls(failure.error, reveal_sensitive),
            }
        )
        writer.writerow(row)
    return buffer.getvalue()


def render_batch_format(
    batch: BatchReport,
    output_format: str,
    *,
    reveal_sensitive: bool,
    color: bool = False,
    include_banner: bool = True,
) -> str:
    if output_format == "json":
        return (
            json.dumps(batch.to_dict(reveal_sensitive), ensure_ascii=False, indent=2)
            + "\n"
        )
    if output_format == "csv":
        return render_batch_csv(batch, reveal_sensitive)
    if output_format == "html":
        if len(batch.reports) != 1 or batch.errors:
            raise ScanError(
                "El HTML estático admite una sola URL. Para lotes usa TXT, JSON o CSV."
            )
        return render_html(batch.reports[0], reveal_sensitive)
    return render_batch_console(
        batch,
        color=color,
        reveal_sensitive=reveal_sensitive,
        include_banner=include_banner,
    )


def _animate_banner_if_interactive(batch: BatchReport, args: argparse.Namespace) -> bool:
    """Dibuja el escudo con entrada progresiva y avisa si ya lo emitió.

    Solo ocurre en un terminal interactivo con color: cuando la salida se
    redirige, el banner viaja dentro del propio texto del informe y el
    resultado es byte a byte el mismo que antes.
    """

    if args.quiet or args.no_color or not sys.stdout.isatty():
        return False
    if determine_output_format(args) not in {"console", "txt"}:
        return False
    animate_brand_banner(sys.stdout, Palette(True), batch.version)
    return True


def write_batch_output(batch: BatchReport, args: argparse.Namespace) -> None:
    output_format = determine_output_format(args)

    if args.output:
        # Exportar no reemplaza la salida normal: por defecto se conserva el
        # resultado legible en pantalla y se crea una copia sin ANSI.
        if not args.quiet and args.output != "-":
            console = render_batch_format(
                batch,
                "console",
                reveal_sensitive=args.show_sensitive,
                color=(not args.no_color and sys.stdout.isatty()),
            )
            print(console, end="")

        content = render_batch_format(
            batch,
            output_format,
            reveal_sensitive=args.show_sensitive,
            color=False,
        )
        if args.output == "-":
            print(content, end="")
            return
        path = Path(args.output).expanduser()
        atomic_write_text(
            path,
            content,
            encoding="utf-8-sig" if output_format == "csv" else "utf-8",
            force=getattr(args, "force", False),
        )
        print(
            "Reporte "
            f"{output_format.upper()} guardado en: "
            f"{sanitize_terminal_text(path.resolve())}"
        )
    else:
        animated = _animate_banner_if_interactive(batch, args)
        content = render_batch_format(
            batch,
            output_format,
            reveal_sensitive=args.show_sensitive,
            include_banner=not animated,
            color=(
                output_format in {"console", "txt"}
                and not args.no_color
                and sys.stdout.isatty()
            ),
        )
        print(content, end="")


def atomic_write_text(
    path: Path,
    content: str,
    *,
    encoding: str,
    force: bool = False,
) -> None:
    """Publica el reporte de forma atómica y evita sobrescrituras accidentales."""

    temporary: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and not force:
            raise ScanError(
                f"El archivo de salida ya existe: {path}. Usa --force para reemplazarlo."
            )
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding=encoding,
            newline="",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if force:
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise ScanError(
                    f"El archivo de salida ya existe: {path}. Usa --force para reemplazarlo."
                ) from exc
            temporary.unlink()
    except ScanError:
        raise
    except OSError as exc:
        raise ScanError(f"No se pudo guardar el reporte {path}: {exc}") from exc
    finally:
        if temporary is not None and temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass


def write_output(report: ScanReport, args: argparse.Namespace) -> None:
    """Compatibilidad para consumidores que aún entregan un único reporte."""
    batch = BatchReport(
        tool=report.tool,
        version=report.version,
        timestamp=report.timestamp,
        requested_targets=[report.requested_url],
        reports=[report],
        errors=[],
    )
    write_batch_output(batch, args)
