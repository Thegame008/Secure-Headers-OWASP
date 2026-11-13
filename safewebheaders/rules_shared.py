"""Reglas compartidas por varios analizadores de cabeceras."""

from __future__ import annotations

from collections.abc import Sequence

from .constants import RFC9110_FIELD_ORDER
from .models import Finding
from .profiles import finding
from .utils import analyze_repeated_field, format_repeated_field


def repeated_field_finding(
    header: str,
    values: Sequence[str],
    *,
    category: str = "incorrectas",
    references: Sequence[str] = (),
) -> Finding:
    """Construye el hallazgo de una cabecera de seguridad repetida.

    Distingue el duplicado exacto del conflicto real, porque la causa y la
    conversación con el cliente son distintas: lo primero suele ser una capa
    de infraestructura que repite lo que ya emite la aplicación; lo segundo es
    una contradicción entre dos configuraciones.
    """

    analysis = analyze_repeated_field(values)
    detail = format_repeated_field(list(values))

    if not analysis.identical:
        title = f"{header} llega repetida con valores contradictorios"
        severity = "alta"
        cause = (
            "Los campos no coinciden entre sí, de modo que dos configuraciones "
            "distintas están escribiendo la cabecera con intenciones opuestas."
        )
        risk = (
            f"RFC 9110 §5.3 prohíbe repetir un campo cuya gramática no es una lista, "
            f"y permite al receptor recombinar las líneas como «{analysis.combined}», "
            "que no es un valor válido para esta cabecera. Cada navegador, proxy o CDN "
            "puede quedarse con el primer campo, con el último o descartar la cabecera "
            "entera: la protección no es predecible y puede desaparecer por completo."
        )
    else:
        title = f"{header} llega repetida con el mismo valor"
        severity = "media"
        if analysis.differs_only_in_case:
            cause = (
                "Los campos son equivalentes salvo por el uso de mayúsculas, lo que "
                "indica que dos componentes distintos escriben la cabecera por su "
                "cuenta y ninguno comprueba si el otro ya la emitió."
            )
        elif analysis.differs_only_in_whitespace:
            cause = (
                "Los campos solo difieren en espacios, lo que apunta a dos "
                "componentes que emiten la cabecera de forma independiente."
            )
        else:
            cause = (
                "Los campos son idénticos, lo que suele significar que la aplicación "
                "y una capa intermedia (proxy inverso, CDN o WAF) añaden la misma "
                "cabecera sin comprobar si ya existía."
            )
        risk = (
            f"Aunque la intención no es ambigua, RFC 9110 §5.3 prohíbe repetir un "
            f"campo cuya gramática no es una lista y permite al receptor recombinar "
            f"las líneas como «{analysis.combined}», que no es un valor válido para "
            "esta cabecera. Un navegador que aplique esa recombinación puede "
            "descartar la cabecera y dejar la respuesta sin la protección."
        )

    return finding(
        category,
        "incorrecta",
        severity,
        header,
        title,
        evidence=(
            f"{analysis.count} campos recibidos:\n{detail}\n"
            f"Recombinación permitida a un receptor: {analysis.combined}"
        ),
        risk=f"{cause} {risk}",
        recommendation=(
            f"Emite {header} una sola vez. Identifica qué componente la añade por "
            "duplicado revisando la aplicación y cada capa intermedia, y deja que "
            "solo una la escriba; el resto debe respetar la cabecera existente en "
            "lugar de volver a añadirla."
        ),
        references=[RFC9110_FIELD_ORDER, *references],
    )
