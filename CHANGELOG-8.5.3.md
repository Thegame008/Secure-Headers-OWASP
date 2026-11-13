# SafeWebHeaders 8.5.3

Fecha de cierre: 2026-09-19.

Corrige el tratamiento de las cabeceras que llegan repetidas en la misma
respuesta. Afecta por igual a la CLI y a la interfaz web, que comparten motor.

## El defecto

Una respuesta con dos campos del mismo nombre se presentaba unida por una barra:

```
X-Frame-Options    SAMEORIGIN | SAMEORIGIN
```

Eso se lee como si la cabecera tuviera un único valor compuesto, cuando la
realidad de la respuesta es otra:

```
X-Frame-Options: SAMEORIGIN
X-Frame-Options: SAMEORIGIN
```

La representación era engañosa y el análisis, superficial: un único mensaje
genérico («Se recibieron varios campos») que no distinguía un duplicado exacto
de una contradicción, no comparaba los valores y no explicaba la consecuencia.

## Representación

Cada campo ocupa su propia línea, numerado, tanto en «Configuración actual»
como en la evidencia:

```
Configuración actual en la URL: [campo 1] SAMEORIGIN
                                [campo 2] SAMEORIGIN
Evidencia: 2 campos recibidos:
           [campo 1] SAMEORIGIN
           [campo 2] SAMEORIGIN
           Recombinación permitida a un receptor: SAMEORIGIN, SAMEORIGIN
```

La interfaz web muestra el mismo texto: su hoja de estilos ya respetaba los
saltos de línea. La vista RAW no cambia, porque reproduce la respuesta tal como
llegó.

`append_field()` sanea ahora el texto línea a línea en vez de hacerlo antes de
dividir, de modo que los saltos de línea del informe se respetan sin perder la
protección contra secuencias de control procedentes del servidor.

## Análisis

`analyze_repeated_field()` compara los campos normalizando espacios y
mayúsculas, y clasifica el caso:

| Situación | Veredicto | Severidad |
| --- | --- | --- |
| Valores contradictorios (`SAMEORIGIN` y `DENY`) | repetida con valores contradictorios | alta |
| Valores idénticos | repetida con el mismo valor | media |
| Difieren solo en mayúsculas (`SAMEORIGIN` / `sameorigin`) | repetida con el mismo valor | media |
| Difieren solo en espacios | repetida con el mismo valor | media |

Cada caso explica su causa probable. Los duplicados exactos suelen venir de la
aplicación y una capa intermedia (proxy inverso, CDN o WAF) añadiendo la misma
cabecera sin comprobar si ya existía; las diferencias de mayúsculas delatan dos
componentes que la escriben por su cuenta; los valores contradictorios indican
dos configuraciones con intenciones opuestas.

## Fundamento y consecuencia

RFC 9110 §5.3 establece que un emisor no debe generar varias líneas con el mismo
nombre de campo salvo que la gramática de ese campo admita una lista separada
por comas, y que un receptor puede recombinar las líneas en una sola separándolas
por coma. `X-Frame-Options`, `X-Content-Type-Options` y
`Strict-Transport-Security` no son campos de tipo lista, de modo que la
recombinación produce un valor que su propia gramática no reconoce
(`SAMEORIGIN, SAMEORIGIN`). El navegador puede quedarse con el primer campo, con
el último o descartar la cabecera entera: la protección deja de ser predecible y
puede desaparecer. La evidencia muestra explícitamente esa recombinación.

`Content-Security-Policy` queda deliberadamente fuera: el estándar CSP define que
varias políticas se aplican simultáneamente, así que repetirla es legítimo.

## Referencias

El hallazgo cita RFC 9110 §5.3 en primer lugar, seguido de las referencias
propias de cada cabecera:
https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3

## Compatibilidad

- Sin cambios en las opciones, los formatos de salida ni las claves JSON.
- `current_value` puede contener saltos de línea cuando la cabecera está
  repetida; antes contenía el separador ` | `.
- Se actualizó una prueba de `test_regressions_v71.py` que esperaba el título
  genérico anterior.
