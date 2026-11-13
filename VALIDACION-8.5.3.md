# Validación de SafeWebHeaders 8.5.3

Fecha de cierre: 2026-09-19.

## Alcance

La validación cubre el tratamiento de cabeceras repetidas de 8.5.3, el criterio
revisado de HSTS de 8.5.2, la corrección
crítica de 8.5.1 y las mejoras de presentación de 8.5.0, y confirma que no
alteran el motor de reglas heredado de 8.4.1 ni las capacidades de 8.4.2. Se
comprueban los encabezados internos de CSP, el bloque de notas, los resaltados
de consola, el logo y su banner, el menú lateral, las gráficas, el tema claro y
el descubrimiento del favicon.

## Regresiones obligatorias

- Los encabezados `RESUMEN DE HALLAZGOS CSP` y `ANÁLISIS DETALLADO DE CSP` van
  precedidos de una línea en blanco y de una regla de subrayado, y el resumen
  precede al detalle.
- El bloque de notas contiene una regla de 72 caracteres, numera cada nota y no
  contiene ninguna banda de signos de admiración.
- `url_badge()` no añade relleno lateral y devuelve texto plano sin color.
- Un valor de cabecera largo se resalta abriendo y cerrando el fondo en cada
  línea envuelta, sin espacios finales dentro del realce.
- El realce de valores es opcional: `append_field()` sin `highlight=` no emite
  ninguna secuencia de fondo.
- El logo contiene las tres barras de la pila de cabeceras, el sello de
  verificación y el azul de marca.
- El banner dibuja el escudo con bloques, se estrecha hacia la punta y usa un
  tono distinto para la pila de cabeceras.
- La animación se omite en salida no interactiva y produce exactamente el mismo
  texto que el banner estático, sin secuencias de control.
- La interfaz declara el menú lateral, `renderSectionNav`, y las secciones de
  pruebas de concepto y validador de cookies.
- El interruptor de tema existe, expone `role="switch"` y etiqueta accesible, y
  la hoja define `:root[data-theme="light"]` con `color-scheme: light`.
- La regla del tema claro solo contiene variables y `color-scheme`: ninguna
  declaración de estructura o tamaño.
- Las gráficas se generan con `createElementNS` y no referencian ningún recurso
  remoto.
- Los tonos de las gráficas reutilizan las variables de categoría.
- El favicon se descubre por `<link rel="icon">` con prioridad sobre el respaldo
  por convención, que incluye `/apple-touch-icon.png`.
- `document_preview` nunca aparece en el reporte público.
- No se intenta recuperar favicon para objetivos que no son HTTP.
- `app.js` no encadena ninguna asignación sobre `Element.append()`.
- La interfaz ofrece autocompletado y sugerencias de cabeceras ocultables antes
  de escanear, alimentadas por `/api/health`.
- El catálogo de cabeceras excluibles llega canónico, ordenado y sin duplicados.
- El ocultamiento posterior al análisis es un filtro de vista y no aparece en la
  función que dibuja la vista RAW.
- Una cabecera excluida antes de escanear sigue presente en la vista RAW y
  figura en `excluded_headers`.
- Todo `max-age` por debajo de 15768000 (seis meses) produce un veredicto
  incorrecto que cita el mínimo exigible.
- Todo `max-age` igual o superior a 15768000 produce un veredicto correcto, con
  y sin `includeSubDomains`, con y sin `preload`, y por encima de dos años.
- La ausencia de `includeSubDomains` se comunica como opción condicionada al
  estado HTTPS de los subdominios, nunca como carencia que degrade.
- La recomendación nunca empuja hacia `preload`.
- Una duración entre seis meses y dos años se acompaña de la referencia
  recomendada sin cambiar el estado.
- `preload` sin `includeSubDomains`, o con `max-age` inferior a un año, produce
  un veredicto incorrecto que nombra el requisito incumplido.
- `max-age=0` sigue siendo incorrecto.
- Las referencias de todo hallazgo de HSTS incluyen las tres fuentes.
- La duración se reporta en días, meses o años según su magnitud.
- Una cabecera repetida se lista con un campo por línea y sin separador de
  barra, en consola y en la interfaz web.
- Dos campos idénticos producen el veredicto «mismo valor» con severidad media
  y explican la causa probable (capa intermedia que reemite la cabecera).
- Dos campos contradictorios producen el veredicto «contradictorios» con
  severidad alta.
- Las diferencias exclusivas de mayúsculas o de espacios no se reportan como
  contradicción.
- La evidencia muestra la recombinación que RFC 9110 §5.3 permite a un receptor.
- RFC 9110 §5.3 encabeza las referencias del hallazgo.
- El tratamiento alcanza a X-Frame-Options, X-Content-Type-Options y
  Strict-Transport-Security.
- Content-Security-Policy queda fuera: varias políticas son legítimas.
- Una cabecera con un solo campo se muestra igual que antes.
- La vista RAW conserva las dos líneas tal como llegaron.

## Comandos de reproducción

```bash
python -m pytest -q --cov=safewebheaders --cov-report=term
python -m compileall -q safewebheaders tests safewebheaders.py mejora.py upload/mejora.py tools/build_release.py
ruff format --check safewebheaders tests safewebheaders.py mejora.py upload/mejora.py tools/build_release.py
ruff check safewebheaders tests safewebheaders.py mejora.py upload/mejora.py tools/build_release.py
mypy safewebheaders
bandit -q -r safewebheaders safewebheaders.py mejora.py upload/mejora.py tools/build_release.py
vulture safewebheaders --min-confidence 80
radon cc safewebheaders -s -a
node --check safewebheaders/web/assets/app.js
UV_CACHE_DIR=/tmp/safewebheaders-v850-uv-cache uv lock --check
python -m build --outdir dist-v850-final
twine check dist-v850-final/*
python tools/build_release.py --dist-dir dist-v850-final
```

## Resultado de cierre

| Control | Resultado |
| --- | --- |
| Suite completa | 391 pruebas superadas, 0 fallidas |
| Regresiones 8.5.x | 61 pruebas específicas superadas (`test_regressions_v850.py`) |
| Regresiones heredadas | 330 pruebas de 8.4.2 y anteriores; cuatro actualizadas por cambios deliberados de criterio |
| Matriz HSTS | 11 combinaciones de duración y directivas verificadas de extremo a extremo |
| Campos repetidos | Idénticos, contradictorios, con diferencia de mayúsculas y de espacios, en las dos superficies |
| Compilación | `compileall` limpio en los 23 módulos y la fachada |
| JavaScript | `node --check` limpio sobre `app.js` |
| Frontend | Flujo completo sobre un DOM fiel a la API real: envío del formulario, informe renderizado, 7 hallazgos visibles, ocultamiento de `Server` (7 → 6) y `Server` intacto en la vista RAW |
| Servidor real | Escaneo local con favicon por `<link rel="icon">`, inventario completo y las cuatro PoC servidas |
| Wheel / sdist | Construidos y verificados; incluyen activos web, pruebas y documentos 8.5.0 |
| ZIP de entrega | Reproducible, con `SHA256SUMS.txt` regenerado y verificado |
| Versión | `8.5.0` coherente en `constants.py`, `pyproject.toml`, `MANIFEST.in`, README, banner CLI y GUI |

### Nota sobre el entorno de validación

La ejecución de cierre se realizó en un entorno sin acceso a red. La suite se
corrió con un runner compatible con el subconjunto de pytest empleado por el
proyecto y las distribuciones se construyeron con `setuptools.build_meta` sin
aislamiento. Las herramientas de calidad (`ruff`, `mypy`, `bandit`, `vulture`,
`radon`, `twine`) no pudieron instalarse y deben ejecutarse antes de publicar.

El frontend se validó ejecutando `app.js` sobre un DOM simulado en Node, no en
un navegador real. El simulador de 8.5.0 devolvía un nodo desde `append()` y por
eso no detectó el fallo que dejó la interfaz inservible; ahora reproduce la API
real (`append()` sin valor de retorno, `className` sincronizado con `classList`,
`lastChild`) y ejecuta el flujo completo de la interfaz. Aun así, conviene una
revisión visual del tema claro, del menú lateral y de las gráficas antes de usar
la interfaz ante un cliente.

## Nota sobre el arnés de pruebas

Al ejecutar las pruebas parametrizadas de 8.5.3 se detectó que el runner mínimo
desempaquetaba una tupla como varios parámetros cuando la prueba declaraba un
solo nombre, lo que producía fallos que no existían en el producto. Se corrigió
el runner, no las pruebas.

## Nota sobre el cambio de criterio

Tres pruebas de `test_regressions_v6.py` codificaban la línea base anterior
(«dos años + includeSubDomains obligatorio»). Se actualizaron porque el criterio
que verificaban era incorrecto frente a las fuentes, no porque estorbaran. Un
sitio evaluado con 8.5.1 puede pasar de incorrecto a correcto en HSTS sin haber
cambiado nada: es el efecto buscado.

## Límites deliberados

- La animación del banner es puramente cosmética y nunca altera el texto que se
  guarda en un archivo o se canaliza a otra herramienta.
- Las gráficas resumen el inventario de cabeceras; no sustituyen al detalle por
  hallazgo ni introducen criterios nuevos.
- El tema claro redefine color, no contraste semántico: cada categoría conserva
  su tono propio en ambos modos.
- El favicon exige una petición adicional al objetivo y queda registrado en las
  notas cuando se usa.
- Las pruebas de concepto se ejecutan contra el objetivo real desde el navegador
  del analista y requieren autorización escrita.
- La herramienta no puede saber si un dominio tiene subdominios sin HTTPS, de
  modo que nunca exige `includeSubDomains`: lo presenta como opción con su
  condición y deja la decisión al analista.
- Tampoco comprueba si el dominio está efectivamente en la lista de precarga;
  solo evalúa si la política declarada cumpliría los requisitos de admisión.
- Ante una cabecera repetida, la herramienta no puede saber qué componente la
  emite por duplicado: describe la causa más probable y deja la localización al
  analista, que es quien conoce la arquitectura del cliente.
- Tampoco puede predecir qué campo elegirá cada navegador: por eso el hallazgo
  describe el rango de comportamientos posibles en lugar de afirmar uno.
