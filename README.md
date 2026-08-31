# SafeWebHeaders 8.5.1

SafeWebHeaders es un auditor CLI y GUI local de cabeceras HTTP de seguridad para
una o varias URL. Clasifica la respuesta antes de aplicar reglas, conserva
campos duplicados, sigue redirecciones de forma opcional, analiza CSP, cookies y
CORS, y exporta evidencia a consola, TXT, JSON, CSV o HTML.

La versión 8.5.0 rehace la presentación en las dos superficies: identidad
visual nueva, consola más legible y una interfaz web organizada como espacio de
trabajo con menú lateral, gráficas y tema claro/oscuro. Hereda íntegras las
correcciones de análisis de 8.4.1 y las capacidades de 8.4.2. Conserva el mismo
motor de reglas para CLI y GUI, la identidad azul real con logo propio, la
separación entre cabeceras y cookies, y la navegación interna por objetivo de la
GUI. Corrige cinco defectos de análisis detectados en auditoría de código: dos
falsos negativos de CSP, una redacción indebida de evidencia CORS, informes
esenciales vacíos en objetivos que redirigen, y la comparación sensible a
mayúsculas de los prefijos de cookie.

También se incorporan `OPTIONS` y `POST` de forma segura y explícita. En POST el
analista debe indicar el cuerpo y su `Content-Type`; ese cuerpo no se copia al
reporte. No se exponen PUT, PATCH ni DELETE porque una herramienta de auditoría
de cabeceras no debería facilitar operaciones mutantes o destructivas por
accidente.

## Novedades de 8.5.1

- **corrección crítica**: la interfaz web no podía auditar ninguna URL. El
  generador del anillo encadenaba una asignación sobre `Element.append()`, que
  devuelve `undefined`, y el análisis fallaba con «Cannot set properties of
  undefined (setting 'textContent')»;
- el campo **Ocultar cabeceras del informe** ofrece ahora autocompletado con el
  catálogo de cabeceras excluibles del servidor y sugerencias de un toque;
- nuevo **ocultamiento posterior al análisis**: desde el área de cabeceras se
  puede ocultar cualquier cabecera del informe sin volver a escanear. Es un
  filtro de vista y afecta a hallazgos, inventario y gráficas;
- **la vista RAW nunca se altera**, ni por la exclusión previa ni por el
  ocultamiento posterior: la evidencia de la respuesta se conserva íntegra.

## Novedades de 8.5.0

### Identidad
- logo rediseñado: escudo con la pila de cabeceras HTTP y sello de
  verificación. Es el favicon de la interfaz y la fuente del banner de consola;
- el banner de la CLI dibuja ese mismo escudo con bloques de media altura y una
  entrada progresiva fila a fila, solo en terminal interactiva con color.

### Consola
- los encabezados `RESUMEN DE HALLAZGOS CSP` y `ANÁLISIS DETALLADO DE CSP` van
  precedidos de una línea en blanco, en versalitas y con regla de subrayado;
- el bloque de notas sustituye la banda de signos de admiración por una regla
  horizontal, y numera cada nota;
- el resaltado de la URL cubre exactamente el texto, sin relleno lateral;
- el valor de cada cabecera se resalta con fondo propio, aplicado por fragmento
  ya recortado para que nunca se desborde en las líneas envueltas.

### Interfaz web
- espacio de trabajo con **menú lateral** de secciones: Resumen, Cabeceras,
  Pruebas de concepto, Validador de cookies, Vista RAW, Redirecciones y Notas;
- **gráficas** en el área de cabeceras: anillo de reparto y barras por
  categoría, dibujadas con SVG generado en el cliente, sin librerías ni
  peticiones externas, y con los mismos colores de categoría del resto;
- **interruptor de tema claro/oscuro** que respeta `prefers-color-scheme` la
  primera vez; el tema claro solo redefine tokens de color;
- el **favicon del objetivo** se descubre ahora también por
  `<link rel="icon">` y llega activado de forma predeterminada.

## Novedades de 8.4.2

- las **cabeceras heredadas u obsoletas** tienen color propio (amarillo) en la
  CLI y en la GUI; antes compartían naranja con las incorrectas en la web y cian
  con las cookies en la consola;
- el informe web encabeza con el **favicon del objetivo** junto a la URL: lo
  descarga el servidor local y lo incrusta como `data:`, de modo que el
  navegador nunca contacta al sitio auditado. Es opt-in porque añade una
  petición a `/favicon.ico`, y queda registrada en las notas del informe;
- nuevo **inventario de cabeceras**: una franja compacta con los nombres
  agrupados en faltantes, mal configuradas, correctas, obsoletas, divulgación y
  cookies;
- nueva opción **ocultar cabeceras del informe**, equivalente a
  `--exclude-header`, disponible también en el modo de evidencia pegada;
- nueva área **Pruebas de concepto** con las cuatro PoC de la CLI (framing,
  framing interactivo, CORS y CSP) generadas y servidas desde el servidor local;
- la PoC de CORS se ejecuta con el **Origin real de la interfaz**, de modo que la
  sonda del servidor y la comprobación del navegador son comparables sin montar
  un `http.server` aparte;
- tipografía general un punto mayor y separación visual explícita entre las
  áreas de cabeceras, cookies y pruebas de concepto.

## Novedades de 8.4.1

- `frame-ancestors https://*`, `http://*`, `*://*` y `*:*` vuelven a tratarse
  como lo que son: el conjunto global de orígenes, no una allowlist;
- `script-src https://*` recibe la misma severidad alta que `script-src https:`,
  y `script-src-elem`/`script-src-attr` normalizan mayúsculas;
- `Access-Control-Allow-Credentials` deja de ocultarse como si fuera un secreto:
  su valor es la evidencia principal del análisis CORS;
- el alcance esencial conserva las observaciones contextuales de HSTS y la
  cadena de navegación, incluida la degradación HTTPS → HTTP;
- los prefijos `__Secure-`, `__Host-` y `__Host-Http-`/`__HostHttp-` se comparan
  sin distinguir mayúsculas, como hace RFC 6265bis;
- el resaltado CSP identifica directivas por token completo, sin marcar
  `script-src` por un problema exclusivo de `script-src-elem`.

## Novedades heredadas de 8.4.0

- branding azul rey, logo vectorial, favicon y banner equivalente en la CLI;
- GET, HEAD, OPTIONS y POST con ayuda contextual en GUI y `--help`;
- perfil Automático, Web/API explicado directamente junto al selector;
- rojo y símbolo `-` para ausencias; naranja y símbolo `!` para incorrectas;
- hallazgos planos, sin píldoras ni bordes laterales coloreados por cabecera;
- áreas independientes de **Cabeceras** y **Cookies**, con submenú por URL;
- corrección de la navegación `meta refresh` después de POST/OPTIONS: el salto
  de cliente se solicita con GET y nunca reenvía el cuerpo anterior.

## Línea base para documentos web

Por decisión de alcance de SafeWebHeaders 8.5.1, el análisis predeterminado se
centra en tres cabeceras esenciales cuando la respuesta efectiva es un
documento HTML. En API, assets, descargas, redirecciones y respuestas sin cuerpo
solo aplica los controles que tienen efecto en ese contexto.

| Cabecera | Criterio de SafeWebHeaders 8.5.1 |
| --- | --- |
| `X-Frame-Options` | Debe existir en HTML interactivo. `DENY` y `SAMEORIGIN` son válidos; `ALLOW-FROM` está obsoleto. CSP `frame-ancestors` es la defensa moderna, pero se informa por separado. |
| `Strict-Transport-Security` | En un dominio HTTPS, la línea base reforzada es `max-age=63072000; includeSubDomains`. `preload` no se exige automáticamente porque requiere una decisión operativa difícil de revertir. |
| `Content-Security-Policy` | Debe existir en contenido renderizable y se analiza directiva por directiva. No existe una política universal que sea correcta para todas las aplicaciones. |

Estas cabeceras recomendadas no generan un hallazgo por ausencia. Si el servidor
las envía, SafeWebHeaders sí comprueba que su configuración sea válida:

| Cabecera opcional | Validación cuando está presente |
| --- | --- |
| `Referrer-Policy` | En `--all-headers` debe existir en HTML y usar una política reconocida. OWASP propone `strict-origin-when-cross-origin`; otras políticas válidas pueden ser más restrictivas. |
| `X-Content-Type-Options` | Debe ser un único campo con el valor exacto `nosniff`. |
| `Content-Type` | Se comprueba tipo MIME, duplicados, parámetros y `charset` de HTML. También ayuda a la clasificación automática, pero no se cuenta como cabecera de seguridad obligatoria. |
| `Permissions-Policy` | Se comprueba la sintaxis y se advierte si `geolocation`, `camera` o `microphone` se abren globalmente. No se inventan directivas obligatorias: la allowlist depende de la aplicación. |

### Qué dicen OWASP y MDN realmente

OWASP recomienda las seis cabeceras de seguridad citadas y para CSP remite a una
configuración propia de cada sitio. Eso es una recomendación de endurecimiento,
no una obligación universal para cada respuesta. La guía práctica de MDN/HTTP
Observatory marca HSTS, anti-clickjacking, CSP y Referrer-Policy como requeridos.
En esa misma tabla, la verificación de MIME aparece como no obligatoria y
`Permissions-Policy` no forma parte de la lista de mínimos.
Además, MDN clasifica actualmente `Permissions-Policy` como experimental y de
disponibilidad limitada.

Por tanto, “las seis son obligatorias según OWASP y Mozilla” sería una frase
demasiado absoluta. SafeWebHeaders 8.5.1 usa HSTS, CSP y X-Frame-Options como
alcance esencial predeterminado. El informe `--all-headers` añade
Referrer-Policy y trata `X-Content-Type-Options`, `Content-Type` y
`Permissions-Policy` como controles contextuales.

Otros controles como COOP, COEP, CORP, CORS, `Cache-Control`,
`Clear-Site-Data` e `Integrity-Policy` se validan cuando están presentes o
cuando el contexto los exige. No se inventa una ausencia universal que pueda
romper OAuth, pagos, recursos de terceros o caché pública legítima.

### Alcance predeterminado y `--all-headers`

El modo esencial ya no necesita una bandera. Este comando analiza HSTS, CSP y
X-Frame-Options, y conserva siempre obsoletas y divulgaciones:

```bash
safewebheaders https://example.com
```

En el modo predeterminado, las únicas cabeceras de línea base que se clasifican como
correctas, ausentes o incorrectas son `Strict-Transport-Security`,
`Content-Security-Policy` y `X-Frame-Options`. Las cabeceras heredadas u
obsoletas (`X-XSS-Protection`, `Expect-CT`, `Public-Key-Pins`,
`Feature-Policy`, etc.) y las divulgaciones (`Server`, `X-Powered-By`,
`X-AspNet-Version`, etc.) se conservan siempre porque siguen siendo
accionables.

Se omiten Referrer-Policy, XCTO, Content-Type, Permissions-Policy,
COOP/COEP/CORP, Cache-Control, CORS e informativos ajenos al alcance esencial,
salvo una comprobación solicitada expresamente como `--value-cookie`,
`--test-cors` o `--sensitive-response`.

Desde 8.4.1, el alcance esencial **nunca** oculta una observación de sus tres
cabeceras. Si HSTS no puede evaluarse porque la respuesta llega por HTTP, porque
el host es una dirección IP o porque el objetivo redirige hacia HTTPS, el
informe lo dice explícitamente en vez de dejar la cabecera fuera. La cadena de
navegación también se evalúa, de modo que una degradación HTTPS → HTTP aparece
como hallazgo incorrecto de severidad alta sin necesidad de `--all-headers`.
Una nota visible deja constancia del alcance en todos los formatos. Para obtener
el informe completo:

```bash
safewebheaders https://example.com --all-headers
```

`--essential-only` continúa aceptándose de forma oculta para scripts 8.2.0,
pero ya no es necesario ni aparece en la ayuda pública.

Fuentes principales:

- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [MDN Practical security implementation guides](https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides)
- [MDN Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

## Instalación y ejecución

Requiere Python 3.10 o superior.

Linux, Kali o macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python safewebheaders.py https://example.com
```

Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python safewebheaders.py https://example.com
```

También puede instalarse la wheel incluida en `dist/` y usar el comando:

```bash
safewebheaders https://example.com
```

## Interfaz web local 8.5.1

Inicia el servidor y abre la GUI automáticamente:

```bash
python safewebheaders.py --web
python safewebheaders.py --gui
```

Si instalaste la wheel, puedes usar cualquiera de estos comandos:

```bash
safewebheaders --web
safewebheaders-web
python -m safewebheaders.web
```

Se intenta usar `http://127.0.0.1:8080/`. Si Windows rechaza ese puerto, la
herramienta selecciona automáticamente otro puerto local libre y muestra la URL
real en la terminal. Para elegir otro puerto, pedir uno libre desde el inicio o
evitar que se abra el navegador:

```bash
safewebheaders --web --web-port 9090
safewebheaders --web --web-port 0
safewebheaders --web --no-browser
safewebheaders-web --port 9090 --no-browser
```

La GUI ofrece cuatro flujos:

1. **Una URL:** solicita el objetivo, sigue opcionalmente 3xx y `meta refresh`,
   y analiza las cabeceras de la respuesta final.
2. **Varias URL:** no impone un número fijo de objetivos; recibe uno por línea,
   elimina duplicados y conserva errores individuales. El lote se procesa de
   forma secuencial y está acotado únicamente por el cuerpo local de 1 MiB y los
   recursos disponibles del equipo.
3. **Pegar cabeceras:** interpreta uno o varios bloques `HTTP/1.1 200 OK` con
   campos duplicados y continuación de líneas. La URL de evidencia es
   obligatoria, pero se identifica como un dato aportado por el analista: este
   modo no comprueba por red que las cabeceras procedan realmente de ella.
4. **Solo CSP:** acepta el valor de la política o líneas completas
   `Content-Security-Policy:` y `Content-Security-Policy-Report-Only:`. La URL
   obligatoria permite relacionar la evidencia con el sitio revisado.

La identidad visual usa azul rey (`#1769ff`) y un escudo propio que combina
los signos de código, tres líneas de cabecera y una marca de verificación. El
mismo símbolo se sirve como favicon y se traduce a un banner monoespaciado en
la CLI, por lo que no depende de fuentes, CDN ni imágenes externas.

Cada URL evaluada despliega un submenú con **Resumen**, **Cabeceras**, **Vista
RAW**, **Redirecciones** y **Notas** cuando correspondan. **Cookies** solo
aparece cuando el usuario activa *Evaluar cookies* o el reporte contiene esa
categoría. Así, una revisión de cabeceras no se mezcla visualmente con la
revisión opt-in de `Set-Cookie`.

La vista **Cabeceras HTTP · vista RAW** reproduce la línea de estado y los
campos observados en un bloque tipo terminal. Verde representa configuración
correcta; rojo identifica una ausencia; naranja identifica una configuración
incorrecta; cian identifica cookies; ámbar señala obsoletas/advertencias;
morado identifica divulgación y gris, contexto. Sigue siendo una vista reconstruida porque
Requests no conserva los bytes exactos del socket ni necesariamente el orden
físico original. Cookies, tokens y nonces se ocultan salvo que se active
deliberadamente **Revelar valores sensibles**.

En los resultados CSP, la GUI conserva el mismo criterio visual del CLI y del
HTML exportado: los tramos que originan una configuración incorrecta o una
advertencia aparecen en rojo, y las directivas restrictivas reconocidas en
verde. Primero se presenta la lista copiable de subhallazgos y, debajo, su
evidencia, protección, riesgo y recomendación.

El checkbox **Analizar todas las cabeceras** equivale exactamente a
`--all-headers`. Desmarcado, la GUI usa el alcance esencial predeterminado. Las
comprobaciones explícitas, como **Evaluar cookies**, siguen funcionando por sí
solas igual que `--value-cookie` en el CLI.

### Si Windows muestra `WinError 10013`

Desde 8.3.0 el servidor prueba otro puerto automáticamente. Si Windows también
rechaza el puerto libre, revisa qué proceso o reserva afecta al equipo:

```powershell
netstat -ano | findstr :8080
netsh interface ipv4 show excludedportrange protocol=tcp
python safewebheaders.py --web --web-port 0
```

No es necesario ejecutar como administrador por defecto. Si incluso el puerto
`0` falla, revisa las reglas del Firewall de Windows o del antivirus para
`python.exe`; el programa mostrará un error corto en vez de un traceback.

### Modelo de seguridad de la GUI

- el servidor solo escucha en `127.0.0.1` y no puede configurarse para exponerlo
  directamente a la LAN;
- cada arranque genera un token aleatorio exigido por la API y valida `Host`,
  `Origin` y `Content-Type` para reducir ataques desde otra página del navegador;
- HTML, CSS y JavaScript se sirven desde el paquete, sin CDN, analítica ni
  telemetría;
- la propia GUI entrega CSP, X-Frame-Options, XCTO, Referrer-Policy,
  Permissions-Policy, COOP y CORP;
- el cuerpo JSON, la evidencia manual y cada URL tienen límites de tamaño; no
  existe un máximo numérico artificial para el lote.

Este servidor está diseñado para uso **local por el pentester**. No debe
publicarse directamente en Internet: un despliegue compartido necesita
autenticación, autorización, HTTPS, control de concurrencia, aislamiento de
escaneos, lista de destinos y protección SSRF acorde con la infraestructura.

La ayuda integrada es la referencia rápida:

```bash
safewebheaders --help
```

## Interfaz CLI 8.5.1

### Objetivos y clasificación

Una o varias URL:

```bash
safewebheaders https://uno.example https://dos.example
safewebheaders --url-file urls.txt
```

`--response-type auto|web|api` no cambia la respuesta descargada: define qué
reglas son aplicables. `auto` es el valor recomendado y usa el estado HTTP y
`Content-Type` para distinguir documento, API, asset, descarga o redirección.
`web` fuerza las reglas propias de un documento HTML; `api` evita reportar como
ausentes controles exclusivos del navegador en JSON/XML. Fuerza uno de estos
perfiles solo cuando el servidor declare un `Content-Type` incorrecto y
conozcas el contexto real.

### Métodos HTTP

SafeWebHeaders admite cuatro métodos deliberadamente acotados:

| Método | Uso en el auditor |
| --- | --- |
| `GET` | Predeterminado. Obtiene la representación normal y permite detectar HTML y `meta refresh`. |
| `HEAD` | Solicita solo metadatos. Puede devolver cabeceras distintas y no permite inspeccionar redirecciones de cliente en el cuerpo. |
| `OPTIONS` | Consulta las capacidades del endpoint; es útil para revisar `Allow`/CORS, aunque sus cabeceras pueden diferir de GET. |
| `POST` | Reproduce un endpoint que exige cuerpo. Puede ejecutar lógica de negocio y debe usarse únicamente con autorización. |

Ejemplos:

```bash
safewebheaders https://api.example/recurso --method OPTIONS
safewebheaders https://api.example/consulta --method POST \
  --content-type application/json \
  --data '{"consulta":"valor-de-prueba"}'
safewebheaders https://api.example/consulta --method POST \
  --content-type application/json \
  --data-file cuerpo.json
```

`--data`/`--request-body` acepta texto y `--data-file`/`--request-body-file`
lee un archivo de hasta 1 MiB. Se recomienda el archivo si el cuerpo es
sensible, para evitar el historial del shell. La GUI limita el cuerpo POST a
256 KiB para mantener acotada su API local. El cuerpo nunca se serializa en el
reporte. En un lote se envía el mismo cuerpo a cada URL. Tras un 301/302/303 o
un `meta refresh`, si la navegación cambia a GET, el informe deja constancia y
no reenvía el cuerpo POST.

PUT, PATCH y DELETE no se incluyen: normalmente modifican o eliminan estado y
no aportan una ventaja proporcional para auditar las cabeceras de respuesta.

### `--show-headers`: vista tipo curl, no bytes RAW

`--show-headers` imprime la línea de estado y todos los campos recibidos,
incluidos valores duplicados, para cada respuesta observada. La vista es
**reconstruida**: Requests/urllib3 no conservan la línea de estado ni el orden
físico exacto de todos los bytes del socket. La salida lo etiqueta expresamente
como “tipo curl (reconstruida, no bytes RAW)”.

```bash
safewebheaders https://example.com --show-headers
safewebheaders http://example.com --follow-redirects --show-headers
```

Para comparar únicamente cabeceras con curl:

```bash
curl -sS -D - -o /dev/null https://example.com
curl -sS -L -D - -o /dev/null http://example.com
```

`curl -i` mezcla cabeceras y cuerpo. `-D - -o /dev/null` muestra los bloques de
cabeceras y descarta el cuerpo; `-L` sigue redirecciones. Ni siquiera la salida
textual de HTTP/2 debe confundirse con los frames binarios exactos de la red.

Por seguridad, `Set-Cookie`, tokens, consultas sensibles y nonces/hashes CSP se
ocultan. `--reveal-sensitive` los muestra deliberadamente y puede dejar
secretos en la terminal o en un reporte.

### Redirecciones

Sin `--follow-redirects`, una respuesta 3xx muestra el estado, la URL y
`Location`, indicando que el destino no se solicitó. Con la opción activa se
muestran:

- cantidad separada de redirecciones HTTP y navegaciones HTML;
- tipo, estado y URL de cada salto;
- destino anunciado por `Location` o `meta refresh`;
- destino que SafeWebHeaders solicitó realmente;
- URL final evaluada;
- cambio de host y degradación HTTPS a HTTP;
- cabeceras de cada respuesta si también se usa `--show-headers`.

```bash
safewebheaders http://example.com --follow-redirects
```

`--max-redirects` dejó de ser una opción pública. Existe un límite interno de
20 saltos para cortar bucles o cadenas anormales; alcanzar el límite produce un
error claro. Seguir indefinidamente no permitiría distinguir “llegará al final”
de un bucle permanente.

SafeWebHeaders sigue primero las redirecciones HTTP 3xx. Si un servidor HTTPS
anuncia un destino HTTP y ese salto falla por conexión o tiempo de espera, la
herramienta reintenta la misma dirección por HTTPS, conserva el `Location`
original como evidencia y registra la variante segura como destino realmente
solicitado. No se hace esta sustitución si el destino HTTP responde normalmente.

Con `--follow-redirects`, un `<meta http-equiv="refresh">` de la respuesta HTML
también se sigue sin ejecutar el documento. Si ese HTML HTTPS anuncia HTTP, se
prioriza la variante HTTPS. El salto aparece como `meta-refresh` y puede
continuar hacia nuevos 3xx hasta la URL final, cuyas cabeceras son las auditadas.
Sin el flag solo se informa el destino. La CLI **no ejecuta JavaScript**, eventos,
service workers ni código de navegador; una redirección implementada únicamente
por JavaScript debe analizarse manualmente. Una respuesta 401/403 que anuncie
`Negotiate` o `NTLM` mediante `WWW-Authenticate` se identifica como una barrera
SSO/NTLM, no como una redirección fallida.

Ejemplo equivalente al flujo observado en MinTIC:

```bash
safewebheaders https://www.mintic.gov.co/ --follow-redirects
```

La cadena informa la URL inicial, el destino HTTP anunciado, la recuperación
HTTPS, el `meta refresh`, los 3xx posteriores y
`https://www.mintic.gov.co/portal/inicio/` como URL final evaluada.

### Tiempo de espera

Los antiguos `--connect-timeout`, `--read-timeout` y `--resolve-timeout` se
consolidaron en una sola opción:

```bash
safewebheaders https://sitio-lento.example --timeout 30
```

El valor predeterminado es 15 segundos. Se aplica por fase a la conexión y a la
espera de datos, y también acota la resolución DNS usada solo para mostrar IP.
No es un cronómetro global de toda la ejecución: redirecciones y sondas
adicionales realizan más de una petición. Si se supera, el reporte indica que
la URL no respondió dentro del tiempo configurado. La resolución DNS de la
conexión HTTP depende del sistema operativo o del proxy y no siempre respeta un
timeout de Requests con exactitud.

### Analizar una CSP sin conectarse a una web

`--analyze-csp` revisa una cadena `Content-Security-Policy` localmente. Sirve
para evaluar una política antes de desplegarla, revisar una propuesta o usar el
parser en CI. No hace peticiones y no comprueba si el servidor realmente la
entrega.

```bash
safewebheaders --analyze-csp "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
```

El nombre anterior `--csp-policy` era ambiguo y quedó como alias oculto de
compatibilidad.

En un escaneo normal, el bloque CSP muestra el valor de cada política sin
anteponer etiquetas dentro del propio valor. Cuando existen varias cabeceras
CSP simultáneas, cada política se presenta por separado y se explica que el
navegador exige cumplirlas todas. Los tokens peligrosos se resaltan en rojo y
los controles restrictivos reconocidos en verde en el renderer de consola/TXT
y en HTML. A
continuación aparece primero una lista copiable con los títulos de todos los
subhallazgos y después, en el mismo orden, la evidencia, la protección que
aporta la directiva, el riesgo, la recomendación y las referencias. JSON
conserva las claves existentes y añade `policies`, `policy_context` y `purpose`.

### Cabeceras de petición y entornos autenticados

`-H` o `--header` añade una cabecera a la petición y puede repetirse:

```bash
safewebheaders https://api.example/me \
  -H "Authorization: Bearer TOKEN" \
  -H "X-Tenant: laboratorio"
```

Casos prácticos:

- auditar una ruta autenticada con `Authorization` o una cookie de laboratorio;
- atravesar un WAF que espera una cabecera concreta;
- reproducir el `Origin` o `Referer` de un flujo autorizado;
- seleccionar un tenant o una versión de API.

Para evitar secretos en el historial de la terminal, usa un archivo UTF-8 con
una cabecera por línea:

```bash
safewebheaders https://api.example/me --header-file headers.private
```

No incluyas saltos de línea en los valores. La herramienta rechaza nombres y
valores HTTP inválidos.

`--use-environment` habilita explícitamente `HTTP_PROXY`, `HTTPS_PROXY`,
`NO_PROXY`, `REQUESTS_CA_BUNDLE` y credenciales `.netrc`. Es útil en redes
corporativas, proxys de inspección o CI configurado. Está apagado por defecto
para que una variable o un `.netrc` inesperado no cambien la solicitud.

### Secretos en redirecciones

`--forward-custom-secrets` no agrega cabeceras nuevas. Su función es permitir
que secretos personalizados ya añadidos con `-H`, por ejemplo `X-API-Key`, se
reenvíen cuando una redirección cambia de origen.

Sin esa opción, SafeWebHeaders elimina esos secretos en cambios de origen.
`Authorization` y `Cookie` conservan además las protecciones de Requests. Usa
la opción solo si controlas y confías en todos los destinos:

```bash
safewebheaders https://entrada.example \
  --follow-redirects \
  -H "X-API-Key: TOKEN" \
  --forward-custom-secrets
```

El nombre anterior `--keep-sensitive-headers-on-redirect` quedó oculto porque
podía interpretarse como “crear cabeceras” en vez de “reenviar secretos”.

### Validaciones adicionales

| Opción | Qué hace | Cuándo aporta valor |
| --- | --- | --- |
| `--value-cookie` | Activa la revisión de los atributos `Secure`, `HttpOnly` y `SameSite` de cada `Set-Cookie`. | Auditar cookies cuando esa evidencia forma parte del alcance. Sin la opción no se genera la categoría de cookies. |
| `--reveal-sensitive` | Desactiva la redacción de cookies, tokens, parámetros sensibles y material nonce/hash. | Diagnóstico puntual en una terminal y archivo controlados. No usar en reportes compartidos. |
| `--check-nonce-reuse` | Realiza una segunda petición cuando la CSP contiene nonces y compara ambos valores. | Detectar nonces estáticos o cacheados. Un nonce debe ser impredecible y distinto por respuesta. |
| `--test-cors` | Realiza otra petición con un `Origin` aleatorio no confiable y analiza ACAO, credenciales y `Vary`. | Detectar reflexión directa o configuraciones obviamente permisivas. Es una sonda HTTP, no una prueba completa de navegador ni de preflight. |
| `--sensitive-response` | Exige `Cache-Control: no-store` para el endpoint evaluado. | Paneles, datos personales, tokens o respuestas autenticadas que no deben almacenarse. |

Las cookies `Set-Cookie` se evalúan **solo** con `--value-cookie`. Sin la opción,
la categoría de cookies no aparece en el análisis. Los valores permanecen
ocultos incluso al activar la revisión; `--reveal-sensitive` es una decisión
independiente y explícita. Si también se solicita `--show-headers`, la vista de
cabeceras conserva `Set-Cookie` como evidencia HTTP, con su valor redactado.

### Exclusiones

`--exclude-header` omite una regla conocida y puede repetirse o recibir varios
nombres separados por coma:

```bash
safewebheaders https://example.com \
  --exclude-header Strict-Transport-Security \
  --exclude-header "X-Frame-Options,Permissions-Policy"
```

Acepta nombres HTTP reales y los alias `HSTS`, `CSP`, `XFO`, `XCTO`,
`Referrer`, `Cookies` y `CORS`. `--list-excludable-headers` dejó de mostrarse en
la ayuda porque la validación sugiere coincidencias ante errores y esta
documentación enumera los principales; el alias permanece aceptado para
automatizaciones 8.0.

## Prueba CORS y resultado esperado

La opción `--poc-cors` ejecuta primero una sonda con el Origin configurado y
genera un HTML que repite la lectura desde un navegador real, sin y con
credenciales:

```bash
safewebheaders https://api.example/me \
  --poc-cors \
  --poc-origin http://127.0.0.1:8000

python -m http.server 8000 --bind 127.0.0.1 --directory safewebheaders-pocs
```

Abre exactamente la URL local que imprime la herramienta. Si se abre con
`file://`, otro puerto u otro host, el Origin no coincide y la PoC deshabilita
los botones para evitar una conclusión falsa.

| Resultado del navegador | Interpretación correcta |
| --- | --- |
| Lectura bloqueada o petición fallida | JavaScript no recibió el cuerpo. Revisa consola y red: CORS, TLS, DNS, autenticación o conectividad pueden producir un resultado parecido. |
| Lectura sin credenciales permitida | Ese Origin puede leer la respuesta pública. Puede ser intencional y no demuestra exposición privada. |
| Lectura autenticada permitida | Revisa DevTools para confirmar que viajaron cookies. Solo es explotable si el cuerpo contiene datos sensibles que ese Origin no debía leer. `SameSite` y el bloqueo de cookies de terceros pueden impedir que viaje la sesión. |

La PoC muestra estado HTTP, URL final, si hubo redirect, tipo de contenido,
modo de credenciales y hasta 200.000 caracteres del cuerpo. Tiene un timeout de
15 segundos, no envía los datos a terceros y no afirma vulnerabilidad solo por
ver `Access-Control-Allow-Origin`.

Limitación deliberada: no automatiza todos los métodos, cabeceras y preflights
posibles. Para una auditoría CORS exhaustiva hay que probar la lógica de
allowlist por endpoint y por credencial.

## PoC de framing y overlay

PoC básica:

```bash
safewebheaders https://example.com/login --poc-frame
```

PoC interactiva:

```bash
safewebheaders https://example.com/login --poc-frame-overlay
```

En la versión 8.1.2:

- el iframe de la web real permanece al 100 % de opacidad;
- el formulario overlay queda por delante y su propia opacidad puede variar de
  0 % a 100 %;
- hay controles de posición horizontal/vertical, ancho, centrado y guías de
  alineación;
- usuario y contraseña ficticios se reflejan en vivo debajo del marco, para
  demostrar que la interacción aparente ocurrió sobre la página real;
- el submit se bloquea, la CSP local usa `form-action 'none'`, no existe
  `fetch()`/XHR para transmitir datos y los campos se limpian al abandonar la
  página.

Usa solo valores ficticios. Si XFO o CSP `frame-ancestors` impiden renderizar el
iframe, el overlay por sí solo no demuestra clickjacking. El evento `load` de un
iframe tampoco prueba que el contenido sea visible; confirma el resultado en la
pantalla y en la consola del navegador.

## Exportaciones y CI

`--output`, `--export` y `-o` guardan una copia y mantienen el resumen en
pantalla. Añade `--quiet` para guardar sin repetir el análisis completo.

```bash
safewebheaders https://example.com -o reporte.html
safewebheaders --url-file urls.txt -o reporte.json --quiet
safewebheaders --url-file urls.txt --format csv --output -
```

Un archivo existente no se reemplaza sin `--force`. La escritura es atómica y
la salida CSV neutraliza fórmulas. JSON y HTML preservan la cadena HTTP y, con
`--show-headers`, los bloques reconstruidos de cada respuesta.

Las decisiones operativas que cambian el alcance o generan artefactos —por
ejemplo `--all-headers`, recuperación segura de un salto, seguimiento de
`meta refresh`, `--insecure` o la creación de una PoC— se agrupan al final de la
salida legible dentro de un bloque separado **IMPORTANTE — NOTAS DE LA
EVALUACIÓN**. HTML usa una tarjeta resaltada; JSON y CSV conservan las notas como
datos estructurados.

`--fail-on none|incorrect|absent|warning|any` permite integrar el resultado en
CI:

| Código | Significado |
| --- | --- |
| `0` | Escaneo completado y no se activó la condición de fallo. |
| `1` | Lote parcialmente completado: algunas URL fallaron. |
| `2` | Entrada inválida, error operativo o todas las URL fallaron. |
| `3` | El análisis terminó y `--fail-on` encontró el estado indicado. |
| `130` | Cancelación por teclado. |

## TLS, proxy y certificados cliente

```bash
safewebheaders https://target.test --ca-bundle empresa-ca.pem
safewebheaders https://target.test --proxy http://127.0.0.1:8080
safewebheaders https://target.test --cert cliente.pem --cert-key cliente.key
safewebheaders https://target.test --cert cliente.p12 --certpass-file p12.pass
```

`--insecure` desactiva la validación de identidad TLS y debe limitarse a
pruebas autorizadas con certificados de laboratorio. El reporte deja constancia
de esa decisión.

## Compatibilidad de nombres 8.0

| Opción 8.0/8.2 | Opción pública 8.5.1 | Decisión |
| --- | --- | --- |
| `--csp-policy` | `--analyze-csp` | Renombrada; alias oculto. |
| `--profile` | `--response-type` | Renombrada; `auto` sigue recomendado. |
| `--connect-timeout`, `--read-timeout`, `--resolve-timeout` | `--timeout` | Consolidadas; alias ocultos. |
| `--request-header` | `-H`, `--header` | Renombrada al estilo curl; alias oculto. |
| `--request-header-file` | `--header-file` | Simplificada; alias oculto. |
| `--trust-env` | `--use-environment` | Renombrada para explicar la acción; alias oculto. |
| `--show-sensitive` | `--reveal-sensitive` | Renombrada para hacer explícito el riesgo; alias oculto. |
| `--keep-sensitive-headers-on-redirect` | `--forward-custom-secrets` | Renombrada y limitada conceptualmente a secretos personalizados. |
| `--max-redirects` | Límite interno | Retirada de la ayuda; se mantiene un corte contra bucles. |
| `--list-excludable-headers` | Documentación y sugerencias de validación | Retirada de la ayuda; alias oculto. |
| `--value-cookies`, `--check-cookies` | `--value-cookie` | La revisión sigue siendo opt-in; los nombres anteriores quedan como alias ocultos. |
| `--essential-only` | Predeterminado / `--all-headers` | El alcance esencial ahora es el predeterminado; el nombre anterior queda como alias oculto. |

Los alias ocultos pueden retirarse en una próxima versión mayor. No se
recomiendan para scripts nuevos.

## Arquitectura para mantenimiento

```text
safewebheaders/
├── cli.py             interfaz, validación y orquestación
├── transport.py       HTTP, TLS, certificados y redirecciones seguras
├── navigation.py      cadena HTTP, meta refresh y recuperación HTTPS
├── manual.py          parser y reportes de evidencia HTTP/CSP pegada
├── web/
│   ├── server.py      servidor local, token, CSP y validaciones HTTP
│   ├── service.py     adaptador entre formularios y el motor
│   └── assets/        HTML, CSS, JavaScript y logo SVG sin dependencias externas
├── profiles.py        clasificación de documentos, API, assets y descargas
├── rules_basic.py     HSTS, Content-Type, XCTO, Referrer y diagnósticos HTML/SSO
├── rules_csp.py       parser CSP y X-Frame-Options
├── rules_context.py   Permissions-Policy, cookies, CORS y controles contextuales
├── engine.py          ejecución y deduplicación de reglas
├── presentation.py    consola, HTML, redacción y vista tipo curl
├── output.py          JSON, CSV y escritura atómica
├── pocs.py            PoC de framing, CORS y CSP
├── models.py          objetos de dominio serializables
└── utils.py           normalización, exclusiones y resolución DNS
```

`safewebheaders.py` y `mejora.py` son fachadas de compatibilidad. La lógica
nueva debe vivir en el módulo correspondiente y acompañarse de pruebas en
`tests/`.

Comandos de desarrollo:

```bash
python -m pytest
ruff check safewebheaders tests tools
mypy safewebheaders
bandit -q -r safewebheaders
python -m build
twine check dist/*
```

## Alcance y uso responsable

SafeWebHeaders analiza respuestas puntuales. No reemplaza una auditoría de TLS,
revisión de código, pruebas de autenticación/autorización, CSRF, XSS, cachés,
service workers, extensiones del navegador ni todos los endpoints de una
aplicación.

Una cabecera ausente no demuestra por sí sola una vulnerabilidad explotable.
Una cabecera presente tampoco demuestra que la aplicación completa sea segura.
Ejecuta sondas y PoC únicamente contra sistemas propios o con autorización
expresa.
