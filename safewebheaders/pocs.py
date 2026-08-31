"""Pocs de SafeWebHeaders."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path
from urllib.parse import urlsplit

from .models import (
    ResponseSnapshot,
    ScanError,
    ScanReport,
)
from .presentation import (
    html_escape,
    javascript_literal,
)
from .rules_csp import (
    csp_frame_ancestor_policies,
    describe_frame_ancestor_policies,
)


def poc_slug(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or "politica-local"
    safe_host = re.sub(r"[^A-Za-z0-9._-]+", "-", host).strip("-.") or "objetivo"
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
    return f"{safe_host}-{digest}"


def next_available_path(directory: Path, stem: str) -> Path:
    candidate = directory / f"{stem}.html"
    counter = 2
    while candidate.exists():
        candidate = directory / f"{stem}-{counter}.html"
        counter += 1
    return candidate


def prepare_poc_directory(path_value: str) -> Path:
    directory = Path(path_value).expanduser()
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ScanError(
            f"No se pudo crear el directorio de PoC {directory}: {exc}"
        ) from exc
    if not directory.is_dir():
        raise ScanError(f"La ruta de --poc-dir no es un directorio: {directory}")
    return directory


def write_poc(path: Path, content: str) -> Path:
    try:
        path.write_text(content, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise ScanError(f"No se pudo guardar la PoC {path}: {exc}") from exc
    return path.resolve()


def generate_frame_poc(
    report: ScanReport, directory: Path, *, interactive: bool = False
) -> Path:
    stem = "poc-frame-overlay" if interactive else "poc-frame"
    path = next_available_path(directory, f"{stem}-{poc_slug(report.final_url)}")
    return write_poc(path, build_frame_poc(report, interactive=interactive))


def build_frame_poc(report: ScanReport, *, interactive: bool = False) -> str:
    """Devuelve el HTML de la PoC de framing sin escribirlo en disco.

    La GUI necesita el contenido en memoria para servirlo desde el servidor
    local; la CLI sigue guardándolo mediante ``generate_frame_poc``.
    """

    target = report.final_url
    xfo = (
        " | ".join(report.response_headers.get("x-frame-options", []))
        or "No encontrada"
    )
    policies = csp_frame_ancestor_policies(
        ResponseSnapshot(
            url=report.final_url,
            status_code=report.status_code,
            reason=report.reason,
            headers=report.response_headers,
            display_names=report.display_names,
        )
    )
    frame_values = describe_frame_ancestor_policies(policies)
    target_js = javascript_literal(target)
    target_parts = urlsplit(target)
    target_origin = f"{target_parts.scheme}://{target_parts.netloc}"
    if interactive:
        content = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; frame-src {html_escape(target_origin)}; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'none'; base-uri 'none'">
  <title>PoC interactiva de framing — SafeWebHeaders</title>
  <style>
    :root {{ color-scheme:dark; --bg:#071018; --panel:#0d1b25; --line:#29404f; --accent:#36f1cd; --warn:#ffc857; --bad:#ff5d73; }}
    * {{ box-sizing:border-box; }} body {{ margin:0; padding:24px; color:#e8edf2; background:var(--bg); font:15px/1.5 Segoe UI,Arial,sans-serif; }}
    main {{ max-width:1180px; margin:auto; }} code,pre {{ color:#b9ffe6; background:var(--panel); }}
    pre {{ padding:14px; border:1px solid var(--line); border-radius:10px; white-space:pre-wrap; word-break:break-word; }}
    .notice {{ padding:14px; border-left:4px solid var(--warn); background:#171b1f; }}
    .controls {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; margin:18px 0; padding:14px; border:1px solid var(--line); border-radius:12px; background:var(--panel); }}
    .controls label {{ display:grid; gap:5px; }} button {{ padding:10px 14px; border:1px solid #416070; border-radius:8px; color:#fff; background:#173044; cursor:pointer; }}
    .stage {{ position:relative; height:650px; overflow:hidden; border:4px solid var(--bad); border-radius:12px; background:#fff; }}
    iframe {{ width:100%; height:100%; border:0; background:white; }}
    .decoy {{ position:absolute; z-index:4; left:35%; top:32%; width:360px; max-width:calc(100% - 16px); color:#111; border-radius:12px; }}
    .decoy.guides {{ outline:2px dashed var(--accent); outline-offset:4px; }}
    .decoy-surface {{ padding:22px; background:#fff; border:1px solid #b9c2ca; border-radius:12px; box-shadow:0 18px 55px #0009; opacity:.35; }}
    .decoy h2 {{ margin:0 0 4px; }} .decoy p {{ margin:.2rem 0 14px; color:#46525c; }} .decoy label {{ display:grid; gap:5px; margin:10px 0; }}
    .decoy input {{ width:100%; padding:10px; border:1px solid #8e9aa5; border-radius:7px; color:#111; background:#fff; }} .decoy button {{ width:100%; background:#1769aa; }}
    #capture {{ margin-top:16px; padding:14px; border-left:4px solid var(--accent); background:var(--panel); white-space:pre-wrap; }}
    .danger {{ color:#ff9cab; font-weight:700; }} .switch {{ display:flex!important; align-items:center; gap:8px!important; }}
    .switch input {{ width:auto; }} .hint {{ color:#9fb1bd; font-size:13px; }}
  </style>
</head>
<body><main>
  <h1>PoC interactiva de framing y superposición</h1>
  <p><strong>Objetivo:</strong> <a href="{html_escape(target)}" target="_blank" rel="noopener noreferrer">{html_escape(target)}</a></p>
  <pre>X-Frame-Options: {html_escape(xfo)}
Content-Security-Policy frame-ancestors: {html_escape(frame_values)}</pre>
  <p class="notice"><strong>Uso controlado:</strong> esta demostración no transmite ni almacena datos.
  Escribe únicamente valores ficticios. Si la página objetivo no se renderiza dentro del iframe, la
  superposición por sí sola no demuestra clickjacking.</p>
  <div class="controls">
    <label>Opacidad del overlay <input id="opacity" type="range" min="0" max="100" value="35"><output id="opacity-value">35%</output></label>
    <label>Posición horizontal <input id="left" type="range" min="0" max="70" value="35"></label>
    <label>Posición vertical <input id="top" type="range" min="0" max="70" value="32"></label>
    <label>Ancho del overlay <input id="width" type="range" min="260" max="560" value="360"><output id="width-value">360 px</output></label>
    <label class="switch"><input id="guides" type="checkbox" checked> Mostrar guía de alineación</label>
    <button id="toggle" type="button">Ocultar formulario superpuesto</button>
    <button id="center" type="button">Centrar overlay</button>
    <button id="reload" type="button">Recargar iframe</button>
  </div>
  <p class="hint">Alinea el overlay sobre el formulario real, desmarca la guía y reduce su opacidad. El iframe permanece visible al 100%; el formulario transparente queda por encima y recibe la interacción.</p>
  <p id="state">Preparando el iframe…</p>
  <div class="stage">
    <iframe id="target" title="Objetivo de la PoC"></iframe>
    <form id="decoy" class="decoy guides" autocomplete="off" action="about:blank">
      <div id="decoy-surface" class="decoy-surface">
        <h2>Acceso de demostración</h2>
        <p>Formulario ficticio colocado por encima del objetivo.</p>
        <label>Usuario ficticio <input id="demo-user" name="swh-demo-user" required autocomplete="off" data-lpignore="true"></label>
        <label>Contraseña ficticia <input id="demo-pass" name="swh-demo-pass" type="password" required autocomplete="new-password" data-lpignore="true"></label>
        <label><span><input id="show-pass" type="checkbox"> Mostrar contraseña de prueba</span></label>
        <button type="submit">Simular inicio de sesión</button>
      </div>
    </form>
  </div>
  <div id="capture">CAPTURA LOCAL DE DEMOSTRACIÓN\nUsuario: \nContraseña: \n\nNo se envía ni almacena información. No se envió información durante esta prueba.</div>
  <script>
    const targetUrl = {target_js};
    const frame = document.getElementById("target");
    const state = document.getElementById("state");
    const decoy = document.getElementById("decoy");
    const capture = document.getElementById("capture");
    const user = document.getElementById("demo-user");
    const pass = document.getElementById("demo-pass");
    const surface = document.getElementById("decoy-surface");
    frame.addEventListener("load", () => {{
      state.textContent = "El navegador emitió load. Confirma visualmente que el objetivo se renderizó; load no es concluyente.";
    }});
    frame.addEventListener("error", () => {{
      state.textContent = "El navegador informó un error. Revisa la consola para saber si X-Frame-Options o CSP bloquearon.";
    }});
    frame.src = targetUrl;
    document.getElementById("opacity").addEventListener("input", (event) => {{
      const value = Number(event.target.value);
      surface.style.opacity = String(value / 100);
      document.getElementById("opacity-value").textContent = value + "%";
    }});
    document.getElementById("left").addEventListener("input", (event) => {{ decoy.style.left = event.target.value + "%"; }});
    document.getElementById("top").addEventListener("input", (event) => {{ decoy.style.top = event.target.value + "%"; }});
    document.getElementById("width").addEventListener("input", (event) => {{
      decoy.style.width = event.target.value + "px";
      document.getElementById("width-value").textContent = event.target.value + " px";
    }});
    document.getElementById("guides").addEventListener("change", (event) => {{ decoy.classList.toggle("guides", event.target.checked); }});
    document.getElementById("reload").addEventListener("click", () => {{ frame.src = targetUrl; }});
    document.getElementById("center").addEventListener("click", () => {{
      decoy.style.left = "35%"; decoy.style.top = "32%"; decoy.style.width = "360px";
      document.getElementById("left").value = "35"; document.getElementById("top").value = "32";
      document.getElementById("width").value = "360"; document.getElementById("width-value").textContent = "360 px";
    }});
    document.getElementById("toggle").addEventListener("click", (event) => {{
      const hidden = decoy.hidden;
      decoy.hidden = !hidden;
      event.target.textContent = hidden ? "Ocultar formulario superpuesto" : "Mostrar formulario superpuesto";
    }});
    document.getElementById("show-pass").addEventListener("change", (event) => {{ pass.type = event.target.checked ? "text" : "password"; }});
    function updateCapture() {{
      capture.textContent = "CAPTURA LOCAL DE DEMOSTRACIÓN\\nUsuario: " + user.value + "\\nContraseña: " + pass.value +
        "\\n\\nNo se envía ni almacena información. No se envió información durante esta prueba.";
      capture.classList.toggle("danger", Boolean(user.value || pass.value));
    }}
    user.addEventListener("input", updateCapture);
    pass.addEventListener("input", updateCapture);
    decoy.addEventListener("submit", (event) => {{
      event.preventDefault();
      updateCapture();
      capture.textContent += "\\n\\nEnvío bloqueado deliberadamente por la PoC.";
    }});
    window.addEventListener("pagehide", () => {{ user.value = ""; pass.value = ""; }});
  </script>
</main></body></html>"""
        return content

    content = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PoC anti-framing — SafeWebHeaders</title>
  <style>
    body {{ margin:0; padding:24px; color:#e8edf2; background:#071018; font:15px/1.5 Segoe UI,Arial,sans-serif; }}
    main {{ max-width:1100px; margin:auto; }} code,pre {{ color:#b9ffe6; background:#0d1b25; }}
    pre {{ padding:14px; border:1px solid #29404f; border-radius:10px; white-space:pre-wrap; }}
    .notice {{ padding:14px; border-left:4px solid #ffc857; background:#171b1f; }}
    iframe {{ width:100%; height:620px; margin-top:16px; border:4px solid #ff5d73; background:white; }}
    #state {{ font-weight:700; color:#58c7f3; }}
  </style>
</head>
<body><main>
  <h1>PoC básica de framing</h1>
  <p><strong>Objetivo:</strong> <a href="{html_escape(target)}" target="_blank" rel="noopener noreferrer">{html_escape(target)}</a></p>
  <pre>X-Frame-Options: {html_escape(xfo)}
Content-Security-Policy frame-ancestors: {html_escape(frame_values)}</pre>
  <p class="notice"><strong>Cómo interpretar:</strong> si el navegador muestra la página dentro del marco,
  la protección no bloqueó este origen de prueba. Si muestra un error o un marco vacío, abre las herramientas
  de desarrollador: el navegador suele registrar si bloqueó por X-Frame-Options o CSP frame-ancestors.
  El evento <code>load</code> por sí solo no demuestra que el contenido haya sido renderizado.</p>
  <p id="state">Preparando el iframe…</p>
  <iframe id="target" title="Objetivo de la PoC"></iframe>
  <script>
    const target = {target_js};
    const frame = document.getElementById("target");
    const state = document.getElementById("state");
    frame.addEventListener("load", () => {{
      state.textContent = "El navegador emitió load. Verifica visualmente el contenido y la consola; este evento no es concluyente.";
    }});
    frame.addEventListener("error", () => {{
      state.textContent = "El navegador informó un error al cargar el iframe. Revisa la consola para identificar el control aplicado.";
    }});
    frame.src = target;
  </script>
</main></body></html>"""
    return content


def generate_cors_poc(
    report: ScanReport, directory: Path, configured_origin: str
) -> Path:
    path = next_available_path(directory, f"poc-cors-{poc_slug(report.final_url)}")
    return write_poc(
        path,
        build_cors_poc(
            report,
            configured_origin,
            serve_directory=directory,
            file_name=path.name,
        ),
    )


def build_cors_poc(
    report: ScanReport,
    configured_origin: str,
    *,
    serve_directory: Path | None = None,
    file_name: str = "poc-cors.html",
    served_url: str | None = None,
) -> str:
    """Devuelve el HTML de la PoC de CORS sin escribirlo en disco.

    ``served_url`` lo usa la GUI: la PoC ya se sirve desde el servidor local, de
    modo que el analista no necesita levantar un ``http.server`` aparte y el
    Origin real coincide con el que se usó en la sonda.
    """

    target = report.final_url
    target_js = javascript_literal(target)
    origin_js = javascript_literal(configured_origin)
    origin_parts = urlsplit(configured_origin)
    origin_port = origin_parts.port or (443 if origin_parts.scheme == "https" else 80)
    probe_headers = report.cors_probe_headers
    acao = " | ".join(probe_headers.get("access-control-allow-origin", []))
    acac = " | ".join(probe_headers.get("access-control-allow-credentials", []))
    vary = " | ".join(probe_headers.get("vary", []))
    probe_status = report.cors_probe_status_code
    if not acao:
        static_assessment = (
            "La sonda HTTP no recibió Access-Control-Allow-Origin para el Origin de prueba. "
            "El navegador normalmente bloqueará la lectura cross-origin."
        )
        static_class = "neutral"
    elif acao == configured_origin and acac == "true":
        static_assessment = (
            "El servidor autorizó exactamente el Origin de prueba y permitió credenciales. "
            "Confirma en el navegador si una respuesta autenticada y sensible puede leerse."
        )
        static_class = "warn"
    elif acao == configured_origin:
        static_assessment = (
            "El servidor autorizó exactamente el Origin de prueba sin habilitar credenciales. "
            "Puede permitir lectura de datos públicos o respuestas sin sesión."
        )
        static_class = "warn"
    elif acao == "*":
        static_assessment = (
            "El servidor permite lectura desde cualquier Origin sin credenciales. Los navegadores "
            "bloquean el comodín cuando fetch incluye credenciales."
        )
        static_class = "warn"
    else:
        static_assessment = (
            "La respuesta autorizó un Origin distinto al usado por esta PoC; el navegador "
            "normalmente bloqueará la lectura desde el Origin de prueba."
        )
        static_class = "neutral"
    if served_url is not None:
        serve_hint = (
            "Ya se está sirviendo desde el servidor local de SafeWebHeaders; "
            "no necesitas publicarla en otro sitio."
        )
        open_hint = served_url
    elif (
        serve_directory is not None
        and origin_parts.scheme == "http"
        and origin_parts.hostname in {"127.0.0.1", "localhost", "::1"}
    ):
        serve_hint = (
            f"python -m http.server {origin_port} --bind {origin_parts.hostname} "
            f'--directory "{serve_directory.resolve()}"'
        )
        open_hint = f"{configured_origin}/{file_name}"
    else:
        serve_hint = (
            "Publica este archivo en el servidor que controla el Origin indicado."
        )
        open_hint = f"{configured_origin}/{file_name}"
    content = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PoC CORS — SafeWebHeaders</title>
  <style>
    body {{ margin:0; padding:24px; color:#e8edf2; background:#071018; font:15px/1.5 Segoe UI,Arial,sans-serif; }}
    main {{ max-width:1050px; margin:auto; }} button {{ margin:6px 8px 6px 0; padding:10px 14px; cursor:pointer; }}
    pre {{ min-height:180px; padding:14px; overflow:auto; color:#b9ffe6; background:#0d1b25; border:1px solid #29404f; border-radius:10px; white-space:pre-wrap; }}
    .notice {{ padding:14px; border-left:4px solid #ffc857; background:#171b1f; }} .bad {{ color:#ff7b8d; font-weight:700; }}
    .probe {{ padding:14px; border:1px solid #29404f; border-left:5px solid #58c7f3; border-radius:10px; background:#0d1b25; }}
    .probe.warn {{ border-left-color:#ffc857; }} .probe.neutral {{ border-left-color:#58c7f3; }}
    #browser-verdict {{ padding:14px; border-left:4px solid #58c7f3; background:#0d1b25; font-weight:700; }}
  </style>
</head>
<body><main>
  <h1>PoC de lectura CORS</h1>
  <p><strong>Objetivo:</strong> <code>{html_escape(target)}</code></p>
  <p><strong>Origin usado por el escáner:</strong> <code>{html_escape(configured_origin)}</code></p>
  <p><strong>Servidor sugerido:</strong> <code>{html_escape(serve_hint)}</code></p>
  <p><strong>URL para abrir:</strong> <code>{html_escape(open_hint)}</code></p>
  <section class="probe {static_class}">
    <h2>1. Resultado de la sonda realizada por SafeWebHeaders</h2>
    <pre>HTTP: {html_escape(str(probe_status) if probe_status is not None else "No disponible")}
Access-Control-Allow-Origin: {html_escape(acao or "No encontrada")}
Access-Control-Allow-Credentials: {html_escape(acac or "No encontrada")}
Vary: {html_escape(vary or "No encontrada")}</pre>
    <p>{html_escape(static_assessment)}</p>
  </section>
  <h2>2. Confirmación en un navegador real</h2>
  <p id="origin-state" class="notice"></p>
  <button id="without">Probar lectura pública (sin credenciales)</button>
  <button id="with">Probar lectura autenticada (con cookies)</button>
  <p id="browser-verdict">Prueba del navegador pendiente.</p>
  <pre id="result">Sin ejecutar.</pre>
  <section class="probe neutral">
    <h2>3. Resultado esperado</h2>
    <ul>
      <li><strong>Lectura bloqueada:</strong> el navegador no entrega el cuerpo a JavaScript; revisa la consola para distinguir CORS de un fallo TLS, de red o autenticación.</li>
      <li><strong>Lectura sin credenciales:</strong> CORS permite leer la respuesta pública. Puede ser intencional y no demuestra exposición de información privada.</li>
      <li><strong>Lectura con credenciales:</strong> solo es un hallazgo explotable si la sesión viajó realmente y el cuerpo contiene datos sensibles que este Origin no debía leer.</li>
    </ul>
  </section>
  <p class="notice"><strong>Interpretación:</strong> “lectura permitida” confirma que JavaScript desde este Origin
  pudo leer la respuesta, pero no equivale por sí sola a una vulnerabilidad. Solo constituye un riesgo relevante
  si el endpoint entrega información que ese Origin
  no debería leer; para una prueba autenticada también deben viajar cookies válidas. “Bloqueada” suele indicar
  que CORS no autorizó la lectura, aunque un fallo TLS, de red o de autenticación puede producir el mismo mensaje.
  Esta página no exfiltra información: muestra el resultado localmente.</p>
  <script>
    const target = {target_js};
    const expectedOrigin = {origin_js};
    const state = document.getElementById("origin-state");
    const result = document.getElementById("result");
    const browserVerdict = document.getElementById("browser-verdict");
    const withoutButton = document.getElementById("without");
    const withButton = document.getElementById("with");
    const originMatches = location.origin === expectedOrigin;
    if (!originMatches) {{
      state.textContent = "Origin incorrecto: la página se está sirviendo desde " + location.origin +
        ", pero el escáner probó " + expectedOrigin + ". Sirve el archivo desde la URL indicada arriba.";
      withoutButton.disabled = true;
      withButton.disabled = true;
    }} else {{
      state.textContent = "Origin correcto. La petición del navegador será comparable con la prueba del escáner.";
    }}
    async function run(credentials) {{
      result.textContent = "Enviando petición…";
      browserVerdict.textContent = "Prueba en curso…";
      withoutButton.disabled = true;
      withButton.disabled = true;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 15000);
      try {{
        const response = await fetch(target, {{
          method:"GET", mode:"cors", credentials, cache:"no-store",
          redirect:"follow", signal:controller.signal
        }});
        const body = (await response.text()).slice(0, 200000);
        browserVerdict.textContent = credentials === "include"
          ? "LECTURA AUTENTICADA PERMITIDA (modo credenciales). Confirma en DevTools que viajaron cookies y revisa la sensibilidad del cuerpo."
          : "LECTURA SIN CREDENCIALES PERMITIDA. Esto puede ser intencional para contenido público.";
        result.textContent = "LECTURA PERMITIDA POR EL NAVEGADOR\\n" +
          "status=" + response.status + "\\n" +
          "final_url=" + response.url + "\\n" +
          "redirected=" + response.redirected + "\\n" +
          "content_type=" + (response.headers.get("content-type") || "no expuesto") + "\\n" +
          "credentials=" + credentials + "\\n" +
          "body_chars_shown=" + body.length + "\\n\\n" + body;
      }} catch (error) {{
        browserVerdict.textContent = error.name === "AbortError"
          ? "LECTURA NO CONFIRMADA. La petición superó 15 segundos."
          : "LECTURA NO CONFIRMADA. El navegador bloqueó CORS o la petición falló por otra causa; revisa la consola.";
        result.textContent = "LECTURA BLOQUEADA O PETICIÓN FALLIDA\\ncredentials=" + credentials + "\\n" + error;
      }} finally {{
        clearTimeout(timer);
        withoutButton.disabled = !originMatches;
        withButton.disabled = !originMatches;
      }}
    }}
    withoutButton.addEventListener("click", () => run("omit"));
    withButton.addEventListener("click", () => run("include"));
  </script>
</main></body></html>"""
    return content


def generate_csp_poc(report: ScanReport, directory: Path) -> Path:
    path = next_available_path(directory, f"poc-csp-{poc_slug(report.final_url)}")
    return write_poc(path, build_csp_poc(report))


def build_csp_poc(report: ScanReport) -> str:
    """Devuelve el HTML de la PoC de CSP sin escribirlo en disco."""

    target = report.final_url
    enforced = report.response_headers.get("content-security-policy", [])
    report_only = report.response_headers.get("content-security-policy-report-only", [])
    policy_rows = (
        "".join(
            f"<li><strong>CSP aplicada #{index}:</strong><pre>{html_escape(value)}</pre></li>"
            for index, value in enumerate(enforced, start=1)
        )
        or "<li><strong>No se recibió una CSP aplicada.</strong></li>"
    )
    policy_rows += "".join(
        f"<li><strong>CSP Report-Only #{index}:</strong><pre>{html_escape(value)}</pre></li>"
        for index, value in enumerate(report_only, start=1)
    )
    csp_details = [
        item
        for item in report.findings
        if item.category == "csp"
        and item.status in {"ausente", "incorrecta", "advertencia"}
    ]
    detail_rows = (
        "".join(
            "<li><strong>"
            + html_escape(item.title)
            + "</strong><br>"
            + html_escape(item.risk or item.evidence)
            + "</li>"
            for item in csp_details
        )
        or "<li>No se detectaron debilidades accionables mediante el análisis estático.</li>"
    )
    payloads = [
        (
            "Script inline",
            "<script>document.body.dataset.swh='inline-ejecutado'</script>",
        ),
        (
            "Manejador inline",
            "<img src=x onerror=\"document.body.dataset.swh='handler-ejecutado'\">",
        ),
        (
            "Eval",
            "<script>eval(\"document.body.dataset.swh='eval-ejecutado'\")</script>",
        ),
    ]
    payload_rows = "".join(
        f"<h3>{html_escape(label)}</h3><pre>{html_escape(payload)}</pre>"
        for label, payload in payloads
    )
    content = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kit de validación CSP — SafeWebHeaders</title>
<style>body{{margin:0;padding:24px;color:#e8edf2;background:#071018;font:15px/1.5 Segoe UI,Arial,sans-serif}}
main{{max-width:1050px;margin:auto}}pre{{padding:14px;color:#b9ffe6;background:#0d1b25;border:1px solid #29404f;border-radius:10px;white-space:pre-wrap;word-break:break-word}}
.notice{{padding:14px;border-left:4px solid #ffc857;background:#171b1f}}li{{margin-bottom:14px}}</style></head>
<body><main><h1>Kit de validación manual de CSP</h1>
<p><strong>Objetivo:</strong> <code>{html_escape(target)}</code></p>
<div class="notice"><strong>Alcance real:</strong> una política débil no demuestra XSS. Para convertir una
debilidad de CSP en una PoC explotable debe existir un punto de inyección compatible con la fuente permitida.
Los payloads siguientes no exfiltran datos y deben utilizarse únicamente en un punto de inyección autorizado.
No se copia la CSP a una etiqueta meta porque <code>frame-ancestors</code> no funciona desde meta y las fuentes
relativas cambiarían de significado en un archivo local.</div>
<h2>Políticas observadas</h2><ul>{policy_rows}</ul>
<h2>Observaciones estáticas</h2><ul>{detail_rows}</ul>
<h2>Payloads inocuos para un punto de inyección confirmado</h2>{payload_rows}
<p>Para comprobar <code>frame-ancestors</code> o X-Frame-Options en el navegador, genera además la PoC con
<code>--poc-frame</code>.</p></main></body></html>"""
    return content


def generate_requested_pocs(report: ScanReport, args: argparse.Namespace) -> list[Path]:
    if not (args.poc_frame or args.poc_frame_overlay or args.poc_cors or args.poc_csp):
        return []
    directory = prepare_poc_directory(args.poc_dir)
    generated: list[Path] = []
    if args.poc_frame:
        generated.append(generate_frame_poc(report, directory))
    if args.poc_frame_overlay:
        generated.append(generate_frame_poc(report, directory, interactive=True))
    if args.poc_cors:
        generated.append(generate_cors_poc(report, directory, args.poc_origin))
    if args.poc_csp:
        generated.append(generate_csp_poc(report, directory))
    for path in generated:
        report.notes.append(f"PoC HTML generada: {path}")
    return generated
