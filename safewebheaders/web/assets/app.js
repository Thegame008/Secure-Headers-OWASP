"use strict";

const state = {
  mode: "single",
  batch: null,
  selected: { type: "result", index: 0, section: "report-summary" },
};
const token = document.querySelector('meta[name="safewebheaders-token"]').content;
const form = document.getElementById("scan-form");
const statusBox = document.getElementById("status");
const resultsSection = document.getElementById("results");
const targetList = document.getElementById("target-list");
const reportView = document.getElementById("report-view");


/* ------------------------------------------------------------------ *
 * Tema claro / oscuro. La preferencia se guarda en el propio documento
 * y se sincroniza con prefers-color-scheme la primera vez.
 * ------------------------------------------------------------------ */
const themeButton = document.getElementById("theme-toggle");
const themeLabel = document.getElementById("theme-label");

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const dark = theme === "dark";
  themeButton.setAttribute("aria-checked", dark ? "true" : "false");
  themeLabel.textContent = dark ? "Oscuro" : "Claro";
}

applyTheme(window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark");
themeButton.addEventListener("click", () => {
  applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
});


/* ------------------------------------------------------------------ *
 * Cabeceras ocultables. Antes de escanear se sugieren desde el
 * catálogo del servidor; después del análisis se puede ocultar
 * cualquier cabecera del informe sin volver a escanear.
 * ------------------------------------------------------------------ */
const excludedInput = document.getElementById("excluded-headers");
const excludedDatalist = document.getElementById("excludable-headers");
const suggestionRow = document.getElementById("excluded-suggestions");
const QUICK_SUGGESTIONS = ["Server", "X-Powered-By", "X-AspNet-Version", "Set-Cookie", "X-XSS-Protection"];

function excludedNames() {
  return excludedInput.value
    .split(/[\s,;]+/)
    .map((name) => name.trim())
    .filter(Boolean);
}

function toggleExcluded(name) {
  const current = excludedNames();
  const lowered = current.map((item) => item.toLowerCase());
  const at = lowered.indexOf(name.toLowerCase());
  if (at >= 0) current.splice(at, 1);
  else current.push(name);
  excludedInput.value = current.join(", ");
  paintSuggestions();
}

function paintSuggestions() {
  const active = new Set(excludedNames().map((name) => name.toLowerCase()));
  suggestionRow.replaceChildren();
  QUICK_SUGGESTIONS.forEach((name) => {
    const chip = element("button", "suggestion-chip", name);
    chip.type = "button";
    chip.classList.toggle("active", active.has(name.toLowerCase()));
    chip.addEventListener("click", () => toggleExcluded(name));
    suggestionRow.append(chip);
  });
}

async function loadExcludableCatalog() {
  try {
    const response = await fetch("/api/health");
    const data = await response.json();
    (data.excludable_headers || []).forEach((name) => {
      const option = document.createElement("option");
      option.value = name;
      excludedDatalist.append(option);
    });
  } catch (_error) {
    // El autocompletado es un extra: su ausencia no impide escribir a mano.
  }
}

excludedInput.addEventListener("input", paintSuggestions);
paintSuggestions();
loadExcludableCatalog();

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function setStatus(type, message) {
  statusBox.hidden = false;
  statusBox.className = `status ${type}`;
  statusBox.replaceChildren();
  if (type === "loading") statusBox.append(element("span", "status-spinner"));
  statusBox.append(document.createTextNode(message));
}

function setMode(mode) {
  state.mode = mode;
  document.querySelectorAll(".mode-tab").forEach((tab) => {
    const active = tab.dataset.mode === mode;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", active ? "true" : "false");
  });
  document.querySelectorAll(".mode-panel").forEach((panel) => {
    const active = panel.dataset.panel === mode;
    panel.classList.toggle("active", active);
    panel.hidden = !active;
  });
  const isUrl = mode === "single" || mode === "batch";
  const isCsp = mode === "csp";
  document.querySelectorAll(".url-option").forEach((item) => { item.hidden = !isUrl; });
  document.querySelectorAll(".non-csp-option").forEach((item) => { item.hidden = isCsp; });
  document.getElementById("all-headers").closest("label").hidden = isCsp;
  syncScopeOptions();
  syncMethodOptions();
  statusBox.hidden = true;
}

document.querySelectorAll(".mode-tab").forEach((tab) => {
  tab.addEventListener("click", () => setMode(tab.dataset.mode));
});

function commonOptions() {
  return {
    follow_redirects: document.getElementById("follow-redirects").checked,
    all_headers: document.getElementById("all-headers").checked,
    evaluate_cookies: document.getElementById("evaluate-cookies").checked,
    reveal_sensitive: document.getElementById("reveal-sensitive").checked,
    use_environment: document.getElementById("use-environment").checked,
    insecure: document.getElementById("insecure").checked,
    method: document.getElementById("method").value,
    profile: document.getElementById("profile").value,
    timeout: Number(document.getElementById("timeout").value),
    request_body: document.getElementById("post-body").value,
    request_content_type: document.getElementById("post-content-type").value,
    excluded_headers: document.getElementById("excluded-headers").value,
    prepare_cors_poc: document.getElementById("prepare-cors-poc").checked,
    show_favicon: document.getElementById("show-favicon").checked,
  };
}

function syncScopeOptions() {
  const allHeaders = document.getElementById("all-headers").checked;
  const label = document.getElementById("all-headers").closest("label");
  label.title = allHeaders
    ? "Informe completo activado"
    : "Modo esencial predeterminado; las comprobaciones explícitas, como cookies, siguen disponibles";
}

document.getElementById("all-headers").addEventListener("change", syncScopeOptions);
syncScopeOptions();

const methodHelp = {
  GET: "GET obtiene la representación normal y permite detectar redirecciones HTML.",
  HEAD: "HEAD solicita únicamente metadatos; no permite revisar meta refresh ni contenido HTML.",
  OPTIONS: "OPTIONS consulta capacidades del endpoint; sus cabeceras pueden diferir de GET.",
  POST: "POST envía el cuerpo definido abajo y puede ejecutar lógica del servidor.",
};

const profileHelp = {
  auto: "Usa Content-Type para aplicar únicamente las reglas que corresponden.",
  web: "Fuerza reglas de documento HTML, incluso si Content-Type está mal declarado.",
  api: "Evita ausencias exclusivas del navegador en respuestas JSON o XML.",
};

function syncMethodOptions() {
  const method = document.getElementById("method").value;
  const isUrl = state.mode === "single" || state.mode === "batch";
  document.getElementById("post-options").hidden = !(isUrl && method === "POST");
  document.getElementById("method-help").textContent = methodHelp[method];
}

function syncProfileHelp() {
  const profile = document.getElementById("profile").value;
  document.getElementById("profile-help").textContent = profileHelp[profile];
}

document.getElementById("method").addEventListener("change", syncMethodOptions);
document.getElementById("profile").addEventListener("change", syncProfileHelp);
syncMethodOptions();
syncProfileHelp();

function requestPayload() {
  const options = commonOptions();
  if (state.mode === "single") {
    return { mode: "url", targets: document.getElementById("single-url").value, options };
  }
  if (state.mode === "batch") {
    return { mode: "url", targets: document.getElementById("batch-urls").value, options };
  }
  if (state.mode === "headers") {
    options.profile = document.getElementById("manual-profile").value;
    return {
      mode: "headers",
      evidence_url: document.getElementById("headers-url").value,
      raw_headers: document.getElementById("raw-headers").value,
      options,
    };
  }
  return {
    mode: "csp",
    evidence_url: document.getElementById("csp-url").value,
    csp_policy: document.getElementById("csp-policy").value,
    options,
  };
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const buttons = form.querySelectorAll('button[type="submit"]');
  buttons.forEach((button) => { button.disabled = true; });
  setStatus("loading", "Analizando. Las URL lentas o con redirecciones pueden tardar varios segundos…");
  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-SafeWebHeaders-Token": token },
      body: JSON.stringify(requestPayload()),
    });
    let data;
    try { data = await response.json(); } catch (_error) { data = { error: "Respuesta inválida del servidor local." }; }
    if (!response.ok) throw new Error(data.error || `Error HTTP ${response.status}`);
    state.batch = data;
    state.selected = data.results.length
      ? { type: "result", index: 0, section: "report-summary" }
      : { type: "error", index: 0, section: "" };
    renderBatch();
    const evaluated = data.results.length;
    const failed = data.errors.length;
    setStatus(failed ? "error" : "success", `Análisis terminado: ${evaluated} resultado(s), ${failed} error(es).`);
    resultsSection.hidden = false;
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    setStatus("error", error instanceof Error ? error.message : "No fue posible completar el análisis.");
  } finally {
    buttons.forEach((button) => { button.disabled = false; });
  }
});

function formatDate(value) {
  if (!value) return "No disponible";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString("es-CO", { hour12: false });
}

function formatMs(value) {
  const number = Number(value || 0);
  if (number < 1000) return `${number} ms`;
  return `${(number / 1000).toFixed(2)} s`;
}

function renderBatch() {
  const batch = state.batch;
  targetList.replaceChildren(element("p", "target-label", "OBJETIVOS"));
  const activeReport = state.selected.type === "result" ? batch.results[state.selected.index] : null;
  renderSectionNav(activeReport, state.selected.index);
  batch.results.forEach((report, index) => {
    const group = element("div", "target-group");
    const button = element("button", "target-item", null);
    button.type = "button";
    const active = state.selected.type === "result" && state.selected.index === index;
    button.classList.toggle("active", active);
    button.title = report.final_url;
    button.append(element("strong", "", report.final_url));
    button.append(element("small", "target-status", `${report.status_code || "LOCAL"} · ${report.summary.incorrectas + report.summary.ausentes} por revisar`));
    button.addEventListener("click", () => {
      state.selected = { type: "result", index, section: "report-summary" };
      renderBatch();
    });
    group.append(button);
    targetList.append(group);
  });
  batch.errors.forEach((failure, index) => {
    const button = element("button", "target-item error", null);
    button.type = "button";
    button.classList.toggle("active", state.selected.type === "error" && state.selected.index === index);
    button.title = failure.requested_url;
    button.append(element("strong", "", failure.requested_url));
    button.append(element("small", "target-status", "ERROR DE SOLICITUD"));
    button.addEventListener("click", () => { state.selected = { type: "error", index, section: "" }; renderBatch(); });
    targetList.append(button);
  });

  const batchSummary = document.getElementById("batch-summary");
  const total = batch.results.length + batch.errors.length;
  batchSummary.hidden = total <= 1;
  if (total > 1) {
    batchSummary.textContent = `${total} objetivo(s) · ${batch.results.length} evaluado(s) · ${batch.errors.length} con error`;
  }
  reportView.replaceChildren();
  if (state.selected.type === "result") renderReport(batch.results[state.selected.index], state.selected.index);
  else renderError(batch.errors[state.selected.index]);
}

function reportNavigation(report) {
  const categories = report.categories || [];
  const cookieCategory = categories.find((category) => category.key === "cookies");
  const headerCount = categories
    .filter((category) => category.key !== "cookies")
    .reduce((total, category) => total + category.findings.length, 0);
  const items = [{ id: "report-summary", label: "Resumen", icon: "◱", count: null }];
  items.push({ id: "report-headers", label: "Cabeceras", icon: "▤", count: headerCount });
  if (report.poc?.available) {
    items.push({ id: "report-poc", label: "Pruebas de concepto", icon: "◈", count: report.poc.kinds.length });
  }
  if (report.cookie_analysis_enabled || cookieCategory) {
    items.push({ id: "report-cookies", label: "Validador de cookies", icon: "◍", count: cookieCategory?.findings.length || 0 });
  }
  items.push({ id: "report-raw", label: "Vista RAW", icon: "⌗", count: report.raw_header_blocks?.length || 0 });
  if (report.navigation_count) items.push({ id: "report-redirects", label: "Redirecciones", icon: "↪", count: report.navigation_count });
  if (report.notes?.length) items.push({ id: "report-notes", label: "Notas", icon: "✎", count: report.notes.length });
  return items;
}

function renderSectionNav(report, index) {
  const nav = document.getElementById("section-nav");
  nav.replaceChildren();
  if (!report) return;
  reportNavigation(report).forEach((item) => {
    const link = element("button", "section-link");
    link.type = "button";
    link.classList.toggle("active", state.selected.section === item.id);
    link.append(element("span", "section-icon", item.icon));
    link.append(element("span", "section-name", item.label));
    if (item.count !== null) link.append(element("span", "section-count", item.count));
    link.addEventListener("click", () => {
      state.selected = { type: "result", index, section: item.id };
      renderBatch();
      requestAnimationFrame(() => document.getElementById(item.id)?.scrollIntoView({ behavior: "smooth", block: "start" }));
    });
    nav.append(link);
  });
}

function metric(label, value, tone) {
  const card = element("div", `metric ${tone}`);
  card.append(element("span", "", label), element("strong", "", value));
  return card;
}

function renderReport(report, index) {
  const summaryArea = element("section", "report-summary-area");
  summaryArea.id = "report-summary";
  const identity = element("div", "report-identity");
  const identityCopy = element("div", "identity-copy");
  const heading = element("h3", "");
  heading.append(faviconMark(report));
  heading.append(element("span", "identity-url", report.final_url));
  identityCopy.append(heading);
  identityCopy.append(element("p", "", `Solicitada: ${report.requested_url}`));
  const status = element("span", `status-pill ${report.status_code >= 400 ? "error" : ""}`, report.status_code ? `${report.status_code} ${report.reason || ""}` : "ANÁLISIS LOCAL");
  identity.append(identityCopy, status);
  summaryArea.append(identity);
  const inventory = renderInventory(report, index);
  if (inventory) summaryArea.append(inventory);

  const summary = report.summary;
  const metrics = element("div", "metrics");
  metrics.append(
    metric("Correctas", summary.correctas, "success"),
    metric("Ausentes", summary.ausentes, "absent"),
    metric("Incorrectas", summary.incorrectas, "incorrect"),
    metric("Cookies", summary.cookies, "cookies"),
    metric("Obsoletas", summary.obsoletas, "legacy"),
    metric("Divulgaciones", summary.divulgaciones, "recon"),
    metric("Informativas", summary.informativas, "info"),
  );
  summaryArea.append(metrics);

  const metadata = element("div", "metadata");
  const metadataValues = [
    ["Fecha y hora", formatDate(report.timestamp)],
    ["IP resueltas", report.resolved_ips?.join(", ") || "No disponible"],
    ["Duración", formatMs(report.elapsed_ms)],
    ["Perfil", profileLabel(report.profile)],
    ["Método", report.method],
    ["Validación TLS", report.tls_verification],
  ];
  metadataValues.forEach(([label, value]) => {
    const cell = element("div"); cell.append(element("span", "", label), element("strong", "", value)); metadata.append(cell);
  });
  summaryArea.append(metadata);
  reportView.append(summaryArea);

  if (report.navigation_count) renderRedirects(report);
  renderAnalysisAreas(report, index);
  if (report.poc?.available) renderPocArea(report);
  renderRaw(report);
  if (report.notes?.length) renderNotes(report.notes);
}

function hostInitial(report) {
  try { return new URL(report.final_url).hostname.replace(/^www\./, "").charAt(0).toUpperCase() || "?"; }
  catch (_error) { return "?"; }
}

function faviconMark(report) {
  // El servidor incrusta el icono como data: URI; el navegador nunca contacta
  // al sitio auditado desde esta interfaz.
  if (report.favicon && report.favicon.startsWith("data:image/")) {
    const wrapper = element("span", "site-favicon");
    const image = document.createElement("img");
    image.src = report.favicon;
    image.alt = "";
    image.loading = "lazy";
    wrapper.append(image);
    return wrapper;
  }
  return element("span", "site-favicon placeholder", hostInitial(report));
}

const INVENTORY_GROUPS = [
  ["ausentes", "Faltantes", "absent"],
  ["incorrectas", "Mal configuradas", "incorrect"],
  ["correctas", "Correctas", "success"],
  ["obsoletas", "Obsoletas", "legacy"],
  ["divulgacion", "Divulgan información", "recon"],
  ["cookies", "Cookies", "cookies"],
];

function renderInventory(report, index) {
  const inventory = report.header_inventory || {};
  const visible = {};
  Object.entries(inventory).forEach(([key, names]) => {
    visible[key] = names.filter((name) => !isHidden(index, name));
  });
  const groups = INVENTORY_GROUPS.filter(([key]) => (visible[key] || []).length);
  if (!groups.length) return null;
  const section = element("div", "header-inventory");
  section.append(element("p", "inventory-kicker", "INVENTARIO DE CABECERAS"));
  const grid = element("div", "inventory-grid");
  groups.forEach(([key, label, tone]) => {
    const column = element("div", `inventory-group ${tone}`);
    const names = visible[key];
    column.append(element("h5", "", `${label} (${names.length})`));
    const chips = element("div", "inventory-chips");
    names.forEach((name) => chips.append(element("span", "inventory-chip", name)));
    column.append(chips);
    grid.append(column);
  });
  section.append(grid);
  return section;
}

function profileLabel(profile) {
  return {
    auto: "Automático",
    web: "Página web / HTML",
    api: "API / JSON / XML",
    "csp-only": "Solo Content-Security-Policy",
  }[profile] || profile;
}

/* ------------------------------------------------------------------ *
 * Gráficas del área de cabeceras. Se dibujan con SVG generado en el
 * cliente: sin librerías externas y sin peticiones a la red.
 * ------------------------------------------------------------------ */
const CHART_TONES = {
  correctas: "success",
  ausentes: "absent",
  incorrectas: "incorrect",
  obsoletas: "legacy",
  divulgacion: "recon",
  cookies: "cookies",
};
const CHART_LABELS = {
  correctas: "Correctas",
  ausentes: "Faltantes",
  incorrectas: "Mal configuradas",
  obsoletas: "Obsoletas",
  divulgacion: "Divulgación",
  cookies: "Cookies",
};

function svgNode(name, attributes) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", name);
  Object.entries(attributes).forEach(([key, value]) => node.setAttribute(key, String(value)));
  return node;
}

function donutChart(slices, total) {
  const size = 168;
  const radius = 62;
  const thickness = 22;
  const svg = svgNode("svg", { viewBox: `0 0 ${size} ${size}`, class: "chart-donut", role: "img" });
  // Element.append() devuelve undefined: el título se construye aparte.
  const chartTitle = svgNode("title", {});
  chartTitle.textContent = `Distribución de ${total} hallazgos de cabeceras`;
  svg.append(chartTitle);
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  svg.append(svgNode("circle", {
    cx: size / 2, cy: size / 2, r: radius, fill: "none",
    "stroke-width": thickness, class: "chart-track",
  }));
  slices.forEach((slice) => {
    const length = (slice.value / total) * circumference;
    const arc = svgNode("circle", {
      cx: size / 2, cy: size / 2, r: radius, fill: "none",
      "stroke-width": thickness,
      "stroke-dasharray": `${length} ${circumference - length}`,
      "stroke-dashoffset": -offset,
      transform: `rotate(-90 ${size / 2} ${size / 2})`,
      class: `chart-arc tone-${slice.tone}`,
    });
    svg.append(arc);
    offset += length;
  });
  const value = svgNode("text", { x: size / 2, y: size / 2 - 2, class: "chart-center-value" });
  value.textContent = String(total);
  const caption = svgNode("text", { x: size / 2, y: size / 2 + 16, class: "chart-center-label" });
  caption.textContent = "hallazgos";
  svg.append(value, caption);
  return svg;
}

function barChart(slices, maximum) {
  const wrapper = element("div", "chart-bars");
  slices.forEach((slice) => {
    const row = element("div", "chart-bar-row");
    row.append(element("span", "chart-bar-label", slice.label));
    const track = element("div", "chart-bar-track");
    const fill = element("div", `chart-bar-fill tone-${slice.tone}`);
    fill.style.width = `${Math.max(3, (slice.value / maximum) * 100)}%`;
    track.append(fill);
    row.append(track, element("span", "chart-bar-value", slice.value));
    wrapper.append(row);
  });
  return wrapper;
}

function renderHeaderCharts(report, index) {
  const inventory = report.header_inventory || {};
  const slices = Object.keys(CHART_TONES)
    .map((key) => ({
      key,
      label: CHART_LABELS[key],
      tone: CHART_TONES[key],
      value: (inventory[key] || []).filter((name) => !isHidden(index, name)).length,
    }))
    .filter((slice) => slice.value > 0);
  if (!slices.length) return null;
  const total = slices.reduce((sum, slice) => sum + slice.value, 0);
  const maximum = Math.max(...slices.map((slice) => slice.value));
  const panel = element("div", "chart-panel");
  const donutBox = element("div", "chart-box");
  donutBox.append(element("h5", "", "Reparto de hallazgos"));
  donutBox.append(donutChart(slices, total));
  const legend = element("div", "chart-legend");
  slices.forEach((slice) => {
    const item = element("span", `chart-legend-item tone-${slice.tone}`);
    item.append(element("i", ""), document.createTextNode(`${slice.label} · ${slice.value}`));
    legend.append(item);
  });
  donutBox.append(legend);
  const barBox = element("div", "chart-box");
  barBox.append(element("h5", "", "Cabeceras por categoría"));
  barBox.append(barChart(slices, maximum));
  panel.append(donutBox, barBox);
  return panel;
}

/* Cabeceras ocultadas después del análisis. Es un filtro de vista: no
   altera el informe, ni la vista RAW, ni el JSON exportado. */
const hiddenByTarget = new Map();

function hiddenSet(index) {
  if (!hiddenByTarget.has(index)) hiddenByTarget.set(index, new Set());
  return hiddenByTarget.get(index);
}

function isHidden(index, header) {
  return hiddenSet(index).has(String(header || "").toLowerCase());
}

function visibleFindings(category, index) {
  return category.findings.filter((finding) => !isHidden(index, finding.header));
}

function reportHeaderNames(report) {
  const names = [];
  (report.categories || []).forEach((category) => {
    category.findings.forEach((finding) => {
      if (finding.header && !names.some((n) => n.toLowerCase() === finding.header.toLowerCase())) {
        names.push(finding.header);
      }
    });
  });
  return names.sort((a, b) => a.localeCompare(b));
}

function renderHideControls(report, index) {
  const names = reportHeaderNames(report);
  if (!names.length) return null;
  const box = element("details", "hide-controls");
  const hidden = hiddenSet(index);
  const summary = element("summary", "", `Ocultar cabeceras de esta vista${hidden.size ? ` (${hidden.size})` : ""}`);
  box.append(summary);
  box.append(element("p", "hide-note", "Filtro visual: no cambia el análisis, la vista RAW ni el JSON exportado. Para excluir una comprobación de la evidencia, usa «Ocultar cabeceras del informe» antes de escanear."));
  const chips = element("div", "hide-chips");
  names.forEach((name) => {
    const chip = element("button", "hide-chip", name);
    chip.type = "button";
    chip.setAttribute("aria-pressed", hidden.has(name.toLowerCase()) ? "true" : "false");
    chip.classList.toggle("active", hidden.has(name.toLowerCase()));
    chip.addEventListener("click", () => {
      const key = name.toLowerCase();
      if (hidden.has(key)) hidden.delete(key);
      else hidden.add(key);
      renderBatch();
    });
    chips.append(chip);
  });
  box.append(chips);
  if (hidden.size) {
    const reset = element("button", "secondary-button", "Mostrar todas");
    reset.type = "button";
    reset.addEventListener("click", () => { hidden.clear(); renderBatch(); });
    box.append(reset);
  }
  return box;
}


function renderAnalysisAreas(report, index) {
  const categories = report.categories || [];
  const headerCategories = categories.filter((category) => category.key !== "cookies");
  const cookieCategory = categories.find((category) => category.key === "cookies");

  const headers = element("section", "analysis-area headers-area");
  headers.id = "report-headers";
  headers.append(sectionHeading("Análisis de cabeceras HTTP", "Configuración, evidencia, riesgo y recomendación"));
  const controls = renderHideControls(report, index);
  if (controls) headers.append(controls);
  const charts = renderHeaderCharts(report, index);
  if (charts) headers.append(charts);
  const visibleCategories = headerCategories
    .map((category) => ({ ...category, findings: visibleFindings(category, index) }))
    .filter((category) => category.findings.length);
  if (visibleCategories.length) {
    visibleCategories.forEach((category) => headers.append(renderCategory(category)));
  } else {
    headers.append(element("p", "empty-analysis", headerCategories.length
      ? "Todas las cabeceras con hallazgos están ocultas en esta vista."
      : "No se generaron hallazgos de cabeceras para este alcance."));
  }
  reportView.append(headers);

  if (report.cookie_analysis_enabled || cookieCategory) {
    const cookies = element("section", "analysis-area cookies-area");
    cookies.id = "report-cookies";
    cookies.append(sectionHeading("Análisis independiente de cookies", "Atributos Secure, HttpOnly y SameSite de cada Set-Cookie"));
    const visibleCookies = cookieCategory
      ? { ...cookieCategory, findings: visibleFindings(cookieCategory, index) }
      : null;
    if (visibleCookies && visibleCookies.findings.length) cookies.append(renderCategory(visibleCookies));
    else cookies.append(element("p", "empty-analysis", cookieCategory
      ? "Las cookies con hallazgos están ocultas en esta vista."
      : "La comprobación fue solicitada, pero la respuesta no incluyó cabeceras Set-Cookie."));
    reportView.append(cookies);
  }
}

const POC_HINTS = {
  frame: "Genera una página que intenta enmarcar el objetivo en un iframe. Si el sitio se ve, X-Frame-Options y frame-ancestors no lo impiden.",
  "frame-overlay": "Añade un formulario señuelo superpuesto y controles de opacidad para demostrar clickjacking de forma visual.",
  cors: "Ejecuta fetch() contra el objetivo desde el Origin de esta interfaz, con y sin credenciales, y muestra si la respuesta puede leerse.",
  csp: "Resume las políticas CSP aplicadas y en modo reporte para adjuntarlas como evidencia.",
};

async function requestPoc(report, kind, button, output) {
  button.disabled = true;
  output.replaceChildren(element("span", "poc-pending", "Generando…"));
  try {
    const response = await fetch("/api/poc", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-SafeWebHeaders-Token": token },
      body: JSON.stringify({ poc_id: report.poc_id, kind }),
    });
    let data;
    try { data = await response.json(); } catch (_error) { data = { error: "Respuesta inválida del servidor local." }; }
    if (!response.ok) throw new Error(data.error || `Error HTTP ${response.status}`);
    output.replaceChildren();
    const open = element("a", "poc-link", "Abrir en pestaña nueva");
    open.href = data.url;
    open.target = "_blank";
    open.rel = "noopener noreferrer";
    const download = element("a", "poc-link secondary", "Descargar HTML");
    download.href = data.url;
    download.download = data.filename;
    output.append(open, download);
  } catch (error) {
    output.replaceChildren(element("span", "poc-error", error instanceof Error ? error.message : "No fue posible generar la PoC."));
  } finally {
    button.disabled = false;
  }
}

function renderPocArea(report) {
  const section = element("section", "analysis-area poc-area");
  section.id = "report-poc";
  section.append(sectionHeading("Pruebas de concepto locales", "Se generan y se sirven desde este equipo; no se publica nada en Internet"));
  const warning = element("p", "poc-warning", "[!] Ejecuta estas pruebas únicamente sobre objetivos para los que tengas autorización escrita.");
  section.append(warning);
  const grid = element("div", "poc-grid");
  report.poc.kinds.forEach((item) => {
    const card = element("div", `poc-card${item.enabled ? "" : " disabled"}`);
    card.append(element("h5", "", item.label));
    card.append(element("p", "", POC_HINTS[item.kind] || ""));
    const actions = element("div", "poc-actions");
    const button = element("button", "secondary-button", item.enabled ? "Generar PoC" : "No disponible");
    button.type = "button";
    button.disabled = !item.enabled;
    const output = element("div", "poc-output");
    if (!item.enabled && item.kind === "cors") {
      output.append(element("span", "poc-pending", "Marca «Preparar PoC de CORS» y vuelve a analizar la URL con GET."));
    }
    button.addEventListener("click", () => requestPoc(report, item.kind, button, output));
    actions.append(button);
    card.append(actions, output);
    grid.append(card);
  });
  section.append(grid);
  if (report.poc.cors_probe_origin) {
    section.append(element("p", "poc-note", `Sonda CORS ejecutada con Origin ${report.poc.cors_probe_origin}.`));
  }
  reportView.append(section);
}

function sectionHeading(title, note) {
  const wrapper = element("div", "report-section-heading");
  wrapper.append(element("h4", "", title));
  if (note) wrapper.append(element("p", "", note));
  return wrapper;
}

function renderRedirects(report) {
  const section = element("section", "report-section");
  section.id = "report-redirects";
  section.append(sectionHeading("Cadena de navegación", `${report.redirect_count} HTTP · ${report.client_redirect_count} HTML`));
  const list = element("div", "redirect-list");
  report.redirects.forEach((hop) => {
    const row = element("div", "redirect-hop");
    const type = hop.redirect_kind === "meta-refresh" ? "META" : hop.redirect_kind === "http" || hop.location ? "HTTP" : "FINAL";
    row.append(element("span", "redirect-type", type), element("span", "redirect-status", hop.status_code));
    const urls = element("div", "redirect-url", hop.url);
    if (hop.redirect_target || hop.location) urls.append(element("small", "", `Anunciado: ${hop.redirect_target || hop.location}`));
    if (hop.effective_redirect_target) urls.append(element("small", "", `Solicitado: ${hop.effective_redirect_target}`));
    row.append(urls); list.append(row);
  });
  section.append(list); reportView.append(section);
}

function statusTone(line) {
  const match = line.match(/^HTTP\/\S+\s+(\d{3})/i);
  if (!match) return "info";
  const status = Number(match[1]);
  if (status >= 400) return "status-risk";
  if (status >= 300) return "status-warning";
  return "status-success";
}

function renderRawLine(line, tones) {
  const row = element("div", "raw-line");
  if (/^HTTP\//i.test(line)) {
    row.classList.add(statusTone(line)); row.textContent = line; return row;
  }
  const separator = line.indexOf(":");
  if (separator < 1) { row.textContent = line; return row; }
  const name = line.slice(0, separator);
  const value = line.slice(separator + 1);
  const normalized = name.trim().toLowerCase();
  const tone = tones[normalized] || "info";
  if (["success", "warning", "legacy", "absent", "incorrect", "cookies", "recon"].includes(tone)) row.classList.add(tone);
  row.append(element("span", "raw-name", `${name}:`), element("span", "raw-value", value));
  return row;
}

function renderRaw(report) {
  const section = element("section", "report-section");
  section.id = "report-raw";
  section.append(sectionHeading("Cabeceras HTTP · vista RAW", "Reconstruida; no representa los bytes exactos del socket"));
  const shell = element("div", "raw-shell");
  const toolbar = element("div", "raw-toolbar");
  const dots = element("div", "terminal-dots"); dots.append(element("i"), element("i"), element("i"));
  toolbar.append(dots, element("span", "", `${report.raw_header_blocks.length} respuesta(s)`)); shell.append(toolbar);
  report.raw_header_blocks.forEach((block, index) => {
    const wrapper = element("div", "raw-block");
    wrapper.append(element("div", "raw-url", `RESPUESTA ${index + 1} · ${block.url}`));
    const lines = element("div", "raw-lines");
    block.text.split("\n").forEach((line) => lines.append(renderRawLine(line, report.header_tones || {})));
    wrapper.append(lines); shell.append(wrapper);
  });
  section.append(shell);
  const legend = element("div", "legend");
  [["success", "Correcta"], ["absent", "Ausente"], ["incorrect", "Incorrecta"], ["cookies", "Cookie"], ["legacy", "Obsoleta / heredada"], ["recon", "Divulgación"], ["info", "Contexto"]].forEach(([tone, label]) => legend.append(element("span", tone, label)));
  section.append(legend); reportView.append(section);
}

function findingField(label, value, code = false) {
  if (value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length)) return null;
  const wrapper = element("div", "finding-field");
  wrapper.append(element("dt", "", label));
  const definition = element("dd");
  if (code) definition.append(element("code", "", value)); else definition.textContent = value;
  wrapper.append(definition); return wrapper;
}

function cspPoliciesField(finding) {
  if (!finding.policies?.length) return null;
  const wrapper = element("div", "finding-field");
  wrapper.append(element("dt", "", finding.policies.length > 1 ? "Políticas aplicadas" : "Configuración actual"));
  const definition = element("dd", "csp-policies");
  if (finding.policy_context) definition.append(element("p", "csp-context", finding.policy_context));
  finding.policies.forEach((policy) => {
    const block = element("div", "csp-policy");
    if (finding.policies.length > 1) block.append(element("span", "csp-policy-label", `Política aplicada #${policy.index}`));
    const code = element("code");
    const markedPolicy = finding.policy_spans?.find((item) => item.index === policy.index);
    const spans = Array.isArray(markedPolicy?.spans) && markedPolicy.spans.length ? markedPolicy.spans : [{ text: policy.value, tone: "neutral" }];
    spans.forEach((span) => {
      const tone = span.tone === "bad" ? "csp-bad" : span.tone === "good" ? "csp-good" : "";
      code.append(element("span", tone, span.text));
    });
    block.append(code); definition.append(block);
  });
  wrapper.append(definition); return wrapper;
}

function referencesField(references) {
  if (!references?.length) return null;
  const wrapper = element("div", "finding-field"); wrapper.append(element("dt", "", "Referencias"));
  const definition = element("dd");
  references.forEach((reference, index) => {
    try {
      const parsed = new URL(reference);
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("scheme");
      const link = element("a", "", reference); link.href = parsed.href; link.target = "_blank"; link.rel = "noopener noreferrer"; definition.append(link);
    } catch (_error) { definition.append(document.createTextNode(reference)); }
    if (index < references.length - 1) definition.append(element("br"));
  });
  wrapper.append(definition); return wrapper;
}

function cspDetails(details) {
  if (!details?.length) return null;
  const wrapper = element("div", "csp-detail-list");
  const summary = element("ul", "csp-issue-summary");
  details.forEach((detail) => summary.append(element("li", "", `[!] ${detail.title}`)));
  wrapper.append(summary);
  details.forEach((detail) => {
    const card = element("div", "csp-detail"); card.append(element("strong", "", `[!] ${detail.title}`));
    const text = [detail.purpose && `Protección: ${detail.purpose}`, detail.evidence && `Evidencia: ${detail.evidence}`, detail.risk && `Riesgo: ${detail.risk}`, detail.recommendation && `Recomendación: ${detail.recommendation}`].filter(Boolean).join("\n");
    if (text) card.append(element("p", "", text)); wrapper.append(card);
  });
  return wrapper;
}

function renderCategory(category) {
  const safeKeys = new Set(["correctas", "ausentes", "incorrectas", "cookies", "obsoletas", "divulgacion", "informativas", "exclusiones"]);
  const key = safeKeys.has(category.key) ? category.key : "informativas";
  const section = element("section", `category ${key}`);
  const title = element("div", "category-title"); title.append(element("span", "", category.symbol), element("h4", "", `${category.label} (${category.findings.length})`)); section.append(title);
  category.findings.forEach((finding, index) => {
    const card = element("details", "finding-card"); card.open = index === 0 && category.findings.length === 1;
    const summary = element("summary", "finding-summary"); summary.append(element("strong", "", finding.header), element("span", "", finding.observation)); card.append(summary);
    const content = element("dl", "finding-content");
    [
      finding.policies?.length ? cspPoliciesField(finding) : findingField("Configuración actual", finding.current_value, true),
      findingField("Criterio", finding.criterion),
      findingField("Observación", finding.observation),
      findingField("Evidencia", finding.evidence, true),
      findingField("Riesgo", finding.risk),
      findingField("Recomendación", finding.recommendation),
      referencesField(finding.references),
    ].filter(Boolean).forEach((field) => content.append(field));
    const details = cspDetails(finding.details); if (details) { const wrap = element("div", "finding-field"); wrap.append(element("dt", "", "Hallazgos CSP"), element("dd")); wrap.lastChild.append(details); content.append(wrap); }
    card.append(content); section.append(card);
  });
  return section;
}

function renderNotes(notes) {
  const section = element("section", "important-notes");
  section.id = "report-notes";
  section.append(element("span", "important-label", "[!] IMPORTANTE"), element("h4", "", "Notas de la evaluación"));
  const list = element("ul"); notes.forEach((note) => list.append(element("li", "", note))); section.append(list); reportView.append(section);
}

function renderError(failure) {
  const panel = element("div", "error-panel");
  panel.append(element("h3", "", "No se pudo evaluar la URL"), element("p", "", failure.requested_url), element("p", "", failure.error));
  reportView.append(panel);
}

document.getElementById("download-json").addEventListener("click", () => {
  if (!state.batch) return;
  const blob = new Blob([`${JSON.stringify(state.batch, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a"); link.href = url; link.download = `safewebheaders-${new Date().toISOString().replace(/[:.]/g, "-")}.json`; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

document.getElementById("print-report").addEventListener("click", () => {
  document.querySelectorAll(".finding-card").forEach((card) => { card.open = true; });
  window.print();
});
