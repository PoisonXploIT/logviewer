/* ============================================================
   Visor de Logs Unificado - app.js (Fase 2)
   Modulos internos: api, theme, ui, filters, charts, table.
   Sesiones multi-archivo, cola de carga con progreso, compresion.
   Sin bundler: todo en este archivo, solo dependencias locales.
   ============================================================ */
"use strict";

/* ---------- api ---------- */
// Token anti-CSRF por proceso: lo pide el servidor en /api/csrf y viaja
// en el header X-CSRF-Token de todos los POST (sin el header, 403).
let csrfToken = "";
const csrfHeaders = () => ({ "X-CSRF-Token": csrfToken });

const api = {
  csrf: () => fetch("/api/csrf").then((r) => r.json()),
  summary: (name) =>
    fetch("/api/summary" + (name ? "?name=" + encodeURIComponent(name) : ""))
      .then((r) => r.json()),
  sessions: () => fetch("/api/sessions").then((r) => r.json()),
  progress: (name) =>
    fetch("/api/progress?name=" + encodeURIComponent(name)).then((r) => r.json()),
  activate: (name) =>
    fetch("/api/activate", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...csrfHeaders() },
      body: JSON.stringify({ name }),
    }).then((r) => r.json()),
  remove: (name) =>
    fetch("/api/remove", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...csrfHeaders() },
      body: JSON.stringify({ name }),
    }).then((r) => r.json()),
  rows: (params) => fetch("/api/rows?" + new URLSearchParams(params)).then((r) => r.json()),
  templates: (name, min, level) =>
    fetch("/api/templates?name=" + encodeURIComponent(name) +
      "&min=" + (min || 1)
      + (level ? "&level=" + encodeURIComponent(level) : ""))
      .then((r) => r.json()),
  histogram: (name, gran) =>
    fetch("/api/histogram?name=" + encodeURIComponent(name) +
      "&gran=" + (gran || "min"))
      .then((r) => r.json()),
  context: (params) =>
    fetch("/api/context?" + new URLSearchParams(params)).then((r) => r.json()),
  // Fase 10B: runbooks (errores conocidos)
  runbookMatch: (msg) =>
    fetch("/api/runbooks/match?msg=" + encodeURIComponent(msg || ""))
      .then((r) => r.json()),
  runbookCreate: (body) =>
    fetch("/api/runbooks", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...csrfHeaders() },
      body: JSON.stringify(body),
    }).then((r) => r.json()),
  runbookUpdate: (id, body) =>
    fetch("/api/runbooks?id=" + id, {
      method: "PUT",
      headers: { "Content-Type": "application/json", ...csrfHeaders() },
      body: JSON.stringify(body),
    }).then((r) => r.json()),
  runbookRemove: (id) =>
    fetch("/api/runbooks?id=" + id, {
      method: "DELETE",
      headers: csrfHeaders(),
    }).then((r) => r.json()),
  // Fase 12A: LLM local
  config: () => fetch("/api/config").then((r) => r.json()),
  settings: () => fetch("/api/settings").then((r) => r.json()),
  settingsSave: (data) =>
    fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...csrfHeaders() },
      body: JSON.stringify(data),
    }).then((r) => r.json()),
  analyze: (line) =>
    fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...csrfHeaders() },
      body: JSON.stringify({ line }),
    }).then((r) => r.json()),
  // Fase 12C: diagnostico rapido (LLM local resume las plantillas de error)
  diagnose: (name, level) =>
    fetch("/api/diagnose", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...csrfHeaders() },
      body: JSON.stringify({ name, level }),
    }).then((r) => r.json()),
  // Fase 13: ingesta desde Splunk local
  splunkSearch: (search, name, count) =>
    fetch("/api/splunk/search", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...csrfHeaders() },
      body: JSON.stringify({ search, name, count }),
    }).then((r) => r.json()),
  top: (field, limit, name) =>
    fetch("/api/top?field=" + field + "&limit=" + limit +
      (name ? "&name=" + encodeURIComponent(name) : ""))
      .then((r) => r.json()),
  exportUrl: (params) => "/api/export?" + new URLSearchParams(params),
  watch: (name, enabled) =>
    fetch("/api/watch", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...csrfHeaders() },
      body: JSON.stringify({ name, enabled }),
    }).then((r) => r.json()),
  tail: (name, last) =>
    fetch("/api/tail?name=" + encodeURIComponent(name) + "&last=" + last)
      .then((r) => r.json()),
  upload: (files) => {
    const fd = new FormData();
    files.forEach((f) => fd.append("file", f));
    return fetch("/upload", {
      method: "POST",
      headers: csrfHeaders(),
      body: fd,
    }).then((r) => r.json());
  },
};

/* ---------- theme ---------- */
const theme = {
  KEY: "lv-theme",
  get() {
    const saved = localStorage.getItem(this.KEY);
    if (saved === "dark" || saved === "light") return saved;
    return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  },
  apply(t) {
    document.documentElement.setAttribute("data-theme", t);
    localStorage.setItem(this.KEY, t);
    const u = document.querySelector("#theme-icon use");
    if (u) u.setAttribute("href", t === "dark" ? "#i-sun" : "#i-moon");
  },
  toggle() {
    this.apply(this.get() === "dark" ? "light" : "dark");
  },
};

/* ---------- ui ---------- */
const ui = {
  toastTimer: null,
  esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/'/g, "&#39;").replace(/"/g, "&quot;");
  },
  fmtNum(n) {
    return (n == null ? 0 : n).toLocaleString("es");
  },
  fmtBytes(n) {
    if (n == null) return "";
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + " MB";
    return (n / 1024 / 1024 / 1024).toFixed(2) + " GB";
  },
  toast(msg) {
    const t = document.getElementById("toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(this.toastTimer);
    this.toastTimer = setTimeout(() => t.classList.remove("show"), 2500);
  },
  status(state, text) {
    const pill = document.getElementById("status-pill");
    pill.dataset.state = state;
    document.getElementById("status-text").textContent = text;
  },
  async copy(text) {
    try {
      await navigator.clipboard.writeText(text);
      this.toast("Copiado al portapapeles");
    } catch (e) {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        this.toast("Copiado al portapapeles");
      } catch (e2) {
        this.toast("No se pudo copiar");
      }
      document.body.removeChild(ta);
    }
  },
};

/* ---------- estado de la app ---------- */
const app = {
  llmEnabled: false, // Fase 12A: lo pone /api/config al arrancar
  repoUrl: "",      // URL publica del repo (avisos de funciones SOLO local)
  fmt: "",
  name: "",
  size: 0,
  total: 0,
  page: 1,
  pageSize: 500,
  pageRows: [],
  filteredTotal: 0,
  templates: [],
  gran: "min",
  hist: [],
  top: {},
  sessions: [],
  active: "",
  encoding: "",
  compressed: "",
};

const SUPPORTED_EXTS = [".log", ".txt", ".csv", ".json",
                        ".gz", ".bz2", ".xz", ".zip"];
const MAX_FILE_SIZE = 500 * 1024 * 1024;

function extOf(name) {
  const i = name.lastIndexOf(".");
  return i >= 0 ? name.slice(i).toLowerCase() : "";
}

/* ---------- filters ---------- */
const filters = {
  state: { level: "", code: "", ip: "", path: "", q: "", dt: "",
           tpl: "", dtFrom: "", dtTo: "" },
  params() {
    const p = {};
    for (const [k, v] of Object.entries(this.state)) if (v) p[k] = v;
    // Los rangos viajan con nombre de servidor
    if (p.dtFrom) { p.dt_from = p.dtFrom; delete p.dtFrom; }
    if (p.dtTo) { p.dt_to = p.dtTo; delete p.dtTo; }
    return p;
  },
  activeCount() {
    return Object.values(this.state).filter((v) => v !== "").length;
  },
  syncInputs() {
    document.getElementById("fip").value = this.state.ip;
    document.getElementById("fpath").value = this.state.path;
    document.getElementById("fq").value = this.state.q;
    document.getElementById("fdt").value = this.state.dt;
    document.getElementById("ftpl").value = this.state.tpl;
    document.getElementById("fdfrom").value = this.state.dtFrom;
    document.getElementById("fdto").value = this.state.dtTo;
  },
  reset() {
    this.state = { level: "", code: "", ip: "", path: "", q: "", dt: "",
                   tpl: "", dtFrom: "", dtTo: "" };
    this.syncInputs();
    this.paintChips();
  },
  paintChips() {
    document.querySelectorAll("#lvchips .chip").forEach((c) =>
      c.classList.toggle("on", c.dataset.val === this.state.level));
    document.querySelectorAll("#codechips .chip").forEach((c) =>
      c.classList.toggle("on", c.dataset.val === this.state.code));
    const n = this.activeCount();
    const badge = document.getElementById("filters-count");
    badge.textContent = n + (n === 1 ? " activo" : " activos");
    badge.classList.toggle("hidden", n === 0);
  },
};

/* ---------- presets de filtros (Fase 5) ---------- */
const presets = {
  KEY: "lv-presets",
  list() {
    try {
      return JSON.parse(localStorage.getItem(this.KEY) || "[]");
    } catch (e) {
      return [];
    }
  },
  saveAll(items) {
    localStorage.setItem(this.KEY, JSON.stringify(items));
  },
  add(name, filterState) {
    const items = this.list();
    const i = items.findIndex((p) => p.name === name);
    const entry = { name, filters: filterState };
    if (i >= 0) items[i] = entry; else items.push(entry);
    this.saveAll(items);
  },
  remove(name) {
    this.saveAll(this.list().filter((p) => p.name !== name));
  },
};

function renderPresets() {
  const el = document.getElementById("presets");
  const items = presets.list();
  el.innerHTML = items.map((p) =>
    '<div class="preset-item" data-name="' + ui.esc(p.name) + '" '
    + 'role="button" tabindex="0" title="Aplicar preset">' +
    '<span class="preset-name">' + ui.esc(p.name) + "</span>" +
    '<button class="preset-remove" data-name="' + ui.esc(p.name) +
    '" title="Borrar preset" aria-label="Borrar preset ' + ui.esc(p.name) + '">' +
    '<svg class="icon"><use href="#i-x"></use></svg></button>' +
    "</div>"
  ).join("");
  el.querySelectorAll(".preset-item").forEach((item) => {
    const act = () => applyPreset(item.dataset.name);
    item.addEventListener("click", (e) => {
      if (e.target.closest(".preset-remove")) return;
      act();
    });
    item.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); act(); }
    });
  });
  el.querySelectorAll(".preset-remove").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      presets.remove(btn.dataset.name);
      renderPresets();
    });
  });
  document.getElementById("preset-save").disabled = !app.active;
}

function applyPreset(name) {
  const p = presets.list().find((x) => x.name === name);
  if (!p) return;
  filters.state = Object.assign(
    { level: "", code: "", ip: "", path: "", q: "", dt: "" },
    p.filters);
  filters.syncInputs();
  filters.paintChips();
  app.page = 1;
  renderRows();
  ui.toast("Preset aplicado: " + name);
}

function saveCurrentPreset() {
  if (!app.active) return;
  const def = "Preset " + (presets.list().length + 1);
  const name = prompt("Nombre del preset", def);
  if (!name || !name.trim()) return;
  presets.add(name.trim(), Object.assign({}, filters.state));
  renderPresets();
  ui.toast("Preset guardado: " + name.trim());
}

/* ---------- charts ---------- */
const charts = {
  registry: [],
  cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  },
  destroy() {
    this.registry.forEach((c) => c.destroy());
    this.registry = [];
  },
  bar(canvasId, data, onPick) {
    const el = document.getElementById(canvasId);
    if (!el) return;
    const c = new Chart(el, {
      type: "bar",
      data: {
        labels: data.map((x) => x[0]),
        datasets: [{ data: data.map((x) => x[1]) }],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        onClick: (evt, elements) => {
          if (!elements.length) return;
          onPick(data[elements[0].index][0]);
        },
        plugins: { legend: { display: false } },
        scales: {
          x: {
            ticks: { color: this.cssVar("--mut"), font: { size: 11 } },
            grid: { color: this.cssVar("--line-2") },
          },
          y: {
            ticks: { color: this.cssVar("--ink"), font: { size: 11 } },
            grid: { display: false },
          },
        },
      },
    });
    this.registry.push(c);
  },
  donut(canvasId, data, colorFn) {
    const el = document.getElementById(canvasId);
    if (!el) return;
    const c = new Chart(el, {
      type: "doughnut",
      data: {
        labels: data.map((x) => x[0]),
        datasets: [{
          data: data.map((x) => x[1]),
          backgroundColor: data.map((x) => colorFn(x[0])),
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "62%",
        plugins: {
          legend: {
            position: "right",
            labels: { color: this.cssVar("--mut"), boxWidth: 10, font: { size: 11 } },
          },
        },
      },
    });
    this.registry.push(c);
  },
};

function codeColor(code) {
  const n = parseInt(code, 10);
  if (isNaN(n)) return charts.cssVar("--mut");
  if (n < 300) return charts.cssVar("--ok");
  if (n < 400) return charts.cssVar("--warn");
  if (n < 500) return charts.cssVar("--bad");
  return charts.cssVar("--crit");
}

function levelColor(lv) {
  const map = {
    INF: "--ok", WRN: "--warn", ERR: "--bad", CRIT: "--crit", DBG: "--dbg", RAW: "--mut",
  };
  return charts.cssVar(map[lv] || "--mut");
}

/* ---------- KPIs ---------- */
function sparkHtml(vals) {
  if (!vals || !vals.length) return '<div class="spark" aria-hidden="true"></div>';
  const max = Math.max(...vals);
  return '<div class="spark" aria-hidden="true">' +
    vals.map((v) =>
      '<span style="height:' + Math.max(4, Math.round(v / max * 22)) + 'px"></span>'
    ).join("") + "</div>";
}

function renderKpis(s) {
  const cards = [
    { icon: "i-lines", label: "Líneas totales", value: s.total,
      spark: app.top.ips || app.top.levels || [] },
  ];
  if (s.ips != null)
    cards.push({ icon: "i-globe", label: "IPs únicas", value: s.ips, spark: app.top.ips || [] });
  if (s.paths != null)
    cards.push({ icon: "i-path", label: "Paths únicos", value: s.paths, spark: app.top.paths || [] });
  if (s.codes != null)
    cards.push({ icon: "i-badge", label: "Códigos HTTP", value: s.codes, spark: app.top.codes || [] });
  if (s.levels != null)
    cards.push({ icon: "i-layers", label: "Niveles", value: s.levels, spark: app.top.levels || [] });
  document.getElementById("kpis").innerHTML = cards.map((k) =>
    '<div class="kpi-card">' +
    '<div class="kpi-top"><svg class="icon"><use href="#' + k.icon + '"></use></svg>' +
    "<span>" + k.label + "</span></div>" +
    '<div class="kpi-value">' + ui.fmtNum(k.value) + "</div>" +
    sparkHtml(k.spark) +
    "</div>"
  ).join("");
}

/* ---------- segmentacion ---------- */
async function fetchTops(name) {
  app.top = {};
  if (app.fmt === "apache" || app.fmt === "w3c") {
    const [ips, paths, codes] = await Promise.all([
      api.top("ip", 30, name), api.top("path", 40, name), api.top("code", 100, name),
    ]);
    app.top.ips = ips.top;
    app.top.paths = paths.top;
    app.top.codes = codes.top;
  } else {
    const [lv, ips] = await Promise.all([
      api.top("level", 100, name), api.top("ip", 30, name),
    ]);
    app.top.levels = lv.top;
    app.top.ips = ips.top;
    if (app.fmt === "syslog") {
      const [hosts, apps] = await Promise.all([
        api.top("host", 30, name), api.top("app", 30, name),
      ]);
      app.top.hosts = hosts.top;
      app.top.apps = apps.top;
    }
  }
}

function segPanel(title, canvasId) {
  return '<div class="seg-panel"><h2>' + title + "</h2>" +
    '<div class="chart-box"><canvas id="' + canvasId + '"></canvas></div></div>';
}

function renderSeg() {
  charts.destroy();
  const seg = document.getElementById("seg");
  const panels = [];
  const pick = (field) => (val) => applyTopFilter(field, val);

  if (app.fmt === "apache" || app.fmt === "w3c") {
    if (app.top.ips && app.top.ips.length)
      panels.push([segPanel("Top IPs", "chart-ips"),
        () => charts.bar("chart-ips", app.top.ips, pick("ip"))]);
    if (app.top.paths && app.top.paths.length)
      panels.push([segPanel("Top Paths", "chart-paths"),
        () => charts.bar("chart-paths", app.top.paths, pick("path"))]);
    if (app.top.codes && app.top.codes.length)
      panels.push([segPanel("Códigos HTTP", "chart-codes"),
        () => charts.donut("chart-codes", app.top.codes, codeColor)]);
  } else {
    if (app.top.levels && app.top.levels.length)
      panels.push([segPanel("Niveles", "chart-levels"),
        () => charts.donut("chart-levels", app.top.levels, levelColor)]);
    if (app.top.ips && app.top.ips.length)
      panels.push([segPanel("Top IPs", "chart-ips"),
        () => charts.bar("chart-ips", app.top.ips, pick("ip"))]);
    if (app.fmt === "syslog") {
      if (app.top.hosts && app.top.hosts.length)
        panels.push([segPanel("Top Hosts", "chart-hosts"),
          () => charts.bar("chart-hosts", app.top.hosts, pick("host"))]);
      if (app.top.apps && app.top.apps.length)
        panels.push([segPanel("Top Apps", "chart-apps"),
          () => charts.bar("chart-apps", app.top.apps, pick("app"))]);
    }
  }

  seg.innerHTML = panels.map((p) => p[0]).join("");
  panels.forEach((p) => p[1]());
}

function applyTopFilter(field, val) {
  if (field === "ip") filters.state.ip = val;
  else if (field === "path") filters.state.path = val;
  else if (field === "code") filters.state.code = val;
  else if (field === "level") filters.state.level = val;
  else filters.state.q = val;
  filters.syncInputs();
  filters.paintChips();
  app.page = 1;
  renderRows();
}

/* ---------- chips ---------- */
function chipHtml(field, val, label) {
  return '<span class="chip" data-field="' + field + '" data-val="' +
    ui.esc(val) + '" role="button" tabindex="0">' + label + "</span>";
}

function renderLevelChips(top) {
  const order = ["INF", "WRN", "ERR", "CRIT", "DBG", "RAW"];
  const present = order.filter((l) => top.some((x) => x[0] === l));
  top.forEach((x) => { if (!present.includes(x[0])) present.push(x[0]); });
  const counts = {};
  top.forEach((x) => { counts[x[0]] = x[1]; });
  const el = document.getElementById("lvchips");
  el.innerHTML =
    chipHtml("level", "", "Todos") +
    present.map((l) =>
      chipHtml("level", l,
        '<span class="badge lv-' + ui.esc(l) + '">' + ui.esc(l) + "</span>" +
        '<span class="cnt">x' + ui.fmtNum(counts[l] || 0) + "</span>")
    ).join("");
  bindChips(el);
}

function renderCodeChips(top) {
  const el = document.getElementById("codechips");
  el.innerHTML =
    chipHtml("code", "", "Todos") +
    top.map((x) =>
      chipHtml("code", x[0],
        '<span class="badge ' + codeClass(x[0]) + '">' + ui.esc(x[0]) + "</span>" +
        '<span class="cnt">x' + ui.fmtNum(x[1]) + "</span>")
    ).join("");
  bindChips(el);
}

function codeClass(c) {
  const n = parseInt(c, 10);
  if (isNaN(n)) return "";
  if (n < 300) return "c2";
  if (n < 400) return "c3";
  if (n < 500) return "c4";
  return "c5";
}

function bindChips(container) {
  container.querySelectorAll(".chip").forEach((c) => {
    const act = () => {
      filters.state[c.dataset.field] = c.dataset.val;
      filters.paintChips();
      app.page = 1;
      renderRows();
    };
    c.addEventListener("click", act);
    c.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); act(); }
    });
  });
}

/* ---------- tabla ---------- */
function theadCols() {
  if (app.fmt === "apache" || app.fmt === "w3c")
    return ["ts", "ip", "method", "path", "code", "bytes"];
  if (app.fmt === "syslog")
    return ["ts", "host", "app", "pid", "msg"];
  return ["ts", "level", "msg"];
}

const MONO_COLS = ["ts", "ip", "path", "host", "app", "pid"];

function copyBtn(i, col) {
  return '<button class="copy-cell" data-idx="' + i + '" data-col="' + col + '" ' +
    'title="Copiar" aria-label="Copiar ' + col + '">' +
    '<svg class="icon"><use href="#i-copy"></use></svg></button>';
}

/* ---------- Fase 7C: resaltado seguro de terminos ---------- */
function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function hlTerms() {
  const p = filters.params();
  return [p.q, p.ip, p.path].filter((t) => t && String(t).trim());
}

// Escapa el texto y envuelve las coincidencias de los filtros activos
// (q/ip/path) en <mark>. El resaltado se hace sobre el texto original y
// cada trozo se escapa por separado: un "<script>" del log no se inyecta.
function hlText(s) {
  s = s == null ? "" : String(s);
  const terms = hlTerms().map(escapeRe);
  if (!terms.length) return ui.esc(s);
  const re = new RegExp("(" + terms.join("|") + ")", "gi");
  const parts = s.split(re);
  let out = "";
  for (let i = 0; i < parts.length; i++) {
    if (!parts[i]) continue;
    out += (i % 2 === 1)
      ? "<mark>" + ui.esc(parts[i]) + "</mark>"
      : ui.esc(parts[i]);
  }
  return out;
}

function rowHtml(r, i, cols) {
  return "<tr data-idx=\"" + i + "\">" + cols.map((c) => {
    if (c === "code" && r.code)
      return '<td><span class="badge ' + codeClass(r.code) + '">' +
        ui.esc(r.code) + "</span>" + copyBtn(i, "code") + "</td>";
    if (c === "level" && r.level)
      return '<td><span class="badge lv-' + ui.esc(r.level) + '">' +
        ui.esc(r.level) + "</span>" + copyBtn(i, "level") + "</td>";
    if (c === "msg")
      return '<td class="msg"><span class="celltext">' + hlText(r.msg) +
        "</span>" + copyBtn(i, "msg") + "</td>";
    const cls = MONO_COLS.includes(c) ? "lbl" : "";
    return '<td class="' + cls + '">' + hlText(r[c] || "") + copyBtn(i, c) +
      "</td>";
  }).join("") + "</tr>";
}

async function renderRows(opts) {
  const follow = !!(opts && opts.follow);
  // Si seguia el final (tail), mantenerse en la ultima pagina
  const wasLast = follow && app.filteredTotal > 0 &&
    app.page >= Math.max(1, Math.ceil(app.filteredTotal / app.pageSize));
  const params = Object.assign({}, filters.params(),
    { name: app.active, page: app.page, size: app.pageSize });
  document.getElementById("count").textContent = "Cargando...";
  try {
    let res = await api.rows(params);
    const pages0 = Math.max(1, Math.ceil(res.total / res.size));
    if (wasLast && res.page < pages0) {
      // Llegaron lineas nuevas: salta a la ultima pagina
      res = await api.rows(Object.assign({}, params, { page: pages0 }));
    }
    app.total = res.total;
    app.filteredTotal = res.total;
    app.page = res.page;
    app.pageRows = res.rows;
    const cols = theadCols();
    document.getElementById("thead").innerHTML =
      "<tr>" + cols.map((c) =>
        '<th class="' + (MONO_COLS.includes(c) ? "lbl" : "") + '">' +
        c.toUpperCase() + "</th>").join("") + "</tr>";
    document.getElementById("tbody").innerHTML =
      res.rows.map((r, i) => rowHtml(r, i, cols)).join("");
    const pages = Math.max(1, Math.ceil(res.total / res.size));
    document.getElementById("count").textContent =
      ui.fmtNum(res.total) + " filas";
    document.getElementById("pageinfo").textContent =
      ui.fmtNum(res.total) + " filas - página " + res.page + " de " + ui.fmtNum(pages);
    document.getElementById("prev").disabled = res.page <= 1;
    document.getElementById("next").disabled = res.page >= pages;
    renderHistogram();
  } catch (e) {
    document.getElementById("count").textContent = "Error: " + e.message;
  }
}

function ctxLineHtml(no, text, cur) {
  return '<div class="ctx-line' + (cur ? " cur" : "") + '">'
    + '<span class="ctx-no">' + no + "</span><span>"
    + hlText(text) + "</span></div>";
}

/* ---------- Fase 9B: Errores agrupados por plantilla ---------- */
async function renderTemplates() {
  if (!app.active) return;
  try {
    const res = await api.templates(app.active);
    app.templates = res.templates || [];
  } catch (e) {
    app.templates = [];
  }
  const badge = document.getElementById("tpl-count");
  if (!badge) return;
  badge.textContent = ui.fmtNum(app.templates.length) + " plantillas";
  badge.classList.remove("hidden");
  if (!document.getElementById("tpl-body").classList.contains("hidden")) {
    paintTemplates();
  }
}

function tplCell(t, max) {
  const s = t || "";
  return '<span class="celltext">' + ui.esc(s.length > max ? s.slice(0, max) : s) +
    (s.length > max ? "&hellip;" : "") + "</span>";
}

function paintTemplates() {
  const tb = document.getElementById("tpl-tbody");
  if (!tb) return;
  tb.innerHTML = app.templates.map((t, i) =>
    '<tr class="tpl-row" data-i="' + i + '" title="' + ui.esc(t.template) + '">'
    + "<td>" + ui.fmtNum(t.count) + "</td>"
    + '<td class="msg">' + tplCell(t.template, 120) + "</td>"
    + '<td class="lbl">' + ui.esc(t.first || "") + "</td>"
    + '<td class="lbl">' + ui.esc(t.last || "") + "</td>"
    + '<td class="msg">' + tplCell(t.example, 120) + "</td>"
    + "</tr>").join("");
  tb.querySelectorAll(".tpl-row").forEach((row) => {
    row.addEventListener("click", () => {
      const t = app.templates[parseInt(row.dataset.i, 10)];
      if (!t) return;
      filters.state.tpl = t.template;
      filters.syncInputs();
      filters.paintChips();
      app.page = 1;
      renderRows();
    });
  });
}

/* ---------- Fase 9C: histograma temporal ---------- */
async function renderHistogram() {
  if (!app.active) return;
  try {
    const res = await api.histogram(app.active, app.gran);
    app.hist = res.buckets || [];
  } catch (e) {
    app.hist = [];
  }
  drawHistogram();
}

function drawHistogram() {
  const cv = document.getElementById("hiscanvas");
  if (!cv) return;
  const W = Math.max(300, cv.parentElement.clientWidth - 2);
  const H = 90;
  const dpr = window.devicePixelRatio || 1;
  cv.width = W * dpr; cv.height = H * dpr;
  cv.style.width = W + "px"; cv.style.height = H + "px";
  const ctx = cv.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, H);
  const buckets = app.hist || [];
  if (!buckets.length) {
    ctx.fillStyle = getComputedStyle(document.body)
      .getPropertyValue("--muted") || "#888";
    ctx.font = "12px sans-serif";
    ctx.fillText("Sin datos con fecha", 10, H / 2);
    return;
  }
  const max = Math.max(...buckets.map((b) => b.count));
  const bw = W / buckets.length;
  ctx.fillStyle = getComputedStyle(document.body)
    .getPropertyValue("--acc") || "#4f8cff";
  ctx.globalAlpha = 0.9;
  buckets.forEach((b, i) => {
    const h = Math.max(2, (b.count / max) * (H - 8));
    ctx.fillRect(i * bw + 1, H - h, Math.max(1, bw - 2), h);
  });
  ctx.globalAlpha = 1;
}

function setGran(g) {
  app.gran = g;
  document.getElementById("gran-min")
    .classList.toggle("on", g === "min");
  document.getElementById("gran-hour")
    .classList.toggle("on", g === "h");
  renderHistogram();
}

// Convierte el inicio de un bucket en su rango cerrado [from, to].
// El to es el ultimo segundo del bucket para que barras adyacentas
// no se solapen (el filtro dt_to es inclusivo).
function histRange(t) {
  if (!t.match(/^(\d{4}-\d{2}-\d{2})T\d{2}(?::\d{2})?$/)) return null;
  // Ultimo segundo del bucket (min: HH:MM:59; hora: HH:59:59)
  const to = t.length === 16 ? t + ":59" : t + ":59:59";
  return { from: t, to };
}

function histClick(e) {
  const cv = e.currentTarget;
  const n = app.hist.length;
  if (!n) return;
  const rect = cv.getBoundingClientRect();
  const x = e.clientX - rect.left;
  const bw = rect.width / n;
  const i = Math.min(n - 1, Math.max(0, Math.floor(x / bw)));
  const r = histRange(app.hist[i].t);
  if (!r) return;
  filters.state.dtFrom = r.from;
  filters.state.dtTo = r.to;
  filters.syncInputs();
  app.page = 1;
  renderRows();
}

/* ---------- drawer ---------- */
const drawer = {
  KV_FIELDS: [
    ["ts", "Fecha"], ["level", "Nivel"], ["ip", "IP"], ["host", "Host"],
    ["app", "App"], ["pid", "PID"], ["method", "Método"], ["path", "Path"],
    ["code", "Código"], ["bytes", "Bytes"], ["msg", "Mensaje"],
  ],
  get closed() {
    return !document.getElementById("drawer").classList.contains("open");
  },
  open(row) {
    document.getElementById("drawer-kv").innerHTML =
      this.KV_FIELDS
        .filter(([k]) => row[k] !== undefined && row[k] !== "")
        .map(([k, label]) =>
          "<tr><th>" + label + "</th><td>" + ui.esc(row[k]) + "</td></tr>")
        .join("");
    // Fase 7C: raw con escape + resaltado de los terminos activos
    document.getElementById("drawer-raw").innerHTML = hlText(row.raw || "");
    this._setCtxAvailability(row);
    renderDrawerRunbooks(row); // Fase 10B: errores conocidos
    this.anRow = row;          // Fase 12A: fila que mandara "Analizar"
    this._resetAnalyze();     // limpiar el resultado anterior
    const el = document.getElementById("drawer");
    el.classList.add("open");
    el.setAttribute("aria-hidden", "false");
    document.getElementById("drawer-backdrop").classList.remove("hidden");
  },
  close() {
    const el = document.getElementById("drawer");
    el.classList.remove("open");
    el.setAttribute("aria-hidden", "true");
    document.getElementById("drawer-backdrop").classList.add("hidden");
  },
  _setCtxAvailability(row) {
    // Fase 7B: solo se ofrece contexto si la fila expone su rowid
    // (Fase 13: un dataset de Splunk no tiene archivo original)
    const btn = document.getElementById("drawer-ctx-btn");
    const pre = document.getElementById("drawer-ctx");
    if (app.fmt !== "splunk" &&
        row && row.rowid !== undefined && row.rowid >= 0) {
      this.ctxRow = row;
      btn.classList.remove("hidden");
    } else {
      this.ctxRow = null;
      btn.classList.add("hidden");
    }
    pre.hidden = true;
  },
  _resetAnalyze() {
    // Fase 12A: la seccion LLM del drawer. Con llm:true, boton Analizar;
    // con llm:false, aviso de funcion SOLO local (visible siempre)
    const wrap = document.getElementById("anwrap");
    const res = document.getElementById("an-result");
    wrap.hidden = false;
    applyAnLocalNote();
    res.hidden = true;
    res.textContent = "";
  },
};

async function showDrawerContext() {
  const btn = document.getElementById("drawer-ctx-btn");
  const pre = document.getElementById("drawer-ctx");
  if (!drawer.ctxRow) return;
  btn.disabled = true;
  pre.textContent = "Cargando contexto...";
  pre.hidden = false;
  try {
    const res = await api.context({
      name: app.active,
      row: drawer.ctxRow.rowid,
      n: 5,
    });
    let no = res.line - res.before.length;
    let html = "";
    for (const t of res.before) html += ctxLineHtml(no++, t, false);
    html += ctxLineHtml(no++, res.current, true);
    for (const t of res.after) html += ctxLineHtml(no++, t, false);
    pre.innerHTML = html;
  } catch (e) {
    pre.textContent = "Error: " + e.message;
  } finally {
    btn.disabled = false;
  }
}

/* ---------- Fase 10B: runbooks (errores conocidos) ---------- */
let rbModalId = null; // id del runbook en edicion; null = alta nueva

function rbCardHtml(rb) {
  const bits = [];
  if (rb.explicacion) bits.push(
    "<div><b>Que es:</b> " + ui.esc(rb.explicacion) + "</div>");
  if (rb.causa) bits.push(
    "<div><b>Causa probable:</b> " + ui.esc(rb.causa) + "</div>");
  if (rb.solucion) bits.push(
    "<div><b>Solucion:</b> " + ui.esc(rb.solucion) + "</div>");
  if (rb.ref) bits.push(
    '<div class="rb-ref"><b>Referencia interna:</b> ' +
    ui.esc(rb.ref) + "</div>");
  return '<div class="rb-card" data-id="' + rb.id + '">' +
    '<code class="rb-pattern">' + ui.esc(rb.pattern) + "</code>" +
    '<span class="rb-kind">' + ui.esc(rb.kind) + "</span>" +
    bits.join("") +
    '<div class="rb-actions">' +
    '<button class="btn tiny rb-edit" data-id="' + rb.id + '">Editar</button> ' +
    '<button class="btn tiny ghost rb-del" data-id="' + rb.id +
    '">Borrar</button>' +
    "</div></div>";
}

async function renderDrawerRunbooks(row) {
  const list = document.getElementById("rb-list");
  const count = document.getElementById("rb-count");
  if (!row) { drawer.rbRow = null; list.innerHTML = ""; return; }
  drawer.rbRow = row;
  count.textContent = "Errores conocidos: cargando...";
  list.innerHTML = "";
  try {
    const res = await api.runbookMatch(row.msg || "");
    if (res.error) throw new Error(res.error);
    const ms = res.matches || [];
    drawer.rbMatches = ms;
    count.textContent = "Errores conocidos: " + ms.length;
    list.innerHTML = ms.map(rbCardHtml).join("") ||
      '<p class="rb-empty">Sin errores conocidos para esta línea.</p>';
  } catch (e) {
    count.textContent = "Errores conocidos";
    list.innerHTML = '<p class="rb-empty">Error: ' + ui.esc(e.message) +
      "</p>";
  }
}

function openRbModal(rb, presetPattern) {
  const setVal = (id, v) => {
    document.getElementById(id).value = v || "";
  };
  if (rb) {
    rbModalId = rb.id;
    document.getElementById("rb-modal-title").textContent =
      "Editar runbook";
    setVal("rbf-pattern", rb.pattern);
    setVal("rbf-kind", rb.kind);
    setVal("rbf-explicacion", rb.explicacion);
    setVal("rbf-causa", rb.causa);
    setVal("rbf-solucion", rb.solucion);
    setVal("rbf-ref", rb.ref);
  } else {
    rbModalId = null;
    document.getElementById("rb-modal-title").textContent =
      "Nuevo runbook";
    // Alta desde la linea: patron prellenado con la plantilla (glob)
    setVal("rbf-pattern", presetPattern || "");
    setVal("rbf-kind", presetPattern ? "glob" : "regex");
    setVal("rbf-explicacion", "");
    setVal("rbf-causa", "");
    setVal("rbf-solucion", "");
    setVal("rbf-ref", "");
  }
  document.getElementById("rb-modal").classList.remove("hidden");
}

function closeRbModal() {
  document.getElementById("rb-modal").classList.add("hidden");
}

async function saveRbModal() {
  const body = {
    pattern: document.getElementById("rbf-pattern").value.trim(),
    kind: document.getElementById("rbf-kind").value,
    explicacion: document.getElementById("rbf-explicacion").value.trim(),
    causa: document.getElementById("rbf-causa").value.trim(),
    solucion: document.getElementById("rbf-solucion").value.trim(),
    ref: document.getElementById("rbf-ref").value.trim(),
  };
  if (!body.pattern) { ui.toast("Falta el patron"); return; }
  const btn = document.getElementById("rb-save");
  btn.disabled = true;
  try {
    const res = rbModalId
      ? await api.runbookUpdate(rbModalId, body)
      : await api.runbookCreate(body);
    if (res && res.error) throw new Error(res.error);
    closeRbModal();
    ui.toast("Runbook guardado");
    renderDrawerRunbooks(drawer.rbRow);
  } catch (e) {
    ui.toast("Error: " + e.message);
  } finally {
    btn.disabled = false;
  }
}

/* ---------- Ajustes del LLM local (config editable desde la UI) ---------- */
async function openLlmModal() {
  const setVal = (id, v) => {
    document.getElementById(id).value = (v === undefined || v === null) ? "" : v;
  };
  try {
    const s = await api.settings();
    setVal("llmf-url", s.url || "");
    setVal("llmf-model", s.model || "local");
    setVal("llmf-timeout", s.timeout || 45);
    setVal("llmf-lang", s.lang || "auto");
  } catch (e) {
    setVal("llmf-url", "");
    setVal("llmf-model", "local");
    setVal("llmf-timeout", 45);
    setVal("llmf-lang", "auto");
  }
  document.getElementById("llm-modal").classList.remove("hidden");
}

function closeLlmModal() {
  document.getElementById("llm-modal").classList.add("hidden");
}

async function saveLlmModal() {
  const btn = document.getElementById("llm-save");
  btn.disabled = true;
  try {
    const body = {
      url: document.getElementById("llmf-url").value.trim(),
      model: document.getElementById("llmf-model").value.trim(),
      timeout: parseInt(document.getElementById("llmf-timeout").value, 10),
      lang: document.getElementById("llmf-lang").value,
    };
    const res = await api.settingsSave(body);
    if (res && res.error) throw new Error(res.error);
    app.llmEnabled = !!res.llm;
    setDiagnoseVisible(app.llmEnabled);
    drawer._resetAnalyze();
    closeLlmModal();
    ui.toast("Ajustes del LLM guardados");
  } catch (e) {
    ui.toast("Error: " + e.message);
  } finally {
    btn.disabled = false;
  }
}

/* ---------- Fase 12A: analisis con LLM local ---------- */
/* Fase 12A: aviso de version sin LLM local (llm:false) en el drawer.
   Con llm:true, boton Analizar y sin aviso; con llm:false, aviso
   legible de funcion SOLO local, siempre visible al abrir una fila,
   con enlace a la version local si /api/config da repo_url. */
function applyAnLocalNote() {
  const note = document.getElementById("an-local-note");
  const btn = document.getElementById("an-btn");
  if (app.llmEnabled) {
    note.hidden = true;
    btn.hidden = false;
  } else {
    note.hidden = false;
    btn.hidden = true;
    const line = document.getElementById("an-repo-line");
    const a = document.getElementById("an-repo-link");
    if (app.repoUrl) {
      a.href = app.repoUrl;
      a.textContent = app.repoUrl;
      line.classList.remove("hidden");
    } else {
      line.classList.add("hidden");
    }
  }
}

async function runAnalyze() {
  const btn = document.getElementById("an-btn");
  const res = document.getElementById("an-result");
  if (!drawer.anRow) return;
  btn.disabled = true;
  res.hidden = false;
  res.textContent = "Preguntando al LLM local...";
  try {
    const r = await api.analyze(drawer.anRow.raw || "");
    if (r.error) throw new Error(r.error);
    res.textContent = (r.cached ? "[cache] \n\n" : "") + r.answer;
  } catch (e) {
    // Nunca se pinta un exito con explicacion vacia: el error se muestra
    // tal cual (el servidor ya lo envia amigable y sin content vacio)
    res.textContent = "Error: " + e.message;
  } finally {
    btn.disabled = false;
  }
}

/* ---------- Fase 13: ingesta desde Splunk local ---------- */
function setSplunkVisible(v) {
  // La seccion SIEMPRE es visible: con splunk:true la caja SPL; con
  // splunk:false el aviso del operador (sin caja de texto ni boton)
  document.getElementById("splunk-wrap").classList.remove("hidden");
  document.getElementById("splunk-local-note")
    .classList.toggle("hidden", !!v);
  const ta = document.getElementById("splunk-spl");
  const go = document.getElementById("splunk-go");
  ta.classList.toggle("hidden", !v);
  go.classList.toggle("hidden", !v);
}

async function runSplunkImport() {
  const spl = document.getElementById("splunk-spl").value.trim();
  if (!spl) { ui.toast("Pega primero una query SPL"); return; }
  const btn = document.getElementById("splunk-go");
  const status = document.getElementById("splunk-status");
  btn.disabled = true;
  status.textContent = "Consultando Splunk local...";
  try {
    const r = await api.splunkSearch(spl, "", 1000);
    if (r.error) throw new Error(r.error);
    status.textContent = ui.fmtNum(r.rows) + " filas cargadas";
    ui.toast("Splunk: " + ui.fmtNum(r.rows) + " filas en \"" + r.name + "\"");
    // Deja la sesion activa con la maquinaria normal (filtros, export,
    // diagnostico rapido)
    await refreshSessions();
    await loadDashboard(r.name);
  } catch (e) {
    status.textContent = "Error: " + e.message;
    ui.toast("Error Splunk: " + e.message);
  } finally {
    btn.disabled = false;
  }
}

/* ---------- Fase 12C: diagnostico rapido (LLM local, plantillas ERR) ---------- */
function setDiagnoseVisible(v) {
  document.getElementById("act-diagnose")
    .classList.toggle("hidden", !v);
}

async function runDiagnose() {
  if (!app.name) { ui.toast("No hay dataset activo"); return; }
  const modal = document.getElementById("diag-modal");
  const status = document.getElementById("diag-status");
  const concl = document.getElementById("diag-conclusion");
  const topEl = document.getElementById("diag-top");
  // Re-inicio del panel (si se reabre con un analisis anterior pintado)
  concl.classList.add("hidden");
  topEl.classList.add("hidden");
  topEl.innerHTML = "";
  status.textContent = "Recogiendo plantillas de error...";
  modal.classList.remove("hidden");
  const btn = document.getElementById("act-diagnose");
  btn.disabled = true;
  let n = 0;
  try {
    // Mismo computo que hara el servidor: para poder decir "N plantillas"
    const t = await api.templates(app.name, 1, "ERR");
    n = t.total || 0;
  } catch (e) { /* sin recuento: sigue sin el numero */ }
  status.textContent = ("Analizando " + ui.fmtNum(n) +
                        " plantillas... (el LLM local puede tardar)");
  try {
    const r = await api.diagnose(app.name, "ERR");
    if (r.error) throw new Error(r.error);
    status.textContent = ((r.cached ? "[cache] " : "") +
                          "Analizadas " + ui.fmtNum(r.analyzed) +
                          " plantillas. Conclusion:");
    concl.textContent = r.conclusion || "";
    concl.classList.remove("hidden");
    for (const t of r.top || []) {
      const li = document.createElement("li");
      li.innerHTML = ("<span class=\"diag-count\">"
                      + ui.fmtNum(t.count) + "</span>"
                      + "<code class=\"diag-tpl\">" + ui.esc(t.template)
                      + "</code><div class=\"diag-ex\">" + ui.esc(t.linea)
                      + "</div>");
      topEl.appendChild(li);
    }
    topEl.classList.remove("hidden");
  } catch (e) {
    status.textContent = "Error: " + e.message;
  } finally {
    btn.disabled = false;
  }
}

async function delRb(id) {
  if (!confirm("Borrar este runbook?")) return;
  try {
    const res = await api.runbookRemove(id);
    if (res && res.error) throw new Error(res.error);
    ui.toast("Runbook borrado");
    renderDrawerRunbooks(drawer.rbRow);
  } catch (e) {
    ui.toast("Error: " + e.message);
  }
}

/* ---------- sesiones ---------- */
async function refreshSessions() {
  const res = await api.sessions();
  app.sessions = res.sessions;
  app.active = res.active;
  renderSessions();
}

function sessionMeta(s) {
  const bits = [s.format];
  bits.push(ui.fmtNum(s.total) + " líneas");
  if (s.encoding) bits.push(s.encoding);
  if (s.compressed) bits.push(s.compressed);
  return bits.join(" · ");
}

function renderSessions() {
  const el = document.getElementById("sessions");
  el.innerHTML = app.sessions.map((s) =>
    '<div class="session-item' + (s.active ? " active" : "") +
    '" data-name="' + ui.esc(s.name) + '">' +
    '<div class="s-name"><span>' + ui.esc(s.name) + "</span>" +
    '<button class="session-remove" data-name="' + ui.esc(s.name) +
    '" title="Quitar de la sesion" aria-label="Quitar ' + ui.esc(s.name) + '">' +
    '<svg class="icon"><use href="#i-x"></use></svg></button></div>' +
    '<div class="s-meta">' + ui.esc(sessionMeta(s)) + "</div>" +
    "</div>"
  ).join("");
  el.querySelectorAll(".session-item").forEach((item) => {
    item.addEventListener("click", (e) => {
      if (e.target.closest(".session-remove")) return;
      switchSession(item.dataset.name);
    });
  });
  el.querySelectorAll(".session-remove").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      removeSession(btn.dataset.name);
    });
  });
}

async function switchSession(name) {
  if (name === app.active) return;
  if (tail.on()) {
    try { await api.watch(app.active, false); } catch (e) { /* */ }
    tail.stop();
  }
  try {
    const res = await api.activate(name);
    app.sessions = res.sessions;
    app.active = res.active;
    renderSessions();
    await loadDashboard(name);
  } catch (e) {
    ui.toast("Error: " + e.message);
  }
}

async function removeSession(name) {
  const wasActive = app.active === name;
  if (tail.on() && tail.name === name) {
    tail.stop();
  }
  try {
    await api.remove(name);
    await refreshSessions();
    if (wasActive) {
      if (app.active && app.sessions.length) {
        await loadDashboard(app.active);
      } else {
        clearView();
      }
    }
    ui.toast("Quitado: " + name);
  } catch (e) {
    ui.toast("Error: " + e.message);
  }
}

/* ---------- progreso ---------- */
function progressItem(name, phase, pct, message) {
  const isErr = phase === "error";
  return '<div class="progress-item' + (isErr ? " error" : "") +
    '" id="prog-' + ui.esc(name) + '">' +
    '<div class="p-name"><span>' + ui.esc(name) + "</span>" +
    '<span class="p-pct">' + (isErr ? "error" : pct + "%") + "</span></div>" +
    '<div class="progress-bar"><div class="fill" style="width:' +
    (isErr ? 100 : pct) + '%"></div></div>' +
    (isErr ? '<div class="s-meta">' + ui.esc(message) + "</div>" : "") +
    "</div>";
}

function updateProgressUI(name, p) {
  const el = document.getElementById("prog-" + name);
  const list = document.getElementById("progress-list");
  if (!el) {
    list.insertAdjacentHTML("beforeend", progressItem(name, p.phase, p.pct, p.message));
  } else if (p.phase === "error") {
    el.classList.add("error");
    el.querySelector(".p-pct").textContent = "error";
    el.querySelector(".fill").style.width = "100%";
    el.insertAdjacentHTML("beforeend",
      '<div class="s-meta">' + ui.esc(p.message) + "</div>");
  } else {
    el.querySelector(".p-pct").textContent = p.pct + "%";
    el.querySelector(".fill").style.width = p.pct + "%";
  }
  list.classList.toggle("hidden",
    !document.querySelectorAll(".progress-item").length);
}

function removeProgressUI(name) {
  const el = document.getElementById("prog-" + name);
  if (el) el.remove();
  const list = document.getElementById("progress-list");
  list.classList.toggle("hidden",
    !document.querySelectorAll(".progress-item").length);
}

function pollProgress(name) {
  return new Promise((resolve) => {
    const t = setInterval(async () => {
      try {
        const p = await api.progress(name);
        updateProgressUI(name, p);
        if (p.phase === "done" || p.phase === "error") {
          clearInterval(t);
          setTimeout(() => {
            removeProgressUI(name);
            resolve();
          }, p.phase === "done" ? 700 : 1500);
        }
      } catch (e) {
        /* reintentar en el siguiente tick */
      }
    }, 500);
  });
}

/* ---------- carga de archivo(s) ---------- */
async function upload(files) {
  const list = Array.from(files || []);
  if (!list.length) return;
  const ok = list.filter((f) => SUPPORTED_EXTS.includes(extOf(f.name)));
  const bad = list.filter((f) => !SUPPORTED_EXTS.includes(extOf(f.name)));
  const tooBig = ok.filter((f) => f.size > MAX_FILE_SIZE);
  if (bad.length)
    ui.toast("Extension no soportada: " + bad.map((f) => f.name).join(", "));
  if (tooBig.length)
    ui.toast("Supera 500 MB: " + tooBig.map((f) => f.name).join(", "));
  const toSend = ok.filter((f) => f.size <= MAX_FILE_SIZE);
  if (!toSend.length) return;

  ui.status("loading", "Cargando " + toSend.length + " archivo(s)");
  try {
    const res = await api.upload(toSend);
    if (res.error) throw new Error(res.error);
    await Promise.all(res.started.map((name) => pollProgress(name)));
    // El ultimo archivo subido pasa a ser el activo (si se cargo bien)
    if (res.started.length) {
      const act = await api.activate(res.started[res.started.length - 1]);
      if (act.active) {
        app.sessions = act.sessions;
        app.active = act.active;
      }
    }
    // Si el tail apuntaba a otro dataset, se apaga
    if (tail.on() && tail.name !== app.active) {
      try { await api.watch(tail.name, false); } catch (e) { /* */ }
      tail.stop();
    }
    await refreshSessions();
    if (app.active) {
      await loadDashboard(app.active);
    }
  } catch (e) {
    ui.status("error", "Error de carga");
    ui.toast("Error: " + e.message);
  }
}

async function loadDashboard(name) {
  try {
    const s = await api.summary(name);
    if (!s) throw new Error("dataset no disponible");
    app.fmt = s.format;
    app.name = s.name;
    app.size = s.size;
    app.total = s.total;
    app.encoding = s.encoding || "";
    app.compressed = s.compressed || "";
    app.page = 1;
    filters.reset();
    showDash();
    await fetchTops(name);
    renderKpis(s);
    renderChipsFromTops();
    renderSeg();
    renderRows();
    renderTemplates();
    renderPresets();
    ui.status("ok", ui.fmtNum(s.total) + " líneas · " + s.format);
  } catch (e) {
    ui.status("error", "Error de carga");
    ui.toast("Error: " + e.message);
  }
}

function showDash() {
  document.getElementById("empty").classList.add("hidden");
  document.getElementById("dash").classList.remove("hidden");
  const card = document.getElementById("filecard");
  card.classList.remove("hidden");
  document.getElementById("file-name").textContent = app.name;
  const bits = [app.fmt, ui.fmtBytes(app.size),
                ui.fmtNum(app.total) + " líneas"];
  if (app.encoding) bits.push(app.encoding);
  if (app.compressed) bits.push(app.compressed);
  document.getElementById("file-meta").textContent = bits.join(" · ");
  document.getElementById("act-export").disabled = false;
  document.getElementById("act-clear").disabled = false;
  document.getElementById("act-tail").disabled = false;
  document.getElementById("act-diagnose").disabled = !app.llmEnabled;
}

function renderChipsFromTops() {
  const hasCodes = !!(app.top.codes && app.top.codes.length);
  const hasLevels = !!(app.top.levels && app.top.levels.length);
  if (hasCodes) renderCodeChips(app.top.codes);
  if (hasLevels) renderLevelChips(app.top.levels);
  document.getElementById("fgroup-code").style.display = hasCodes ? "" : "none";
  document.getElementById("fgroup-level").style.display = hasLevels ? "" : "none";
  filters.paintChips();
}

async function clearView() {
  if (tail.on()) {
    try { await api.watch(tail.name, false); } catch (e) { /* */ }
    tail.stop();
  }
  drawer.close();
  charts.destroy();
  for (const s of app.sessions.slice()) {
    try { await api.remove(s.name); } catch (e) { /* ya no existe */ }
  }
  app.fmt = "";
  app.name = "";
  app.total = 0;
  app.page = 1;
  app.pageRows = [];
  app.filteredTotal = 0;
  app.top = {};
  app.sessions = [];
  app.active = "";
  filters.reset();
  document.getElementById("dash").classList.add("hidden");
  document.getElementById("empty").classList.remove("hidden");
  document.getElementById("filecard").classList.add("hidden");
  document.getElementById("act-export").disabled = true;
  document.getElementById("act-clear").disabled = true;
  document.getElementById("act-tail").disabled = true;
  document.getElementById("act-diagnose").disabled = true;
  renderSessions();
  renderPresets();
  ui.status("idle", "Sin archivo");
}

/* ---------- tail en vivo ---------- */
const tail = {
  name: "",
  timer: null,
  on() { return this.timer !== null; },
  start(name) {
    this.stop();
    this.name = name;
    document.getElementById("act-tail").classList.add("on");
    this.timer = setInterval(() => this.poll(), 2000);
    this.poll();
    ui.status("live", "LIVE · " + name);
  },
  stop() {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.name = "";
    document.getElementById("act-tail").classList.remove("on");
    // Solo restaura si el indicador sigue en LIVE (no pisar otros estados)
    if (document.getElementById("status-pill").dataset.state === "live") {
      ui.status("ok", ui.fmtNum(app.total) + " lineas · " + app.fmt);
    }
  },
  async poll() {
    if (!this.on() || this.name !== app.active) return;
    try {
      const res = await api.tail(this.name, 500);
      if (!res.watching) {
        // El servidor lo apago (dataset quitado): sincroniza la UI
        this.stop();
        return;
      }
      if (res.total_new > 0) {
        await refreshLive();
      }
    } catch (e) {
      /* reintentar en el siguiente tick */
    }
  },
};

async function toggleTail() {
  if (!app.active) {
    ui.toast("Carga un archivo primero");
    return;
  }
  if (tail.on()) {
    try { await api.watch(app.active, false); } catch (e) { /* sin servidor */ }
    tail.stop();
  } else {
    try {
      await api.watch(app.active, true);
      tail.start(app.active);
    } catch (e) {
      ui.toast("Error: " + e.message);
    }
  }
}

/* Refresco en vivo: KPIs, chips, graficos y tabla sin perder filtros ni pagina.
   Re-entrante: si llega otro refresco mientras uno corre, se repite al
   terminar para no dejar la UI atrasada. */
let liveBusy = false;
let livePending = false;
async function refreshLive() {
  if (liveBusy) {
    livePending = true;
    return;
  }
  liveBusy = true;
  try {
    do {
      livePending = false;
      const s = await api.summary(app.active);
      if (!s) return;
      app.total = s.total;
      await fetchTops(app.active);
      renderKpis(s);
      renderChipsFromTops();
      renderSeg();
      await renderRows({ follow: true });
      renderTemplates();
    } while (livePending);
  } catch (e) {
    /* reintentar en el siguiente tick */
  } finally {
    liveBusy = false;
  }
}

/* ---------- export (Fase 5: CSV o JSON Lines) ---------- */
function exportData() {
  const fmt = document.getElementById("export-format").value;
  const params = Object.assign({}, filters.params(), {
    name: app.active, format: fmt,
  });
  window.open(api.exportUrl(params), "_blank");
}

/* ---------- auditoria (Fase 5) ---------- */
async function refreshAudit() {
  try {
    const res = await fetch("/api/audit").then((r) => r.json());
    const el = document.getElementById("audit-body");
    const badge = document.getElementById("audit-count");
    const items = res.audit || [];
    badge.textContent = String(items.length);
    badge.classList.toggle("hidden", items.length === 0);
    el.innerHTML = items.slice(0, 100).map((e) =>
      '<div class="audit-item">' +
      '<span class="audit-ts">' + ui.esc(e.ts) + "</span>" +
      '<span class="audit-action">' + ui.esc(e.action) + "</span>" +
      '<span class="audit-detail">' + ui.esc(auditDetail(e)) + "</span>" +
      "</div>"
    ).join("") || '<div class="muted">Sin entradas</div>';
  } catch (e) {
    /* sin servidor */
  }
}

function auditDetail(e) {
  const bits = [];
  if (e.user && e.user !== "local") bits.push(e.user);
  if (e.file) bits.push(e.file);
  if (e.format) bits.push(e.format);
  if (e.total) bits.push(e.total + " lineas");
  if (e.rows) bits.push(e.rows + " filas");
  if (e.size) bits.push(ui.fmtBytes(e.size));
  if (e.backend) bits.push(e.backend);
  if (e.ip) bits.push(e.ip);
  return bits.join(" · ");
}

/* ---------- modo presentacion (Fase 5) ---------- */
function togglePresent() {
  const on = document.body.classList.toggle("present");
  const btn = document.getElementById("btn-present");
  btn.classList.toggle("on", on);
  btn.setAttribute("aria-pressed", String(on));
  if (on) {
    document.getElementById("filters-panel").classList.add("collapsed");
  }
}

/* ---------- cableado ---------- */
function wire() {
  const fileInput = document.getElementById("file");

  // Si el logo no carga, se oculta (sin handler inline: CSP estricta)
  const logo = document.querySelector("img.logo");
  if (logo)
    logo.addEventListener("error", () => { logo.style.display = "none"; });

  document.getElementById("btn-theme").addEventListener("click", () => {
    theme.toggle();
    if (app.fmt) renderSeg();
  });

  const openPicker = () => fileInput.click();
  document.getElementById("act-load").addEventListener("click", openPicker);
  document.getElementById("empty-load").addEventListener("click", openPicker);
  fileInput.addEventListener("change", () => {
    upload(fileInput.files);
    fileInput.value = "";
  });

  document.getElementById("act-export").addEventListener("click", exportData);
  document.getElementById("btn-export").addEventListener("click", exportData);
  document.getElementById("act-clear").addEventListener("click", clearView);
  document.getElementById("act-tail").addEventListener("click", toggleTail);
  document.getElementById("btn-present").addEventListener("click", togglePresent);
  document.getElementById("preset-save").addEventListener("click", saveCurrentPreset);
  document.getElementById("audit-toggle").addEventListener("click", () => {
    const body = document.getElementById("audit-body");
    const isHidden = body.classList.toggle("hidden");
    document.getElementById("audit-toggle").setAttribute(
      "aria-expanded", String(!isHidden));
    if (!isHidden) refreshAudit();
  });

  // Tail: al volver a primer plano, recupera las lineas que el navegador
  // pudo haber retrasado (throttling de timers en segundo plano)
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && tail.on()) tail.poll();
  });

  // Drag & drop (varios archivos a la vez)
  const empty = document.getElementById("empty");
  document.addEventListener("dragover", (e) => {
    e.preventDefault();
    if (!empty.classList.contains("hidden")) empty.classList.add("over");
  });
  document.addEventListener("dragleave", (e) => {
    if (!e.relatedTarget) empty.classList.remove("over");
  });
  document.addEventListener("drop", (e) => {
    e.preventDefault();
    empty.classList.remove("over");
    if (e.dataTransfer.files.length) upload(e.dataTransfer.files);
  });

  // Filtros: inputs con debounce
  let debounce = null;
  ["fip", "fpath", "fq", "fdt", "ftpl", "fdfrom", "fdto"].forEach((id) => {
    document.getElementById(id).addEventListener("input", (e) => {
      const key = { fip: "ip", fpath: "path", fq: "q", fdt: "dt",
                   ftpl: "tpl", fdfrom: "dtFrom", fdto: "dtTo" }[id];
      clearTimeout(debounce);
      debounce = setTimeout(() => {
        filters.state[key] = e.target.value.trim();
        filters.paintChips();
        app.page = 1;
        renderRows();
      }, 300);
    });
  });

  document.getElementById("filters-reset").addEventListener("click", () => {
    filters.reset();
    app.page = 1;
    renderRows();
  });

  // Panel de filtros plegable (persistido)
  const panel = document.getElementById("filters-panel");
  const toggle = document.getElementById("filters-toggle");
  const collapsed = localStorage.getItem("lv-filters-collapsed") === "1";
  if (collapsed) {
    panel.classList.add("collapsed");
    toggle.setAttribute("aria-expanded", "false");
  }
  toggle.addEventListener("click", () => {
    const isCollapsed = panel.classList.toggle("collapsed");
    toggle.setAttribute("aria-expanded", String(!isCollapsed));
    localStorage.setItem("lv-filters-collapsed", isCollapsed ? "1" : "0");
  });

  // Fase 9B: panel 'Errores agrupados' plegable
  const tplBody = document.getElementById("tpl-body");
  document.getElementById("tpl-toggle").addEventListener("click", () => {
    const hidden = tplBody.classList.toggle("hidden");
    document.getElementById("tpl-toggle").setAttribute(
      "aria-expanded", String(!hidden));
    if (!hidden) paintTemplates();
  });

  // Fase 9C: granularidad del histograma
  document.getElementById("gran-min").addEventListener(
    "click", () => setGran("min"));
  document.getElementById("gran-hour").addEventListener(
    "click", () => setGran("h"));
  document.getElementById("hiscanvas").addEventListener("click",
    (e) => histClick(e));

  // Paginacion
  document.getElementById("prev").addEventListener("click", () => {
    if (app.page > 1) { app.page--; renderRows(); }
  });
  document.getElementById("next").addEventListener("click", () => {
    if (app.page * app.pageSize < app.total) { app.page++; renderRows(); }
  });

  // Copia por celda
  document.getElementById("tbody").addEventListener("click", (e) => {
    const btn = e.target.closest(".copy-cell");
    if (!btn) return;
    const row = app.pageRows[parseInt(btn.dataset.idx, 10)];
    if (row) ui.copy(row[btn.dataset.col] || "");
  });

  // Drawer
  document.getElementById("tbody").addEventListener("dblclick", (e) => {
    const tr = e.target.closest("tr[data-idx]");
    if (!tr) return;
    const row = app.pageRows[parseInt(tr.dataset.idx, 10)];
    if (row) drawer.open(row);
  });
  document.getElementById("drawer-close").addEventListener("click", drawer.close);
  document.getElementById("drawer-backdrop").addEventListener("click", drawer.close);
  // Fase 7B: contexto de la linea en el log original
  document.getElementById("drawer-ctx-btn")
    .addEventListener("click", showDrawerContext);

  // Fase 12A: boton "Analizar" del drawer (solo si /api/config dice que si)
  document.getElementById("an-btn").addEventListener("click", runAnalyze);

  // Fase 13: seccion "Importar de Splunk" (visible solo si esta configurado)
  document.getElementById("splunk-go")
    .addEventListener("click", runSplunkImport);

  // Fase 12C: boton "Diagnostico rapido" (solo si /api/config dice llm:true)
  document.getElementById("act-diagnose")
    .addEventListener("click", runDiagnose);
  document.getElementById("diag-close")
    .addEventListener("click", () => {
      document.getElementById("diag-modal").classList.add("hidden");
    });

  // Fase 10B: runbooks (errores conocidos) desde el drawer
  document.getElementById("rb-new-btn").addEventListener("click", () => {
    // El matcher prueba el patron contra msg: prellenamos con msg (glob)
    const row = drawer.rbRow;
    openRbModal(null, row ? (row.msg || "") : "");
  });
  document.getElementById("rb-list").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-id]");
    if (!btn) return;
    const id = parseInt(btn.dataset.id, 10);
    if (btn.classList.contains("rb-edit")) {
      // Busca el runbook en la lista pintada (solo hay matches)
      const res = drawer.rbMatches || [];
      const rb = res.find((x) => x.id === id);
      if (rb) openRbModal(rb);
    } else if (btn.classList.contains("rb-del")) {
      delRb(id);
    }
  });
  document.getElementById("rb-save")
    .addEventListener("click", saveRbModal);
  document.getElementById("rb-cancel").addEventListener(
    "click", closeRbModal);
  document.getElementById("rb-modal-close").addEventListener(
    "click", closeRbModal);

  // Ajustes del LLM local (config editable desde la UI)
  const btnLlm = document.getElementById("btn-llm-settings");
  if (btnLlm) btnLlm.addEventListener("click", openLlmModal);
  document.getElementById("llm-save").addEventListener(
    "click", saveLlmModal);
  document.getElementById("llm-cancel").addEventListener(
    "click", closeLlmModal);
  document.getElementById("llm-modal-close").addEventListener(
    "click", closeLlmModal);

  // Guia de uso (boton de interrogacion en la cabecera)
  const btnHelp = document.getElementById("btn-help");
  if (btnHelp) btnHelp.addEventListener("click", () => {
    document.getElementById("help-modal").classList.remove("hidden");
  });
  document.getElementById("help-close").addEventListener("click", () => {
    document.getElementById("help-modal").classList.add("hidden");
  });

  // Atajos de teclado (Fase 5). No se disparan si el foco esta en un input.
  document.addEventListener("keydown", (e) => {
    const inField = /^(input|textarea|select)$/.test(e.target.tagName);
    if (e.key === "Escape") {
      if (!drawer.closed) drawer.close();
      else if (document.body.classList.contains("present")) togglePresent();
      return;
    }
    if (inField) return;
    const k = e.key.toLowerCase();
    if (k === "p") { e.preventDefault(); togglePresent(); }
    else if (k === "t") { e.preventDefault(); toggleTail(); }
    else if (k === "e") { e.preventDefault(); exportData(); }
    else if (e.key === "/") { e.preventDefault(); document.getElementById("fq").focus(); }
    else if (k === "g") { e.preventDefault(); document.getElementById("fip").focus(); }
  });
}

/* ---------- init ---------- */
async function init() {
  try {
    const c = await api.csrf();
    csrfToken = c.token;
  } catch (e) {
    /* sin servidor: los POST fallaran con 403, como el resto */
  }
  // Fase 12A: si no hay LLM configurado, el boton Analizar NO aparece
  // (Fase 13: igual para Splunk: sin contrasena no aparece la seccion)
  try {
    const cfg = await api.config();
    app.llmEnabled = !!cfg.llm;
    app.repoUrl = cfg.repo_url || "";
    setSplunkVisible(!!cfg.splunk);
  } catch (e) {
    app.llmEnabled = false;
    app.repoUrl = "";
    setSplunkVisible(false);
  }
  // Fase 12C: el boton "Diagnostico rapido" sigue la misma regla
  setDiagnoseVisible(app.llmEnabled);
  theme.apply(theme.get());
  wire();
  renderPresets();
  refreshAudit();
  // Recupera la sesion si el servidor ya tiene datasets
  try {
    const res = await api.sessions();
    if (res.sessions && res.sessions.length) {
      app.sessions = res.sessions;
      app.active = res.active || res.sessions[0].name;
      renderSessions();
      await loadDashboard(app.active);
      // Recupera el estado LIVE si el servidor sigue vigilando
      const act = res.sessions.find((s) => s.name === app.active);
      if (act && act.watching) {
        tail.start(app.active);
      }
    }
  } catch (e) {
    /* primer arranque: sin sesion */
  }
  renderPresets();
}

init();
