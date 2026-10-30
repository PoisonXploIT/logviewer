# Unified Log Viewer

A **100% local** web tool (Python, stdlib only, zero dependencies) to view
and filter log files in your browser. Your logs **never** leave your
machine: all filtering happens server-side on your own computer, and the
LLM analysis runs against a model on `127.0.0.1`. Built for SOC analysts
and security students who want fast triage without shipping sensitive logs
anywhere.

**Version 1.2** — local-first, offline-capable, nothing goes to the cloud.

## Why local

Your logs are your most sensitive data. Most "free" log analyzers upload
your logs to a third party to process them. This tool does the opposite:

- The whole tool runs on your machine (Python stdlib, no installs).
- The LLM analysis connects only to a model on `127.0.0.1`
  (LM Studio / Ollama / llama.cpp). No line of a log is ever sent to an
  external server.
- Splunk ingestion talks only to your own local Splunk.
- Run it, analyze, close. No account, no telemetry, no data leaving home.

If you want to deploy it somewhere, that's up to you: fork the repo and
adapt it to your own setup. Out of the box it is a local tool.

## Features

- **Multi-format ingestion**: Apache/NCS (CLF), W3C Extended (IIS), JSON
  Lines, generic. Auto-detection of format and encoding (utf-8, cp1252,
  latin-1). Compressed files `.gz`, `.bz2`, `.xz`, `.zip` (magic-byte
  detection, not extension).
- **Server-side filtering**: level, HTTP code, IP, path, free text, date
  range — combinable. Multi-value with commas (`200,301`) and exclusion with
  `!` (`!10.0.0.5`).
- **Full-text search**: FTS5 (SQLite) for instant search over millions of
  lines on large datasets.
- **Error clustering**: identical errors are grouped into unique templates
  with their count and a sample line, so you see the forest instead of
  thousands of identical `ERR` lines.
- **Line context**: click any row to open a drawer with the parsed fields,
  the raw line, and a "view context" button showing surrounding lines.
- **Live tail**: follow lines appended to the active file in real time.
- **Histogram**: temporal distribution of the filtered rows (per minute /
  hour); click a bar to apply that time range.
- **Runbooks**: your own local "known error -> solution" database, with
  regex/glob pattern matching against each line.
- **Local LLM analysis**: "Analyze this line" and "Quick diagnosis" send
  content to a local model on `127.0.0.1`. Nothing leaves your machine.
- **Local Splunk ingestion**: run a SPL query against your own local Splunk
  and load the result as a dataset.
- **Export**: filtered rows to CSV or JSON Lines (streamed, chunked).
- **Dashboard**: KPIs, Chart.js charts, presets, presentation mode,
  keyboard shortcuts, audit log.

## Requirements

- Python 3.8+ (no pip packages — stdlib only).
- Optional, for LLM analysis: a local OpenAI-compatible model server on
  `127.0.0.1` (LM Studio, Ollama, or llama.cpp).
- Optional, for Splunk: a local Splunk instance with REST API access.

## Getting started

```bash
cd logviewer-phase1
python server.py
```

Then open in your browser:

```
http://127.0.0.1:8765/
```

- Custom port: `python server.py 9000`
- Tail a file from the terminal without starting the HTTP server:
  `python server.py --tail path/to/file.log --lines 50`
- By default the server only listens on `127.0.0.1` (not exposed to the
  network). Use `--host 0.0.0.0` or `PORT=<n>` to bind elsewhere if you
  really want to.
- On startup the temp folder `%TEMP%\logviewer\` is cleaned.
- File limits: 500 MB per file, 1 GB per upload batch, 2 GB decompressed.
- Accepted extensions: `.log .txt .csv .json .jsonl .gz .bz2 .xz .zip`
  (`.jsonl` = JSON Lines, one JSON object per line with `ts`/`level`/`msg`; auto-detected as format `json`)
- Large datasets (over a threshold) automatically use a SQLite backend, so
  logs with millions of lines don't exhaust memory.

## Using the tool

1. Start the server and open `http://127.0.0.1:8765/`.
2. Drag one or more log files onto the page, or click "Cargar archivo"
   (Upload). The browser uploads them to the server, which detects format
   and encoding and parses each file in the background (progress bar per
   file).
3. Each loaded file appears in the **Sessions** panel. Click to switch, `x`
   to remove. The active file drives the dashboard.
4. **Filters** are combinable and applied server-side: level chips, HTTP
   code chips, IP, path, free text, date/time. Commas mean OR, `!` means
   exclude. Clicking a chart segment or a chip applies it as a filter.
5. **Export** the filtered rows to CSV or JSON Lines via the format selector.
6. **Runbooks**: manage known errors from the row drawer.
7. **Diagnosis**: open a row and click "Analyze", or use "Quick diagnosis"
   to have the local LLM summarize all error templates.
8. **Presentation mode**: the "Presentacion" button (or `p`) hides the
   sidebar/header/filters and shows the table full-screen. `Esc` closes it.

## Uso con OperVanta (piloop / buzón / SOC)

El visor entiende de serie los logs que genera OperVanta. No hay que
convertir nada: se cargan los ficheros tal cual y el servidor detecta el
formato.

### Qué subir

| Fichero OperVanta | Ruta típica | Formato detectado |
|---|---|---|
| `buzon.log`, `orquestador.log` | `piloop-proyectos\buzon\` | `piloop` |
| `soc\triage.log` | `piloop-proyectos\buzon\soc\` | `triage` |
| `soc\alertas.jsonl`, `soc\eventos.jsonl` | `piloop-proyectos\buzon\soc\` | `json` (JSON Lines) |
| `soc\dataset.jsonl`, `soc\triage-dataset.jsonl` | `piloop-proyectos\buzon\soc\` | `json` (registro envuelto en `datos`/`alerta`/`data`) |

Se pueden arrastrar varios ficheros a la vez o usar "Cargar archivo". Cada
fichero queda como una sesión en el panel **Sessions**; el dashboard y los
filtros actúan sobre la sesión activa.

### Cómo se detecta cada formato

- **`piloop`** — `2026-10-12 20:40:16 logs: rotado buzon.log (>0.0 MB)`.
  Fecha, hora y componente opcional; la línea no lleva nivel, así que se
  infiere del texto (`error`, `except`, `traceback`, `denied` -> `ERR`;
  `warn`, `aviso` -> `WRN`; `ok`, `completado`, `rotado`, `iniciado` ->
  `INF`; si no hay pistas, `INF`). Las líneas sin timestamp (stack traces,
  continuaciones) se guardan como `RAW` y se ven igual en la tabla.
- **`triage`** — `23:36:54 [x] F-LAYA2 -> real_incident conf 0.8 sev 2.0
  accion yes | ESCALADA t4f87df76`. Se extraen hora, fuente, firma,
  veredicto, confianza, severidad, acción y tarea. La hora va sin fecha: se
  completa con la fecha del fichero cuando se conoce. El nivel se deduce:
  `sev >= 2.0` o `accion yes` -> `ERR`; `sev >= 1.0`, o confianza alta con
  veredicto de incidente -> `WRN`; el resto -> `INF`.
- **`json`** — una línea por objeto JSON. El nivel se toma de `level`/`lvl`
  o, si no viene, de `sev` (`baja` -> `WRN`, `media` -> `INF`, `alta` ->
  `ERR`, `critica` -> `CRIT`; también se aceptan números 0..3: >=3 CRIT,
  >=2 ERR, >=1 WRN). La IP se busca en `ip`, `src`, `dst`, `client_ip`...

### Columnas de OperVanta que se conservan

Al parsear JSON Lines del SOC no se pierde ninguna columna: además de
`ts`, `level`, `ip` y `msg` se guardan `fuente`, `firma`, `tenant`, `tarea`,
`dedupe`, `evidencia`, `riesgo`, `url`, `sev` (original, sin transformar),
`src` y `dst`. Aparecen en el drawer de la fila y en la exportación a CSV o
JSON Lines. En el formato `piloop` se conserva además el `comp` (componente).

### Panel Dashboard SOC (severidad, fuente, tarea)

Con una sesión de alertas cargada, el botón **Dashboard SOC** abre un modal
con el agregado calculado en el servidor (`GET /api/soc/dashboard`). Se
filtra por severidad, fuente y tarea, y muestra:

- **Chips de severidad**: `CRIT = n`, `ERR = n`, `WRN = n`, `INF = n`.
- **Chips de tarea**: `abierta`, `encolada`, `descartada`, `sin_dato`.
- **Tabla "Por fuente"**: Fuente | Alertas | CRIT | ERR | WRN | INF.
- **Tabla "Alertas"**: ts | Fuente | Firma | Sev | Tarea | Estado. La
  columna Sev muestra el nivel normalizado y, entre paréntesis, el valor
  original del fichero (p. ej. `err (alta)`).

### Correlación alertas x triage

El botón **Correlación SOC** cruza `alertas.jsonl` con `triage.log` por
firma (`GET /api/correlate`). La tabla resultante tiene las columnas Firma,
Estado, Motivo, Tarea y Triage (veredicto, confianza y tarea de escalado de
cada línea de triage).

### Filtros aplicables

Los filtros de nivel (`CRIT`, `ERR`, `WRN`, `INF`), texto libre, rango de
fecha (`dt_from`/`dt_to`, timestamps normalizados a ISO) e IP funcionan sobre
estos formatos igual que sobre un Apache o un W3C. Comas = OR, `!` =
exclusión.

## Local LLM (Analyze line and Quick diagnosis)

- Sends one line (or the error templates) to an OpenAI-compatible LLM running
  on **your** machine (LM Studio, Ollama, llama.cpp). Nothing goes online.
- The LLM destination is **loopback only** (`localhost` / `127.x`). External
  servers are rejected (anti-SSRF, enforced in three layers: when saving the
  URL, when making the request, and against redirects).
- **Setup:**
  1. Start your model (e.g. `llama-server` on a port like 8096).
  2. Open the LLM settings in the UI (gear icon in the header).
  3. Set the base URL (`http://127.0.0.1:8096/v1`), the model name, a
     generous timeout (reasoning models are slow), and the response language
     (Auto / Spanish / English). Save.
- Environment variables: `LOGVIEWER_LLM_URL`, `LOGVIEWER_LLM_MODEL`
  (default "local"), `LOGVIEWER_LLM_TIMEOUT` (default 10 s). Values can also
  be changed from the UI (persisted in `%TEMP%\logviewer\settings.json`).

## Local Splunk (Import from Splunk)

- Runs a SPL query against your own local Splunk and loads the result as a
  dataset (filter, export, diagnose). The SPL runs on your Splunk (that is
  where the computational load goes); the viewer only fetches the result
  (capped row count).
- The connection is configured via environment variables; the viewer does
  not connect to third-party Splunks.
- **Setup:** environment variables
  - `SPLUNK_URL` (default `https://localhost:8089`)
  - `SPLUNK_USER` (no default; empty if not set - there is no `admin`
    fallback). Set it together with `SPLUNK_PASS`: with an empty user the
    basic auth will be rejected by Splunk.
  - `SPLUNK_PASS` (required; if missing, the Splunk section is hidden)
  - `LOGVIEWER_SPLUNK_VERIFY` (default: verification ON). The TLS certificate
    is verified by default. Set `LOGVIEWER_SPLUNK_VERIFY=0` only for a local
    Splunk with a self-signed certificate that cannot be validated; it is
    never off by default. Better option: `LOGVIEWER_SPLUNK_CAFILE=/path/ca.pem`
    to trust the Splunk CA without disabling verification.
- Note: for Azure AD JSON events (sourcetype `ms:aad:signin`) use `| spath`
  to extract the fields (`userPrincipalName`, `ipAddress`, `failureReason`)
  that live inside the `_raw` field.

## Security

- **SQL injection**: all queries are parameterized (`?`), including FTS5.
- **XSS**: all log content is escaped on render; CSP `default-src 'self'`,
  `X-Frame-Options: DENY`, no inline scripts.
- **CSRF**: every mutating request requires an `X-CSRF-Token` (403 if
  missing).
- **Path traversal**: `resolve_static()` and `safe_session_name()` prevent
  escaping the static and session directories.
- **Zip bombs / DoS**: decompression is capped at 2 GB during streaming;
  max 2 concurrent uploads (503 when busy).
- **CSV injection**: cells starting with `=`, `+`, `-`, `@` (or tab/newline)
  are prefixed with `'`.
- **SSRF (local LLM)**: the LLM destination is loopback-only, enforced at
  save time, request time, and against HTTP redirects.
- **No hardcoded credentials**: Splunk and LLM settings come from
  environment variables, never from the source.
- **Audit log**: tracks actions with user and remote IP for attribution.

## API

| Method | Route | Purpose |
|---|---|---|
| GET | `/` | UI (static/index.html) |
| GET | `/static/*` | Assets (path-traversal protected) |
| POST | `/upload` | Multipart upload, multiple files, threaded |
| GET | `/api/sessions` | List datasets + active |
| POST | `/api/activate` | Set active dataset |
| POST | `/api/remove` | Remove a dataset |
| GET | `/api/progress?name=` | Upload progress |
| GET | `/api/summary?name=` | KPIs (mem or sqlite backend) |
| GET | `/api/rows?name=&level=&code=&ip=&path=&q=&dt=&page=&size=` | Filtered rows |
| GET | `/api/top?name=&field=&limit=` | Top N |
| GET | `/api/templates?name=&level=` | Error templates (clustering) |
| GET | `/api/histogram?name=&gran=` | Temporal histogram |
| GET | `/api/context?name=&row=&n=` | Line context (before/after) |
| GET | `/api/runbooks` | List runbooks |
| POST | `/api/runbooks` | Create a runbook |
| PUT | `/api/runbooks?id=` | Edit a runbook |
| DELETE | `/api/runbooks?id=` | Delete a runbook |
| GET | `/api/runbooks/match?msg=` | Runbooks matching a message |
| GET | `/api/config` | {llm, url, model, timeout, splunk, repo_url} |
| GET/POST | `/api/settings` | Read/save local LLM settings |
| POST | `/api/analyze` | Local: analyze one line with the local LLM |
| POST | `/api/diagnose` | Local: quick diagnosis over error templates |
| GET | `/api/splunk/sources` | Local: list indexes |
| POST | `/api/splunk/search` | Local: run a SPL query into a dataset |
| POST | `/api/watch` | Toggle live tail |
| GET | `/api/tail?name=&last=` | Drain new lines |
| GET | `/api/audit` | Audit log |
| GET | `/api/health` | Service status: version, backend (mem/sqlite), uptime |
| GET | `/api/export?name=&format=csv\|json` | Streamed export |

## Project structure

```
server.py            Entry point + CLI (imports the modules below)
config.py            Constants and environment configuration
security.py          Session cookie, headers, CSRF, rate limiting
parsers.py           Format detection, parsers and row filters
stores.py            Global state and dataset backend (MemStore/SqlStore)
api.py               HTTP handler, routes, LLM, Splunk, tail, audit, server
static/index.html    UI
static/app.js        Frontend logic
static/styles.css    Styles
static/vendor/       Vendored Chart.js
test_parsers.py      331 unit tests (parsers OperVanta incluidos)
LICENSE
```

## Tests

```bash
python -m unittest test_parsers -q
```

**331 tests, todo verde** (verificado el 2026-10-30 con Python 3.12).
Cubren: parsers Apache/W3C/syslog/generic/JSON, detección de formato,
formatos OperVanta (`piloop` y `triage`), normalización de severidad y de
timestamps, templates/clustering, runbooks, correlación alertas x triage,
dashboard SOC, ajustes y caché del LLM, ingesta Splunk y comprobaciones
SSRF.

## License

See `LICENSE`.

---

## Contacto

- Pagina: [sammideblas.com](https://sammideblas.com)
- Email: analista@sammideblas.com
