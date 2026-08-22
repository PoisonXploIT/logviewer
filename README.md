# Unified Log Viewer

A local web server (Python, stdlib only, zero dependencies) to view and
filter log files in the browser. The log is **never** embedded in the HTML:
all filtering happens server-side and the browser only receives the requested
page. Designed for SOC analysts and security students who want fast triage
without shipping logs to the cloud.

**Version 1.2** — 100% offline by default, with optional local-only LLM
analysis and local Splunk ingestion.

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
- **Local LLM analysis (local-only)**: "Analyze this line" and "Quick
  diagnosis" send content to a local model (LM Studio / Ollama / llama.cpp)
  on `127.0.0.1`. Nothing leaves your machine.
- **Local Splunk ingestion (local-only)**: run a SPL query against your own
  local Splunk and load the result as a dataset.
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
- By default the server only listens on `127.0.0.1` (not exposed to the
  network). Use `--host 0.0.0.0` or `PORT=<n>` to bind elsewhere.
- On startup the temp folder `%TEMP%\logviewer\` is cleaned.
- File limits: 500 MB per file, 1 GB per upload batch, 2 GB decompressed.
- Accepted extensions: `.log .txt .csv .json .gz .bz2 .xz .zip`
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
7. **Diagnosis** (local-only): open a row and click "Analyze", or use
   "Quick diagnosis" to have the local LLM summarize all error templates.
8. **Presentation mode**: the "Presentacion" button (or `p`) hides the
   sidebar/header/filters and shows the table full-screen. `Esc` closes it.

## Local-only features (by security design)

Two features depend on services that live on your own machine and are, by
design, **not** available from a version deployed to the internet:

### Local LLM (Analyze line and Quick diagnosis)

- Sends one line (or the error templates) to an OpenAI-compatible LLM running
  on **your** machine (LM Studio, Ollama, llama.cpp). Nothing goes online.
- The LLM destination is **loopback only** (`localhost` / `127.x`). External
  servers are rejected (anti-SSRF, enforced in three layers: when saving the
  URL, when making the request, and against redirects). On a deployed web
  version there is no model in the container, so the button is hidden and the
  UI explains it is a local-only feature.
- **Setup (local):**
  1. Start your model (e.g. `llama-server` on a port like 8096).
  2. Open the LLM settings in the UI (gear icon in the header).
  3. Set the base URL (`http://127.0.0.1:8096/v1`), the model name, a
     generous timeout (reasoning models are slow), and the response language
     (Auto / Spanish / English). Save.
- Environment variables: `LOGVIEWER_LLM_URL`, `LOGVIEWER_LLM_MODEL`
  (default "local"), `LOGVIEWER_LLM_TIMEOUT` (default 10 s). Values can also
  be changed from the UI (persisted in `%TEMP%\logviewer\settings.json`).

### Local Splunk (Import from Splunk)

- Runs a SPL query against your own local Splunk and loads the result as a
  dataset (filter, export, diagnose). The SPL runs on your Splunk (that is
  where the computational load goes); the viewer only fetches the result
  (capped row count).
- The connection is configured by the **operator** of the server via
  environment variables; the viewer does not connect to third-party Splunks.
- **Setup (local):** environment variables
  - `SPLUNK_URL` (default `https://localhost:8089`)
  - `SPLUNK_USER` (default `admin`)
  - `SPLUNK_PASS` (required; if missing, the Splunk section is hidden)
- Note: for Azure AD JSON events (sourcetype `ms:aad:signin`) use `| spath`
  to extract the fields (`userPrincipalName`, `ipAddress`, `failureReason`)
  that live inside the `_raw` field.

### Web-version notice

On a deployed instance without local LLM/Splunk, the UI shows clear notices
instead of just hiding the features: "LLM analysis is a local-only feature,
download the local version from the repository" (link via
`LOGVIEWER_REPO_URL`) and "Splunk connectivity is configured by the
operator".

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
- **Audit log**: tracks actions with user and remote IP (attribution; the
  auth boundary is your reverse proxy / identity-aware gateway when
  deployed).

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
| POST | `/api/analyze` | Local-only: analyze one line with the local LLM |
| POST | `/api/diagnose` | Local-only: quick diagnosis over error templates |
| GET | `/api/splunk/sources` | Local-only: list indexes |
| POST | `/api/splunk/search` | Local-only: run a SPL query into a dataset |
| POST | `/api/watch` | Toggle live tail |
| GET | `/api/tail?name=&last=` | Drain new lines |
| GET | `/api/audit` | Audit log |
| GET | `/api/export?name=&format=csv\|json` | Streamed export |

## Project structure

```
server.py            Single-file server (Python stdlib)
static/index.html    UI
static/app.js        Frontend logic
static/styles.css    Styles
static/vendor/       Vendored Chart.js
test_parsers.py      148 unit tests
LICENSE
```

## Tests

```bash
python test_parsers.py
```

148 tests: parsers, ts normalization, templates/clustering, runbooks,
LLM settings/cache/language, Splunk ingestion, SSRF checks.

## Deployment

The server is a normal Python process: `python server.py` runs it locally,
or `PORT=<n> python server.py` makes it listen on `0.0.0.0:<n>` for any
hosting provider you choose. There is no built-in authentication: if you
expose it beyond localhost, put it behind your own reverse proxy /
identity-aware gateway. The web version does **not** include the local LLM
or local Splunk (they are local-only features).

## License

See `LICENSE`.
