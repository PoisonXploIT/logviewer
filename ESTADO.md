# ESTADO DEL PROYECTO (ancla de contexto)

Este archivo es la fuente de verdad para retomar el trabajo en cualquier
sesion nueva. Leer esto primero; no hace falta historial de conversacion.
Actualizar al terminar cada fase o checkpoint importante.

## Proyecto
Visor de Logs Unificado: servidor web local (Python stdlib, sin pip) para ver
y filtrar logs en el navegador. 100% offline (air-gapped). UI corporativa.

## Rutas
- Original (no tocar):  C:\Users\Sammi\Documents\Destino\LOGS RAW\logviewer
- Backup Fase 0:        logviewer-backup-2026-08-19
- Backup Fase 1:        logviewer-backup-phase1-2026-08-19
- Trabajo actual:        logviewer-phase1   (aqui se trabaja)
- Logs de ejemplo:      LOGS RAW\access\ (Apache .md), LOGS RAW\Zscaler\

## Estado por fases
- Fase 1 (HECHA): rediseño UI corporativo, tema claro/oscuro, dashboard,
  KPIs, graficos Chart.js vendoreado, drawer detalle, filtros, 18 tests.
- Fase 2 (HECHA): compresion (.gz/.bz2/.xz/.zip por magico), encoding
  (utf-8-sig/utf-8/cp1252/latin-1), multi-archivo con sesiones, progreso
  por polling, errores amigables, 35 tests + smoke_phase2.py.
- Fase 3 (HECHA): tail en vivo. Watcher por dataset sobre la copia
  temporal (hilo daemon, poll 0.5 s), buffer con tope 10000, deteccion de
  truncamiento (tamano baja -> relee desde 0), lineas parciales (sin \n)
  se retienen hasta completarse. POST /api/watch activa/desactiva,
  GET /api/tail drena el buffer, parsea con el formato del dataset y lo
  anade al dataset (filtros/KPIs/chips/graficos se actualizan en vivo).
  UI: boton "Tail en vivo", polling 2 s, indicador LIVE (punto rojo
  parpadeante), se sigue la ultima pagina, recarga de LIVE tras recargar
  la pagina, se apaga al cambiar/quitar dataset o limpiar.
- Fase 4 (HECHA): backend SQLite hibrido (umbral por tamano). La carga es
  en streaming (no carga el archivo entero en memoria). Si el numero de
  filas supera SQLITE_THRESHOLD (200000 por defecto, configurable por
  LOGVIEWER_SQLITE_THRESHOLD), migra a un backend SQLite (SqlStore) en
  %TEMP%\logviewer\sqlite\<name>.db. Los datasets pequenos quedan en
  memoria (MemStore, comportamiento original). El filtrado, el top N, los
  KPIs, el tail y el export funcionan sobre ambos backends (misma
  interfaz). Se resuelve el OOM de ~2M+ lineas (verificado con 2M lineas).
- Fase 5 (HECHA): presets de filtros (localStorage), export JSON Lines
  (ademas de CSV), auditoria de acciones (upload/loaded/export/activate/
  remove, en memoria + %TEMP%\logviewer\audit.log), modo presentacion
  (oculta sidebar/header/filtros, tabla a pantalla completa) y atajos de
  teclado (p presentacion, t tail, e export, / texto libre, g IP, Esc
  cierra drawer/sale de presentacion). ARIA: roles y aria-label en presets,
  drawer y auditoria.
- Fase 6 (HECHA): deploy Railway. main() lee $PORT (la inyecta Railway)
  y escucha en 0.0.0.0; en local sigue 127.0.0.1:8765. --host fuerza la
  direccion. La auditoria registra el campo "user" (header
  Cf-Access-Login-User de Cloudflare Access, o "local" si no esta).
  railway.json (start: python server.py) y DEPLOY.md con el patron de
  sec.sammideblas.com: dominio propio + CNAME + politica Access (GET y
  POST) y URL publica de Railway desactivada. Datos efimeros (Opcion A):
  los datasets mueren con el contenedor; sin persistencia.

## Contrato API (no romper)
- GET  /                  UI (static/index.html)
- GET  /static/*          assets (anti path traversal, resolve_static)
- POST /upload            multipart, varios archivos, valida y lanza hilos
- GET  /api/sessions      lista datasets + activo
- POST /api/activate      {"name": ...}
- POST /api/remove        {"name": ...}
- GET  /api/progress?name=  {phase, pct, message}
- GET  /api/summary?name=   KPIs (por defecto el activo); incluye "backend"
  ("mem" o "sqlite")
- GET  /api/rows?name=&level=&code=&ip=&path=&q=&dt=&page=&size=
- GET  /api/top?name=&field=&limit=
- GET  /api/export?name=&format=csv|json&...  CSV o JSON Lines de filas
  filtradas (format por defecto csv; json anade el campo "raw"). Se envia
  en streaming por lotes con Transfer-Encoding: chunked (sin cuerpo
  entero en memoria).
- GET  /api/audit  {audit: [...]}  entradas de auditoria (mas reciente
  primero); accion, ts, user (Cf-Access-Login-User o "local") y detalles
  (file, format, total, rows, size, backend)
- POST /api/watch  {name, enabled}  activa/desactiva el watcher
- GET  /api/tail?name=&last=N  drena lineas nuevas (parseadas) y las
  anade al dataset; {watching, rows, total_new, total, truncated}
- GET  /api/sessions  incluye "watching" por dataset

## Decisiones clave
- Solo stdlib. Frontend sin bundler (app.js modular por secciones).
- Tail: el parseo incremental ocurre al drenar /api/tail (no en el
  watcher); el dataset crece y los filtros siguen siendo del servidor.
- Chart.js 4.5.1 vendoreado en static/vendor/chart.min.js.
- Iconos: sprite SVG propio de 17 iconos (no Phosphor completo).
- Sin fuentes woff2: Consolas/system monospace.
- Estado servidor: SESSIONS dict + ACTIVE + LOCK; carga en hilos con
  PROGRESS por nombre.
- Parser: (lines, progress=None) -> (rows, counters); cada fila tiene "raw".
- Carga en streaming (Fase 4): no carga el archivo entero en memoria; parsea
  en lotes de PARSE_CHUNK (50000) lineas. Backend hibrido: MemStore (pequeños)
  o SqlStore (grandes, > SQLITE_THRESHOLD filas). Limites: 500 MB/archivo,
  1 GB/lote, 2 GB descomprimido.
- Sin emojis en ninguna salida. Responder en espanol.

## Como verificar
- python test_parsers.py          (50 tests)
- python smoke_phase2.py          (sube a un servidor en :8799)
- python smoke_phase3.py          (tail en vivo en :8798)
- python smoke_phase4.py          (backend SQLite hibrido en :8797)
- python smoke_phase5.py          (export JSON Lines + auditoria en :8796)
- python server.py 8765           (arranque; limpia %TEMP%\logviewer\sessions
  y %TEMP%\logviewer\sqlite)
- Browser CDP: node "C:\Users\Sammi\.pi\agent\skills\browser-tools\browser-start.js"
  y browser-nav.js / browser-eval.js / browser-screenshot.js

## Notas Fase 3
- El watcher lee la copia en %TEMP%\logviewer\sessions\, no el original
  del usuario (la copia es la que se parseo). Para "seguir" un log que
  crece, hay que re-subirlo (el watcher se reinicia sin duplicar).
- Chrome throttling: en pestaña en segundo plano el polling de 2 s se
  retrasa; el watcher sigue bufferizando (tope 10000) y al volver a
  primer plano (visibilitychange) se recupera. Sin datos perdidos.
- refreshLive es re-entrante (liveBusy/livePending): no deja la UI
  atrasada si dos polls se solapan.
- renderRows({follow:true}) salta a la ultima pagina si el usuario la
  seguia; si no, se queda en la pagina donde estaba.

## Notas Fase 5
- Presets: se guardan en localStorage (clave lv-presets) como
  {name, filters}. Son por navegador (no por dataset); al aplicar se
  restaura el estado de filtros y se vuelve a la pagina 1.
- Export JSON Lines: /api/export?format=json devuelve una linea JSON por
  fila (incluye el campo "raw"). El CSV es el formato por defecto.
- Auditoria: registro en memoria (tope 500) + archivo %TEMP%\logviewer\
  audit.log (JSON Lines). Acciones: upload, loaded, export, activate,
  remove. Se consulta con GET /api/audit (mas reciente primero).
- Modo presentacion: body.present oculta sidebar/header/filtros/KPIs y
  deja la tabla a pantalla completa. Se activa con el boton o la tecla
  "p"; Esc lo cierra (si el drawer no esta abierto).
- Atajos: p presentacion, t tail, e export, / texto libre, g IP, Esc
  cierra drawer o sale de presentacion. No se disparan si el foco esta en
  un input/textarea/select.

## Streaming de la subida (EN PAUSA)
- El pico de RAM de la subida (el cuerpo multipart entero en memoria,
  hasta 1 GB por lote) queda documentado y se deja en pausa por el plan
  Railway Hobby (8 GB RAM): entra con margen. Si un dia el plan baja o
  se quiere endurecer, el arreglo es reescribir _upload para desmontar
  el multipart al vuelo (escribir a disco mientras llega) y/o bajar
  MAX_SIZE/TOTAL_MAX. Ver DEPLOY.md.

## Arreglos post-revision (2026-08-20)
- Export en streaming: /api/export ya no construye el cuerpo entero en
  memoria; pagina por lotes de 5000 filas (EXPORT_BATCH) y lo envia con
  Transfer-Encoding: chunked, flush cada 64 KB. Un dataset SQLite de
  millones de filas no OOM y la BD solo se bloquea por lote, no durante
  todo el export. Verificado en smoke_phase5.py (cabecera chunked +
  contenido intacto).
- Cuerpos JSON invalidos: _read_json_body devuelve None si el body no es
  JSON valido (antes lanzaba excepcion sin respuesta); /api/activate,
  /api/remove y /api/watch responden 400 "cuerpo JSON invalido".
  Verificado en smoke_phase5.py.

## Hardening de seguridad (2026-08-20)
- Nombres de sesion sanitizados con `safe_session_name()`: se aplica
  `os.path.basename()`, se reemplazan caracteres peligrosos y se evita el
  path traversal en upload, watcher, SQLite y remove.
- `LOGVIEWER_SQLITE_THRESHOLD` se valida al importar; valores no numericos o
  menores de 1000 caen al valor por defecto (200000).
- `MAX_DECOMP_SIZE` (2 GB) se aplica durante la descompresion en streaming
  (gzip/bz2/xz/zip) para mitigar zip bombs.

## Notas de entorno
- Python 3.12.10, Windows, bash (Git Bash). Puerto por defecto 8765.
- Chrome CDP en :9222 con perfil aislado (browser-start.js).
- El servidor loguea peticiones a %TEMP%\logviewer\requests.log.
- OOM en memoria con ~2M+ lineas: resuelto en Fase 4 (backend SQLite).
  Verificado con 2M lineas (150 MB) en ~13 s sin OOM.
- SQLITE_THRESHOLD configurable por LOGVIEWER_SQLITE_THRESHOLD (por defecto
  200000). Los .db viven en %TEMP%\logviewer\sqlite\ y se borran al quitar
  el dataset o al arrancar el servidor.
