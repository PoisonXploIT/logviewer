# PLAN DE FASES 7+ — Visor de Logs Unificado

Restriccion de diseño (2026-08-21): **ningun dato de los logs sale a
internet**. Todo lo que sigue es local: SQLite, calculo en el servidor y,
como mucho, un LLM en localhost (LM Studio/Ollama) que nunca sale de la
maquina. Las integraciones con APIs externas (AbuseIPDB, Stack Exchange,
LLM en la nube) quedan descartadas salvo decision expresa del usuario.

Cada fase es independiente, desplegable y verificable por separado
(mismo patron que las fases 1-6: tests + smoke en puerto propio).

## Fase 7 — Contexto de lineas y busqueda precisa (local)

Objetivo: diagnosticar un error sin exportar ni abrir el archivo.

- **Contexto tipo `grep -C`**: en el drawer de detalle, boton "Ver
  contexto" que muestra las N lineas anteriores/posteriores del log
  original (por `rowid` en SQLite / indice en MemStore).
  API: `GET /api/context?name=&row=<id>&n=5`.
- **Rango de fechas real (desde/hasta)**: al parsear, normalizar el
  timestamp de cada formato a ISO (`ts_norm`); filtros `dt_from`/`dt_to`
  en `/api/rows`. Mantiene la subcadena actual como fallback.
- **Resaltado de la coincidencia**: el termino de `q`/ip/path se marca
  con `<mark>` en la tabla y en la linea raw del drawer (escapado antes,
  sin XSS).
- **Exclusion y multivalor**: prefijo `!` para excluir (`!10.0.0.5`) y
  coma para varios valores (`200,301`). Solo en el parser de filtros del
  servidor; la UI no cambia de momento.

Verificacion: tests nuevos en test_parsers.py (rango, exclusion,
contexto) + smoke_phase7.py.

## Fase 8 — Full-text search con FTS5 (local)

Objetivo: "texto libre" instantaneo en datasets de millones de lineas.

- Tabla virtual FTS5 sobre `raw`/`msg` en SqlStore (stdlib `sqlite3`
  lo incluye). Indice construido durante la carga en streaming.
- `/api/rows?q=` usa MATCH cuando el dataset es SQLite; MemStore sigue
  con subcadena. Ranking por relevancia opcional.
- Indices b-tree en `level`, `code`, `ip`, `ts_norm` para acelerar los
  filtros concretos.

Verificacion: benchmark con 2M lineas (mismo set que Fase 4): tiempo de
busqueda antes/despues; smoke_phase8.py.

## Fase 9 — Agrupacion de errores y panorama temporal (local)

Objetivo: ver el bosque, no 482 filas iguales.

- **Clustering por plantilla**: normalizar cada mensaje (numeros, IPs,
  rutas y hex -> `*`) y agrupar por plantilla. Vista "Errores
  agrupados": plantilla, count, primera/ultima vez, ejemplo. Clic ->
  filtra el dataset por esa plantilla.
- **Histograma temporal de resultados**: banda sobre la tabla con la
  distribucion por minuto/hora de las filas filtradas (canvas propio o
  Chart.js vendoreado). Sirve para ver picos de errores.

Verificacion: tests de la normalizacion de plantillas + smoke_phase9.py.

## Fase 10 — Base local de errores conocidos / runbooks (local)

Objetivo: "cotejar errores y dar solucion" SIN internet.

- SQLite local (`%TEMP%\logviewer\runbooks.db` o archivo del proyecto):
  tabla de patrones (regex/glob sobre el mensaje) -> {explicacion, causa
  probable, solucion, referencia interna}.
- El drawer muestra coincidencias de runbook para esa linea ("Errores
  conocidos: 1"). CRUD sencillo desde la UI (anadir patron desde una
  linea con un clic).
- Se puede precargar con los errores ya vistos en los analisis de
  LOGS RAW (Zscaler, honeypot WordPress).

Verificacion: tests del matcher de patrones + smoke_phase10.py.

## Fase 11 (DESCARTADA por el usuario, 2026-08-21) — Enriquecimiento de IPs

- Solo tendria sentido para reputacion de IPs publicas (AbuseIPDB,
  GreyNoise). Expone **solo la IP consultada** (que en logs de honeypot
  suele ser del atacante, no propia), nunca lineas completas.
- Diseño si algun dia se activa: boton manual por IP, cache en SQLite,
  key por `LOGVIEWER_<SERVICIO>_KEY`, desactivado por defecto, redactado
  en audit.log.
- **Estado: DESCARTADA por el usuario (2026-08-21)** por la restriccion de
  privacidad. No se implementa. La alternativa local era GeoIP/ASN offline
  con bases descargables (p.ej. DB-IP lite), pero quedo descartada tambien.

## Fase 12 (HECHA, 2026-08-21) — LLM local para explicar errores

- Boton "Analizar" en el drawer que manda SOLO esa linea a un LLM en
  `127.0.0.1` (LM Studio / Ollama, API OpenAI-compatible, via `urllib`).
- Nada sale de la maquina: el modelo corre local. Config:
  `LOGVIEWER_LLM_URL` (si no esta, el boton no aparece).
- Prompt fijo del sistema: explicar la linea, causa probable, pasos de
  solucion. Respuesta cacheada por hash del mensaje.

Estado: viable porque el equipo ya tiene LM Studio instalado; decidir
despues de las fases 7-10.

## Orden recomendado

7 -> 8 -> 9 -> 10 (todo local, sin riesgo) y despues decidir 11/12.
Esfuerzo estimado: 7 media, 8 media, 9 media-alta, 10 baja, 11/12 bajas.
