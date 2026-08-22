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
- Fase 7A (HECHA): ts_norm + rango de fechas real. Cada fila lleva "ts_norm"
  (ISO canónico, calculado con norm_ts() al parsear: carga streaming y tail).
  Acepta CLF (21/Aug/2026:...), ISO 8601 (T o espacio, fraccion, Z u offset)
  y epoch (s/ms); con tz -> UTC, sin tz -> hora local; si no parsea, "".
  Filtros dt_from/dt_to (ISO) en /api/rows sobre MemStore (comparacion
  lexicografica de ts_norm) y SqlStore (WHERE ts_norm >= / <=; columna
  anadida a COLUMNS). El filtro "dt" por subcadena queda como fallback.
- Fase 7B (HECHA): contexto tipo grep -C. Cada fila lleva "_line" (numero
  de linea 0-based en el archivo, guardado al parsear: parsers lo emiten y
  _flush/_tail lo hacen absoluto). GET /api/context?name=&row=&n=5 devuelve
  before/current/after del log original (leido por streaming con errores=
  replace); row = indice de lista en MemStore ("_idx" mantenido en add_rows,
  expuesto como "rowid" en page_filtered) o rowid en SQLite (columna nueva
  "line INTEGER" en la tabla; SqlStore.line_of(rowid)). UI: boton "Ver
  contexto" en el drawer (solo si la fila tiene rowid), muestra las lineas
  raw con su numero y resalta la actual. smoke_phase7.py (puerto 8795).
- Fase 7C (HECHA): resaltado de coincidencias. hlText() en app.js: escapa el
  texto y envuelve las coincidencias de los filtros activos (q/ip/path) en
  <mark>; el split con grupo de captura se hace sobre el texto original y
  cada trozo se escapa por separado, asi un "<script>" del log no se inyecta.
  Se aplica a celdas de la tabla, raw del drawer y lineas de contexto.
  Verificado en navegador real (CDP): 0 elementos script inyectados,
  <mark> presente en tabla y drawer, boton de contexto funcional.
- Fase 7D (HECHA): exclusion y multivalor en filtros. parse_terms() +
  terms_pass(): coma = multivalor (OR), prefijo "!" por termino = exclusion
  (AND NOT); sin positivos solo aplican las exclusiones; level/code siguen
  exactos, ip/path/q subcadena insensible a mayusculas. MemStore lo usa en
  apply_filters; SqlStore via _field_clause() (IN / != para exactos,
  instr(lower(...)) > 0 / = 0 para subcadena) con paridad garantizada.
  La UI no cambia en esta sub-fase. Tests de paridad MemStore/SQLite +
  smoke_phase7.py (level=!INF, q multivalor, combinado).
- Fase 8A (HECHA): FTS5 external-content. En SqlStore._create_schema:
  tabla virtual `fts USING fts5(search, content='rows',
  content_rowid='rowid')` unida a la columna search existente (sin
  duplicar datos); se alimenta en _insert_rows (carga streaming, tail y
  migracion comparten ese punto) con los rowids del lote; si la BD venia
  de una version anterior sin FTS, `rebuild` al abrir. Indices b-tree
  nuevos: idx_ts_norm e idx_ip (level/code ya existian). Tests: dataset
  grande forzando SQLITE_THRESHOLD=100 -> SqlStore con fts coherente.
- Fase 8B (HECHA): /api/rows con q usa FTS5 MATCH cuando es SqlStore
  (_fts_clause en _where): multivalor a OR de frases, "!" a operador NOT
  de FTS5; sin positivos no hay MATCH posible y se cae a clausulas SQL
  instr(lower(search), lower(?)) = 0 (documentado); frase entre comas
  dobles = aproximacion del match por subcadena con varios tokens.
  MemStore sigue por subcadena. Ranking bm25: opcional y no implementado
  de momento. Tests de paridad substring/MATCH en casos cubiertos.
- Fase 8C (HECHA): benchmark 2M lineas + smoke_phase8.py (puerto 8794,
  umbral forzado a 1000: /api/summary dice backend=sqlite y q responde
  por FTS). Benchmark real (benchmark_fts.py, set determinista de 2M
  lineas / 121 MB, seed fija):
    * Carga + parseo + FTS: ~40 s. Rebuild FTS (BD vieja): ~5 s.
    * instr (antes): siempre ~0.48 s sin importar selectividad
      (escaneo completo; no hay indice posible sobre search).
    * FTS MATCH (despues): token raro 0.0000 s (~1000x mejor);
      termino medio (153k hits) ~0.23 s; frase que matchea TODO
      (2M hits) ~0.69 s (el coste es materializar 2M rowids).
  BUG corregido de paso: re-subir un dataset con el mismo nombre
  apilaba filas sobre la BD anterior (migrate_to_sqlite abria la BD
  vieja). Ahora _load_worker cierra el dataset viejo antes de parsear
  y load_file borra restos de .db/.wal/.shm al empezar. Test de
  regresion: test_reupload_same_name_no_dup.
- Fase 9A (HECHA): columna `template` calculada EN EL PARSING (nunca
  normalizada sobre la marcha en SQL). make_template() normaliza IPs,
  hex largo y numeros a '*' (regex RE_TPL_IP/HEX/NUM) y se guarda en
  r["template"] en los dos puntos donde ya se hace _make_search/ts_norm
  (_flush de carga streaming y tail). Añadida a SqlStore.COLUMNS (salta
  al insert, SELECT y schema; load_file borra la BD vieja asi no hay
  esquema antiguo sin la columna). Tests: IP, hex largo, numeros en
  medio, ya limpio, vacio/None + integracion MemStore/SqlStore.
- Fase 9B (HECHA): vista 'Errores agrupados'. API GET /api/templates?name=&min=
  -> store.templates() en ambos backends: GROUP BY template con COUNT,
  MIN/MAX(ts_norm), ejemplo = raw de la primera fila del grupo
  (HAVING c >= min, ORDER BY c DESC LIMIT 200; agregacion equivalente en
  MemStore). Filtro nuevo `tpl` (exacto) en /api/rows: apply_filters y
  SqlStore._where. UI: panel plegable 'Errores agrupados' (Veces,
  Plantilla, Primera/Ultima vez, Ejemplo); clic en una fila aplica el
  filtro tpl a la tabla (input #ftpl sincronizado). Verificado en
  navegador real via CDP (perfil aislado :9222): panel abre con 3
  plantillas, top count=4, clic filtra a '4 filas'. smoke_phase9.py
  (puerto 8793) verde.
- Fase 9C (HECHA): histograma temporal. API GET /api/histogram?name=&gran=min|h
  -> store.histogram(q, gran) en ambos backends: buckets por truncado de
  ts_norm (16 chars = minuto, 13 = hora), respeta TODOS los filtros de
  /api/rows (level/code/ip/path/q/dt/tpl/rango); SQL con
  substr(ts_norm,1,N) GROUP BY. UI: banda sobre la tabla con canvas
  (min/hora), clic en una barra aplica el rango [from, ultimo segundo]
  a los filtros dt_from/dt_to (inputs #fdfrom/#fdto nuevos, visibles y
  editables). Verificado CDP: 3 buckets minuto / 2 hora, clic filtra a
  '4 filas' sin solaparse con la barra vecina. smoke_phase9.py ampliado
  (buckets [4,1,1] min y [4,2] hora; filtrado por tpl) verde.
- Fase 10A (HECHA): BD runbooks persistente + matcher de patrones. SQLite en
  %TEMP%\logviewer\runbooks.db (NO se borra al arrancar ni al quitar el
  dataset; fuera de la limpieza de main()). RunbookStore: tabla runbooks
  (id, pattern, kind regex|glob, explicacion, causa, solucion, ref,
  created_at) + indice UNIQUE sobre pattern (idempotencia para 10C).
  match_runbooks(msg, rbs): regex -> re.search (compilacion cacheada con
  lru_cache), glob -> fnmatch sobre el msg entero; patron invalido NUNCA
  coincide (no rompe la lista). API: POST /api/runbooks (valida pattern y
  compila el regex antes de guardar; duplicado por patron -> 409),
  GET /api/runbooks (lista), DELETE /api/runbooks?id= (do_DELETE nuevo con
  CSRF como do_POST), GET /api/runbooks/match?msg= (runbooks que coinciden).
  Auditoria: acciones runbook_add / runbook_del. Tests TestRunbooks:
  regex, glob, sin coincidencia, varios/orden, patron invalido,
  vacio/None + CRUD del store en BD temporal. Verificado por HTTP
  (CSRF 403, regex invalido 400, alta 200, duplicado 409, match, DELETE).
- Fase 10B (HECHA): drawer "Errores conocidos" + CRUD de runbooks desde la UI.
  Drawer: seccion nueva bajo el contexto que consulta
  /api/runbooks/match?msg=<msg de la fila> al abrir y pinta
  "Errores conocidos: N" con una tarjeta por match (patron, tipo,
  explicacion, causa probable, solucion, referencia interna) + botones
  Editar/Borrar. Boton "Nuevo runbook desde esta linea" abre el editor
  prellenando patron = msg de la fila con kind=glob (el matcher prueba el
  patron contra msg, asi que al guardar coincide de inmediato). Editor:
  modal propio (#rb-modal) con patron/tipo/explicacion/causa/solucion/ref;
  alta -> POST, edicion -> PUT /api/runbooks?id= (do_PUT nuevo con CSRF,
  RunbookStore.update, 400 patron/regex invalido, 409 duplicado, 404 inexistente,
  auditoria runbook_edit), borrar -> DELETE con confirm(). CSS: .drawer-rb,
  .rb-card, modal-backdrop/modal-panel. Verificado con CDP (p10_ui.log):
  drawer muestra 1 match con solucion, alta desde la linea prellena
  pattern+glob y deja 2 matches, borrar los dos deja 0.
- Fase 10C (HECHA): precarga idempotente de runbooks con precargar_runbooks.py
  (stdlib, usa server.runbooks_store(); valida todos los regex ANTES de
  tocar la BD; el UNIQUE INDEX sobre pattern hace re-ejecutable: lo que ya
  existe se cuenta como "ya existe"). Ejecutado: 13 creados, segunda
  corrida 0 creados / 13 ya existian. Verificado con msgs reales:
  msg ZSATunnel "ConvertInterfaceLuidToAlias Failed..." coincide con su
  runbook; linea raw real del dump de access (fr34k.php) coincide con el
  suyo. Runbooks precargados (patron regex, kind regex salvo nota):
    * Zscaler (8): ConvertInterfaceLuidToAlias Failed | getValue: failed
      for Registry.*VHSignature | reading registry: HKEY_LOCAL_MACHINE |
      Exception getting local socket's zpn port | Resolving OnNet dns
      hostname failed | PerformSDRequest\(\) Exception: Connection refused |
      BRK_MT_CLOSED_FROM_ASSISTANT | Failed to parse NP tunnel ip.
    * Honeypot WordPress (5): fr34k\.php (webshell RCE) | ee-upload-
      engine\.php (CVE-2022-1119) | xp_cmdshell (SQLi->RCE) | pmahomme
      (phpMyAdmin expuesto) | 197\.13\.28\. (fuerza bruta cluster).
    Cada uno con explicacion, causa probable, solucion y referencia interna
    al fichero del vault (ZSAService/ZSATunnel de LOGS RAW/Zscaler e
    INFORME_Accesos_WordPress_Honeypot.md / 00_METODO_POST.md de access/).
    AVISO: smoke_phase10.py borra TODOS los runbooks (limpieza defensiva);
    si se re-ejecuta, volver a correr precargar_runbooks.py.
- Fase 12A (HECHA): boton "Analizar" en el drawer -> LLM local
  OpenAI-compatible via urllib. Config LOGVIEWER_LLM_URL (base, p. ej.
  http://127.0.0.1:8080/v1 de LM Studio o :11434/v1 de Ollama) y opcional
  LOGVIEWER_LLM_MODEL (defecto "local"); si no esta definida el boton NO
  aparece (GET /api/config -> {llm:false}) y POST /api/analyze da 404.
  Prompt fijo del sistema: explicar la linea, causa probable y pasos de
  solucion. Solo se manda ESA linea (row.raw). Respuesta cacheada por hash
  (sha256(modelo + linea)) en %TEMP%\logviewer\llm_cache.db (persistente,
  fuera de la limpieza de arranque); los fallos NUNCA se cachean.
  PUNTOS CRITICOS cubiertos: max_tokens generoso (4096) porque los modelos
  de RAZONAMIENTO devuelven "reasoning_content" y un "content" que puede
  llegar vacio si el presupuesto se gasta en razonar -> si content llega
  vacio sale como error amigable "el LLM no devolvio texto" (503), nunca
  como exito con explicacion vacia. Timeout corto (10 s): 503/timeout/
  conexion negada fallan limpio con mensaje amigable y NUNCA cuelgan la
  peticion. UI: seccion "Analizar con LLM local" en el drawer (#anwrap),
  visible solo si /api/config dice llm:true; clic -> POST /api/analyze;
  segunda vez sale de cache con prefijo [cache]. Verificado por CDP:
  boton aparece, primera respuesta del mock sin cache, segunda con [cache].
- Fase 12B (HECHA): selector de idioma de la respuesta del LLM + guia de
  uso. SettingsStore gana "llm_lang" (default "auto"; set valida auto/es/
  en y un valor invalido cae a "auto"); llm_config() expone "lang"; el
  prompt del sistema es ahora llm_system_prompt(lang) ("auto" -> idioma de
  la linea, "es" -> espanol, "en" -> ingles) y ask_llm/llm_key lo aceptan
  como parametro: el cache distingue idiomas (misma linea, es/en -> hashes
  distintos). /api/analyze pasa el lang de llm_config() a ask_llm y a
  llm_key. GET/POST /api/settings exponen y aceptan "lang"; auditoria
  settings_update incluye llm_lang. UI: select "Idioma de la respuesta"
  (auto/es/en) en el modal #llm-modal; openLlmModal lo rellena,
  saveLlmModal lo envia y tras guardar refresca app.llmEnabled y el
  drawer (#an-result se muestra tal cual, sin traducir). Boton de ayuda
  (icono de interrogacion) en la cabecera -> modal #help-modal con guia
  breve en espanol: cargar log, filtrar, contexto de una linea, tail en
  vivo, exportar y seccion LLM local (Analizar esta en el drawer al abrir
  una fila, solo manda ESA linea, idioma configurable en ajustes). Cache-
  busting ?v= subido a 9 (app.js) y 7 (styles.css). Tests: TestLLMLang
  (default auto, set es/en, invalido cae a auto, llm_key es/en distintos,
  prompt por idioma); smoke_phase12.py actualizado (/api/settings acepta
  lang, valor invalido cae a auto, el analyze lo pasa al prompt end-to-end,
  llm_key distingue es/en). Verificado con LLM local real (qwen3.8-27b-xl,
  :8096; :8081 estaba caido en la verificacion): lang=es responde en
  espanol. NO se cambia el idioma global de la interfaz: sigue en espanol
  (ver PENDIENTE DE DECIDIR).
- Fase 12C (HECHA): boton "Diagnostico rapido" -> el LLM local resume TODAS
  las lineas de error del dataset activo. API POST /api/diagnose {name,
  level?} (level por defecto ERR). NUNCA se mandan miles de lineas al LLM:
  solo las plantillas unicas (mismo computo que /api/templates, ahora con
  filtro por nivel: store.templates(level=) en MemStore y SqlStore) con su
  count y una linea de ejemplo. Maximo DIAGNOSE_MAX_PER_CALL=50 plantillas
  por llamada; si hay mas, loteo en pila (run_diagnose): llamadas
  secuenciales donde cada una lleva el resumen acumulado de los lotes
  anteriores y la ultima genera la conclusion final unica (60 plantillas
  -> 2 llamadas: 50 + [resumen+10]). Tope total DIAGNOSE_TOTAL_MAX=200
  (mismo que /api/templates). Cache por hash de dataset+level+lang(+modelo)
  en llm_cache.db (diagnose_key reusa llm_key); los fallos NUNCA se
  cachean. Respuesta {cached, conclusion, top:[{template,count,linea}] (top
  10 por count), analyzed}. La conclusion pide explicitamente la(s)
  plantilla(s) de MAYOR count con su linea de ejemplo (accionable). Auditoria
  "diagnose" (name, level, analyzed, cached/error). Timeout y lang del LLM
  los mismos de /api/analyze (llm_config). UI: boton en la sidebar (icono
  alerta, sin emojis), visible solo si /api/config dice llm:true y habilitado
  con dataset activo; al pulsar abre modal #diag-modal con "Analizando N
  plantillas..." (N previo via /api/templates?level=ERR, que ahora acepta
  level) y pinta la conclusion + lista top. Cache-busting ?v=10 (app.js) /
  8 (styles.css). Tests: TestDiagnose (60 plantillas -> 2 llamadas; 50 -> 1;
  vacio no pregunta; fallo nunca es exito; clave por dataset+level+lang+
  modelo); smoke_phase12.py ampliado (seccion E: sube p12c.log con 3
  plantillas ERR, el mock ecoa el prompt y se comprueba que van
  plantillas+count y no lineas sueltas, conclusion + top[0].count=5, la
  segunda vez cached sin nueva llamada). Verificado con LLM local real
  (qwen3.8-27b-xl en :8096; :8081 caido al probar): lang=es -> conclusion en
  espanol que apunta a la plantilla mas frecuente (5 ocurrencias) con su
  linea de ejemplo, y CDP: boton visible, modal abre con conclusion + top,
  cierre OK. NO sale nada a internet: solo el mismo ask_llm contra
  LOGVIEWER_LLM_URL (localhost).
- Fase 13 (HECHA): ingesta desde Splunk local. Config por env: SPLUNK_URL
  (defecto https://localhost:8089), SPLUNK_USER (defecto Sammi) y
  SPLUNK_PASS (si falta, la seccion NO aparece en la UI; /api/config ->
  {splunk:false}). La contrasena NUNCA va en el codigo: solo env vars.
  Backend: splunk_query() con urllib (TLS CERT_NONE como curl -k del
  script de referencia scripts/splunk_search.sh, basic auth) contra
  POST /services/search/jobs (exec_mode=oneshot, output_mode=json,
  earliest_time=0); fuerza el prefijo "search " si falta (peculiaridad de
  este Splunk 10.4). Tope duro SPLUNK_MAX_ROWS=5000 filas por dataset
  (el SPL filtra y agrega; no se traen 2M filas). API: GET
  /api/splunk/sources (indices via REST /services/data/2.0/indexes;
  INFORMATIVO: si el usuario no puede listar (404 en este entorno) lo
  documenta y sigue sirviendo la ingesta; primary=botsv3) y POST
  /api/splunk/search {search, name?, count?} -> dataset MemStore con
  format="splunk" que queda ACTIVO: msg = campo "line" o k=v de los
  campos, raw = JSON de los campos, ip por src_ip/ip/src/clientip,
  ts por _time (epoch -> norm_ts), level vacio. Auditoria: splunk_search
  (con el SPL truncado a 200 chars) y splunk_sources. Maquinaría existente:
  /api/rows (filtros q/ip...), /api/templates, /api/export (csv/json),
  KPIs e histograma funcionan sobre el dataset; el contexto de linea NO
  aplica (404 en /api/context + boton oculto en la UI: no hay archivo
  original). Diagnóstico rápido y plantillas: los datasets Splunk no
  tienen niveles syslog, asi _diagnose cae a TODAS las plantillas si no
  hay filas ERR y /api/templates ignora el level (format=splunk).
  UI: seccion "Importar de Splunk" en la sidebar (#splunk-wrap, visible
  solo si /api/config dice splunk:true) con textarea SPL + boton
  "Buscar y cargar" -> POST /api/splunk/search, refresca sesiones y
  carga el dashboard (app.fmt="splunk"). Cache-busting ?v=11 (app.js) /
  9 (styles.css). Tests: TestSplunkQuery en test_parsers.py (7 tests con
  mock HTTP real en 127.0.0.1: prefijo search, URL/auth basic/cuerpo
  oneshot, tope de count, puerto caido -> ValueError amigable, flag
  splunk_enabled, filtro de indices internos _, conversión de filas
  _time/line/ip/raw/template/_search). smoke_phase13.py (puerto 8792)
  contra el Splunk REAL: query de password spray en botsv3 (failureReason
  "Invalid username or password" | stats count by ipAddress,
  userPrincipalName | where count >= 2 | head 10) -> dataset activo con
  filas reales, filtros, plantillas, export ndjson, contexto 404,
  /api/diagnose con LLM mock (conclusion [smoke-llm]) y auditoria
  splunk_search. La contrasena la lee del env SPLUNK_PASS o del default
  del script de referencia (no esta en el repo). NO sale nada a internet:
  solo Splunk local + LLM localhost.

  NOTA IMPORTANTE (verificado 2026-08-21, me costo un 404): en botsv3 el
  sourcetype ms:aad:signin guarda los datos (userPrincipalName, ipAddress,
  failureReason, loginStatus) DENTRO del campo _raw como JSON, NO como
  campos top-level. Un stats count by ipAddress, userPrincipalName sin
  spath devuelve 0 filas (la query del smoke original falla asi). La query
  correcta para AAD es: search index=botsv3 sourcetype="ms:aad:signin" |
  spath | where loginStatus!="Success" AND failureReason!="null" | stats
  count by userPrincipalName, ipAddress, failureReason | sort - count |
  head 10. El password spray real de froth.ly: fyodor (16, 199.66.91.253),
  klagerfield (8+, misma IP 199.66.91.253) -> patron de pulverizacion que
  el Diagnostico rapido detecta. Para sourcetypes planos (linux_secure,
  WinEventLog 4625) los campos SI son top-level y spath sobra.
- Fase 11 (DESCARTADA a peticion del usuario, 2026-08-21): reputacion de IPs
  NO se implementa (nada sale a internet). Restriccion de diseño: ningun
  dato de los logs sale a internet (todo local; LLM solo en localhost).
  Backup pre-fases 7-12:
  logviewer-backup-pre7-2026-08-21 (robocopy /MIR, sin __pycache__/.git).

## PENDIENTE DE DECIDIR (no es un fallo)
- Idioma global de la interfaz (Fase 12B, fuera de alcance a peticion):
  hoy solo cambia el idioma en que RESPONDE el LLM; la UI sigue en
  espanol. Hacer i18n de toda la interfaz seria un cambio grande (las
  cadenas estan repartidas entre index.html y app.js, sin capa de
  traduccion); queda como idea pendiente de decidir.
- Probar que modelo local encaja mejor con el boton "Analizar" (Fase 12A).
  Candidatos: el M (Qwen3.8-27B IQ2_M, :8086), el XL (Qwen3.8-27B Q2_K_XL,
  :8096, 90K ctx) y el MoE 35B A3B (Qwen3.6-35b, benchmark bueno con datos).
  NO hay que tocar codigo: basta LOGVIEWER_LLM_URL (base, p. ej.
  http://127.0.0.1:8096/v1) + LOGVIEWER_LLM_MODEL para apuntar al que se
  pruebe; el visor lee la env var al arrancar. Hacer la prueba en el futuro
  cuando el usuario lo pida; decidir por calidad de respuesta y velocidad
  (prefiere velocidad sobre precision en inferencia local).

## VERSION 1.2 (2026-08-21) — marcada en la UI (brand-sub "Unificado · v1.2")
- Guia de uso ampliada con las funciones nuevas: "Diagnostico rapido"
  (Fase 12C) e "Importar de Splunk" (Fase 13), incluida la nota del
  `| spath` para ms:aad:signin. Cache-busting subido a ?v=12.
- SSRF secure: el destino del LLM SOLO puede ser loopback (localhost/127.x).
  Triple capa: _is_loopback/_llm_url_host (host literal, sin DNS),
  rechazo 400 en POST /api/settings al guardar, y _LoopbackRedirectHandler
  que no sigue redirecciones a no-loopback (cierra el SSRF ciego por 302).
  Verificado: 169.254.169.254 y hostname interno -> 400; redirect 302 a
  no-loopback -> bloqueado; loopback legitimo funciona. UI: "v1.2 · SSRF
  secure".
- Una sola base de codigo para local y nube (Railway): las funciones se
  condicionan por /api/config y, cuando una NO esta disponible en la
  version desplegada, se muestra un AVISO claro en lenguaje humano (no
  solo ocultar el boton):
    * LLM (llm:false): en el drawer, la seccion "Analizar con LLM local"
      (#anwrap) SIEMPRE es visible; con llm:true sale el boton Analizar y
      con llm:false sale el aviso "El analisis con LLM es una funcion SOLO
      local: no envia ningun dato a internet y requiere un modelo que corra
      en tu maquina. En esta version web no esta disponible." + (si hay
      repo_url) "Descarga la version local desde el repositorio" con enlace.
      Sin LOGVIEWER_REPO_URL, el aviso se muestra sin enlace.
    * LLM caido (llm:true pero sin respuesta): el error de /api/analyze
      sale en lenguaje humano: "no se pudo contactar con el modelo local:
      comprueba que esta arrancado y que la URL en Ajustes es correcta. Si
      no funciona, puede que esta version web no tenga acceso a tu modelo
      local"; el 503 queda como estado tecnico de la peticion, no como
      mensaje principal.
    * Splunk (splunk:false): la seccion "Importar de Splunk"
      (#splunk-wrap) SIEMPRE es visible; con splunk:true la caja SPL y con
      splunk:false el aviso "La conexion a Splunk la configura el operador
      del servidor. En esta version no hay Splunk conectado." (sin caja de
      texto ni boton). Con splunk:true pero Splunk caido: 502 con "El
      Splunk no responde: contacta con el operador del servidor para que
      revise la conexion".
    * Config nueva: LOGVIEWER_REPO_URL (env, opcional) -> /api/config lo
      expone como "repo_url". Sin cambios de seguridad: el SSRF loopback se
      mantiene intacto y nada sale a internet.
  Tests: TestEnvNotices en test_parsers.py (public_config expone repo_url
  con/sin env, wiring del aviso del drawer y del enlace, mensajes de
  conexion LLM/Splunk en lenguaje humano); smoke_phase12.py ampliado
  (seccion F: con llm:false, /api/config da repo_url y la UI servida trae el
  aviso "SOLO local" con el enlace ligado a app.repoUrl y el aviso Splunk
  del operador; ademas el dataset de 12C ahora se nombra unico por corrida
  para que la cache de diagnose no rompa la re-ejecucion). Verificado CDP
  (llm:false + repo_url: drawer con aviso y href=repo_url; sin repo_url:
  aviso sin enlace; llm:true: boton y sin aviso; splunk:false: aviso del
  operador sin caja SPL; LLM caido: mensaje humano en #an-result).
  Cache-busting ?v=13 (app.js) / 10 (styles.css).

## AUDITORIA DE SEGURIDAD (2026-08-21) — modelo local Qwen3.8-27B XL
- Resultado: SEGURA PARA DESPLEGAR DETRAS DE CLOUDFLARE ACCESS, con
  condiciones. Ver AUDITORIA_SEGURIDAD_PROMPT.md (el prompt) y el informe
  completo en la sesion. Sin hallazgos criticos/altos.
- [OK] path traversal, SQL injection, XSS, CSRF, zip bomb, secretos, fuga
  de info, upload, cabeceras, CSV injection, SSRF por settings/LLM/Splunk.
- [BAJA, arreglado] SSRF ciego por redireccion: urlopen seguia 302 a
  no-loopback. Fix: _LoopbackRedirectHandler. Verificado con mock 302.
- Condiciones de deploy (operativas, de DEPLOY.md): (1) cerrar URL publica
  de Railway, (2) LOGVIEWER_REQUIRE_CF=1, (3) dominio + CNAME + Access.
- Riesgos residuales aceptados por diseño: header Cf-Access spoofeable,
  stores compartidos entre usuarios (runbooks/settings/llm_cache),
  credencial Splunk compartida, datos efimeros.

## VERSION 1.3+ — PENDIENTES BLOQUEADOS POR EVALUACION DE SEGURIDAD
El usuario quiere este orden: evaluacion de seguridad de la herramienta
(modelo cloud Kimi 3) -> si es fiable, publicar. NO tocar hasta que pase.
1. Evaluacion de seguridad con Kimi 3 (modelo cloud) como auditoria.
2. Subir la herramienta a un repo PRIVADO de GitHub (git init en
   logviewer-phase1, remoto privado, .gitignore ya existe).
3. Deploy a Railway (ya hay railway.json + DEPLOY.md de la Fase 6; el
   server ya lee $PORT y escucha 0.0.0.0). Revisar que la Fase 6 sigue
   valida tras las fases 7-13.
4. Actualizar la web sammideblas.com con las funciones de la herramienta:
   post 0x74 ya borrado en Destino/BLOG/Posts, falta pasar a HTML Blogger
   con capturas reales (placeholder IMG_01..IMG_11) y deploy.
- El post 0x74 queda con placeholders IMG_xx a sustituir por URLs de
  Blogger una vez se tomen las capturas.

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
- GET  /api/runbooks            lista runbooks (BD persistente, Fase 10A)
- POST /api/runbooks            {pattern, kind regex|glob, explicacion,
                                 causa, solucion, ref} -> runbook creado;
                                 400 patron/regex invalido, 409 duplicado
- DELETE /api/runbooks?id=N     quita un runbook (404 si no existe)
- GET  /api/runbooks/match?msg= runbooks cuyo patron coincide con el msg
- PUT  /api/runbooks?id=N         edicion (mismas validaciones que el POST)
- GET  /api/config            {llm: bool, url, model, timeout, splunk,
                             repo_url}
                             (Fase 12A: decide si aparece el boton
                             Analizar; Fase 13: "splunk" = hay SPLUNK_PASS,
                             decide si aparece la seccion de Splunk;
                             repo_url = LOGVIEWER_REPO_URL, enlace de
                             descarga de la version local en los avisos de
                             funciones SOLO local; vacio si no esta)
- GET  /api/splunk/sources    {indexes, primary, hint} o {indexes:[],
                             note, primary, hint} si el usuario no puede
                             listar indices (Fase 13; solo con SPLUNK_PASS)
- POST /api/splunk/search     {search, name?, count?} -> ejecuta el SPL en
                             Splunk local y crea un dataset MemStore activo
                             con format="splunk" ({name, rows}); tope duro
                             SPLUNK_MAX_ROWS=5000; 404 sin SPLUNK_PASS,
                             502 amigable si la query/Conexion falla,
                             404 si no devuelve filas (Fase 13)
- GET  /api/settings          config del LLM {llm, url, model, timeout,
                             lang} (persistente en settings.json; Fase 12B:
                             "lang" auto/es/en es el idioma de la respuesta)
- POST /api/settings          {url?, model?, timeout?, lang?}; valida URL
                             (http/https) y timeout (>=1); un lang invalido
                             cae a "auto"; auditoria settings_update
- POST /api/analyze           {line} -> {cached, answer}; cache por hash del
                             mensaje; 503 con mensaje amigable si el LLM no
                             responde o devuelve content vacio (razonamiento);
                             404 si LOGVIEWER_LLM_URL no esta definida
- POST /api/diagnose          {name, level?} -> {cached, conclusion,
                             top:[{template,count,linea}], analyzed}; resume
                             con el LLM local las plantillas unicas del nivel
                             (defecto ERR) del dataset; max 50 plantillas por
                             llamada (loteo en pila si hay mas); cache por
                             hash de dataset+level+lang(+modelo); fallos no
                             se cachean (503 amigable); 404 sin LLM ni sin
                             dataset (Fase 12C)
- GET  /api/templates?name=&min=&level=   level opcional: solo filas de ese
                             nivel exacto (Fase 12C; antes era min/limit)

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
- python test_parsers.py          (148 tests; TestSplunkQuery = Fase 13,
                                   TestEnvNotices = avisos SOLO local v1.2)
- python smoke_phase2.py          (sube a un servidor en :8799)
- python smoke_phase3.py          (tail en vivo en :8798)
- python smoke_phase4.py          (backend SQLite hibrido en :8797)
- python smoke_phase5.py          (export JSON Lines + auditoria en :8796)
- python smoke_phase7.py          (ts_norm + rango + contexto en :8795)
- python smoke_phase8.py          (FTS5 backend sqlite en :8794)
- python smoke_phase9.py          (template + /api/templates + histograma en :8793)
- python smoke_phase10.py         (runbooks: precarga, match, 400/409, PUT, DELETE)
- python smoke_phase13.py         (ingesta Splunk real en :8792: password
                                   spray en botsv3 -> dataset activo, filtros,
                                   plantillas, export ndjson, contexto 404,
                                   /api/diagnose con LLM mock y auditoria
                                   splunk_search; la contrasena por env
                                   SPLUNK_PASS o default del script)
- python smoke_phase12.py         (12A: LLM mock + cache + razonamiento vacio
                                   en :8790, puerto caido en :8789, sin LLM
                                   en :8788; 12B: /api/settings con lang,
                                   invalido cae a auto, prompt end-to-end y
                                   llm_key es/en distintos; 12C: /api/diagnose
                                   conclusion+top con plantillas ERR y cache)
- python precargar_runbooks.py    (10C: idempotente; re-ejecutarlo si el
                                  smoke de la Fase 10 limpio la BD)
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

## Arreglos post-revision (2026-08-21)
- Modo presentacion roto: al ocultar el sidebar, `.app-body` seguia con
  `grid-template-columns: 220px 1fr` y la tabla caia en la columna de 220px
  (no se veia nada util). Fix CSS: `body.present .app-body` pasa a `1fr` y
  `body.present #tblwrap` pierde el `max-height: 560px` (flex: 1, tabla a
  pantalla completa). Se sale con el boton "Presentacion" (sigue visible en
  la cabecera de la tabla), la tecla `p` o Esc. Verificado con screenshots.
- `#count` (cabecera de la tabla) se quedaba en "Cargando..." para siempre:
  `renderRows` nunca lo actualizaba tras cargar. Ahora muestra "N filas".
- Layout desbordado (banda vacia de 150px arriba + scroll de pagina):
  el sprite `<svg hidden>` NO se ocultaba (el atributo `hidden` no aplica
  a elementos SVG en Chrome) y, como hijo flex de body, se bloqueificaba
  con el tamaño por defecto de 300x150. Fix: clase `hidden` en el svg.
  Ademas el layout queda fijo al viewport: `body { height: 100vh;
  overflow: hidden }`, `.main` con scroll interno (`overflow-y: auto` +
  `min-height: 0`), sidebar sin sticky (rellena la columna y scrollea
  sola) y filas `auto 1fr` en el responsive. En modo presentacion la
  tabla va de 0 a 100vh exactos, sin scroll de pagina.
- Cache-busting de assets estaticos subido a `?v=4` en index.html.

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
