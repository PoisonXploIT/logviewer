# Prompts para Pi — Fases 7-12 (Visor de Logs Unificado)

Instrucciones de uso:

- Copiar y pegar UN SOLO prompt a la vez, en orden (7A, 7B, ...).
- Cada prompt es autocontenido: Pi empieza leyendo ESTADO.md y PLAN.md.
- Tras cada sub-fase, HERMES verifica contra disco antes de dar luz verde
  al siguiente prompt (tests + smoke + lectura del codigo cambiado).
- Si el contexto se satura a mitad de fase, vaciar sesion y reenviar el
  MISMO prompt: ESTADO.md ya refleja lo hecho y Pi retoma donde quedo.

## Backup obligatorio ANTES de tocar nada (una sola vez)

```bash
cd "C:/Users/Sammi/Documents/Destino/LOGS RAW"
robocopy logviewer-phase1 logviewer-backup-pre7-2026-08-21 /MIR /XF __pycache__ .git /L
robocopy logviewer-phase1 logviewer-backup-pre7-2026-08-21 /MIR /XF __pycache__ .git
```

(primera linea = lista previa de lo que se copiara, segunda = copia real).
Si algo sale mal: `robocopy logviewer-backup-pre7-2026-08-21 logviewer-phase1 /MIR`.

---

# REGLAS PERMANENTES (aplican a TODOS los prompts de abajo)

Rol: implementas una fase pequena y verificable del visor de logs
(`server.py` + `static/`, solo stdlib, sin pip). Trabajas en
`C:\Users\Sammi\Documents\Destino\LOGS RAW\logviewer-phase1`.

Antes de empezar CADA prompt: leer ESTADO.md (ancla de contexto) y la
seccion de tu fase en PLAN.md. No asumas historial de conversacion.

Razonamiento: modelo local, contexto 90K. Razona lo necesario y nada mas:
- Planifica cada cambio en 1-3 frases, no en monologos.
- Ediciones mecanicas en archivos grandes (server.py ~72KB) con scripts o
  edits puntuales; NO regeneres el archivo entero.
- Verifica numeros tecnicos (columnas, nombres de API, puertos) leyendo el
  codigo real antes de afirmar nada.

Al terminar CADA sub-fase:
1. Pasar tests: `python test_parsers.py` (todos en verde).
2. Crear/actualizar su smoke_phaseN.py y pasarlo contra un servidor
   efimero en su puerto propio (mismo patron que smoke_phase2..5).
3. Actualizar ESTADO.md: estado de la sub-fase (HECHA), que cambio,
   como se verifica. Debe poder retomar una sesion nueva solo con
   ESTADO.md + PLAN.md.
4. Anotar en 000_DAYZERO_AGENT.md (vault) el resumen de la sub-fase.

Si algo rompe: detente, describe el fallo y no sigas. El backup de antes
de las fases 7-12 esta en `logviewer-backup-pre7-2026-08-21` (creado con
robocopy al principio); restaurar con robocopy si hace falta.

---

# FASE 7 — Contexto de lineas y busqueda precisa

## Prompt 7A — ts_norm + rango de fechas real

```
Proyecto: visor de logs, en logviewer-phase1 (leer ESTADO.md primero).
Tarea 7A: al parsear cada formato, normalizar el timestamp a ISO en un
campo nuevo "ts_norm" (los parsers ya devuelven "ts"; anadir ts_norm al
mismo punto donde se construye la fila y a _make_search/_COLUMNS de
SqlStore). Anadir filtros dt_from/dt_to (ISO) en /api/rows sobre ambos
backends (MemStore y SqlStore); el filtro "dt" por subcadena queda como
fallback. Tests nuevos en test_parsers.py para ts_norm y rango.
Actualizar ESTADO.md al terminar. Verificar: python test_parsers.py verde.
```

## Prompt 7B — Contexto tipo grep -C

```
Proyecto: visor de logs, logviewer-phase1 (leer ESTADO.md primero).
Tarea 7B: nueva API GET /api/context?name=&row=<rowid>&n=5 que devuelve
las n lineas anteriores y posteriores del log original (SQLite por rowid;
MemStore por indice en la lista de filas, donde se guarda el offset de
linea al parsear). En el drawer de detalle, boton "Ver contexto" que llama
a esa API y muestra las lineas raw con su numero. Tests + smoke_phase7.py
(puerto propio, subir un log pequeno y comprobar contexto). Actualizar
ESTADO.md. Verificar: test_parsers.py + smoke verde.
```

## Prompt 7C — Resaltado de la coincidencia

```
Proyecto: visor de logs, logviewer-phase1 (leer ESTADO.md primero).
Tarea 7C: resaltar el termino buscado (q/ip/path) con <mark> en la tabla
y en la linea raw del drawer. Escapar SIEMPRE antes de insertar HTML
(sin XSS); el resaltado se hace en el cliente sobre el texto ya escapado.
Tests unitarios del escape+resaltado si es factible; smoke_phase7.py
ampliado: comprobar que un <script> en el log no se inyecta. Actualizar
ESTADO.md. Verificar: tests + smoke verde.
```

## Prompt 7D — Exclusion (!) y multivalor (coma)

```
Proyecto: visor de logs, logviewer-phase1 (leer ESTADO.md primero).
Tarea 7D: en el parser de filtros del servidor, soportar prefijo "!" para
excluir (ej. !10.0.0.5) y coma para multivalor (ej. 200,301), en level/
code/ip/path/q sobre ambos backends. La UI no cambia en esta sub-fase;
lo cubren los tests. Tests nuevos de exclusion/multivalor + smoke_phase7.
Actualizar ESTADO.md. Verificar: test_parsers.py + smoke verde.
```

---

# FASE 8 — Full-text search con FTS5

## Prompt 8A — Tabla FTS5 external-content sobre "search"

```
Proyecto: visor de logs, logviewer-phase1 (leer ESTADO.md primero).
Tarea 8A: en SqlStore._create_schema, crear tabla virtual FTS5
external-content unida a la columna existente "search" (no duplicar
datos; content=rows). Alimentarla durante la carga streaming y en
add_rows del tail. Anadir indices b-tree en ts_norm, level, code, ip si
aun no existen. Tests: dataset grande (forzar umbral bajo) con FTS5
presente y coherente con "search". Actualizar ESTADO.md. Verificar:
test_parsers.py verde.
```

## Prompt 8B — MATCH en /api/rows cuando es SQLite

```
Proyecto: visor de logs, logviewer-phase1 (leer ESTADO.md primero).
Tarea 8B: /api/rows? q= usa FTS5 MATCH sobre "search" cuando el backend
es SqlStore; MemStore sigue con subcadena. TRADUCCION DE FILTROS A FTS:
el prefijo de exclusion "!" (Fase 7D) se traduce al operador NOT/- de
FTS5, y el multivalor por coma a OR entre terminos; si la combinacion no
es exacta en FTS, documentalo en un comentario y usa MATCH + clausulas
SQL normales para lo que FTS no cubra (p. ej. ip NOT LIKE). Ranking por
relevancia opcional (bm25) solo cuando no hay otros filtros. Tests:
paridad de resultados entre subcadena y MATCH en los casos cubiertos.
Actualizar ESTADO.md. Verificar: tests verde.
```

## Prompt 8C — Benchmark 2M lineas + smoke

```
Proyecto: visor de logs, logviewer-phase1 (leer ESTADO.md primero).
Tarea 8C: benchmark con el set de ~2M lineas de la Fase 4: tiempo de
busqueda q= antes (instr sobre search) vs despues (FTS5 MATCH), con y
sin indice; anadir los numeros a ESTADO.md (dataset, segundos, mejora).
smoke_phase8.py en puerto propio: subir un dataset grande por encima del
umbral, comprobar que /api/rows responde con FTS5 y que el backend dice
"sqlite". Actualizar ESTADO.md. Verificar: smoke verde + benchmark
ejecutado de verdad (no simulado).
```

---

# FASE 9 — Errores agrupados + histograma

## Prompt 9A — Columna "template" calculada en el parseo (CRITICA)

```
Proyecto: visor de logs, logviewer-phase1 (leer ESTADO.md primero).
Tarea 9A (PUNTO CRITICO A ESCALA): NO normalizar la plantilla sobre la
marcha en SQL. En vez de eso, anadir una columna "template" calculada
EN EL PARSING (mismo punto donde se hace _make_search y ts_norm):
normalizar numeros, IPs, rutas y hex a "*" y guardar el resultado.
Anadirla a SqlStore._COLUMNS y al insert. Tests de la normalizacion
(casos: con IP, con hex largo, con numeros en medio, mensaje ya limpio).
Actualizar ESTADO.md. Verificar: test_parsers.py verde.
```

## Prompt 9B — Vista "Errores agrupados"

```
Proyecto: visor de logs, logviewer-phase1 (leer ESTADO.md primero).
Tarea 9B: nueva API GET /api/templates?name=&min= que agrupa por columna
"template" (GROUP BY en SqlStore; agregacion en MemStore) y devuelve:
plantilla, count, primera/ultima vez, una linea de ejemplo. UI: seccion o
tab "Errores agrupados" con esa tabla; clic en una plantilla filtra el
dataset por ella. Tests de la API + smoke_phase9.py. Actualizar ESTADO.md.
Verificar: tests + smoke verde.
```

## Prompt 9C — Histograma temporal

```
Proyecto: visor de logs, logviewer-phase1 (leer ESTADO.md primero).
Tarea 9C: banda de histograma sobre la tabla con la distribucion por
minuto/hora de las filas FILTRADAS (usar ts_norm; granularidad conmutable
minuto/hora). API GET /api/histogram?name=... con los mismos filtros que
/api/rows. UI: canvas propio o Chart.js vendoreado (ya esta en static/
vendor); clic en una barra aplica ese rango de fechas a la tabla. Tests
de la API + smoke_phase9.py. Actualizar ESTADO.md. Verificar: tests +
smoke verde.
```

---

# FASE 10 — Runbooks locales (errores conocidos)

## Prompt 10A — BD runbooks + matcher de patrones

```
Proyecto: visor de logs, logviewer-phase1 (leer ESTADO.md primero).
Tarea 10A: SQLite local en %TEMP%\logviewer\runbooks.db (no muere con el
dataset): tabla de patrones (regex/glob sobre msg) -> {explicacion, causa
probable, solucion, referencia interna}. API POST /api/runbooks (crear),
GET (lista), DELETE (quitar). Matcher: dado un msg, devuelve los runbooks
que coinciden. Tests del matcher (regex, glob, sin coincidencia, varios).
Actualizar ESTADO.md. Verificar: test_parsers.py verde.
```

## Prompt 10B — Drawer: "Errores conocidos" + alta desde una linea

```
Proyecto: visor de logs, logviewer-phase1 (leer ESTADO.md primero).
Tarea 10B: el drawer de detalle muestra las coincidencias de runbook para
esa linea ("Errores conocidos: N") con su explicacion/solucion. Boton para
crear un runbook desde la linea actual (prellenando el patron) y para
editar/borrarlo. CRUD minimo desde la UI sobre /api/runbooks. smoke_phase10.py
(subir log, abrir drawer, comprobar que aparece el runbook precargado).
Actualizar ESTADO.md. Verificar: tests + smoke verde.
```

## Prompt 10C — Precarga de runbooks

```
Proyecto: visor de logs, logviewer-phase1 (leer ESTADO.md primero).
Tarea 10C: script precargar_runbooks.py que inserta los errores ya vistos
en los analisis de LOGS RAW (Zscaler, honeypot WordPress) como runbooks
iniciales (patron, explicacion, causa probable, solucion, referencia
interna al fichero del vault). Ejecutarlo una vez y dejarlo re-ejecutable
(idempotente por patron). Actualizar ESTADO.md con la lista de runbooks
precargados. Verificar: script ejecutado de verdad + tests verde.
```

---

# FASE 11 — Reputacion de IPs (EN CUARENTENA, NO IMPLEMENTAR)

No se implementa nada sin decision expresa del usuario. Si algun dia se
activa: boton manual por IP, cache en SQLite, key por env var
LOGVIEWER_<SERVICIO>_KEY, desactivado por defecto, redactado en audit.log.
Alternativa local permitida sin salir a internet: GeoIP/ASN offline con
bases descargables (DB-IP lite) consultadas desde disco, como "Fase 11-local".

## Prompt 11A — SOLO si el usuario pide activarla explicitamente

```
Proyecto: visor de logs, logviewer-phase1 (leer ESTADO.md primero).
Tarea 11A: [PREGUNTAR AL USUARIO antes de elegir: GeoIP offline local o
AbuseIPDB/GreyNetwork con su key]. Implementar la variante elegida. Sin
decision expresa del usuario, NO hacer nada y actualizar ESTADO.md
anotando que la Fase 11 sigue en cuarentena.
```

---

# FASE 12 — LLM local para explicar errores (OPCIONAL)

## Prompt 12A — Boton "Analizar" contra 127.0.0.1

```
Proyecto: visor de logs, logviewer-phase1 (leer ESTADO.md primero).
Tarea 12A: boton "Analizar" en el drawer que manda SOLO esa linea a un LLM
en 127.0.0.1 (LM Studio/Ollama, API OpenAI-compatible, via urllib).
Config LOGVIEWER_LLM_URL; si no esta definida, el boton NO aparece.
Prompt fijo del sistema: explicar la linea, causa probable, pasos de
solucion. Respuesta cacheada por hash del mensaje en SQLite.
PUNTO CRITICO: si el LLM no responde (503/timeout/conexion negada), el
boton debe fallar limpiamente (mensaje amigable "el LLM local no esta
disponible"), NUNCA colgar la peticion; timeout corto (10 s). Tests del
cache + smoke_phase12.py con un mock de LLM en 127.0.0.1 y otro caso con
el puerto caido. Actualizar ESTADO.md. Verificar: tests + smoke verde.
```

---

# Checklist de verificacion de Hermes (NO es prompt de Pi)

Tras CADA sub-fase, Hermes verifica contra disco antes de dar luz verde:
- `python test_parsers.py` ejecutado de verdad (no auto-reporte).
- El smoke_phaseN.py correspondiente pasa.
- Lectura del diff real en server.py/static/ (el cambio existe y es el
  descrito en ESTADO.md).
- ESTADO.md actualizado con la sub-fase HECHA y su verificacion.
