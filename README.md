# Visor de Logs Unificado

Servidor web local (Python, solo stdlib, sin dependencias) para ver y filtrar
cualquier archivo de logs en el navegador. Resuelve el problema del visor
estatico anterior: el log NUNCA se embebe en el HTML; todo el filtrado se hace
en el servidor y el navegador solo recibe la pagina pedida.

Fase 1: rediseño visual corporativo, tema claro/oscuro, dashboard con
sidebar, KPIs con sparklines, graficos vendoreados (Chart.js), drawer de
detalle de fila y panel de filtros plegable. 100% offline (air-gapped).

Fase 2: multi-archivo con sesiones, compresion (.gz/.bz2/.xz/.zip), deteccion
de encoding, cola de carga con progreso y errores amigables.

## Arrancar

```bash
cd "C:\Users\Sammi\Documents\Destino\LOGS RAW\logviewer-phase1"
python server.py
```

Luego abrir en el navegador:

```
http://127.0.0.1:8765/
```

- Puerto configurable: `python server.py 9000`
- El servidor solo escucha en 127.0.0.1 (no se expone a la red).
- Al arrancar se limpia la carpeta temporal `%TEMP%\logviewer\`.
- Maximo de archivo: 500 MB; maximo por lote de subida: 1 GB.
- Extensiones aceptadas: `.log .txt .csv .json .gz .bz2 .xz .zip`

## Formatos soportados (deteccion automatica)

| Formato | Deteccion | Campos extraidos |
|---|---|---|
| Apache/NCS (CLF) | >70% de lineas matchean el regex CLF | ip, fecha, metodo, path, codigo, bytes |
| W3C Extended (IIS) | primera linea `#Fields` | columnas mapeadas a ip, fecha, metodo, path, codigo, bytes |
| JSON Lines | >70% de lineas son JSON | ts/time/timestamp, level/lvl, msg/message, ip/client_ip |
| Syslog RFC 5424 | >70% de lineas `VERSION ISO-fecha ...` | timestamp, hostname, app, pid, msg |
| Generico | >70% de lineas `fecha hora NIVEL msg` | fecha, hora, nivel (INF/WRN/ERR/CRIT/DBG), msg |
| RAW | nada de lo anterior | lineas tal cual |

Niveles normalizados: INF/INFO, WRN/WARN/WARNING, ERR/ERROR, CRIT/FATAL,
DBG/DEBUG/TRACE. Las lineas que no se parsean dentro de un formato aparecen
como nivel RAW. Cada fila conserva ademas la linea `raw` original (usada en
el drawer de detalle).

## Interfaz (Fase 1)

- **Header corporativo**: logo, titulo, indicador de estado (sin archivo /
  cargando / N lineas) y boton de tema claro/oscuro (persistido en
  localStorage).
- **Sidebar** con acciones: Cargar archivo, Tail en vivo (Fase 3, desactivado),
  Exportar CSV, Limpiar. Tarjeta con el archivo cargado (nombre, formato,
  tamano, lineas).
- **KPIs en cards** con icono, valor grande y sparkline de la distribucion
  (top 10 del contador correspondiente).
- **Segmentacion** con graficos Chart.js vendoreados: top IPs/paths (barras
  horizontales), codigos HTTP o niveles (donut), top hosts/apps (syslog).
  Clic en un segmento aplica el filtro.
- **Panel de filtros plegable** (estado persistido) agrupado por categoria:
  nivel, codigo HTTP, IP/path, fecha/texto libre. Contador de filtros activos.
- **Tabla profesional**: cabecera sticky, hover, badges de nivel/codigo,
  boton de copiar en cada celda, fila clicables que abren el **drawer de
  detalle** (campos parseados en clave-valor + linea raw con boton copiar).
  Cerrar con Esc.
- **Estado vacio** con guia rapida de 3 pasos.

## Como se usa

1. Arranca el servidor y abre `http://127.0.0.1:8765/`.
2. Arrastra uno o varios archivos de logs a la pagina o haz clic en
   "Cargar archivo". El navegador los sube al servidor, que los guarda en
   `%TEMP%\logviewer\sessions\`, detecta el formato y el encoding y parsea
   cada archivo en segundo plano (se ve la barra de progreso por archivo).
   Se aceptan archivos comprimidos `.gz`, `.bz2`, `.xz` y `.zip` (la
   deteccion es por magico, no por extension).
3. Cada archivo cargado aparece en el panel **Sesiones** del sidebar.
   Se cambia de archivo con un clic y se quita con la x. El archivo activo
   es el que se muestra en el dashboard.
   - **KPIs**: lineas totales, IPs unicas, paths unicos, codigos HTTP, niveles.
   - **Segmentacion**: graficos de top IPs, paths, codigos, niveles, hosts/apps.
   - **Tabla**: paginada a 500 filas por pagina, con anterior/siguiente.
4. **Filtros combinables** (todos se aplican en el servidor):
   - Nivel: chips clicables (Todos / INF / WRN / ERR / CRIT / DBG / RAW).
   - Codigo HTTP: chips clicables (Apache/W3C).
   - IP: texto (subcadena).
   - Path: texto (subcadena).
   - Texto libre: busca en todos los campos.
   - Fecha/hora: acepta `HH:MM:SS`, `YYYY-MM-DD` o `YYYY-MM-DD HH:MM`
     (busca por subcadena en la marca de tiempo de cada linea).
   - Tambien puedes hacer clic en un segmento de los graficos o en un chip
     para aplicarlo como filtro.
5. **Exportar**: exporta las lineas filtradas a CSV o JSON Lines (el
   selector "Formato" de la barra de la tabla elige el formato).
6. **Presets de filtros**: guarda el estado actual de filtros con un
   nombre ("Guardar preset actual" en el sidebar) y aplicalo con un clic.
   Se conservan en el navegador (localStorage).
7. **Auditoria**: el panel "Auditoria" del sidebar muestra las acciones
   registradas (subidas, cargas, exports, activaciones, borrados).
8. **Modo presentacion**: el boton "Presentacion" (o la tecla `p`) oculta
   sidebar, header y filtros y deja la tabla a pantalla completa. Esc lo
   cierra.

## API del servidor

| Metodo | Ruta | Que hace |
|---|---|---|
| GET | `/` | Sirve la interfaz (static/index.html) |
| GET | `/static/*` | Sirve assets de static/ (incluye subcarpetas, anti path traversal) |
| POST | `/upload` | Recibe uno o varios archivos (multipart), valida, guarda y lanza la carga en segundo plano |
| GET | `/api/sessions` | Lista los datasets de la sesion y el activo |
| POST | `/api/activate` | `{"name": "..."}`: cambia el dataset activo |
| POST | `/api/remove` | `{"name": "..."}`: quita un dataset de la sesion |
| GET | `/api/progress?name=` | Progreso de carga de un archivo (phase, pct, message) |
| GET | `/api/summary?name=` | KPIs del dataset (por defecto el activo) |
| GET | `/api/rows?name=&level=&code=&ip=&path=&q=&dt=&page=&size=` | Filtra en el servidor y devuelve la pagina (incluye campo `raw`) |
| GET | `/api/top?name=&field=ip&limit=30` | Top N por campo (ip, path, code, level, method, host, app) |
| GET | `/api/export?name=&format=csv\|json&level=&code=&ip=&path=&q=&dt=` | Descarga CSV o JSON Lines con las lineas filtradas (format por defecto csv) |
| GET | `/api/audit` | Entradas de auditoria (upload, loaded, export, activate, remove) |

## Estructura

```
logviewer-phase1/
├── server.py          # Servidor + parseo + API (todo en un archivo)
├── static/
│   ├── index.html     # Estructura HTML + sprite de iconos SVG
│   ├── styles.css     # Estilos con variables de tema claro/oscuro
│   ├── app.js         # Logica: modulos api, theme, ui, filters, charts, table
│   ├── logo.svg       # Logo placeholder
│   └── vendor/
│       └── chart.min.js  # Chart.js 4.5.1 vendoreado (offline)
├── test_parsers.py    # Tests de parsers, filtros y rutas estaticas
└── README.md
```

## Archivos generados

- `%TEMP%\logviewer\` - copia temporal del archivo cargado (se limpia al
  arrancar el servidor) + `requests.log` (log de peticiones, para diagnosticar).

## Backend hibrido (Fase 4)

- La carga es en streaming: no carga el archivo entero en memoria, parsea en
  lotes. Si el numero de filas supera el umbral (SQLITE_THRESHOLD, 200000 por
  defecto), migra a un backend SQLite; si no, queda en memoria. El filtrado,
  el top N, los KPIs, el tail y el export funcionan sobre ambos backends.
- El campo "Fecha/hora" busca por subcadena en la marca de tiempo tal como
  aparece en el log (cada formato usa su propio formato de fecha).

## Fase 5: presets, export JSON Lines, auditoria, presentacion, atajos

- **Presets de filtros** (localStorage): guarda el estado actual de filtros
  con un nombre y aplicalo con un clic. Se conservan en el navegador.
- **Export JSON Lines**: ademas de CSV, se puede exportar las filas
  filtradas como JSON Lines (una linea JSON por fila, incluye el campo
  `raw`). El selector "Formato" de la barra de la tabla elige el formato.
- **Auditoria**: registro de acciones relevantes (upload, loaded, export,
  activate, remove) en memoria y en `%TEMP%\logviewer\audit.log`. Se consulta
  con `GET /api/audit` y se ve en el panel "Auditoria" del sidebar.
- **Modo presentacion**: oculta sidebar, header y filtros y deja la tabla
  a pantalla completa. Boton "Presentacion" o tecla `p`; Esc lo cierra.
- **Atajos de teclado**: `p` presentacion, `t` tail, `e` export, `/` texto
  libre, `g` IP, `Esc` cierra el drawer o sale de presentacion. No se
  disparan si el foco esta en un campo de texto.
- **ARIA**: roles y `aria-label` en presets, drawer y auditoria; el estado
  y los toasts usan `role="status"` / `aria-live`.

## Seguridad

- **Autenticacion**: la hace Cloudflare Access en el borde (el servidor no
  autentica). El header `Cf-Access-Authenticated-User-Email` (el que inyecta
  Access; `Cf-Access-Login-User` queda como fallback) es *spoofeable*: solo se usa
  para atribuir la auditoria y aislar los datasets por usuario, no para
  autorizar. Con `LOGVIEWER_REQUIRE_CF=1` se rechaza con 403 el acceso
  anonimo al origen (peticiones sin el header); la auditoria guarda la IP
  remota de cada accion para poder rastrear un header falseado. La defensa
  real contra la URL de Railway abierta sigue siendo cerrarla (DEPLOY.md).
- **Aislamiento por usuario**: cada usuario solo ve, exporta y borra sus
  propios datasets. Las copias temporales van en
  `%TEMP%\logviewer\sessions\<usuario>\` y las BD SQLite en
  `%TEMP%\logviewer\sqlite\<usuario>\` (dos usuarios con el mismo nombre
  de archivo ya no se pisan).
- **Anti-CSRF**: `GET /api/csrf` devuelve un token por proceso; todos los
  POST lo exigen en el header `X-CSRF-Token` (403 si falta). Un sitio
  ajeno no puede leer el token (CORS) ni anadir el header sin preflight.
- **Cabeceras**: `X-Content-Type-Options: nosniff` en todas las respuestas;
  CSP estricta + `X-Frame-Options: DENY` en la pagina HTML (sin JS inline).
- **XSS**: todo el contenido de los logs se escapa al renderizar, incluidos
  los niveles desconocidos en los chips de nivel.
- **CSV**: las celdas que empiezan por `=`, `+`, `-`, `@` (o con tab/salto
  de linea) se prefijan con `'` para evitar inyeccion de formulas en
  Excel/LibreOffice.
- **Uploads**: maximo 2 subidas concurrentes (cada una puede leer hasta
  1 GB del cuerpo en RAM); 503 si el servidor esta ocupado.
- **Errores**: las excepciones de carga se loguean a `requests.log` y al
  cliente se le devuelve un mensaje generico (sin rutas internas).

## Roadmap

- Fase 2 (hecho): compresion (.gz/.bz2/.xz/.zip), deteccion de encoding,
  multi-upload con sesiones, progreso de carga, errores amigables.
- Fase 3 (hecho): tail en vivo (/api/watch, /api/tail, UI con polling).
- Fase 4 (hecho): backend SQLite hibrido (umbral por tamano) para logs de
  varios GB; carga en streaming.
- Fase 5 (hecho): presets de filtros, export JSON Lines, auditoria de
  acciones, modo presentacion, atajos de teclado y ARIA.
