# EVALUACION DE SEGURIDAD — Visor de Logs Unificado v1.2 (auditoria Kimi 3)

Eres un auditor de seguridad de aplicaciones web senior. Vas a auditar una
aplicacion web local de analisis de logs escrita en Python stdlib (sin
dependencias externas). Lee el codigo REAL antes de afirmar nada: no hagas
recomendaciones genericas, verifica contra el codigo. Responde en espanol.
El objetivo es decidir si esta herramienta es segura para desplegarla a
internet detras de un proxy de autenticacion (Cloudflare Access).

## Proyecto

- Ruta: C:\Users\Sammi\Documents\Destino\LOGS RAW\logviewer-phase1
- Servidor: server.py (~134 KB, un unico archivo, solo stdlib)
- UI: static/ (index.html, app.js, styles.css, vendor/chart.min.js)
- Tests: test_parsers.py (142 tests) + smoke_phase*.py
- README.md y DEPLOY.md describen el proyecto y el modelo de despliegue.
- ESTADO.md describe el hardening ya aplicado (lee la seccion "Hardening de
  seguridad" y el contrato API).

## Contexto de despliegue (importante para el alcance)

- En LOCAL: escucha en 127.0.0.1:8765, sin autenticacion propia (es un
  visor local, no se expone).
- En PRODUCCION (Railway): se desplegaria SOLO detras de Cloudflare Access
  (autenticacion en el borde, dominio propio, URL publica de Railway
  cerrada). El servidor no autentica; usa un header de Access solo para
  atribuir la auditoria y aislar datasets por usuario. Consulta DEPLOY.md.

## Areas de auditoria (verifica CADA una contra el codigo)

1. **Path traversal**: resolve_static() y safe_session_name() en /static,
   /upload, watcher, SQLite y remove. Prueba con rutas tipo ../../ etc.
2. **Inyeccion**: los parametros de query van a SQL (SqlStore) y a FTS5.
   Verifica que son parametrizados (?, no interpolacion de strings) en
   _where, count_filtered, page_filtered, top, templates, histogram,
   runbooks, diagnose. Busca cualquier f-string SQL con input del usuario.
3. **XSS**: la UI pinta lineas de log (user-supplied). Verifica que el
   resaltado hlText() escapa antes de insertar <mark>, que el drawer y el
   contexto escapan, y que CSP protege. Prueba con una linea <script>.
4. **CSRF**: todos los POST/PUT/DELETE exigen X-CSRF-Token (GET /api/csrf).
   Verifica que ningun POST mutante se olvido el check.
5. **Zip bomb / DoS**: MAX_DECOMP_SIZE (2 GB) y limite por archivo/lote.
   Verifica que la descompresion en streaming respeta el tope ANTES de
   escribir. Busca si un archivo gigante o muchos archivos pueden agotar
   memoria/disco.
6. **Credenciales en el codigo**: SPLUNK_PASS, API keys. Verifica que no
   hay secretos hardcodeados; la contrasena de Splunk y la config del LLM
   deben venir de env vars o del store %TEMP% (no del repo).
7. **Fuga de informacion**: errores al cliente (no deben filtrar rutas
   internas ni stack traces), auditoria con la IP remota, requests.log.
8. **LLM local**: el boton Analizar/Diagnostico manda contenido a un LLM
   configurable por URL (por defecto 127.0.0.1). Verifica que un atacante
   no puede cambiar LOGVIEWER_LLM_URL via /api/settings a un destino
   arbitrario y usarlo como SSRF (si el servidor puede hacer requests a
   URLs que el cliente controla, es un vector SSRF).
9. **Splunk**: splunk_query conecta a SPLUNK_URL con basic auth. Verifica
   si la URL es fija (env) o la controla el cliente. Si el cliente puede
   elegir el SPL, ¿es un vector de exfiltracion o de acceso a Splunk?
10. **Upload**: multipart, limite de concurrentes (2), sanitizacion de
    nombres, sin guardar fuera de %TEMP%\logviewer\sessions\<usuario>.
11. **Cabeceras HTTP**: nosniff, CSP, X-Frame-Options: DENY, Content-Type
    correcto por extension en /static.
12. **CSV injection**: celdas que empiezan por = + - @ se prefijan con '.

## Metodo

- Abre server.py y recorre las funciones HTTP (do_GET, do_POST, do_PUT,
  do_DELETE) y las de parseo/SQL. Comprueba cada area con ejemplos
  concretos de entrada maliciosa.
- Para SQL y XSS, senala la linea exacta del codigo (file:line) que
  verifica o falla cada caso.
- NO sugieras añadir dependencias (pip) — el proyecto es solo stdlib por
  diseño. Las soluciones deben ser stdlib-compatible.
- Recuerda el contexto de despliegue: el servidor NO debe autenticar por si
  mismo (lo hace Access), pero si debe cerrar vectores que un atacante con
  acceso autenticado podria explotar (SSRF via LLM/Splunk, inyeccion,
  XSS, abuso de recursos).

## Informe de salida (estructura obligatoria)

Para cada area (1-12), di: [OK] (sin hallazgo), [HALLAZGO] con severidad
(Critica/Alta/Media/Baja) y evidencia file:line, o [NO APLICA]. Al final:

- RESUMEN EJECUTIVO: ¿es segura para desplegar detras de Cloudflare Access
  en su estado actual? SI / NO / SI CON CONDICIONES.
- HALLAZGOS CRITICOS/ALTOS (si los hay) ordenados por severidad, cada uno
  con: descripcion, evidencia, impacto, y fix stdlib propuesto.
- RIESGOS RESIDUALES aceptados (los que son por diseño, p. ej. header
  spoofeable de Access, datos efimeros).
- Veredicto final y condiciones para el deploy.

Se honesto: si hay un SSRF por /api/settings o /api/splunk/search,
dilo como Critico. Si no lo hay, dilo con la evidencia de por que no.
