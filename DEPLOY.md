# Deploy a Railway (tras Cloudflare Access)

El visor se sube a Railway **solo** si el acceso va por un dominio propio
protegido con Cloudflare Access (mismo patron que sec.sammideblas.com).
Sin esa capa NO se sube: el servidor no tiene autenticacion propia.

## Porque si: Cloudflare Access, no token en la app

- La autenticacion (GitHub o codigo de un solo uso al correo) la gestiona
  Cloudflare; el codigo no cambia para autenticar.
- Detras del Access, cada peticion lleva el header
  `Cf-Access-Authenticated-User-Email` con el correo del usuario. El servidor lo anade
  a la auditoria (Fase 5): quedaria "quien subio/exporto/activo/quito".
  Sin el header (acceso local) se registra como "local".
  (Nota: el header real de Cloudflare Access es `Cf-Access-Authenticated-User-Email`;
  `Cf-Access-Login-User` se mantiene solo como fallback de compatibilidad.)

## Modelo de confianza (leelo antes de operar el deploy)

- El header `Cf-Access-Authenticated-User-Email` es **spoofeable**: cualquier cliente
  puede enviarlo. El servidor solo lo usa para (a) atribuir la auditoria
  y (b) aislar los datasets por usuario. NO autoriza nada: la
  autenticacion la hace Access en el borde.
- Por eso el paso 3 (cerrar la URL publica de Railway) es innegociable:
  si el origen es alcanzable directamente, un atacante puede subirse el
  header de quien sea y, peor, usar el visor sin autenticacion.
- `LOGVIEWER_REQUIRE_CF=1` (variable de entorno en Railway) endurece
  esto: el servidor rechaza con 403 cualquier peticion sin el header.
  No cierra el acceso directo (un atacante con la URL abierta puede
  enviar el header el mismo), pero elimina el uso anonimo y deja cada
  accion rastroable: la auditoria guarda la IP remota, asi que si el
  header esta falseado se ve de que IP sale. La unica defensa real contra
  la URL abierta sigue siendo el paso 3.
  (No se valida el JWT `Cf_Authorization` en el origen: firmatura
  Ed25519 de Cloudflare, y el proyecto es solo stdlib; la validacion la
  hace Access en el borde.)
- La auditoria guarda ademas la IP remota de cada peticion: si el header
  esta falseado, la IP ayuda a rastrear de donde sale.
- Anti-CSRF: `GET /api/csrf` sirve un token por proceso y todos los POST
  lo exigen en el header `X-CSRF-Token` (403 si falta). Un sitio ajeno no
  puede leer el token (CORS) ni anadir el header sin preflight.
- Aislamiento por usuario: cada usuario solo ve, exporta y borra sus
  propios datasets; las copias van en `sessions/<usuario>/` y las BD
  SQLite en `sqlite/<usuario>/` (dos usuarios con el mismo nombre de
  archivo ya no se pisan).
- Cabeceras: `X-Content-Type-Options: nosniff` en todo; CSP estricta +
  `X-Frame-Options: DENY` en la pagina HTML.
- CSV: las celdas que empiezan por `=`, `+`, `-`, `@` se prefijan con `'`
  (anti inyeccion de formulas en Excel).
- Uploads: maximo 2 subidas concurrentes (503 si el servidor esta
  ocupado); las excepciones de carga se loguean y al cliente se le dice
  poco (sin rutas internas).

## Cambios de codigo que ya hay (Fase 6)

- `main()` lee `$PORT` (la que inyecta Railway) y escucha en `0.0.0.0`.
  En local sigue igual: sin `$PORT` escucha en `127.0.0.1:8765`.
  - `python server.py`            -> 127.0.0.1:8765 (local, como antes)
  - `python server.py 9000`       -> 127.0.0.1:9000
  - `PORT=8000 python server.py`  -> 0.0.0.0:8000 (estilo Railway)
  - `--host 0.0.0.0` fuerza la direccion de escucha en cualquier caso.
- La auditoria registra el campo `user` (header de Access o "local").

## Pasos de deploy

1. **Railway**: crear servicio desde esta carpeta (o conectar el repo).
   Nixpacks detecta Python y arranca con `python server.py`
   (`railway.json`). Railway inyecta `$PORT`; el servidor se adapta solo.
2. **Dominio**: en el servicio de Railway, anadir un dominio propio
   (p. ej. `logs.sammideblas.com`) y crear el CNAME que pida Railway.
   En Cloudflare, anadir ese CNAME a la zona.
3. **CIERRA LA PUERTA DIRECTA (el paso que no se salta)**: en Railway,
   desactivar la URL publica del servicio (`*.up.railway.app`).
   Cloudflare Access solo protege el trafico que pasa por tu dominio;
   la URL de Railway seguiria dando acceso directo sin autenticar.
   Con la URL publica desactivada, la unica puerta es el dominio.
4. **Cloudflare Access**: crear una politica para la ruta del dominio
   (mismo flujo que la de sec.sammideblas.com):
   - Insignia: el equipo/usuario (p. ej. login por GitHub).
   - Dominio: el CNAME de Railway.
   - Acciones permitidas: `GET`, `POST` (hacen falta POST para
     /upload, /api/activate, /api/remove, /api/watch).
5. **Probar**:
   - Con la URL de Railway directa: debe dar error de conexion
     (puerta cerrada).
   - Por el dominio sin sesion: Access pide login.
   - Por el dominio con sesion: carga el visor; subir un archivo y ver en
     el panel "Auditoria" que la entrada lleva tu correo en "user".

## Datos: efimeros (Opcion A, a proposito)

El disco del contenedor se borra en cada deploy/reinicio. Los datasets,
las copias temporales y las BD SQLite mueren con el contenedor: se sube
el log, se mira, se cierra. Es un visor, no un almacen. La auditoria en
memoria tambien se borra; el archivo `audit.log` del temp muere igual.
Si un dia hace falta persistencia, se monta un Shared Disk de Railway y
se apunta `LOGVIEWER_DATA_DIR` (hoy no existe; seria una fase aparte).

## Limites y RAM (plan Hobby: 8 GB RAM, 8 vCPU)

- Con 8 GB, la subida entera en memoria (pico de hasta 1 GB por lote)
  entra con margen. El streaming de la subida (anotado en ESTADO.md)
  queda en pausa: no hace falta con este plan.
- Limites actuales: 500 MB por archivo, 1 GB por lote, 2 GB
  descomprimido. Si un dia se fuga la URL, un archivo gigante no mata
  la instancia, pero si se quiere endurecer, bajar MAX_SIZE/TOTAL_MAX
  en server.py es un cambio de una linea.
- Datasets grandes van a SQLite (Fase 4); con 8 GB aguantan logs de
  decenas de millones de lineas sin problema.

## Checklist antes de dar por hecho el deploy

- [ ] Dominio propio enganchado al servicio (CNAME en Cloudflare).
- [ ] URL publica de Railway desactivada (la puerta directa esta cerrada).
- [ ] Politica de Access activa (GET + POST) con la insignia de equipo.
- [ ] Subida de prueba: la auditoria muestra el correo de Access.
- [ ] Sin sesion de Access: el dominio pide login, no carga el visor.
- [ ] `LOGVIEWER_REQUIRE_CF=1` puesta en las variables de Railway.
