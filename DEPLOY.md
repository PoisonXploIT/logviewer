# Deploy a Railway (tras Cloudflare Access)

El visor se sube a Railway **solo** si el acceso va por un dominio propio
protegido con Cloudflare Access (mismo patron que sec.sammideblas.com).
Sin esa capa NO se sube: el servidor no tiene autenticacion propia.

## Porque si: Cloudflare Access, no token en la app

- La autenticacion (GitHub o codigo de un solo uso al correo) la gestiona
  Cloudflare; el codigo no cambia para autenticar.
- Detras del Access, cada peticion lleva el header
  `Cf-Access-Login-User` con el correo del usuario. El servidor lo anade
  a la auditoria (Fase 5): quedaria "quien subio/exporto/activo/quito".
  Sin el header (acceso local) se registra como "local".

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
