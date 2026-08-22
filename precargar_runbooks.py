#!/usr/bin/env python3
"""Fase 10C: precarga de runbooks (errores conocidos) en la BD persistente.

Inserta como runbooks iniciales los errores ya vistos en los analisis de
LOGS RAW (Zscaler y honeypot WordPress). Cada entrada lleva patron, tipo
(regex|glob), explicacion, causa probable, solucion y referencia interna
al fichero del vault donde se verifico el hallazgo.

Idempotente por patron: la tabla tiene indice UNIQUE sobre pattern, asi
re-ejecutar el script NO duplica nada (los que ya existen se cuentan como
"ya existe"). Los regex se validan ANTE de tocar la BD: si un patron no
compila, el script falla sin insertar nada.

Nota: smoke_phase10.py hace limpieza defensiva y borra TODOS los runbooks
(al inicio y al final). Si lo re-ejecutas, vuelve a correr este script
despues para dejar la precarga en su sitio.

Uso:  python precargar_runbooks.py
Salida: codigo 0 si todo bien (creados + ya existentes), 1 si un patron
invalido impide continuar.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server  # noqa: E402  (mismo modulo que el visor; stdlib only)

# Referencias internas al vault (LOGS RAW).
ZSC = ("LOGS RAW/Zscaler/ZSAService_2026-05-11-11-04-39.026725.log")
ZSC_T = ("LOGS RAW/Zscaler/extracted/  (ZSATunnel/ZSATray del mismo dump)")
HON = ("LOGS RAW/INFORME_Accesos_WordPress_Honeypot.md")

# (patron, kind, explicacion, causa probable, solucion, ref)
RUNBOOKS = [
    # ---------------------------------------------------------------- Zscaler
    (r"ConvertInterfaceLuidToAlias Failed", "regex",
     "Zscaler no pudo convertir el LUID de la interfaz a alias; es el ERR "
     "mas frecuente del dump (57+61 apariciones).",
     "Adaptador cambiado o aun no listo cuando arranco el servicio, o datos "
     "WMI desactualizados tras un cambio de red.",
     "Reintentar; si persiste, reiniciar el servicio Zscaler (ZSA) o "
     "reiniciar la maquina; verificar que el adaptador activo sea el "
     "esperado.",
     "LOGS RAW/Zscaler/extracted/  (ZSATunnel del mismo dump)"),

    (r"getValue: failed for Registry.*VHSignature", "regex",
     "Lectura fallida de la clave VHSignature del registro "
     "(Error 0x00000002 = no existe).",
     "Clave opcional ausente en sistemas sin Virtual Hardening; es el "
     "estado normal de esta maquina.",
     "Informativo: no actuar salvo que aparezca junto a otros errores del "
     "mismo proceso.",
     "LOGS RAW/Zscaler/extracted/  (ZSATrayManager/ZSATunnel del dump)"),

    (r"reading registry: HKEY_LOCAL_MACHINE", "regex",
     "Error 0x00000002 leyendo claves de HKLM del perfil de Zscaler.",
     "Lectura transitoria durante el arranque, antes de que el perfil se "
     "aplique por completo.",
     "Reintentar; si persiste tras aplicar el perfil, revisar integridad "
     "del registro (sfc) y re-instalar Zscaler como ultimo recurso.", ZSC),

    (r"Exception getting local socket's zpn port", "regex",
     "El broker ZPN no encontro puerto valido en el socket local al "
     "preparar la conexion privada.",
     "Estado transitorio mientras el tunel se (re)conecta; el socket aun "
     "no esta listo.",
     "Reintentar; si persiste, revisar conectividad hacia la gateway ZPN y "
     "reiniciar el servicio del tunel.",
     "LOGS RAW/Zscaler/extracted/  (ZSATunnel del mismo dump)"),

    (r"Resolving OnNet dns hostname failed", "regex",
     "Fallo de resolucion DNS para los hosts PAC (pac.zscloud.net / "
     "pac.zscalertwo.net); sin PAC no hay politica proxy correcta.",
     "DNS caido, filtrado o split-horizon mal configurado en la red local.",
     "Probar nslookup del host afectado; si persiste, revisar politica DNS/"
     "proxy y el estado del ZIA con la red corporativa.",
     "LOGS RAW/Zscaler/extracted/  (ZSATunnel del mismo dump)"),

    (r"PerformSDRequest\(\) Exception: Connection refused", "regex",
     "ZSD no pudo completar una SD Request: conexion rechazada en el "
     "puerto destino.",
     "Servicio local aun arrancando o bloqueo de red puntual hacia el "
     "destino.",
     "Reintentar; si persiste, reiniciar el servicio Zscaler y verificar "
     "que no haya firewall cortando el rango de puertos del tunel.",
     "LOGS RAW/Zscaler/extracted/  (ZSATrayManager del mismo dump)"),

    (r"BRK_MT_CLOSED_FROM_ASSISTANT", "regex",
     "El tunel ZPN termino porque el extremo remoto (assistant) lo cerro: "
     "zpn_mtunnel_end.",
     "Rekey, roaming o cambio de politica desde la nube; cierre legitimo "
     "del lado servidor.",
     "Es transitorio y se reconecta solo; si se repite a menudo, revisar "
     "licencias/site del ZPN en consola.", ZSC_T),

    (r"Failed to parse NP tunnel ip", "regex",
     "addTrafficForwardingFilters fallo al parsear la IP del tunel NP "
     "(ip vacia); los filtros de trafico se omiten mientras tanto.",
     "Estado transitorio: el tunel aun no tiene IP asignada en ese momento.",
     "Normal si desaparece cuando el tunel sube; si persiste, reiniciar la "
     "componente ZTNA y verificar que la interfaz NP exista.", ZSC_T),

    # ------------------------------------------- Honeypot WordPress (access/)
    (r"fr34k\.php", "regex",
     "Ejecucion del webshell fr34k.php en /wp-content/uploads/simple-file-"
     "list/ (17 peticiones, 16x 200). Compromiso RCE confirmado.",
     "Subida sin autenticar via CVE-2022-1119 (Simple File List) y uso "
     "posterior por el atacante (103.69.55.212).",
     "Aislar el host, borrar el archivo, rotar credenciales y revisar "
     "accesos; en este dataset es material de practica: documentado como "
     "hallazgo CRITICO del informe.", HON),

    (r"ee-upload-engine\.php", "regex",
     "POST al motor de subida de Simple File List: la puerta de entrada del "
     "webshell (200 desde 119.241.22.121).",
     "CVE-2022-1119: endpoint de subida sin autenticacion en el plugin.",
     "Actualizar/quitar el plugin, revisar la carpeta uploads por archivos "
     "dudosos y bloquear el endpoint si no se usa.", HON),

    (r"xp_cmdshell", "regex",
     "Inyeccion SQL avanzada (UNION SELECT sobre information_schema) con "
     "intento de RCE via EXEC xp_cmdshell('cat ../../etc/passwd') en "
     "wp-login.php (parametro mglS=).",
     "Atacante probando cadena completa SQLi->RCE contra la autenticacion "
     "de WordPress; una peticion 200, el resto 403.",
     "Verificar integridad de BD y web (la 200 es sospechosa), WAF/limitar "
     "acceso a wp-login.php y revisar las lineas 216-223 del POST dump.",
     HON + " (00_METODO_POST.md:216-223, IP_168_22_54_119.md)"),

    (r"pmahomme", "regex",
     "Carga de la UI de phpMyAdmin 5.0.4 expuesto en la raiz del sitio "
     "(tema pmahomme, js/config.js, editor SQL) por 156.32.113.25 y "
     "116.23.212.69.",
     "phpMyAdmin colocado junto al WordPress sin proteccion: acceso "
     "directo potencial a toda la BD.",
     "Quitarlo de la raiz web o protegerlo (auth + red restringida); "
     "revisar credenciales de BD usadas por el sitio.", HON),

    (r"197\.13\.28\.", "regex",
     "Cluster 197.13.28.x (11 IPs, .11 a .71) haciendo fuerza bruta "
     "distribuida contra wp-login.php; todas las peticiones cortadas a 403 "
     "por Better WP Security / Loginizer.",
     "Botnet/proxy pool de fuerza bruta distribuida, ruido de fondo del "
     "dataset (horas 05-16).",
     "El bloqueador ya lo frena: verificar que las 403 sigan asi y no "
     "aparezcan 200/302 desde ese cluster; rate-limit si se quiere reducir "
     "ruido.", HON),
]


def main():
    # Validar todos los regex ANTES de tocar la BD (fail fast).
    bad = []
    for pat, kind, *_ in RUNBOOKS:
        if kind == "regex":
            try:
                re.compile(pat)
            except re.error as e:
                bad.append((pat, str(e)))
    if bad:
        print("PATRONES INVALIDOS (nada se inserto):")
        for pat, err in bad:
            print("  - %s -> %s" % (pat, err))
        return 1

    store = server.runbooks_store()
    created, existed = [], []
    for pat, kind, expl, causa, sol, ref in RUNBOOKS:
        try:
            rb = store.add(pat, kind=kind, explicacion=expl, causa=causa,
                           solucion=sol, ref=ref)
            created.append((rb["id"], pat))
        except ValueError:
            existed.append(pat)

    print("Precarga de runbooks (Fase 10C):")
    for rid, pat in created:
        print("  creado   #%d  %s" % (rid, pat))
    for pat in existed:
        print("  ya existe  %s" % pat)
    print("Total: %d creados, %d ya existian, %d en la BD."
          % (len(created), len(existed), len(store.all())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
