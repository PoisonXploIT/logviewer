#!/usr/bin/env python3
"""Smoke visual de la UI (H1, 2026-10-30): se VEN en la pagina de 8877.

Comprueba en el navegador (CDP 127.0.0.1:9222) lo que la API ya confirmo:
filtros de URL aplicados, selector de columnas, empty state, dashboard SOC
y runbooks de OperVanta en el drawer. Solo stdlib + node para el CDP.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

REPO = os.path.dirname(os.path.abspath(__file__))
BT = r"C:\Users\Sammi\.pi\agent\skills\browser-tools"
BASE = "http://127.0.0.1:8877"
results = []


def record(name, ok, detail=""):
    results.append((name, ok, detail))
    print("%s  %s  %s" % ("OK   " if ok else "FALLO", name, detail))


def nav(url, new=False):
    cmd = ["node", BT + r"\browser-nav.js", url]
    if new:
        cmd.append("--new")
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=90).stdout


def eval_js(js):
    r = subprocess.run(["node", BT + r"\browser-eval.js", js],
                       capture_output=True, text=True, timeout=90)
    out = (r.stdout or "").strip()
    try:
        return json.loads(out)
    except ValueError:
        return {"raw": out[:300], "stderr": (r.stderr or "")[:200]}


JS_READY = """
JSON.stringify({
  sessions: document.querySelectorAll('#sessions .session-item').length,
  active: (document.getElementById('file-name')||{}).textContent || '',
  appReady: typeof app === 'object'
})
"""

JS_FILTERS = """
JSON.stringify({
  q: (document.getElementById('fq')||{}).value || '',
  levelChips: document.querySelectorAll('#lvchips .chip, #lvchips button').length,
  rows: document.querySelectorAll('#tbody tr[data-idx]').length,
  count: (document.getElementById('filters-count')||{}).textContent || '',
  kpis: (document.getElementById('kpis')||{}).textContent || ''
})
"""

JS_COLS = """
(() => {
  document.getElementById('cols-toggle').click();
  return JSON.stringify({
    panelVisible: !document.getElementById('cols-panel').classList.contains('hidden'),
    chips: document.querySelectorAll('#cols-list button, #cols-list .col-chip').length,
    help: (document.querySelector('.cols-help')||{}).textContent.trim().slice(0,60)
  });
})()
"""

JS_EMPTY = """
JSON.stringify({
  noResults: !document.getElementById('no-results').classList.contains('hidden'),
  msg: (document.querySelector('.no-results-msg')||{}).textContent || '',
  rows: document.querySelectorAll('#tbody tr[data-idx]').length
})
"""

JS_SOC = """
(() => { document.getElementById('act-soc').click(); return 'click'; })()
"""

JS_SOC_READ = """
JSON.stringify({
  modalVisible: !document.getElementById('soc-modal').classList.contains('hidden'),
  status: (document.getElementById('soc-status')||{}).textContent || '',
  sevChips: document.querySelectorAll('#soc-sev-chips .soc-chip').length,
  tareaChips: document.querySelectorAll('#soc-tarea-chips .soc-chip').length,
  fuenteRows: document.querySelectorAll('#soc-fuente-table tbody tr').length,
  alertRows: document.querySelectorAll('#soc-alert-table tbody tr').length
})
"""

JS_DRAWER = """
(() => {
  const tr = document.querySelector('#tbody tr[data-idx]');
  if (tr) tr.dispatchEvent(new MouseEvent('dblclick', {bubbles: true}));
  return JSON.stringify({opened: !document.getElementById('drawer').classList.contains('hidden')});
})()
"""

JS_RB = """
JSON.stringify({
  count: (document.getElementById('rb-count')||{}).textContent || '',
  items: document.querySelectorAll('#rb-list .rb-card, #rb-list article, #rb-list button[data-id]').length,
  text: (document.getElementById('rb-list')||{}).textContent.replace(/\\s+/g,' ').slice(0,160)
})
"""


def main():
    srv = subprocess.Popen([sys.executable, "server.py", "8877", "--persist"],
                           cwd=REPO, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
    for _ in range(60):
        try:
            if urllib.request.urlopen(BASE + "/api/health", timeout=5).status == 200:
                break
        except Exception:
            time.sleep(0.5)

    # 1) La pagina carga y las sesiones persistidas aparecen
    nav(BASE + "/", new=True)
    time.sleep(4)
    d = eval_js(JS_READY)
    record("UI carga con las sesiones persistidas", d.get("sessions", 0) > 0,
           "sesiones=%s activa=%r" % (d.get("sessions"), d.get("active")))

    # 2) Filtros de la URL aplicados en la UI
    nav(BASE + "/?name=triage.log&q=ESCALADA&level=ERR")
    time.sleep(4)
    d = eval_js(JS_FILTERS)
    rows = d.get("rows", 0)
    record("filtros de URL en la UI (?q=ESCALADA&level=ERR)",
           d.get("q") == "ESCALADA" and rows > 0 and rows <= 12,
           "q=%r filas=%s chips_nivel=%s contadores=%r"
           % (d.get("q"), rows, d.get("levelChips"), d.get("count")))

    # 3) Selector de columnas
    d = eval_js(JS_COLS)
    time.sleep(1)
    d2 = eval_js("""
      JSON.stringify({
        panelVisible: !document.getElementById('cols-panel').classList.contains('hidden'),
        chips: document.querySelectorAll('#cols-list button, #cols-list .col-chip').length
      })
    """)
    record("selector de columnas (P3.1) visible con chips",
           d2.get("panelVisible") and d2.get("chips", 0) > 0,
           "visible=%s chips=%s" % (d2.get("panelVisible"), d2.get("chips")))

    # 4) Empty state
    nav(BASE + "/?name=triage.log&q=zzz_no_existe_en_el_log")
    time.sleep(4)
    d = eval_js(JS_EMPTY)
    record("empty state cuando el filtro no da filas",
           d.get("noResults") and d.get("rows", 1) == 0,
           "msg=%r filas=%s" % (d.get("msg"), d.get("rows")))

    # 5) Dashboard SOC
    nav(BASE + "/?name=alertas.jsonl")
    time.sleep(4)
    eval_js(JS_SOC)
    time.sleep(3)
    d = eval_js(JS_SOC_READ)
    record("dashboard SOC (P4.2) visible y con datos",
           d.get("modalVisible") and (d.get("sevChips", 0) > 0 or d.get("alertRows", 0) > 0),
           "status=%r sev=%s fuente=%s alertas=%s"
           % (d.get("status"), d.get("sevChips"), d.get("fuenteRows"), d.get("alertRows")))

    # 6) Runbooks de OperVanta en el drawer (Fase 10B)
    eval_js("(() => { document.getElementById('soc-close').click(); return 'ok'; })()")
    nav(BASE + "/?name=buzon.log&q=rotado")
    time.sleep(4)
    eval_js(JS_DRAWER)
    time.sleep(3)
    d = eval_js(JS_RB)
    record("runbooks de OperVanta en el drawer (Fase 10B)",
           d.get("items", 0) > 0,
           "count=%r items=%s texto=%r" % (d.get("count"), d.get("items"), d.get("text")))

    # 7) El 429 del rate limit se muestra en la UI (toast)
    nav(BASE + "/")
    time.sleep(3)
    d = eval_js("""
      (async () => {
        const codes = [];
        for (let i = 0; i < 32; i++) {
          const f = new File(['2026-10-30 11:00:00 smoke: linea\\n'],
                             'rate_' + i + '.log', {type: 'text/plain'});
          try { await upload([f]); } catch (e) { codes.push(e.message); }
        }
        return JSON.stringify({
          toast: (document.getElementById('toast') || {}).textContent || '',
          shown: (document.getElementById('toast') || {}).classList.contains('show'),
          errores: codes.filter(c => c.includes('demasiadas')).length
        });
      })()
    """)
    record("el 429 del rate limit llega a la UI (toast)",
           d.get("errores", 0) > 0 or "demasiadas" in (d.get("toast") or ""),
           "toast=%r coincidencias=%s" % (d.get("toast"), d.get("errores")))

    srv.terminate()
    try:
        srv.wait(timeout=10)
    except Exception:
        srv.kill()

    fails = [r for r in results if not r[1]]
    print("\n=== %d comprobaciones visuales, %d fallos ===" % (len(results), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
