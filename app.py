"""
SIEM Dashboard — agregação de eventos de segurança de múltiplos servidores.
Coleta eventos via WinRM/PowerShell, detecta anomalias e exibe em dashboard
web em tempo real com sistema de alertas integrado.
"""

import json
import subprocess
import threading
import time
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

# ── Configuração ───────────────────────────────────────────────────────────────

JANELA_BRUTE_FORCE = 10   # minutos
THRESHOLD_BRUTE    = 5    # falhas para disparar alerta
INTERVALO_COLETA   = 30   # segundos entre coletas
MAX_EVENTOS_FILA   = 500  # eventos mantidos em memória

SERVIDORES = [
    {"nome": os.environ.get("COMPUTERNAME", "localhost"), "host": "localhost"},
]

EVENTOS_MONITORADOS = {
    "4624": ("Login bem-sucedido",   "info"),
    "4625": ("Falha de login",       "danger"),
    "4648": ("Login explícito",      "warning"),
    "4672": ("Privilégio especial",  "warning"),
    "4720": ("Conta criada",         "info"),
    "4726": ("Conta excluída",       "danger"),
    "4740": ("Conta bloqueada",      "danger"),
    "4767": ("Conta desbloqueada",   "info"),
    "4688": ("Processo criado",      "info"),
}

# ── Estado global (em produção usar Redis/DB) ──────────────────────────────────

_lock         = threading.Lock()
_eventos: deque = deque(maxlen=MAX_EVENTOS_FILA)
_alertas: List[dict] = []
_stats = defaultdict(int)
_ultima_coleta: Optional[datetime] = None


# ── Coleta de eventos ──────────────────────────────────────────────────────────

def _coletar_servidor(host: str, nome: str) -> List[dict]:
    ids   = ",".join(EVENTOS_MONITORADOS.keys())
    inicio = (datetime.now() - timedelta(minutes=INTERVALO_COLETA // 60 + 2)).strftime("%Y-%m-%dT%H:%M:%S")

    script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$eventos = Get-WinEvent -FilterHashtable @{{
    LogName   = 'Security'
    Id        = @({ids})
    StartTime = [datetime]::Parse('{inicio}')
}} -MaxEvents 200 -ErrorAction SilentlyContinue

if (-not $eventos) {{ Write-Output '[]'; exit }}

$lista = foreach ($ev in $eventos) {{
    $xml  = [xml]$ev.ToXml()
    $data = $xml.Event.EventData.Data
    $props = @{{}}
    foreach ($d in $data) {{ if ($d.Name) {{ $props[$d.Name] = $d.'#text' }} }}
    [PSCustomObject]@{{
        id          = [string]$ev.Id
        tempo       = $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        usuario     = if ($props['TargetUserName']) {{ $props['TargetUserName'] }} else {{ $props['SubjectUserName'] }}
        ip          = $props['IpAddress']
        estacao     = $props['WorkstationName']
        logon_type  = $props['LogonType']
        processo    = $props['NewProcessName']
        servidor    = '{nome}'
    }}
}}
$lista | ConvertTo-Json -Depth 2
"""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=25
        )
        raw = r.stdout.strip()
        if not raw or raw == "[]":
            return []
        dados = json.loads(raw)
        return dados if isinstance(dados, list) else [dados]
    except Exception:
        return []


def _detectar_brute_force(eventos: List[dict]) -> List[dict]:
    janela   = timedelta(minutes=JANELA_BRUTE_FORCE)
    por_ip   = defaultdict(list)
    por_user = defaultdict(list)
    alertas  = []

    for ev in eventos:
        if ev.get("id") != "4625":
            continue
        try:
            t = datetime.strptime(ev["tempo"], "%Y-%m-%d %H:%M:%S")
        except Exception:
            continue
        ip   = ev.get("ip", "")
        user = ev.get("usuario", "")
        if ip and ip not in ("-", "::1", "127.0.0.1"):
            por_ip[ip].append(t)
        if user and user not in ("-", ""):
            por_user[user].append(t)

    for chave, tempos in {**{"IP:" + k: v for k, v in por_ip.items()},
                           **{"USER:" + k: v for k, v in por_user.items()}}.items():
        tempos.sort()
        i = 0
        while i < len(tempos):
            grupo = [tempos[i]]
            j = i + 1
            while j < len(tempos) and (tempos[j] - tempos[i]) <= janela:
                grupo.append(tempos[j])
                j += 1
            if len(grupo) >= THRESHOLD_BRUTE:
                tipo = "IP" if chave.startswith("IP:") else "Usuário"
                alertas.append({
                    "tipo":     f"Brute Force por {tipo}",
                    "chave":    chave.split(":", 1)[1],
                    "contagem": len(grupo),
                    "inicio":   grupo[0].strftime("%H:%M:%S"),
                    "fim":      grupo[-1].strftime("%H:%M:%S"),
                    "nivel":    "critical",
                    "tempo":    datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                })
                i = j
            else:
                i += 1
    return alertas


def coletar_todos():
    global _ultima_coleta
    novos = []
    for srv in SERVIDORES:
        evs = _coletar_servidor(srv["host"], srv["nome"])
        novos.extend(evs)

    if not novos:
        return

    novos_alertas = _detectar_brute_force(novos)

    with _lock:
        for ev in novos:
            _eventos.appendleft(ev)
            eid = str(ev.get("id", ""))
            _stats[eid] += 1
        _alertas[:0] = novos_alertas
        if len(_alertas) > 50:
            del _alertas[50:]
        _ultima_coleta = datetime.now()


def _loop_coleta():
    while True:
        try:
            coletar_todos()
        except Exception:
            pass
        time.sleep(INTERVALO_COLETA)


# ── API ────────────────────────────────────────────────────────────────────────

@app.route("/api/eventos")
def api_eventos():
    with _lock:
        return jsonify(list(_eventos)[:100])


@app.route("/api/alertas")
def api_alertas():
    with _lock:
        return jsonify(_alertas[:20])


@app.route("/api/stats")
def api_stats():
    with _lock:
        total   = sum(_stats.values())
        falhas  = _stats.get("4625", 0)
        logins  = _stats.get("4624", 0)
        bloqueios = _stats.get("4740", 0)
        return jsonify({
            "total":      total,
            "falhas":     falhas,
            "logins":     logins,
            "bloqueios":  bloqueios,
            "alertas":    len(_alertas),
            "servidores": len(SERVIDORES),
            "coletado":   _ultima_coleta.strftime("%H:%M:%S") if _ultima_coleta else "—",
        })


# ── Frontend ───────────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html><html lang="pt-BR">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIEM Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#020c1b;color:#c9d1d9;min-height:100vh}
header{background:linear-gradient(135deg,#020c1b,#0a2a4a);border-bottom:1px solid #00d4ff33;
       padding:16px 28px;display:flex;align-items:center;justify-content:space-between}
header h1{font-size:1.2rem;color:#00d4ff;letter-spacing:.05em}
.dot-live{width:8px;height:8px;background:#00d4ff;border-radius:50%;
          animation:pulse 1.5s infinite;display:inline-block;margin-right:6px}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(1.4)}}
.container{max-width:1300px;margin:0 auto;padding:20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.stat{background:#0a1628;border:1px solid #00d4ff22;border-radius:8px;padding:16px;text-align:center}
.stat .num{font-size:2rem;font-weight:700;color:#00d4ff}
.stat .label{font-size:.72rem;color:#7ecfff;margin-top:4px;text-transform:uppercase;letter-spacing:.06em}
.stat.danger .num{color:#ef4444}
.stat.warn .num{color:#f59e0b}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:900px){.grid{grid-template-columns:1fr}}
.panel{background:#0a1628;border:1px solid #00d4ff22;border-radius:10px;overflow:hidden}
.panel-header{padding:12px 16px;border-bottom:1px solid #00d4ff22;
              font-size:.78rem;text-transform:uppercase;letter-spacing:.08em;color:#7ecfff}
.panel-body{max-height:420px;overflow-y:auto}
.ev-row{padding:8px 16px;border-bottom:1px solid #ffffff08;font-size:.78rem;
        display:grid;grid-template-columns:80px 90px 130px 1fr;gap:8px;align-items:center}
.ev-row:hover{background:#0d1f38}
.badge{padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:600;text-align:center}
.badge.info{background:#1e3a5f;color:#7ecfff}
.badge.danger{background:#7f1d1d;color:#fca5a5}
.badge.warning{background:#78350f;color:#fcd34d}
.alerta{padding:10px 16px;border-left:3px solid #ef4444;margin:8px 12px;
        background:#1a0a0a;border-radius:0 6px 6px 0;font-size:.8rem}
.alerta .a-tipo{color:#ef4444;font-weight:600;font-size:.75rem;text-transform:uppercase}
.alerta .a-info{color:#c9d1d9;margin-top:2px}
.empty{padding:24px;text-align:center;color:#484f58;font-size:.83rem}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:#00d4ff33}
</style></head>
<body>
<header>
  <h1><span class="dot-live"></span>SIEM Dashboard</h1>
  <span style="font-size:.78rem;color:#7ecfff">Atualizado: <span id="ts">—</span></span>
</header>
<div class="container">
  <div class="stats" id="stats"></div>
  <div class="grid">
    <div class="panel">
      <div class="panel-header">Eventos Recentes</div>
      <div class="panel-body" id="eventos"><p class="empty">Carregando...</p></div>
    </div>
    <div class="panel">
      <div class="panel-header">Alertas Ativos</div>
      <div class="panel-body" id="alertas"><p class="empty">Nenhum alerta.</p></div>
    </div>
  </div>
</div>
<script>
const EVENTOS_MAP = {
  "4624":"Login OK","4625":"Falha Login","4648":"Login Explícito",
  "4672":"Privilégio","4720":"Conta Criada","4726":"Conta Excluída",
  "4740":"Bloqueio","4767":"Desbloqueio","4688":"Processo"
}
const NIVEL_MAP = {
  "4624":"info","4625":"danger","4648":"warning",
  "4672":"warning","4720":"info","4726":"danger",
  "4740":"danger","4767":"info","4688":"info"
}

async function fetchAll(){
  const [stats, eventos, alertas] = await Promise.all([
    fetch('/api/stats').then(r=>r.json()),
    fetch('/api/eventos').then(r=>r.json()),
    fetch('/api/alertas').then(r=>r.json()),
  ])

  document.getElementById('ts').textContent = stats.coletado

  document.getElementById('stats').innerHTML = `
    <div class="stat"><div class="num">${stats.total}</div><div class="label">Eventos</div></div>
    <div class="stat"><div class="num">${stats.logins}</div><div class="label">Logins OK</div></div>
    <div class="stat danger"><div class="num">${stats.falhas}</div><div class="label">Falhas</div></div>
    <div class="stat danger"><div class="num">${stats.bloqueios}</div><div class="label">Bloqueios</div></div>
    <div class="stat warn"><div class="num">${stats.alertas}</div><div class="label">Alertas</div></div>
    <div class="stat"><div class="num">${stats.servidores}</div><div class="label">Servidores</div></div>`

  if(eventos.length === 0){
    document.getElementById('eventos').innerHTML = '<p class="empty">Nenhum evento. Execute como Administrador.</p>'
  } else {
    document.getElementById('eventos').innerHTML = eventos.map(ev => `
      <div class="ev-row">
        <span style="color:#7ecfff;font-family:monospace">${(ev.tempo||'').slice(11,19)}</span>
        <span class="badge ${NIVEL_MAP[ev.id]||'info'}">${EVENTOS_MAP[ev.id]||'Evento '+ev.id}</span>
        <span style="color:#c9d1d9">${ev.usuario||'—'}</span>
        <span style="color:#484f58">${ev.ip&&ev.ip!=='-'?ev.ip:ev.estacao||'—'}</span>
      </div>`).join('')
  }

  if(alertas.length === 0){
    document.getElementById('alertas').innerHTML = '<p class="empty">✓ Nenhum alerta ativo.</p>'
  } else {
    document.getElementById('alertas').innerHTML = alertas.map(a => `
      <div class="alerta">
        <div class="a-tipo">${a.tipo}</div>
        <div class="a-info">${a.chave} — ${a.contagem} tentativas (${a.inicio}–${a.fim})</div>
        <div style="font-size:.7rem;color:#484f58;margin-top:2px">${a.tempo}</div>
      </div>`).join('')
  }
}

fetchAll()
setInterval(fetchAll, 15000)
</script>
</body></html>"""


@app.route("/")
def index():
    return HTML


if __name__ == "__main__":
    print("\n  SIEM Dashboard iniciando...")
    print("  Coletando eventos iniciais...\n")
    coletar_todos()
    t = threading.Thread(target=_loop_coleta, daemon=True)
    t.start()
    print("  Dashboard: http://localhost:5001\n")
    app.run(host="0.0.0.0", port=5001, debug=False)
