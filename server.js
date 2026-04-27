const express = require('express')
const http    = require('http')
const WebSocket = require('ws')
const { execSync } = require('child_process')
const path    = require('path')

const app    = express()
const server = http.createServer(app)
const wss    = new WebSocket.Server({ server })

app.use(express.static(path.join(__dirname, 'public')))
app.use(express.json())

// ── State ─────────────────────────────────────────────────────────────────────
const MAX_EVENTS = 500
let events  = []
let alerts  = []
let alertId = 1

const MONITORED_HOSTS = [
  'localhost', 'SRV-AD01', 'SRV-FILE01', 'SRV-WEB01', 'SRV-DB01'
]

// ── PowerShell helper ─────────────────────────────────────────────────────────
function ps(script) {
  try {
    const out = execSync(
      `powershell -NoProfile -ExecutionPolicy Bypass -Command "${script.replace(/"/g, '\\"')}"`,
      { timeout: 15000, encoding: 'utf8' }
    )
    return JSON.parse(out.trim() || '[]')
  } catch { return [] }
}

// ── Collect Windows security events ──────────────────────────────────────────
function collectEvents() {
  const raw = ps(`
    $ev = Get-WinEvent -FilterHashtable @{LogName='Security';Id=@(4624,4625,4648,4672,4688,4720,4726,4740);StartTime=(Get-Date).AddMinutes(-5)} -MaxEvents 50 -EA SilentlyContinue
    if(-not $ev){Write-Output '[]';exit}
    $ev | Select-Object Id,TimeCreated,Message | ForEach-Object {
      [PSCustomObject]@{
        id=([string](New-Guid)).Substring(0,8); eventId=$_.Id
        time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        msg=($_.Message -split '\`n')[0]
        host=$env:COMPUTERNAME
      }
    } | ConvertTo-Json -Depth 2`)

  const newEvs = Array.isArray(raw) ? raw : (raw ? [raw] : [])

  // Deduplicate by time+eventId
  const existing = new Set(events.map(e => `${e.time}|${e.eventId}`))
  newEvs.forEach(e => {
    if (!existing.has(`${e.time}|${e.eventId}`)) {
      e.type  = eventLabel(e.eventId)
      e.user  = extractField(e.msg, 'Account Name')
      e.srcIp = extractField(e.msg, 'Source Network Address')
      events.unshift(e)
    }
  })
  if (events.length > MAX_EVENTS) events = events.slice(0, MAX_EVENTS)
}

// Simulate extra hosts with mock events in dev environments
function generateMockEvent() {
  const ids   = [4624, 4625, 4625, 4625, 4648, 4688, 4672]
  const users = ['administrator', 'svcBackup', 'lucas.santos', 'guest', 'SYSTEM']
  const ips   = ['192.168.1.10', '192.168.1.55', '10.0.0.23', '172.16.0.5', '::1']
  const hosts = MONITORED_HOSTS
  const eid   = ids[Math.floor(Math.random() * ids.length)]
  return {
    id:      Math.random().toString(36).slice(2, 10),
    eventId: eid,
    type:    eventLabel(eid),
    time:    new Date().toISOString().replace('T', ' ').slice(0, 19),
    host:    hosts[Math.floor(Math.random() * hosts.length)],
    user:    users[Math.floor(Math.random() * users.length)],
    srcIp:   ips[Math.floor(Math.random() * ips.length)],
    msg:     `Event ${eid} — ${eventLabel(eid)}`
  }
}

// ── Detection rules ───────────────────────────────────────────────────────────
function runDetection() {
  const now   = Date.now()
  const win   = 10 * 60 * 1000 // 10 min
  const cutoff = new Date(now - win)

  // Brute force: >5 failures same IP in 10min
  const failures = events.filter(e =>
    e.eventId === 4625 && new Date(e.time) >= cutoff && e.srcIp && e.srcIp !== '-'
  )
  const byIp = {}
  failures.forEach(e => { byIp[e.srcIp] = (byIp[e.srcIp] || 0) + 1 })
  Object.entries(byIp).forEach(([ip, count]) => {
    if (count >= 5 && !alerts.find(a => a.type === 'BruteForce' && a.srcIp === ip && !a.resolved)) {
      alerts.unshift({ id: alertId++, type: 'BruteForce', severity: 'Critical',
        title: `Brute Force detectado — ${ip}`, srcIp: ip,
        detail: `${count} falhas de login em 10 minutos`, time: new Date().toISOString(), resolved: false })
    }
  })

  // After-hours login (23h–6h)
  events.filter(e => e.eventId === 4624).forEach(e => {
    const h = new Date(e.time).getHours()
    if ((h >= 23 || h < 6) && !alerts.find(a => a.type === 'AfterHours' && a.detail?.includes(e.user) && !a.resolved)) {
      alerts.unshift({ id: alertId++, type: 'AfterHours', severity: 'High',
        title: `Login fora do horário — ${e.user}`, srcIp: e.srcIp,
        detail: `Usuário ${e.user} logou às ${e.time}`, time: new Date().toISOString(), resolved: false })
    }
  })

  // Privilege use
  const privEvs = events.filter(e => e.eventId === 4672).slice(0, 3)
  privEvs.forEach(e => {
    if (!alerts.find(a => a.type === 'PrivilegeUse' && a.detail?.includes(e.user))) {
      alerts.unshift({ id: alertId++, type: 'PrivilegeUse', severity: 'Medium',
        title: `Uso de privilégio especial — ${e.user}`, srcIp: e.host,
        detail: `Privilégios especiais atribuídos ao usuário ${e.user}`, time: e.time, resolved: false })
    }
  })

  if (alerts.length > 100) alerts = alerts.slice(0, 100)
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function eventLabel(id) {
  const m = { 4624:'Login Sucesso', 4625:'Login Falha', 4648:'Login Explícito',
               4672:'Privilégio Especial', 4688:'Processo Criado',
               4720:'Conta Criada', 4726:'Conta Deletada', 4740:'Conta Bloqueada' }
  return m[id] || `Evento ${id}`
}
function extractField(msg, field) {
  if (!msg) return '-'
  const m = msg.match(new RegExp(field + '[:\\s]+([^\\n\\r\\t]+)'))
  return m ? m[1].trim() : '-'
}

// ── Broadcast ─────────────────────────────────────────────────────────────────
function broadcast(data) {
  const msg = JSON.stringify(data)
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(msg) })
}

// ── Tick: collect + detect + push ─────────────────────────────────────────────
function tick() {
  try { collectEvents() } catch {}

  // Always add a mock event so the UI is lively in demo mode
  const mock = generateMockEvent()
  events.unshift(mock)
  if (events.length > MAX_EVENTS) events = events.slice(0, MAX_EVENTS)

  runDetection()
  broadcast({ type: 'update', events: events.slice(0, 50), alerts: alerts.slice(0, 20),
    stats: getStats() })
}
setInterval(tick, 5000)
tick()

// ── REST API ──────────────────────────────────────────────────────────────────
function getStats() {
  const failures   = events.filter(e => e.eventId === 4625).length
  const activeAlerts = alerts.filter(a => !a.resolved).length
  const hosts      = [...new Set(events.map(e => e.host))].length
  const byHour     = {}
  events.forEach(e => {
    const h = new Date(e.time).getHours()
    byHour[h] = (byHour[h] || 0) + 1
  })
  return { totalEvents: events.length, activeAlerts, loginFailures: failures,
           monitoredHosts: Math.max(hosts, MONITORED_HOSTS.length), byHour }
}

app.get('/api/events', (_, res) => res.json(events.slice(0, 100)))
app.get('/api/alerts', (_, res) => res.json(alerts))
app.get('/api/stats',  (_, res) => res.json(getStats()))
app.get('/api/hosts',  (_, res) => res.json(MONITORED_HOSTS.map(h => ({
  hostname: h, status: Math.random() > 0.1 ? 'online' : 'offline',
  lastSeen: new Date().toISOString()
}))))
app.post('/api/alerts/:id/resolve', (req, res) => {
  const a = alerts.find(a => a.id === +req.params.id)
  if (a) { a.resolved = true; res.json({ ok: true }) }
  else res.status(404).json({ error: 'not found' })
})

// ── WebSocket ─────────────────────────────────────────────────────────────────
wss.on('connection', ws => {
  ws.send(JSON.stringify({ type: 'init', events: events.slice(0, 50),
    alerts: alerts.slice(0, 20), stats: getStats() }))
})

server.listen(3000, () => console.log('SIEM Dashboard → http://localhost:3000'))
