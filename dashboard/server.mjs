import 'dotenv/config';
import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import db from '../shared/db.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = parseInt(process.env.DASHBOARD_PORT) || 4000;

// SSE clients
const clients = new Set();

function broadcast(data) {
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) {
    try { res.write(msg); } catch { clients.delete(res); }
  }
}

// Poll DB for new activity and broadcast
let lastLogId = 0;
let lastFindingId = 0;

function pollChanges() {
  const newLogs = db.prepare('SELECT * FROM agent_log WHERE id > ? ORDER BY id ASC').all(lastLogId);
  for (const log of newLogs) {
    lastLogId = log.id;
    broadcast({ type: 'log', data: log });
  }

  const newFindings = db.prepare('SELECT * FROM findings WHERE id > ? ORDER BY id ASC').all(lastFindingId);
  for (const f of newFindings) {
    lastFindingId = f.id;
    broadcast({ type: 'finding', data: f });
  }

  const recentUpdates = db.prepare(
    "SELECT * FROM findings WHERE resolved_at IS NOT NULL AND datetime(resolved_at) > datetime('now', '-30 seconds') ORDER BY id ASC"
  ).all();
  for (const f of recentUpdates) {
    broadcast({ type: 'finding-updated', data: f });
  }
}

setInterval(pollChanges, 2000);

// ── API Routes ───────────────────────────────────────────────────

app.get('/api/stats', (req, res) => {
  const open = db.prepare("SELECT count(*) as c FROM findings WHERE status = 'open'").get().c;
  const resolved = db.prepare("SELECT count(*) as c FROM findings WHERE status = 'resolved'").get().c;
  const critical = db.prepare("SELECT count(*) as c FROM findings WHERE severity = 'critical' AND status = 'open'").get().c;
  const high = db.prepare("SELECT count(*) as c FROM findings WHERE severity = 'high' AND status = 'open'").get().c;
  const medium = db.prepare("SELECT count(*) as c FROM findings WHERE severity = 'medium' AND status = 'open'").get().c;
  const low = db.prepare("SELECT count(*) as c FROM findings WHERE severity = 'low' AND status = 'open'").get().c;
  const total = open + resolved;
  const recentLogs = db.prepare("SELECT count(*) as c FROM agent_log WHERE datetime(created_at) > datetime('now', '-5 minutes')").get().c;
  const redActions = db.prepare("SELECT count(*) as c FROM agent_log WHERE team = 'red'").get().c;
  const blueActions = db.prepare("SELECT count(*) as c FROM agent_log WHERE team = 'blue'").get().c;

  res.json({ open, resolved, critical, high, medium, low, total, recentLogs, redActions, blueActions });
});

app.get('/api/findings', (req, res) => {
  const findings = db.prepare('SELECT * FROM findings ORDER BY id DESC').all();
  res.json(findings);
});

app.get('/api/logs', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  const logs = db.prepare('SELECT * FROM agent_log ORDER BY id DESC LIMIT ?').all(limit);
  res.json(logs);
});

app.get('/api/activity', (req, res) => {
  const red = db.prepare("SELECT * FROM agent_log WHERE team = 'red' ORDER BY id DESC LIMIT 50").all();
  const blue = db.prepare("SELECT * FROM agent_log WHERE team = 'blue' ORDER BY id DESC LIMIT 50").all();
  res.json({ red, blue });
});

app.get('/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });
  res.write(`data: ${JSON.stringify({ type: 'connected' })}\n\n`);
  clients.add(res);
  req.on('close', () => clients.delete(res));
});

// Serve dashboard HTML
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Dashboard running at http://localhost:${PORT}`);
});
