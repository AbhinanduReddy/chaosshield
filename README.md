<h1 align="center">
  <img src="https://img.shields.io/badge/STATUS-AUTONOMOUS-ff4444?style=for-the-badge&labelColor=0a0a0f" />
  <br/>
  CHAOS
  <br/>
  <sub><sup>Swarm-Driven Autonomous Security Platform</sup></sub>
</h1>

<p align="center">
  <em>An AI swarm that attacks itself. Zero human intervention. Constant evolution.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Swarm-OFFENSIVE-ff4444?style=flat-square&labelColor=1a1a26" />
  <img src="https://img.shields.io/badge/Swarm-DEFENSIVE-4488ff?style=flat-square&labelColor=1a1a26" />
  <img src="https://img.shields.io/badge/Live-8080-44ff88?style=flat-square&labelColor=1a1a26" />
</p>

---

### What is CHAOS?

CHAOS deploys an **autonomous swarm** — specialized AI units that continuously probe, exploit, and harden your target infrastructure. **Offensive units** hunt for vulnerabilities across every surface: injection flaws, broken auth, exposed configs, weak credentials. **Defensive units** observe, prioritize, and auto-remediate in real-time — hardening configs, rotating secrets, patching attack surfaces.

No playbooks. No manual scanning. Each unit decides its next move autonomously, coordinating through a shared intelligence layer.

The swarm never stops. Watch it live on the dashboard.

---

### Architecture

```
                    ┌─────────────────────┐
                    │   CHAOS Dashboard    │
                    │   localhost:8080     │
                    │   SSE + REST API     │
                    └────────┬────────────┘
                             │
                    ┌────────┴────────────┐
                    │   Swarm Intelligence │
                    │   SQLite (WAL)       │
                    │   findings + logs    │
                    └────────┬────────────┘
                             │
               ┌─────────────┴─────────────┐
               │                           │
      ┌────────┴────────┐       ┌─────────┴───────┐
      │  OFFENSIVE       │       │  DEFENSIVE        │
      │  SWARM            │       │  SWARM            │
      │  Attack Units     │──────▶│  Defense Units    │
      │  15s waves        │       │  20s waves        │
      └────────┬────────┘       └─────────────────┘
               │
    ┌──────────┼──────────┐
    │          │          │
  HTTP      PostgreSQL  Redis
  Probing   Dumping    Key scanning
```

---

### Quick Start

```bash
# 1. Clone
git clone https://github.com/your-user/chaos.git && cd chaos

# 2. Install
npm install

# 3. Configure
cp .env.example .env
# Edit .env with your target details and OpenAI API key

# 4. Deploy the swarm
npm run all
```

Open `http://localhost:8080` — the swarm is already active.

---

### Individual Commands

```bash
npm run red        # Offensive swarm only
npm run blue       # Defensive swarm only
npm run dashboard  # Dashboard only
npm run all        # Full swarm deployment
```

---

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `TARGET_WEB_URL` | Target application URL | `http://localhost:3000` |
| `TARGET_CDN_URL` | Target CDN/Proxy URL | `http://localhost:8080` |
| `TARGET_DB_HOST` | PostgreSQL host | `localhost` |
| `TARGET_DB_PORT` | PostgreSQL port | `5432` |
| `TARGET_DB_USER` | PostgreSQL user | — |
| `TARGET_DB_PASS` | PostgreSQL password | — |
| `TARGET_DB_NAME` | PostgreSQL database | — |
| `TARGET_REDIS_HOST` | Redis host | `localhost` |
| `TARGET_REDIS_PORT` | Redis port | `6379` |
| `TARGET_REDIS_PASS` | Redis password | — |
| `OPENAI_API_KEY` | OpenAI API key | — |
| `OPENAI_MODEL` | Standard model | `gpt-4o-mini` |
| `OPENAI_HIGH_MODEL` | High-capability model | `gpt-4o` |
| `RED_TEAM_INTERVAL_MS` | Offensive wave interval | `15000` |
| `BLUE_TEAM_INTERVAL_MS` | Defensive wave interval | `20000` |
| `DASHBOARD_PORT` | Dashboard port | `8080` |

---

### Offensive Swarm

Deploys in waves. Each wave autonomously selects and executes attack vectors across multiple units:

- HTTP endpoint probing (SQL injection, XSS, path traversal, auth bypass)
- PostgreSQL access and data extraction
- Redis key scanning and raw protocol attacks
- Default credential testing
- JWT analysis and forgery detection
- Security misconfiguration discovery
- OWASP Top 10 mapping

Every finding is categorized by severity (`critical` / `high` / `medium` / `low`) and logged with full attack paths.

### Defensive Swarm

Monitors the shared intelligence layer and auto-remediates on its own wave cycle:

- Credential rotation and password policy enforcement
- Database hardening (connection encryption, access controls)
- Redis ACL tightening
- Header security (CSRF tokens, server token suppression)
- Input validation and prepared statements
- Rate limiting configurations
- Field-level access controls

---

### Dashboard

Real-time SSE-powered swarm intelligence monitor at `localhost:8080`:

- **Threat surface stats** — active/neutralized findings, severity breakdown
- **Live activity feed** — filtered by Offensive / Defensive / Findings
- **Finding cards** — severity badges, attack paths, mitigation details
- **Swarm counters** — total actions per swarm
- **Uptime clock** — how long the swarm has been running

---

### Project Structure

```
chaos/
├── agents/
│   ├── red-team.mjs      # Offensive swarm units
│   └── blue-team.mjs     # Defensive swarm units
├── dashboard/
│   ├── server.mjs        # Express + SSE backend
│   └── index.html        # Swarm intelligence monitor UI
├── shared/
│   └── db.mjs            # SQLite schema + connection
├── .env.example          # Configuration template
├── package.json
└── README.md
```

---

### Built With

- **Node.js** — ESM throughout
- **better-sqlite3** — zero-config embedded database with WAL mode
- **Express** — dashboard API and static serving
- **OpenAI** — autonomous swarm decision-making
- **Server-Sent Events** — real-time dashboard updates

---

### License

MIT
