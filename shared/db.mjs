import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const db = new Database(join(__dirname, '..', 'ralph.db'));

// Enable WAL mode and set busy timeout for concurrent access
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

db.exec(`
  CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    severity TEXT NOT NULL DEFAULT 'info',
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    attack_path TEXT,
    evidence TEXT,
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    mitigation TEXT,
    red_team_run INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS agent_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT,
    finding_id INTEGER REFERENCES findings(id),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS scan_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
  CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
  CREATE INDEX IF NOT EXISTS idx_agent_log_team ON agent_log(team);
  CREATE INDEX IF NOT EXISTS idx_agent_log_created ON agent_log(created_at);
`);

export default db;
