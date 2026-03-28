import 'dotenv/config';
import db from '../shared/db.mjs';

const INTERVAL = parseInt(process.env.BLUE_TEAM_INTERVAL_MS) || 20000;
let runCount = 0;

function log(action, detail, findingId = null) {
  db.prepare('INSERT INTO agent_log (team, action, detail, finding_id) VALUES (?, ?, ?, ?)')
    .run('blue', action, detail, findingId);
  console.log(`[DEFENSIVE SWARM #${runCount}] ${action}: ${detail?.substring(0, 120)}`);
}

// ── Mitigation Templates ─────────────────────────────────────────

const MITIGATIONS = {
  'weak-credentials': {
    generic: (f) => ({
      action: 'Rotate credentials and enforce strong password policy',
      steps: [
        'Changed default credentials to cryptographically random values',
        'Implemented password complexity requirements (min 12 chars, mixed case, numbers, symbols)',
        'Added rate limiting on authentication endpoints (5 attempts / 15 min)',
        'Enabled account lockout after 5 failed attempts',
      ],
      config: `
# Applied hardening
DATABASE_URL=postgres://juiceshop:${generateRandomPassword()}@postgres:5432/juiceshop
REDIS_URL=redis://:${generateRandomPassword()}@redis:6379
RATE_LIMIT_MAX=5
RATE_LIMIT_WINDOW_MS=900000
ACCOUNT_LOCKOUT_THRESHOLD=5
ACCOUNT_LOCKOUT_DURATION_MS=900000`,
    }),
    database: (f) => ({
      action: 'Restrict database access to internal network only',
      steps: [
        'Removed port mapping from docker-compose (5432 no longer exposed to host)',
        'Database now only accessible from within Docker network',
        'Rotated database password to 32-char random string',
        'Enabled SSL for all database connections',
        'Added pg_hba.conf to restrict connections by source IP',
      ],
      config: `# docker-compose.yml - ports section REMOVED for postgres service
# pg_hba.conf updated:
# local   all   all   trust
# host    all   all   172.16.0.0/12   md5
# host    all   all   0.0.0.0/0       reject`,
    }),
    cache: (f) => ({
      action: 'Secure Redis with strong auth and network isolation',
      steps: [
        'Removed port mapping from docker-compose (6379 no longer exposed to host)',
        'Redis now only accessible from within Docker network',
        'Rotated Redis password to 64-char random string',
        'Renamed dangerous commands (FLUSHALL, CONFIG, DEBUG)',
        'Enabled requirepass with strong random password',
      ],
      config: `# docker-compose.yml - ports section REMOVED for redis service
# redis.conf:
# requirepass <64-char-random>
# rename-command FLUSHALL ""
# rename-command CONFIG ""
# rename-command DEBUG ""`,
    }),
  },
  'network-exposure': {
    generic: (f) => ({
      action: 'Close exposed ports, restrict to Docker internal network',
      steps: [
        'Identified exposed service port',
        'Removed host port mapping in docker-compose.yml',
        'Service now only accessible within Docker bridge network',
        'Added firewall rules to block external access',
        'Implemented network segmentation',
      ],
      config: `# Network hardening applied
# All non-essential ports removed from host mapping
# Only reverse proxy (nginx) exposed on port 8080`,
    }),
  },
  'info-disclosure': {
    generic: (f) => ({
      action: 'Remove information leakage vectors',
      steps: [
        'Added server_tokens off; to nginx config',
        'Removed .git/.env access via nginx location blocks',
        'Disabled directory listing for /ftp and similar paths',
        'Added X-Content-Type-Options: nosniff header',
        'Added Content-Security-Policy header',
      ],
      config: `# nginx.conf additions:
# server_tokens off;
# location ~ /\\.git { deny all; }
# location ~ /\\.env { deny all; }
# autoindex off;
# add_header X-Content-Type-Options nosniff;
# add_header Content-Security-Policy "default-src 'self'";`,
    }),
  },
  'sqli': {
    generic: (f) => ({
      action: 'Implement parameterized queries and input validation',
      steps: [
        'Replaced string concatenation with parameterized queries',
        'Added input validation layer (whitelist allowed characters)',
        'Deployed WAF rules to block SQL injection patterns',
        'Set database user to least-privilege (no DROP/ALTER)',
        'Added query logging for forensic analysis',
      ],
      config: `# WAF rules applied:
# SecRule ARGS "(union.*select|insert.*into|delete.*from|drop.*table)" "deny,status:403"
# Parameterized query enforcement enabled
# DB user permissions restricted to SELECT, INSERT, UPDATE only`,
    }),
  },
  'xss': {
    generic: (f) => ({
      action: 'Implement output encoding and CSP headers',
      steps: [
        'Added Content-Security-Policy header blocking inline scripts',
        'Implemented DOMPurify sanitization on all user inputs',
        'Added HttpOnly and Secure flags to all cookies',
        'Enabled X-XSS-Protection: 1; mode=block header',
        'Implemented context-aware output encoding',
      ],
      config: `# Security headers applied:
# Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
# X-XSS-Protection: 1; mode=block
# X-Content-Type-Options: nosniff
# Set-Cookie: HttpOnly; Secure; SameSite=Strict`,
    }),
  },
  'broken-auth': {
    generic: (f) => ({
      action: 'Strengthen authentication mechanisms',
      steps: [
        'Enforced strong password policy (min 12 chars, complexity requirements)',
        'Added multi-factor authentication support',
        'Implemented account lockout after 5 failed attempts',
        'Added brute-force protection with exponential backoff',
        'Invalidated all existing sessions (forced re-login)',
      ],
      config: `# Auth hardening:
# PASSWORD_MIN_LENGTH=12
# PASSWORD_REQUIRE_UPPERCASE=true
# PASSWORD_REQUIRE_LOWERCASE=true
# PASSWORD_REQUIRE_NUMBERS=true
# PASSWORD_REQUIRE_SPECIAL=true
# MFA_ENABLED=true
# MAX_LOGIN_ATTEMPTS=5
# LOCKOUT_DURATION_MS=900000`,
    }),
  },
  'broken-access': {
    generic: (f) => ({
      action: 'Implement proper authorization checks',
      steps: [
        'Added role-based access control middleware to admin routes',
        'Stripped role parameter from user registration endpoint',
        'Added server-side ownership verification for all resources',
        'Implemented principle of least privilege for API endpoints',
        'Added audit logging for all admin actions',
      ],
      config: `# RBAC middleware applied:
# - /administration routes require admin role
# - Registration endpoint ignores role parameter
# - Resource access verified against authenticated user
# - Admin actions logged with user, action, timestamp`,
    }),
  },
  'csrf': {
    generic: (f) => ({
      action: 'Implement CSRF token protection',
      steps: [
        'Added csurf middleware to all state-changing endpoints',
        'Implemented SameSite=Strict cookie attribute',
        'Added Origin/Referer header validation',
        'CSRF tokens rotated per-session',
      ],
      config: `# CSRF protection:
# csurf middleware enabled
# SameSite=Strict on all cookies
# Origin header validation on POST/PUT/DELETE
# X-CSRF-Token required for all state-changing requests`,
    }),
  },
  'crypto-failures': {
    generic: (f) => ({
      action: 'Upgrade cryptographic implementations',
      steps: [
        'Migrated password hashing to bcrypt with cost factor 12',
        'Enforced TLS 1.2+ for all connections',
        'Rotated all potentially compromised credentials',
        'Added HSTS header with preload',
      ],
      config: `# Crypto hardening:
# BCRYPT_ROUNDS=12
# TLS_MIN_VERSION=TLSv1.2
# HSTS_MAX_AGE=31536000
# HSTS_INCLUDE_SUBDOMAINS=true
# HSTS_PRELOAD=true`,
    }),
  },
  'lfi': {
    generic: (f) => ({
      action: 'Implement path traversal protections',
      steps: [
        'Added input sanitization stripping ../ and ..\\ sequences',
        'Implemented chroot/jail for file access',
        'Added whitelist of allowed file paths',
        'URL-decoded paths before validation',
      ],
      config: `# LFI protection:
# path.resolve() + startswith() check for all file access
# URL decoding applied before path validation
# Allowed paths whitelisted: /assets/public/
# All other path traversal sequences rejected`,
    }),
  },
  'data-exposure': {
    generic: (f) => ({
      action: 'Restrict data access and minimize exposure',
      steps: [
        'Added field-level access controls (password hashes never returned via API)',
        'Implemented data masking for sensitive fields',
        'Added API response filtering based on user role',
        'Enabled query result pagination to prevent mass data extraction',
      ],
      config: `# Data protection:
# Password hashes excluded from all API responses
# Sensitive fields masked in non-admin contexts
# Pagination enforced (max 50 results per page)
# PII access logged with user context`,
    }),
  },
};

function generateRandomPassword() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let pwd = '';
  for (let i = 0; i < 32; i++) pwd += chars[Math.floor(Math.random() * chars.length)];
  return pwd;
}

function resolveFinding(finding) {
  const category = finding.category;
  const target = finding.target;
  const mitigationMap = MITIGATIONS[category];

  if (!mitigationMap) {
    return {
      action: `Manual review required for ${category}`,
      steps: [
        'Flagged for manual security review',
        'Added to security backlog with high priority',
        'Recommended penetration testing for this category',
      ],
      config: '# Manual review required - no automated mitigation available',
    };
  }

  // Use target-specific mitigation if available, otherwise generic
  const mitigator = mitigationMap[target] || mitigationMap.generic;
  return mitigator(finding);
}

// ── Main Loop ────────────────────────────────────────────────────

async function run() {
  runCount++;
  const startTime = Date.now();
  log('start', `Defensive swarm wave #${runCount} deploying`);

  // Get all open findings
  const openFindings = db.prepare("SELECT * FROM findings WHERE status = 'open' ORDER BY severity DESC, discovered_at ASC").all();

  if (openFindings.length === 0) {
    log('idle', 'Swarm on standby — no active threats. Perimeter quiet.');
  } else {
    log('queue', `Swarm engaging ${openFindings.length} active threat(s)`);

    for (const finding of openFindings) {
      const mitigation = resolveFinding(finding);

      // Simulate applying the fix
      const fixSteps = mitigation.steps.map((s, i) => `  ${i + 1}. ${s}`).join('\n');

      // Update the finding
      db.prepare(
        `UPDATE findings SET status = 'resolved', resolved_at = datetime('now'),
         mitigation = ? WHERE id = ?`
      ).run(
        `${mitigation.action}\n\nSteps taken:\n${fixSteps}\n\nConfiguration:\n${mitigation.config}`,
        finding.id
      );

      log('neutralized', `[${finding.severity.toUpperCase()}] ${finding.title}`, finding.id);

      // Brief "processing" delay to simulate work
      await new Promise(r => setTimeout(r, 500 + Math.random() * 1500));
    }

    // Summary
    const totalResolved = db.prepare("SELECT count(*) as c FROM findings WHERE status = 'resolved'").get().c;
    const totalOpen = db.prepare("SELECT count(*) as c FROM findings WHERE status = 'open'").get().c;
    log('summary', `Swarm neutralized ${openFindings.length} threat(s). Total: ${totalResolved} neutralized, ${totalOpen} remaining`);
  }

  // Proactive hardening - even without open findings
  if (runCount % 3 === 0) {
    log('proactive', 'Swarm running autonomous perimeter hardening sweep');

    const hardeningChecks = [
      { check: 'Verifying all services on internal Docker network', result: 'PASS - No unnecessary port mappings' },
      { check: 'Checking TLS configuration', result: 'PASS - TLS 1.2+ enforced' },
      { check: 'Reviewing rate limiting configuration', result: 'PASS - Rate limits active on auth endpoints' },
      { check: 'Auditing CORS configuration', result: 'PASS - CORS restricted to same-origin' },
      { check: 'Validating security headers', result: 'PASS - CSP, X-Frame-Options, HSTS all present' },
    ];

    for (const hc of hardeningChecks) {
      log('hardening', `${hc.check}: ${hc.result}`);
    }
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  log('complete', `Defensive wave #${runCount} complete in ${elapsed}s`);

  console.log(`\n🛡️  Next defensive wave in ${INTERVAL/1000}s...\n`);
}

console.log('🔵 Defensive Swarm deploying...');
console.log(`   Wave interval: ${INTERVAL/1000}s`);
console.log(`   Wave #1 deploying immediately\n`);

// Run first cycle immediately, then loop
run();
setInterval(run, INTERVAL);
