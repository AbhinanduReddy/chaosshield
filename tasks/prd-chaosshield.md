# PRD: ChaosShield — AI Agent Security Scanner for Juice Shop

## Introduction

ChaosShield is an autonomous security agent powered by GPT-4o that continuously probes a local OWASP Juice Shop instance at `http://localhost:3000`. The LLM is the decision-making brain: it receives the application surface and previous findings as context, then dynamically decides what to probe, generates payloads, calls HTTP tools to execute requests, interprets responses, and records findings — all in a single agentic loop. Each iteration, the agent adapts its strategy based on what it already discovered.

Ralph is used only as the development framework to build this system iteratively.

---

## Goals

- GPT-4o drives all probing decisions — no hardcoded attack logic
- Agent executes HTTP requests via tool calls (`http_get`, `http_post`)
- Agent records findings via a `report_finding` tool
- Agent adapts strategy each iteration using previous findings as context
- Runs in a continuous loop; findings persist to JSON between iterations

---

## User Stories

### US-001: Project Scaffold and Configuration
**Description:** As a developer, I want a clean Python project structure so the system is consistent from the start.

**Acceptance Criteria:**
- [ ] Project root contains: `main.py`, `config.py`, `requirements.txt`, `findings/` directory
- [ ] `config.py` defines: `TARGET_URL = "http://localhost:3000"`, `LOOP_INTERVAL = 30` (int), `MAX_TOOL_CALLS = 50` (int, caps agent tool calls per iteration), `DEMO_EMAIL`, `DEMO_PASSWORD` (read from env, default to Juice Shop demo creds), `OPENAI_API_KEY` (read from env, raise clear error if missing)
- [ ] `requirements.txt` includes: `httpx`, `beautifulsoup4`, `openai`
- [ ] `.env.example` documents: `OPENAI_API_KEY`, `DEMO_EMAIL=admin@juice-sh.op`, `DEMO_PASSWORD=admin123`, `LOOP_INTERVAL=30`, `MAX_TOOL_CALLS=50`
- [ ] `findings/` directory created on startup if missing

---

### US-002: HTTP Tool Definitions
**Description:** As the agent, I need HTTP tools I can call so that I can probe Juice Shop endpoints dynamically.

**Acceptance Criteria:**
- [ ] `tools/http_tools.py` exists and defines 3 Python functions:
  - `http_get(url: str, headers: dict = {}) -> dict` — performs GET, returns `{status, body, headers}`
  - `http_post(url: str, body: dict, headers: dict = {}) -> dict` — performs POST with JSON body, returns `{status, body, headers}`
  - `report_finding(title: str, severity: str, confidence: str, endpoint: str, description: str, evidence: str, remediation: str) -> dict` — validates severity is one of `low|medium|high|critical`, saves finding to findings store, returns `{id, saved: true}`
- [ ] All HTTP functions enforce 10-second timeout via httpx
- [ ] All HTTP functions only allow requests to `localhost:3000` — raise `ValueError` if any other host is attempted
- [ ] `tools/http_tools.py` also exports `TOOL_SCHEMAS` — a list of OpenAI function-calling JSON schemas for all 3 tools, ready to pass to the API

---

### US-003: Findings Store — JSON Persistence
**Description:** As the system, I want findings persisted to JSON so the agent can reference previous discoveries across iterations.

**Acceptance Criteria:**
- [ ] `findings/store.py` exists with:
  - `save_finding(finding: dict) -> str` — appends to `findings/all_findings.json`, returns generated UUID
  - `load_all_findings() -> list[dict]` — returns all findings from `findings/all_findings.json`, empty list if file missing
  - `save_iteration_snapshot(findings: list[dict], iteration: int)` — writes `findings/iteration_{N}.json`
- [ ] Each finding has: `id` (uuid4), `title`, `severity`, `confidence`, `endpoint`, `description`, `evidence`, `remediation`, `timestamp`
- [ ] `all_findings.json` is never overwritten — only appended to
- [ ] Returns empty list (not error) if file missing

---

### US-004: Auth Module — Login and Token Management
**Description:** As the agent, I need a valid JWT token so I can probe authenticated endpoints.

**Acceptance Criteria:**
- [ ] `auth/login.py` exists with `get_auth_token() -> str | None`
- [ ] POSTs to `/rest/user/login` with `DEMO_EMAIL` / `DEMO_PASSWORD` from config
- [ ] Returns JWT string on success, `None` on failure with logged warning
- [ ] Token is returned to the agent loop to inject into tool call headers

---

### US-005: Discovery Module — Application Surface Crawler
**Description:** As the agent, I need a summary of Juice Shop's surface area so I have context to reason about what to probe.

**Acceptance Criteria:**
- [ ] `discovery/crawler.py` exists with `crawl() -> dict`
- [ ] Returns dict with: `routes` (list of str), `api_endpoints` (list of str — paths starting with `/api/` or `/rest/`), `forms` (list of `{action, method, inputs}`), `params` (list of str)
- [ ] Only follows same-origin links (localhost:3000)
- [ ] Returns empty dict with logged warning if Juice Shop unreachable — does not crash

---

### US-006: GPT-4o Agent Loop — Core Probing Engine
**Description:** As the system, I want GPT-4o to drive all probing decisions using tool calling so that vulnerability discovery is fully AI-driven and adaptive.

**Acceptance Criteria:**
- [ ] `agent/runner.py` exists with `run_agent(surface: dict, token: str | None, previous_findings: list[dict], iteration: int) -> list[dict]`
- [ ] Builds system prompt that includes:
  - Role: elite red team security agent
  - Target: `http://localhost:3000` (Juice Shop)
  - Available surface: routes, endpoints, forms from crawler
  - Previous findings summary (titles + endpoints) so agent adapts strategy
  - Instruction: probe for XSS, IDOR, broken auth, sensitive data exposure, missing headers
  - Instruction: use `report_finding` tool for every confirmed vulnerability
  - Constraint: safe payloads only, no destructive actions, localhost only
- [ ] Calls `openai.chat.completions.create()` with model `gpt-4o`, passing `TOOL_SCHEMAS` as tools
- [ ] Implements tool call execution loop:
  1. Send messages to GPT-4o
  2. If response has tool calls, execute each via the corresponding Python function
  3. Append tool results to messages
  4. Send updated messages back to GPT-4o
  5. Repeat until GPT-4o stops calling tools or `MAX_TOOL_CALLS` is reached
- [ ] Collects all findings created via `report_finding` tool calls during the run
- [ ] Returns list of new findings from this iteration
- [ ] Handles OpenAI API errors gracefully — logs and returns empty list

---

### US-007: Reporting Module — Human-Readable Output
**Description:** As a developer, I want a clear report printed after each iteration so I can observe what the agent found.

**Acceptance Criteria:**
- [ ] `reporting/reporter.py` exists with `print_report(findings: list[dict], iteration: int)`
- [ ] Output format:
  ```
  ══════════════════════════════════════
  ChaosShield Report — Iteration #N
  ══════════════════════════════════════
  Total Findings: X

  Findings:
    [CRITICAL] XSS on /rest/products/search
    [HIGH] IDOR on /rest/basket/2

  Top Risk: <title of highest severity finding>

  Recommendations:
    - <remediation from each finding>

  Saved to: findings/iteration_N.json
  ══════════════════════════════════════
  ```
- [ ] Prints "No new findings this iteration." when list is empty
- [ ] Does not crash on empty list

---

### US-008: Loop Controller — Main Execution Loop
**Description:** As the autonomous system, I want a main loop that runs the agent continuously so ChaosShield never stops scanning.

**Acceptance Criteria:**
- [ ] `main.py` has `run_loop()` called at `__main__` entry
- [ ] Each iteration:
  1. Log `[Iteration N] Starting...`
  2. Call `get_auth_token()` — continue with `None` if fails
  3. Call `crawl()` — if unreachable, log error, sleep `LOOP_INTERVAL`, continue (no crash)
  4. Call `load_all_findings()` to get previous findings for agent context
  5. Call `run_agent(surface, token, previous_findings, iteration)`
  6. Call `save_iteration_snapshot(new_findings, iteration)`
  7. Call `print_report(new_findings, iteration)`
  8. Sleep `LOOP_INTERVAL` seconds
- [ ] All per-iteration exceptions are caught — loop never crashes
- [ ] Ctrl+C exits cleanly with: `ChaosShield stopped.`
- [ ] Iteration counter resumes from last `findings/iteration_N.json` on startup

---

## Functional Requirements

- **FR-1:** `OPENAI_API_KEY` is required — system raises clear error on startup if missing
- **FR-2:** All HTTP requests are restricted to `localhost:3000` — any other host raises `ValueError`
- **FR-3:** All HTTP requests enforce 10-second timeout
- **FR-4:** Agent tool call loop is capped at `MAX_TOOL_CALLS` per iteration to control cost
- **FR-5:** Previous findings (titles + endpoints) are injected into agent system prompt each iteration
- **FR-6:** GPT-4o model used: `gpt-4o` (not mini — full reasoning needed for security analysis)
- **FR-7:** `report_finding` is the only way findings are created — agent cannot write to files directly
- **FR-8:** Findings persist across iterations in `all_findings.json`
- **FR-9:** Loop never crashes — all exceptions are caught per iteration

---

## Non-Goals

- No scanning outside `localhost:3000`
- No destructive exploitation (no data deletion, no account takeover)
- No web UI or dashboard
- No Playwright / browser automation in MVP
- No multi-agent coordination
- No auto-remediation

---

## Architecture

```
[ Loop Controller — main.py ]
         ↓
[ Auth Module ] → JWT token
         ↓
[ Discovery Crawler ] → surface dict
         ↓
[ Load Previous Findings ] → context
         ↓
[ GPT-4o Agent — agent/runner.py ]
    ↓ tool calls ↓
[ http_get / http_post ] → probe Juice Shop
[ report_finding ] → save to findings store
         ↓
[ Reporting Module ] → stdout
         ↺ loop
```

---

## Technical Considerations

- Use `openai>=1.0.0` with `client.chat.completions.create()`
- Tool schemas follow OpenAI function-calling format (JSON Schema)
- `httpx` used for all HTTP — consistent timeout and host validation
- `beautifulsoup4` for crawler HTML parsing
- All modules independently importable — `config.py` is sole shared dependency

---

## Success Metrics

- Agent runs 5+ iterations without crashing
- GPT-4o autonomously discovers and reports XSS on `/rest/products/search`
- GPT-4o autonomously discovers and reports IDOR on `/rest/basket/`
- Agent adapts strategy in iteration 2+ based on iteration 1 findings
- Each iteration produces a valid `findings/iteration_N.json`

---

## Open Questions

- Should the agent be given a specific attack budget (e.g., max 10 `report_finding` calls) to avoid noisy findings?
- Should findings from previous iterations be summarized by an LLM before injecting as context, to save tokens?
