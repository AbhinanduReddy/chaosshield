# ChaosShield

An AI-powered security testing agent that autonomously probes web applications for vulnerabilities using GPT-4o.

## How it works

ChaosShield runs a continuous loop:

1. **Auth** — logs into the target app and obtains a JWT token
2. **Crawl** — discovers routes, API endpoints, and forms (including by scanning JS bundles)
3. **Probe** — an OpenAI GPT-4o agent uses HTTP tools to test for XSS, SQLi, IDOR, broken auth, and sensitive data exposure
4. **Report** — confirmed findings are saved to `findings/` and printed as a human-readable report

Currently targets [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) running locally.

## Requirements

- Python 3.11+
- Docker (to run Juice Shop)
- OpenAI API key

## Setup

```bash
# Start Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and set your OPENAI_API_KEY
```

## Configuration

Create a `.env` file:

```env
OPENAI_API_KEY=sk-...
JUICE_SHOP_URL=http://localhost:3000   # optional, default shown
LOOP_INTERVAL=30                        # seconds between iterations
MAX_TOOL_CALLS=50                       # max agent tool calls per iteration
DEMO_EMAIL=admin@juice-sh.op            # target app credentials
DEMO_PASSWORD=admin123
```

## Running

```bash
python main.py
```

The agent will loop continuously, printing a report after each iteration. Stop with `Ctrl+C`.

## Project structure

```
main.py              # Entry point — main execution loop
config.py            # Environment-based configuration
auth/login.py        # Authenticates against the target app
discovery/crawler.py # Crawls app surface and JS bundles for API endpoints
agent/runner.py      # GPT-4o agent loop with HTTP tools
tools/http_tools.py  # http_get, http_post, report_finding tools
findings/store.py    # Persists findings to JSON
reporting/reporter.py# Formats and prints the findings report
```

## Example output

```
===== ChaosShield Report — Iteration 1 =====

[CRITICAL] SQL Injection in Login
  Endpoint: POST /rest/user/login
  Confidence: high
  Email input `' OR 1=1--` returned 200 with valid JWT token,
  bypassing authentication entirely.

[HIGH] IDOR — User Data Exposure
  Endpoint: GET /api/Users
  Confidence: high
  Unauthenticated GET returns full user list including emails and password hashes.
```
