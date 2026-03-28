import json
import logging

import openai

import config
from tools.http_tools import TOOL_SCHEMAS, http_get, http_post, report_finding

logger = logging.getLogger(__name__)

_TOOL_DISPATCH = {
    "http_get": lambda args: http_get(**args),
    "http_post": lambda args: http_post(**args),
    "report_finding": lambda args: report_finding(**args),
}


def _build_system_prompt(surface: dict, previous_findings: list[dict]) -> str:
    routes = surface.get("routes", [])
    api_endpoints = surface.get("api_endpoints", [])
    forms = surface.get("forms", [])
    params = surface.get("params", [])

    surface_summary = (
        f"Routes discovered: {', '.join(routes) if routes else 'none'}\n"
        f"API endpoints: {', '.join(api_endpoints) if api_endpoints else 'none'}\n"
        f"Forms: {len(forms)} found\n"
        f"Parameters: {', '.join(params) if params else 'none'}"
    )

    if previous_findings:
        findings_summary = "\n".join(
            f"  - [{f.get('severity', '?').upper()}] {f.get('title', 'Unknown')} @ {f.get('endpoint', '?')}"
            for f in previous_findings
        )
        findings_context = f"Previously confirmed vulnerabilities (avoid re-reporting):\n{findings_summary}"
    else:
        findings_context = "No previous findings — this is the first probe iteration."

    return f"""You are an elite red team security agent performing authorized penetration testing against OWASP Juice Shop running at {config.TARGET_URL}.

## Application Surface
{surface_summary}

## Previous Findings
{findings_context}

## Your Mission
Probe the application for the following vulnerability classes:
- Cross-Site Scripting (XSS): Inject payloads into input fields, URL params, and API bodies
- Insecure Direct Object Reference (IDOR): Access resources by manipulating IDs
- Broken Authentication: Test weak credentials, missing auth checks, JWT flaws
- Sensitive Data Exposure: Check API responses for PII, tokens, passwords
- Missing Security Headers: Inspect response headers for security misconfigurations

## Known Juice Shop Endpoints to Probe
Start with these high-value targets (add Authorization header when testing authenticated routes):
- POST /rest/user/login — brute force, SQL injection (try email: `' OR 1=1--`)
- GET /rest/user/whoami — check if unauthenticated access leaks user data
- GET /api/Users — IDOR, check if admin list is exposed without auth
- GET /api/Users/1, /api/Users/2 — IDOR on individual user records
- GET /api/Products — check for sensitive data in product descriptions
- GET /rest/basket/1, /rest/basket/2 — IDOR on other users' baskets
- POST /api/Users — check if account registration allows admin role assignment
- GET /rest/admin/application-configuration — admin endpoint, check if accessible without auth
- GET /rest/saveLoginIp — check security header behavior
- POST /api/Feedbacks — XSS via feedback body field
- GET /rest/products/search?q= — SQL injection via search param (try `q='`)

## Rules of Engagement
1. ONLY target http://localhost:3000 — all requests must go to localhost:3000
2. Use safe, non-destructive payloads (e.g., <script>alert(1)</script> for XSS, `' OR 1=1--` for SQLi)
3. Call report_finding() for EVERY confirmed vulnerability — do not report suspected issues without evidence
4. A finding is confirmed when: you get unexpected data, a 200 on an admin route without auth, reflected input, or an error revealing DB internals
5. Adapt your strategy based on the previous findings listed above — explore new endpoints and attack vectors

Begin your security assessment now."""


def run_agent(
    surface: dict,
    token: str | None,
    previous_findings: list[dict],
    iteration: int,
) -> list[dict]:
    client = openai.OpenAI(api_key=config.OPENAI_API_KEY)

    system_prompt = _build_system_prompt(surface, previous_findings)
    messages = [{"role": "system", "content": system_prompt}]

    if token:
        messages.append({
            "role": "user",
            "content": (
                f"Authentication token obtained: {token}\n"
                "Use this as 'Authorization: Bearer <token>' header in requests that require authentication. "
                "Start your security assessment."
            ),
        })
    else:
        messages.append({
            "role": "user",
            "content": "No authentication token available (login failed or not attempted). "
                       "Test unauthenticated attack surfaces. Start your security assessment.",
        })

    new_findings: list[dict] = []
    tool_call_count = 0

    try:
        while tool_call_count < config.MAX_TOOL_CALLS:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                tools=TOOL_SCHEMAS,
                tool_choice="auto",
            )

            choice = response.choices[0]
            messages.append(choice.message.model_dump(exclude_unset=False))

            if choice.finish_reason != "tool_calls" or not choice.message.tool_calls:
                logger.info("Agent finished — no more tool calls (iteration %d).", iteration)
                break

            for tool_call in choice.message.tool_calls:
                if tool_call_count >= config.MAX_TOOL_CALLS:
                    logger.warning("MAX_TOOL_CALLS (%d) reached, stopping.", config.MAX_TOOL_CALLS)
                    break

                fn_name = tool_call.function.name
                tool_call_count += 1

                try:
                    args = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError as e:
                    result = {"error": f"Invalid JSON arguments: {e}"}
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps(result),
                    })
                    continue

                logger.info("[%d/%d] Calling tool: %s", tool_call_count, config.MAX_TOOL_CALLS, fn_name)

                if fn_name not in _TOOL_DISPATCH:
                    result = {"error": f"Unknown tool: {fn_name}"}
                else:
                    try:
                        result = _TOOL_DISPATCH[fn_name](args)
                        if fn_name == "report_finding" and isinstance(result, dict) and result.get("saved"):
                            finding_record = {**args, "id": result.get("id")}
                            new_findings.append(finding_record)
                            logger.info("Finding recorded: %s [%s]", args.get("title"), args.get("severity"))
                    except Exception as e:
                        result = {"error": str(e)}
                        logger.warning("Tool %s raised exception: %s", fn_name, e)

                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result),
                })

    except openai.APIError as e:
        logger.error("OpenAI API error during iteration %d: %s", iteration, e)
        return new_findings
    except Exception as e:
        logger.error("Unexpected error during agent run (iteration %d): %s", iteration, e)
        return new_findings

    logger.info("Agent loop complete. %d findings, %d tool calls (iteration %d).", len(new_findings), tool_call_count, iteration)
    return new_findings
