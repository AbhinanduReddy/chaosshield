import httpx
from urllib.parse import urlparse

from findings.store import save_finding

_ALLOWED_HOST = "localhost"
_ALLOWED_PORT = 3000
_TIMEOUT = 10.0

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    if host != _ALLOWED_HOST or port != _ALLOWED_PORT:
        raise ValueError(
            f"URL '{url}' is not allowed. Only http://localhost:3000 targets are permitted."
        )


def http_get(url: str, headers: dict = {}) -> dict:
    _validate_url(url)
    try:
        resp = httpx.get(url, headers=headers, timeout=_TIMEOUT, follow_redirects=True)
        return {
            "status": resp.status_code,
            "body": resp.text,
            "headers": dict(resp.headers),
        }
    except httpx.TimeoutException:
        return {"status": 0, "body": "Request timed out", "headers": {}}
    except Exception as e:
        return {"status": 0, "body": str(e), "headers": {}}


def http_post(url: str, body: dict, headers: dict = {}) -> dict:
    _validate_url(url)
    try:
        resp = httpx.post(url, json=body, headers=headers, timeout=_TIMEOUT, follow_redirects=True)
        return {
            "status": resp.status_code,
            "body": resp.text,
            "headers": dict(resp.headers),
        }
    except httpx.TimeoutException:
        return {"status": 0, "body": "Request timed out", "headers": {}}
    except Exception as e:
        return {"status": 0, "body": str(e), "headers": {}}


def report_finding(
    title: str,
    severity: str,
    confidence: str,
    endpoint: str,
    description: str,
    evidence: str,
    remediation: str,
) -> dict:
    severity = severity.lower()
    if severity not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
        )
    finding = {
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "endpoint": endpoint,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
    }
    finding_id = save_finding(finding)
    return {"id": finding_id, "saved": True}


TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "http_get",
            "description": "Perform an HTTP GET request to a URL on localhost:3000.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The full URL to GET (must be http://localhost:3000/...)",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Optional HTTP headers as key-value pairs.",
                        "additionalProperties": {"type": "string"},
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_post",
            "description": "Perform an HTTP POST request with a JSON body to a URL on localhost:3000.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The full URL to POST to (must be http://localhost:3000/...)",
                    },
                    "body": {
                        "type": "object",
                        "description": "JSON body to send in the POST request.",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Optional HTTP headers as key-value pairs.",
                        "additionalProperties": {"type": "string"},
                    },
                },
                "required": ["url", "body"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_finding",
            "description": "Report a confirmed security vulnerability found in the application.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short title of the vulnerability.",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "description": "Severity level of the vulnerability.",
                    },
                    "confidence": {
                        "type": "string",
                        "description": "Confidence level (e.g., high, medium, low).",
                    },
                    "endpoint": {
                        "type": "string",
                        "description": "The API endpoint or URL where the vulnerability was found.",
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed description of the vulnerability.",
                    },
                    "evidence": {
                        "type": "string",
                        "description": "Evidence or proof of the vulnerability (e.g., response snippet).",
                    },
                    "remediation": {
                        "type": "string",
                        "description": "Recommended remediation steps.",
                    },
                },
                "required": [
                    "title",
                    "severity",
                    "confidence",
                    "endpoint",
                    "description",
                    "evidence",
                    "remediation",
                ],
            },
        },
    },
]
