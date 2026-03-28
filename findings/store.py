import json
import os
import uuid
from datetime import datetime, timezone

_FINDINGS_DIR = os.path.join(os.path.dirname(__file__))
_ALL_FINDINGS_FILE = os.path.join(_FINDINGS_DIR, "all_findings.json")


def save_finding(finding: dict) -> str:
    finding_id = str(uuid.uuid4())
    finding["id"] = finding_id
    finding["timestamp"] = datetime.now(timezone.utc).isoformat()

    existing = load_all_findings()
    existing.append(finding)

    with open(_ALL_FINDINGS_FILE, "w") as f:
        json.dump(existing, f, indent=2)

    return finding_id


def load_all_findings() -> list:
    if not os.path.exists(_ALL_FINDINGS_FILE):
        return []
    try:
        with open(_ALL_FINDINGS_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def save_iteration_snapshot(findings: list, iteration: int) -> None:
    snapshot_path = os.path.join(_FINDINGS_DIR, f"iteration_{iteration}.json")
    with open(snapshot_path, "w") as f:
        json.dump(findings, f, indent=2)
