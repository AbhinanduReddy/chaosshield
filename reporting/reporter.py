import os

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def print_report(findings: list[dict], iteration: int) -> None:
    print(f"\n{'='*60}")
    print(f"  ChaosShield Report — Iteration {iteration}")
    print(f"{'='*60}")

    if not findings:
        print("No new findings this iteration.")
        print(f"{'='*60}\n")
        return

    print(f"Total findings: {len(findings)}\n")

    for finding in findings:
        severity = finding.get("severity", "unknown").upper()
        title = finding.get("title", "Untitled")
        endpoint = finding.get("endpoint", "N/A")
        description = finding.get("description", "")
        confidence = finding.get("confidence", "")
        print(f"[{severity}] {title}")
        print(f"  Endpoint:   {endpoint}")
        if confidence:
            print(f"  Confidence: {confidence}")
        if description:
            print(f"  Details:    {description}")
        print()

    top = max(
        findings,
        key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "").lower(), 0),
    )
    print(f"Top Risk: {top.get('title', 'N/A')} [{top.get('severity', '').upper()}]")
    print()

    print("Recommendations:")
    for finding in findings:
        title = finding.get("title", "Untitled")
        remediation = finding.get("remediation", "No remediation provided.")
        print(f"  - [{title}]: {remediation}")

    print()
    save_path = os.path.join("findings", f"iteration_{iteration}.json")
    print(f"Snapshot saved to: {save_path}")
    print(f"{'='*60}\n")
