import glob
import logging
import os
import time

# Ensure findings/ directory exists on startup
os.makedirs("findings", exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def _resume_iteration() -> int:
    """Return the next iteration number by inspecting existing iteration_N.json snapshots."""
    snapshots = glob.glob(os.path.join("findings", "iteration_*.json"))
    if not snapshots:
        return 1
    nums = []
    for path in snapshots:
        basename = os.path.basename(path)  # iteration_N.json
        try:
            n = int(basename[len("iteration_"):-len(".json")])
            nums.append(n)
        except ValueError:
            pass
    return max(nums) + 1 if nums else 1


def run_loop():
    from auth.login import get_auth_token
    from discovery.crawler import crawl
    from findings.store import load_all_findings, save_iteration_snapshot
    from agent.runner import run_agent
    from reporting.reporter import print_report
    from config import LOOP_INTERVAL

    iteration = _resume_iteration()

    try:
        while True:
            logger.info("[Iteration %d] Starting...", iteration)
            try:
                # Step 1: authenticate
                token = get_auth_token()

                # Step 2: crawl application surface
                surface = crawl()
                if not surface:
                    logger.error("[Iteration %d] Juice Shop unreachable — skipping agent run.", iteration)
                    time.sleep(LOOP_INTERVAL)
                    iteration += 1
                    continue

                # Step 3: load all previous findings for agent context
                previous_findings = load_all_findings()

                # Step 4: run the agent
                new_findings = run_agent(surface, token, previous_findings, iteration)

                # Step 5: save iteration snapshot
                save_iteration_snapshot(new_findings, iteration)

                # Step 6: print report
                print_report(new_findings, iteration)

            except Exception:
                logger.exception("[Iteration %d] Unexpected error — continuing loop.", iteration)

            time.sleep(LOOP_INTERVAL)
            iteration += 1

    except KeyboardInterrupt:
        print("ChaosShield stopped.")


if __name__ == "__main__":
    run_loop()
