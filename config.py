import os
import sys

TARGET_URL = os.getenv("TARGET_URL", "http://localhost:3000")

try:
    LOOP_INTERVAL = int(os.getenv("LOOP_INTERVAL", "30"))
except ValueError:
    LOOP_INTERVAL = 30

try:
    MAX_TOOL_CALLS = int(os.getenv("MAX_TOOL_CALLS", "50"))
except ValueError:
    MAX_TOOL_CALLS = 50

DEMO_EMAIL = os.getenv("DEMO_EMAIL", "admin@juice-sh.op")
DEMO_PASSWORD = os.getenv("DEMO_PASSWORD", "admin123")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    print("ERROR: OPENAI_API_KEY environment variable is not set. Please set it before running ChaosShield.", file=sys.stderr)
    sys.exit(1)
