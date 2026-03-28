import logging

import httpx

from config import DEMO_EMAIL, DEMO_PASSWORD, TARGET_URL

logger = logging.getLogger(__name__)


def get_auth_token() -> str | None:
    url = f"{TARGET_URL}/rest/user/login"
    try:
        response = httpx.post(
            url,
            json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD},
            timeout=10,
        )
        if response.status_code == 200:
            data = response.json()
            token = data.get("authentication", {}).get("token")
            if token:
                return token
            logger.warning("Login succeeded but no token in response: %s", data)
            return None
        logger.warning("Login failed with status %d: %s", response.status_code, response.text)
        return None
    except Exception as exc:
        logger.warning("Login request failed: %s", exc)
        return None
