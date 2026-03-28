import logging
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from config import TARGET_URL

logger = logging.getLogger(__name__)

_BASE = TARGET_URL.rstrip("/")
_PARSED_BASE = urlparse(_BASE)


def _is_same_origin(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.netloc == _PARSED_BASE.netloc


_API_PATH_RE = re.compile(r'["\`]((\/rest\/|\/api\/)[a-zA-Z0-9/_\-:{}]+)["\`]')


def _extract_api_paths_from_js(text: str, api_endpoints: list[str]) -> None:
    """Scan JS/HTML text for quoted /rest/ and /api/ path strings."""
    for match in _API_PATH_RE.finditer(text):
        path = match.group(1).rstrip("/") or "/"
        if path not in api_endpoints:
            api_endpoints.append(path)


def crawl() -> dict:
    """Crawl Juice Shop and return discovered surface.

    Returns dict with:
      - routes: list of str
      - api_endpoints: list of str (paths starting with /api/ or /rest/)
      - forms: list of {action, method, inputs}
      - params: list of str
    """
    empty = {"routes": [], "api_endpoints": [], "forms": [], "params": []}

    try:
        with httpx.Client(timeout=10, follow_redirects=True) as client:
            resp = client.get(_BASE)
    except Exception as exc:
        logger.warning("Juice Shop unreachable at %s: %s", _BASE, exc)
        return empty

    visited: set[str] = set()
    routes: list[str] = []
    api_endpoints: list[str] = []
    forms: list[dict] = []
    params: set[str] = set()

    def _process(url: str, html: str) -> list[str]:
        """Parse HTML, record surface info, return new same-origin URLs to visit."""
        parsed_url = urlparse(url)
        path = parsed_url.path or "/"
        if path not in routes:
            routes.append(path)
        if path.startswith("/api/") or path.startswith("/rest/"):
            if path not in api_endpoints:
                api_endpoints.append(path)
        if parsed_url.query:
            for part in parsed_url.query.split("&"):
                key = part.split("=")[0]
                if key:
                    params.add(key)

        soup = BeautifulSoup(html, "html.parser")
        new_urls: list[str] = []

        # Collect links
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            full = urljoin(url, href)
            parsed_full = urlparse(full)
            # Strip fragment/query for deduplication
            clean = parsed_full._replace(fragment="", query="").geturl()
            if _is_same_origin(clean) and clean not in visited:
                new_urls.append(clean)

        # Collect forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name") or inp.get("id") or ""
                itype = inp.get("type", "text")
                if name:
                    inputs.append({"name": name, "type": itype})
                    params.add(name)
            forms.append({"action": action, "method": method, "inputs": inputs})

        # Collect script-referenced API paths
        for script in soup.find_all("script"):
            src = script.get("src", "")
            if src:
                full = urljoin(url, src)
                if _is_same_origin(full) and full not in visited:
                    new_urls.append(full)

        # Extract API paths from inline script content
        _extract_api_paths_from_js(html, api_endpoints)

        return new_urls

    visited.add(_BASE)
    to_visit = _process(_BASE, resp.text)

    # BFS — one level deep to keep crawl bounded
    with httpx.Client(timeout=10, follow_redirects=True) as client:
        for url in to_visit:
            if url in visited:
                continue
            visited.add(url)
            try:
                r = client.get(url)
                content_type = r.headers.get("content-type", "")
                if "html" in content_type:
                    _process(url, r.text)
                elif "javascript" in content_type:
                    _extract_api_paths_from_js(r.text, api_endpoints)
            except Exception as exc:
                logger.debug("Could not fetch %s: %s", url, exc)

    # Always include known Juice Shop REST/API base paths
    for known in ["/rest/", "/api/"]:
        if known not in api_endpoints:
            api_endpoints.append(known)

    return {
        "routes": routes,
        "api_endpoints": api_endpoints,
        "forms": forms,
        "params": sorted(params),
    }
