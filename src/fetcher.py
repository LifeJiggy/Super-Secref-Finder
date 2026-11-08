"""HTTP fetching with proxy, auth, retries, and resource limits."""

from __future__ import annotations

import logging
import mimetypes
import random
import time
from typing import Optional, Tuple
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import ScanConfig
from .ratelimit import HostRateLimiter

logger = logging.getLogger("secref.fetcher")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

_TEXTUAL_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "application/xml",
    "application/xhtml",
    "application/x-www-form-urlencoded",
    "image/svg+xml",
)

_TEXTUAL_EXTENSIONS = (
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json", ".jsonl",
    ".html", ".htm", ".xhtml", ".xml", ".txt", ".md", ".csv", ".yaml",
    ".yml", ".env", ".ini", ".conf", ".config", ".properties", ".map",
    ".svg", ".graphql", ".gql", ".php", ".py", ".rb", ".go", ".java",
)


def _build_session(cfg: ScanConfig) -> requests.Session:
    """Build a requests.Session with retry, proxy, and timeouts."""
    session = requests.Session()

    retry = Retry(
        total=cfg.max_retries,
        backoff_factor=1.0,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "HEAD", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=max(10, cfg.threads))
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if cfg.proxy:
        proxy_url = cfg.proxy
        if cfg.proxy_auth and "@" not in urlparse(proxy_url).netloc:
            parsed = urlparse(proxy_url)
            proxy_url = urlunparse(
                parsed._replace(netloc=f"{cfg.proxy_auth}@{parsed.netloc}")
            )
        session.proxies = {"http": proxy_url, "https": proxy_url}

    session.verify = cfg.verify_ssl
    if not cfg.verify_ssl:
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:  # pragma: no cover - optional
            pass

    ua = cfg.user_agent
    if not ua or ua == "random":
        ua = random.choice(USER_AGENTS)
    session.headers.update({
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    })

    if cfg.custom_headers:
        session.headers.update(cfg.custom_headers)
    if cfg.auth_header:
        session.headers["Authorization"] = cfg.auth_header
    if cfg.cookies:
        _load_cookies(session, cfg.cookies)

    return session


def _load_cookies(session: requests.Session, cookie_source: str) -> None:
    """Load cookies from a file (Netscape format or simple ``key=value``)."""
    try:
        with open(cookie_source, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                if line.startswith("#HttpOnly_"):
                    line = line[len("#HttpOnly_"):]
                elif line.lstrip().startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 7:
                    session.cookies.set(parts[5], parts[6], domain=parts[0], path=parts[2])
                elif "=" in line:
                    name, value = line.split("=", 1)
                    session.cookies.set(name.strip(), value.strip())
    except FileNotFoundError:
        logger.warning(f"Cookie file not found: {cookie_source}")
    except OSError as exc:
        logger.warning(f"Could not read cookie file {cookie_source}: {exc}")


def _is_textual_response(resp: requests.Response, url: str) -> bool:
    """Decide whether a response is worth scanning."""
    content_type = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    if content_type:
        if any(content_type.startswith(prefix) for prefix in _TEXTUAL_CONTENT_TYPES):
            return True
        if content_type == "application/octet-stream":
            path = urlparse(url).path.lower()
            return path.endswith(_TEXTUAL_EXTENSIONS)
        return False

    # No Content-Type: fall back to the URL extension, otherwise allow.
    path = urlparse(url).path.lower()
    if path:
        guessed, _ = mimetypes.guess_type(path)
        if guessed and not (guessed.startswith("text/") or guessed in _TEXTUAL_CONTENT_TYPES):
            return False
    return True


def _decode_content(resp: requests.Response, content: bytes) -> str:
    encoding = resp.encoding or "utf-8"
    try:
        return content.decode(encoding, errors="replace")
    except (LookupError, TypeError):
        return content.decode("utf-8", errors="replace")


def fetch_url(
    cfg: ScanConfig,
    url: str,
    session: Optional[requests.Session] = None,
    method: Optional[str] = None,
    limiter: Optional[HostRateLimiter] = None,
) -> Tuple[Optional[str], Optional[str], Optional[requests.Response]]:
    """Fetch a URL with proxy, auth, retry, jitter, and size limits.

    Returns ``(body_text, final_url, response)`` or ``(None, None, None)``.
    ``method`` overrides ``cfg.method`` (used by the crawler so discovery is
    always a GET).  ``limiter`` applies per-host delay/concurrency and receives
    adaptive backoff hints from 429 responses.
    """
    if session is None:
        session = _build_session(cfg)

    if cfg.jitter:
        time.sleep(random.uniform(0.1, max(0.1, cfg.delay * 0.5)))

    request_method = (method or cfg.method or "GET").upper()
    data = cfg.post_data if request_method == "POST" else None

    attempts = max(1, min(cfg.max_retries, 5))
    for attempt in range(attempts):
        try:
            if limiter is not None:
                with limiter.limit(url):
                    resp = session.request(
                        method=request_method,
                        url=url,
                        timeout=cfg.timeout,
                        allow_redirects=True,
                        data=data,
                        stream=True,
                    )
            else:
                resp = session.request(
                    method=request_method,
                    url=url,
                    timeout=cfg.timeout,
                    allow_redirects=True,
                    data=data,
                    stream=True,
                )
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching {url}")
            return None, None, None
        except requests.exceptions.SSLError:
            logger.warning(f"SSL error fetching {url} — try --no-verify")
            return None, None, None
        except requests.exceptions.ConnectionError as exc:
            logger.warning(f"Connection error for {url}: {exc}")
            return None, None, None
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(f"Unexpected error fetching {url}: {exc}")
            return None, None, None

        try:
            if resp.status_code == 429:
                retry_after_raw = resp.headers.get("Retry-After", "")
                try:
                    retry_after = float(retry_after_raw)
                except (TypeError, ValueError):
                    retry_after = cfg.delay * (2 ** attempt)
                retry_after = max(0.5, min(retry_after, 60.0))
                if limiter is not None:
                    limiter.penalize(url, retry_after)
                if attempt + 1 < attempts:
                    logger.warning(
                        f"Rate limited on {url}, retrying in {retry_after:.1f}s "
                        f"({attempt + 1}/{attempts})"
                    )
                    if limiter is None:
                        time.sleep(retry_after)
                    continue
                logger.warning(f"Rate limited on {url}, giving up")
                return None, None, None

            if resp.status_code != 200:
                logger.debug(f"HTTP {resp.status_code} for {url}")
                return None, None, None

            if not _is_textual_response(resp, url):
                logger.debug(f"Skipping non-text response for {url}")
                return None, None, None

            content = bytearray()
            for chunk in resp.iter_content(chunk_size=16384):
                if not chunk:
                    continue
                content.extend(chunk)
                if len(content) >= cfg.max_response_size:
                    content = content[: cfg.max_response_size]
                    break

            text = _decode_content(resp, bytes(content))
            return text, resp.url, resp
        finally:
            resp.close()

    return None, None, None
