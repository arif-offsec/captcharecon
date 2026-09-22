"""Shared HTTP session — throttle, proxy, retry, custom headers."""

import time
import random
from typing import Optional, Dict

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

BASE_HEADERS = {
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection":      "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


class SessionManager:
    """Thin requests.Session wrapper with throttle, proxy, retry."""

    def __init__(self, proxy=None, timeout=10, user_agent=None, delay=1.0):
        self.timeout   = timeout
        self.delay     = delay
        self._last_req = 0.0

        self.session = requests.Session()
        self.session.headers.update(BASE_HEADERS)
        self.session.headers["User-Agent"] = user_agent or DEFAULT_UA

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
            self.session.verify  = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        retry = Retry(total=3, backoff_factor=0.5,
                      status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://",  adapter)
        self.session.mount("https://", adapter)

    def get(self, url, **kwargs):
        self._throttle()
        return self.session.get(url, timeout=self.timeout, **kwargs)

    def post(self, url, **kwargs):
        self._throttle()
        return self.session.post(url, timeout=self.timeout, **kwargs)

    def head(self, url, **kwargs):
        self._throttle()
        return self.session.head(url, timeout=self.timeout,
                                 allow_redirects=True, **kwargs)

    def get_with_headers(self, url, extra: Dict[str, str], **kwargs):
        self._throttle()
        merged = {**dict(self.session.headers), **extra}
        return self.session.get(url, headers=merged,
                                timeout=self.timeout, **kwargs)

    def use_browser_cookies(self, cookies: Dict[str, str]):
        """Merge cookies captured by a BrowserSession (see --browser) into
        this session — e.g. after headless Chrome clears a JS/redirect
        challenge the target won't pass a plain HTTP client through."""
        if cookies:
            self.session.cookies.update(cookies)

    def rapid_get(self, url, count=10, jitter=0.05):
        """Send `count` requests with minimal delay — for rate limit probing."""
        responses = []
        for _ in range(count):
            try:
                r = self.session.get(url, timeout=self.timeout)
                responses.append(r)
            except requests.RequestException as e:
                responses.append(e)
            time.sleep(jitter + random.uniform(0, 0.05))
        return responses

    def _throttle(self):
        elapsed = time.time() - self._last_req
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_req = time.time()
