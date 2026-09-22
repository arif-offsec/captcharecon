"""
Headless browser session — undetected-chromedriver (uc).

Used as an optional pre-flight fetch (see --browser in cli.py) to get past
basic JS/redirect bot walls before handing the resulting cookies to the
plain `requests` session every module already uses. Everything the browser
instance creates — profile, disk cache, crash dumps — is written under one
private temp directory made for that instance, and removed in close() /
__exit__(), whether the fetch succeeded, failed, or raised.

undetected-chromedriver will NOT clean that directory up itself: it only
auto-removes a profile it creates on its own, and turns that off the moment
you hand it an explicit user_data_dir (confirmed by reading uc 3.5.5's own
source — Chrome.quit() checks `self.keep_user_data_dir`, which is set to
True whenever a caller supplies user_data_dir). That's why the cleanup
below is the only thing that removes it.

`undetected_chromedriver` itself is only imported lazily, inside
BrowserSession, so the rest of the tool keeps working on machines without
Chrome/Chromium, or where the import fails outright — see the note in
_import_uc() below.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, Optional


class BrowserFetchError(RuntimeError):
    """Raised when the headless browser can't be started, or can't load a page."""


@dataclass
class BrowserResponse:
    """Minimal, requests-like view of what the browser loaded."""

    url: str
    html: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    status_code: Optional[int] = None


def _import_uc():
    """
    Import undetected-chromedriver lazily, with a clear, actionable error
    if it fails.

    Known gotcha, confirmed while building this feature: undetected-
    chromedriver 3.5.5 (the latest release on PyPI) still imports
    `distutils`, which the standard library dropped in Python 3.12. On
    3.12+ this import only succeeds if `setuptools` is also installed,
    since setuptools ships a compatibility shim for it. Without setuptools
    present you'll see this fail with "No module named 'distutils'" —
    `pip install setuptools` fixes it. requirements.txt pins setuptools
    for exactly this reason.
    """
    try:
        import undetected_chromedriver as uc
    except Exception as exc:  # broad on purpose: any failure here must fall back cleanly
        hint = ""
        if "distutils" in str(exc):
            hint = (
                " This is the known undetected-chromedriver / Python 3.12+ gap "
                "(it still imports 'distutils'). Try: pip install setuptools"
            )
        raise BrowserFetchError(
            f"undetected-chromedriver is not usable: {exc}.{hint}"
        ) from exc
    return uc


class BrowserSession:
    """
    Headless undetected-chromedriver session with a fully private, disposable
    Chrome profile.

    Usage:
        with BrowserSession(timeout=20) as browser:
            resp = browser.get("https://example.com")
            cookies = browser.cookies_for_requests()
    """

    def __init__(
        self,
        timeout: float = 20.0,
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
        version_main: Optional[int] = None,
    ):
        self.timeout = timeout
        self._driver = None
        self._tmp_dir = tempfile.mkdtemp(prefix="captcharecon-uc-")

        uc = _import_uc()

        try:
            options = uc.ChromeOptions()

            # Keep everything Chrome writes (disk cache, crash dumps) inside
            # our own temp dir too, not scattered into ~/.cache or similar.
            options.add_argument(f"--disk-cache-dir={self._tmp_dir}/cache")
            options.add_argument(f"--crash-dumps-dir={self._tmp_dir}/crashpad")

            if user_agent:
                options.add_argument(f"--user-agent={user_agent}")
            if proxy:
                options.add_argument(f"--proxy-server={proxy}")
                # Matches SessionManager's own proxy behaviour: an
                # intercepting proxy (Burp/Caido/ZAP) presents a MITM cert
                # the browser won't trust otherwise.
                options.add_argument("--ignore-certificate-errors")

            # Best-effort HTTP status + response headers via Chrome's own
            # performance log — Selenium has no direct API for either, and
            # antibot.py needs headers (cf-ray, x-datadome, etc.) to work.
            options.set_capability("goog:loggingPrefs", {"performance": "ALL"})

            kwargs = dict(
                options=options,
                user_data_dir=self._tmp_dir,  # explicit path => uc will NOT
                                               # auto-remove it; _cleanup()
                                               # below is what does that.
                headless=True,                # uc adds the right
                                               # --headless=new/=chrome flag
                                               # for the detected Chrome
                                               # version itself.
                use_subprocess=True,
            )
            if version_main:
                kwargs["version_main"] = version_main

            self._driver = uc.Chrome(**kwargs)
            self._driver.set_page_load_timeout(self.timeout)
        except Exception as exc:
            self._cleanup()
            raise BrowserFetchError(f"could not start headless Chrome: {exc}") from exc

    def __enter__(self) -> "BrowserSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False

    def get(self, url: str) -> BrowserResponse:
        if self._driver is None:
            raise BrowserFetchError("browser session is already closed")
        try:
            self._driver.get(url)
        except Exception as exc:
            raise BrowserFetchError(f"headless browser could not load {url}: {exc}") from exc

        status_code, headers = self._document_response_meta()
        return BrowserResponse(
            url=self._driver.current_url,
            html=self._driver.page_source,
            cookies=self._get_cookies(),
            headers=headers,
            status_code=status_code,
        )

    def cookies_for_requests(self) -> Dict[str, str]:
        """Cookies in the plain {name: value} shape requests.Session.cookies.update() wants."""
        return self._get_cookies()

    def _get_cookies(self) -> Dict[str, str]:
        if self._driver is None:
            return {}
        try:
            return {c["name"]: c["value"] for c in self._driver.get_cookies()}
        except Exception:
            return {}

    def _document_response_meta(self):
        """
        Best-effort (status_code, headers) for the main document, read back
        from Chrome's performance log. A miss (redirect chains, cached
        responses, an older chromedriver build) is expected and non-fatal —
        callers must handle status_code being None / headers being empty.
        """
        status_code, headers = None, {}
        try:
            entries = self._driver.get_log("performance")
        except Exception:
            return status_code, headers

        for entry in entries:
            try:
                message = json.loads(entry["message"])["message"]
            except (KeyError, ValueError, TypeError):
                continue
            if message.get("method") != "Network.responseReceived":
                continue
            params = message.get("params", {})
            if params.get("type") != "Document":
                continue
            response = params.get("response", {})
            # Keep the last Document response: with redirects, that's the
            # final page — the same one page_source/current_url reflect.
            status_code = response.get("status", status_code)
            headers = response.get("headers") or headers
        return status_code, headers

    def close(self):
        if self._driver is not None:
            try:
                self._driver.quit()
            except Exception:
                pass
            self._driver = None
        self._cleanup()

    def _cleanup(self):
        """
        Remove the temp dir, retrying briefly in case Chrome hasn't released
        every file yet. Mirrors undetected-chromedriver's own retry loop for
        this exact problem (see Chrome.quit() in its source) — 5 attempts,
        a short sleep between each, then one ignore_errors sweep so a
        stubborn lock file never turns into a crashed scan.
        """
        for _ in range(5):
            try:
                shutil.rmtree(self._tmp_dir)
                return
            except FileNotFoundError:
                return
            except OSError:
                time.sleep(0.1)
        shutil.rmtree(self._tmp_dir, ignore_errors=True)
