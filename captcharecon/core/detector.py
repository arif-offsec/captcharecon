"""
CAPTCHA Fingerprinting Module
Identifies CAPTCHA provider, version, and configuration leaks
by analysing HTML, script sources, and inline JavaScript.
Does not interact with or trigger the CAPTCHA.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, List
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ── Signature library ─────────────────────────────────────────────────────────
SIGNATURES = {
    "reCAPTCHA v2 (Checkbox)": {
        "html":    [r'class=["\']g-recaptcha["\']', r'data-sitekey'],
        "scripts": [r'google\.com/recaptcha/api\.js(?!\?render=)',
                    r'recaptcha/api\.js(?!\?render=)'],
        "js":      [r'grecaptcha\.ready', r'grecaptcha\.render'],
        "risk":    "Low",
        "notes":   "User must tick a checkbox. Sitekey exposed in HTML.",
    },
    "reCAPTCHA v3 (Invisible)": {
        "html":    [r'data-sitekey'],
        "scripts": [r'recaptcha/api\.js\?render=',
                    r'google\.com/recaptcha/enterprise\.js'],
        "js":      [r'grecaptcha\.execute\(["\'][\w-]+["\'],\s*\{action'],
        "risk":    "Medium",
        "notes":   "Score-based, invisible. Action name and sitekey leaked in JS.",
    },
    "hCaptcha": {
        "html":    [r'class=["\']h-captcha["\']', r'hcaptcha\.com'],
        "scripts": [r'hcaptcha\.com/1/api\.js'],
        "js":      [r'hcaptcha\.execute', r'hcaptcha\.render'],
        "risk":    "Low",
        "notes":   "Checkbox-based. Privacy-focused alternative to reCAPTCHA.",
    },
    "Cloudflare Turnstile": {
        "html":    [r'class=["\']cf-turnstile["\']'],
        "scripts": [r'challenges\.cloudflare\.com/turnstile'],
        "js":      [r'turnstile\.render', r'turnstile\.execute'],
        "risk":    "Medium",
        "notes":   "Modern invisible CAPTCHA by Cloudflare.",
    },
    "FunCaptcha / Arkose Labs": {
        "html":    [r'arkose', r'funcaptcha', r'fc-token'],
        "scripts": [r'funcaptcha\.com', r'arkoselabs\.com'],
        "js":      [r'ArkoseEnforcement', r'arkoseToken'],
        "risk":    "High",
        "notes":   "Game-based challenge. Token is strongly validated server-side.",
    },
    "GeeTest (Slide Puzzle)": {
        "html":    [r'geetest'],
        "scripts": [r'geetest\.com', r'gt\.js'],
        "js":      [r'initGeetest', r'new Geetest'],
        "risk":    "High",
        "notes":   "Sliding puzzle CAPTCHA. Tracks mouse movement.",
    },
    "KeyCAPTCHA": {
        "html":    [r'keycaptcha'],
        "scripts": [r'keycaptcha\.com'],
        "js":      [],
        "risk":    "Medium",
        "notes":   "Jigsaw puzzle CAPTCHA.",
    },
    "Math / Text CAPTCHA (custom)": {
        "html":    [r'captcha', r'solve\s+the\s+equation', r'arithmetic'],
        "scripts": [],
        "js":      [],
        "risk":    "Low",
        "notes":   "Simple custom implementation. Check for token reuse.",
    },
}


@dataclass
class CAPTCHAFinding:
    name:     str
    risk:     str
    sitekey:  Optional[str]  = None
    notes:    str            = ""
    evidence: List[str]      = field(default_factory=list)


class CAPTCHADetector:

    def __init__(self, session, verbose=False):
        self.session = session
        self.verbose = verbose

    def run(self, url, prefetched=None, **_):
        console.print(f"[cyan]Fetching:[/cyan] {url}")

        if prefetched is not None:
            # Already-loaded page from a --browser pre-flight (see cli.py) —
            # reuse it instead of fetching again, so detect sees whatever
            # headless Chrome actually rendered.
            html           = prefetched.html
            status_code    = prefetched.status_code
            content_length = len(html.encode("utf-8", errors="ignore"))
        else:
            try:
                resp = self.session.get(url, allow_redirects=True)
            except requests.RequestException as e:
                console.print(f"[red]Request failed: {e}[/red]")
                return {"error": str(e)}
            html           = resp.text
            status_code    = resp.status_code
            content_length = len(resp.content)

        soup    = BeautifulSoup(html, "lxml")
        scripts = self._collect_scripts(soup)

        findings = []
        for name, sig in SIGNATURES.items():
            m = self._match(html, scripts, sig)
            if m["detected"]:
                findings.append(CAPTCHAFinding(
                    name     = name,
                    risk     = sig["risk"],
                    sitekey  = self._sitekey(html),
                    notes    = sig["notes"],
                    evidence = m["evidence"],
                ))

        self._print(findings, status_code, content_length, soup)

        return {
            "url":           url,
            "status_code":   status_code,
            "captcha_found": len(findings) > 0,
            "captcha_count": len(findings),
            "findings":      [vars(f) for f in findings],
            "forms":         len(soup.find_all("form")),
            "page_title":    soup.title.string.strip() if soup.title else None,
        }

    def _collect_scripts(self, soup):
        parts = []
        for tag in soup.find_all("script"):
            if tag.get("src"):
                parts.append(tag["src"])
            if tag.string:
                parts.append(tag.string)
        return "\n".join(parts)

    def _match(self, html, scripts, sig):
        evidence = []
        combined = html + "\n" + scripts

        for p in sig.get("html", []):
            if re.search(p, html, re.I):
                evidence.append(f"HTML: {p}")

        for p in sig.get("scripts", []):
            if re.search(p, scripts, re.I):
                evidence.append(f"Script: {p}")

        for p in sig.get("js", []):
            if re.search(p, combined, re.I):
                evidence.append(f"JS: {p}")

        return {"detected": bool(evidence), "evidence": evidence}

    def _sitekey(self, html):
        patterns = [
            r'data-sitekey=["\']([A-Za-z0-9_\-]+)["\']',
            r'sitekey["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]+)["\']',
            r'render=([A-Za-z0-9_\-]{20,})',
        ]
        for p in patterns:
            m = re.search(p, html)
            if m:
                return m.group(1)
        return None

    def _print(self, findings, status_code, content_length, soup):
        if not findings:
            console.print(
                f"  [yellow]No known CAPTCHA detected.[/yellow]  "
                f"[dim]HTTP {status_code} | "
                f"{content_length} bytes[/dim]"
            )
            return

        t = Table(box=box.ROUNDED, header_style="bold cyan", show_lines=True)
        t.add_column("CAPTCHA Type",  style="bold white", min_width=28)
        t.add_column("Risk",          min_width=8)
        t.add_column("Sitekey",       style="dim yellow", min_width=20)
        t.add_column("Notes",         style="white",      min_width=40)

        for f in findings:
            col = {"Low": "green", "Medium": "yellow", "High": "red"}.get(f.risk, "white")
            t.add_row(
                f.name,
                f"[{col}]{f.risk}[/{col}]",
                f.sitekey or "[dim]Not found[/dim]",
                f.notes,
            )

        console.print(t)

        if self.verbose:
            for f in findings:
                console.print(f"\n  [bold]{f.name}[/bold] — evidence:")
                for e in f.evidence:
                    console.print(f"    [dim]• {e}[/dim]")
