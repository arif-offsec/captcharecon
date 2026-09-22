"""
Anti-Automation Stack Mapping Module
Detects WAFs, bot management platforms, fingerprinting libraries,
and security header gaps from response headers, cookies, and scripts.
"""

import re

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers":  ["cf-ray", "cf-cache-status", "cf-request-id"],
        "cookies":  ["__cflb", "__cfuid", "cf_clearance"],
        "body":     [r"cloudflare", r"attention required.*cloudflare"],
        "category": "WAF / CDN",
    },
    "Akamai": {
        "headers":  ["x-akamai-transformed", "x-check-cacheable", "akamai-origin-hop"],
        "cookies":  ["ak_bmsc", "bm_sz", "bm_sv"],
        "body":     [r"akamai"],
        "category": "WAF / CDN",
    },
    "AWS WAF / CloudFront": {
        "headers":  ["x-amz-cf-id", "x-amz-cf-pop", "x-cache"],
        "cookies":  ["aws-waf-token"],
        "body":     [r"aws waf", r"request blocked"],
        "category": "WAF / CDN",
    },
    "Imperva Incapsula": {
        "headers":  ["x-cdn", "x-iinfo"],
        "cookies":  ["incap_ses", "visid_incap", "nlbi_"],
        "body":     [r"incapsula"],
        "category": "WAF",
    },
    "F5 BIG-IP ASM": {
        "headers":  ["x-wa-info"],
        "cookies":  ["ts", "tsrce"],
        "body":     [r"the requested url was rejected", r"bigip"],
        "category": "WAF",
    },
    "ModSecurity": {
        "headers":  ["x-modsecurity-id"],
        "cookies":  [],
        "body":     [r"mod_security", r"406 not acceptable"],
        "category": "WAF",
    },
    "Sucuri": {
        "headers":  ["x-sucuri-id", "x-sucuri-cache"],
        "cookies":  [],
        "body":     [r"sucuri website firewall"],
        "category": "WAF",
    },
}

BOT_SIGNATURES = {
    "DataDome": {
        "headers":  ["x-datadome"],
        "cookies":  ["datadome"],
        "scripts":  [r"datadome\.co", r"dd\.js"],
        "body":     [r"datadome"],
        "category": "Bot Management",
    },
    "PerimeterX / HUMAN": {
        "headers":  [],
        "cookies":  ["_px", "_pxvid", "pxcts"],
        "scripts":  [r"client\.px-cdn\.net", r"perimeterx\.net", r"px\.js"],
        "body":     [r"perimeterx", r"_pxhd"],
        "category": "Bot Management",
    },
    "Cloudflare Bot Management": {
        "headers":  ["cf-ray"],
        "cookies":  ["cf_clearance", "__cf_bm"],
        "scripts":  [r"challenges\.cloudflare\.com"],
        "body":     [r"checking your browser", r"cf_chl_prog"],
        "category": "Bot Management",
    },
    "Kasada": {
        "headers":  [],
        "cookies":  ["x-kpsdk-ct", "x-kpsdk-st"],
        "scripts":  [r"kasada\.io", r"kpsdk"],
        "body":     [r"kasada"],
        "category": "Bot Management",
    },
    "Akamai Bot Manager": {
        "headers":  [],
        "cookies":  ["ak_bmsc", "bm_sz"],
        "scripts":  [r"akam\.net", r"bmak\.js"],
        "body":     [r"akamai bot"],
        "category": "Bot Management",
    },
    "Radware Bot Manager": {
        "headers":  [],
        "cookies":  ["rbzid", "rbzsessionid"],
        "scripts":  [r"radware"],
        "body":     [r"radware"],
        "category": "Bot Management",
    },
    "Shape Security / F5": {
        "headers":  [],
        "cookies":  ["shape_id"],
        "scripts":  [r"shape\.io", r"shapearray"],
        "body":     [],
        "category": "Bot Management",
    },
}

FP_SIGNATURES = {
    "FingerprintJS": {
        "patterns": [r"fingerprintjs", r"fp\.min\.js", r"fpjs\.io"],
        "detail":   "Browser fingerprinting. Collects canvas, WebGL, fonts, plugins.",
    },
    "ThreatMetrix": {
        "patterns": [r"threatmetrix", r"h\.online-metrix\.net"],
        "detail":   "Device fingerprinting and fraud detection.",
    },
    "Sift Science": {
        "patterns": [r"sift\.com", r"beacon\.js"],
        "detail":   "Behavioural fraud detection.",
    },
    "Session Recording (Mouseflow/Hotjar/FullStory)": {
        "patterns": [r"mouseflow", r"hotjar", r"fullstory", r"logrocket"],
        "detail":   "Session recording — may feed bot scoring.",
    },
}

SECURITY_HEADERS = {
    "Content-Security-Policy":   "missing — XSS risk",
    "X-Frame-Options":           "missing — clickjacking risk",
    "X-Content-Type-Options":    "missing",
    "Strict-Transport-Security": "missing — HTTPS not enforced",
    "Permissions-Policy":        "missing",
    "Referrer-Policy":           "missing",
}


class AntiBotMapper:

    def __init__(self, session, verbose=False):
        self.session = session
        self.verbose = verbose

    def run(self, url, prefetched=None, **_):
        console.print(f"[cyan]Fetching for stack analysis:[/cyan] {url}")

        if prefetched is not None:
            # Already-loaded page from a --browser pre-flight (see cli.py).
            # Headers/cookies come from Chrome's own performance log and
            # cookie jar rather than a raw HTTP response — see browser.py.
            headers = {k.lower(): v for k, v in (prefetched.headers or {}).items()}
            cookies = {k.lower(): v for k, v in (prefetched.cookies or {}).items()}
            html    = prefetched.html
        else:
            try:
                resp = self.session.get(url, allow_redirects=True)
            except requests.RequestException as e:
                console.print(f"[red]Request failed: {e}[/red]")
                return {"error": str(e)}
            headers = {k.lower(): v for k, v in resp.headers.items()}
            cookies = {c.name.lower(): c.value for c in resp.cookies}
            html    = resp.text

        soup    = BeautifulSoup(html, "lxml")
        scripts = self._scripts(soup)

        result = {
            "url":              url,
            "waf":              self._detect_waf(headers, cookies, scripts, html),
            "bot_management":   self._detect_bot(headers, cookies, scripts, html),
            "fingerprinting":   self._detect_fp(scripts, html),
            "security_headers": self._security_headers(headers),
        }

        self._print(result)
        return result

    def _scripts(self, soup):
        parts = []
        for tag in soup.find_all("script"):
            if tag.get("src"):
                parts.append(tag["src"])
            if tag.string:
                parts.append(tag.string)
        return "\n".join(parts)

    def _detect_waf(self, headers, cookies, scripts, html):
        return self._match_sigs(WAF_SIGNATURES, headers, cookies, scripts, html)

    def _detect_bot(self, headers, cookies, scripts, html):
        return self._match_sigs(BOT_SIGNATURES, headers, cookies, scripts, html)

    def _match_sigs(self, sigs, headers, cookies, scripts, html):
        found = []
        for name, sig in sigs.items():
            ev = []
            for h in sig.get("headers", []):
                if h.lower() in headers:
                    ev.append(f"Header: {h}")
            for c in sig.get("cookies", []):
                for k in cookies:
                    if c.lower() in k:
                        ev.append(f"Cookie: {k}")
            for p in sig.get("scripts", []):
                if re.search(p, scripts, re.I):
                    ev.append(f"Script: {p}")
            for p in sig.get("body", []):
                if re.search(p, html, re.I):
                    ev.append(f"Body: {p}")
            if ev:
                found.append({
                    "name":     name,
                    "category": sig.get("category", "Unknown"),
                    "evidence": ev,
                })
        return found

    def _detect_fp(self, scripts, html):
        found = []
        combined = scripts + "\n" + html
        for name, sig in FP_SIGNATURES.items():
            for p in sig["patterns"]:
                if re.search(p, combined, re.I):
                    found.append({"name": name, "detail": sig["detail"]})
                    break
        return found

    def _security_headers(self, headers):
        result = {}
        for h, missing_note in SECURITY_HEADERS.items():
            val = headers.get(h.lower())
            result[h] = {
                "present": val is not None,
                "value":   val,
                "note":    "present" if val else missing_note,
            }
        return result

    def _print(self, result):
        # WAF
        if result["waf"]:
            t = Table(title="WAF / CDN", box=box.ROUNDED, header_style="bold red")
            t.add_column("Product",  style="bold white")
            t.add_column("Category", style="cyan")
            t.add_column("Evidence", style="dim")
            for item in result["waf"]:
                t.add_row(item["name"], item["category"],
                          " | ".join(item["evidence"][:3]))
            console.print(t)
        else:
            console.print("  [dim]No WAF/CDN detected.[/dim]")

        # Bot management
        if result["bot_management"]:
            t = Table(title="Bot Management", box=box.ROUNDED, header_style="bold red")
            t.add_column("Product",  style="bold white")
            t.add_column("Category", style="cyan")
            t.add_column("Evidence", style="dim")
            for item in result["bot_management"]:
                t.add_row(item["name"], item["category"],
                          " | ".join(item["evidence"][:3]))
            console.print(t)
        else:
            console.print("  [dim]No bot management platform detected.[/dim]")

        # Fingerprinting
        if result["fingerprinting"]:
            console.print("\n  [bold yellow]Fingerprinting libraries:[/bold yellow]")
            for f in result["fingerprinting"]:
                console.print(f"  [yellow]•[/yellow] [bold]{f['name']}[/bold] — {f['detail']}")
        else:
            console.print("  [dim]No fingerprinting libraries detected.[/dim]")

        # Security headers
        t = Table(title="Security Headers", box=box.SIMPLE, header_style="bold cyan")
        t.add_column("Header",  style="white",  min_width=32)
        t.add_column("Status",  min_width=6)
        t.add_column("Note",    style="dim",    min_width=38)
        for h, info in result["security_headers"].items():
            status = "[green]✓[/green]" if info["present"] else "[red]✗[/red]"
            t.add_row(h, status, info["note"])
        console.print(t)
