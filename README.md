# CaptchaRecon

```
  ____           _       _           ____
 / ___|__ _ _ __| |_ ___| |__   __ _|  _ \ ___  ___ ___  _ __
| |   / _` | '_ \ __/ __| '_ \ / _` | |_) / _ \/ __/ _ \| '_ \
| |__| (_| | |_) | || (__| | | | (_| |  _ <  __/ (_| (_) | | | |
 \____\__,_| .__/ \__\___|_| |_|\__,_|_| \_\___|\___\___/|_| |_|
           |_|
CAPTCHA & Anti-Automation Reconnaissance Toolkit
```

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Platform: Kali Linux](https://img.shields.io/badge/platform-Kali%20Linux-557C94.svg)]()
[![Ethical Use Only](https://img.shields.io/badge/use-authorised%20only-red.svg)]()

> **For authorised penetration testing and security research only.**
> Running this tool against systems without explicit written permission may violate
> computer crime laws in your jurisdiction.

---

## What is CaptchaRecon?

CaptchaRecon is a modular reconnaissance and analysis toolkit for web application
penetration testers. It maps the **entire anti-automation defence stack** of a target
application — not to bypass it, but to understand it, identify misconfigurations,
and document findings for a professional pentest report.

It does **NOT** solve, bypass, or interact with any CAPTCHA.

---

## What Happens When You Run It

Before installing and testing this tool, you need to understand exactly what it
does from the moment you press Enter. This is a security tool that requires
**authorised access** to the target — so understanding the full execution flow
is not optional.

When you run:

```bash
captcharecon -u https://target.com/login
```

Here is what happens, in order:

**Step 1 — Banner**
The ASCII logo prints with the version number and licence line.

**Step 2 — Ethics prompt (mandatory)**
```
⚠  AUTHORISED USE ONLY
Do you have explicit authorisation to test the target? [y/N]:
```
Type `y` to continue. Anything else exits immediately. This prompt cannot be
suppressed or bypassed.

**Step 3 — Session summary prints**
```
Target : https://target.com/login
Modules: detect, resilience, ratelimit, antibot
Delay  : 1.0s per request
```

If `--browser` was passed, this is also where headless Chrome runs once
against the target before any module starts — see
[Browser-Assisted Fetch](#browser-assisted-fetch---browser) for exactly
what that does and what it cleans up afterwards.

**Step 4 — Module 1: CAPTCHA Fingerprinting (`detect`)**
- Fetches the page with a GET request
- Parses the full HTML source and collects all script `src` attributes and inline JavaScript
- Checks everything against 8 CAPTCHA provider signatures — HTML patterns, script URLs, JS function names
- Tries to extract any exposed sitekey from the HTML source
- Prints a table: CAPTCHA type, risk level, sitekey if found, notes
- If nothing found: prints "No known CAPTCHA detected"

Does NOT interact with or trigger any CAPTCHA.

**Step 5 — Module 2: Resilience Testing (`resilience`)**
- Fetches the page and finds all `<form>` elements
- For each form, runs 5 checks:
  - Is there a CAPTCHA response field in the form inputs at all?
  - What does the server return if you submit with an empty CAPTCHA token?
  - What does the server return if you remove the CAPTCHA field entirely?
  - Are there low-entropy or predictable token patterns in the HTML?
  - Are there honeypot fields hidden via CSS?
- Prints findings with severity: High, Medium, Low, or Info

**Step 6 — Module 3: Rate Limit Analysis (`ratelimit`)**
- Sends a HEAD request and checks response headers for `X-RateLimit-*`, `Retry-After`, and related headers
- Sends 10 rapid GET requests (configurable) and records every status code
- Analyses response timing: min, max, mean, standard deviation
- Detects soft throttling if response time rises significantly mid-session
- Tests 9 IP spoofing headers one by one: `X-Forwarded-For`, `X-Real-IP`,
  `CF-Connecting-IP`, `True-Client-IP`, `X-Originating-IP`, `X-Remote-IP`,
  `X-Client-IP`, `Forwarded`, and others
- If any header causes the response code to change — flags it as High severity
- Prints status code distribution table and timing summary

**Step 7 — Module 4: Anti-Automation Stack Mapping (`antibot`)**
- Fetches the page and inspects response headers, cookies, and script sources
- Checks against WAF/CDN signatures: Cloudflare, Akamai, AWS WAF/CloudFront,
  Imperva Incapsula, F5 BIG-IP ASM, ModSecurity, Sucuri
- Checks against bot management signatures: DataDome, PerimeterX/HUMAN,
  Cloudflare Bot Management, Kasada, Akamai Bot Manager, Radware, Shape Security/F5
- Scans scripts for fingerprinting libraries: FingerprintJS, ThreatMetrix,
  Sift Science, Mouseflow, Hotjar, FullStory
- Checks 6 security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy
- Prints separate tables for each category

**Step 8 — Summary table with remediation**

One consolidated table across all four modules, sorted by severity, with a
remediation tag on every row:

```
Module                   Result                        Severity   Remediation
Resilience Testing       2 high-severity weakness(es)  High       → Enforce server-side token validation
Rate Limit Analysis      No rate limit triggered        Medium     → Implement lockout after 3-5 attempts
Anti-Automation Mapping  No WAF or bot management       Medium     → Place behind WAF/CDN (Cloudflare, AWS WAF)
CAPTCHA Fingerprinting   1 CAPTCHA type(s) found        Low        → Verify server-side validation enforced
```

Below the table, a **Remediation Detail** section expands each tag into full
technical steps — one numbered block per finding, in the same priority order.
Sorted highest severity first so the most critical items are always at the top.

**Step 9 — Done**

If you passed `--output report.json`, the full JSON report is written at this point.

Total time on a typical login page with default 1.0s delay: roughly 30 to 60 seconds.

---

## Modules

| Module | What it does |
|---|---|
| **detect** | Identifies CAPTCHA type, version, provider, and exposed sitekeys from HTML/JS |
| **resilience** | Tests implementation weaknesses — missing server-side validation, empty tokens, field removal |
| **ratelimit** | Probes throttling, rate limit headers, timing analysis, and IP bypass header effectiveness |
| **antibot** | Detects WAFs, bot management platforms, fingerprinting libraries, and security header gaps |

---

## Open-Source Dependencies

All integrated libraries are free and open-source. No proprietary tools.

| Package | Licence | Purpose |
|---|---|---|
| [requests](https://github.com/psf/requests) | Apache 2.0 | HTTP client |
| [beautifulsoup4](https://www.crummy.com/software/BeautifulSoup/) | MIT | HTML parsing |
| [rich](https://github.com/Textualize/rich) | MIT | Terminal output |
| [urllib3](https://github.com/urllib3/urllib3) | MIT | HTTP transport |
| [lxml](https://github.com/lxml/lxml) | BSD | Fast HTML/XML parser |
| [certifi](https://github.com/certifi/python-certifi) | MPL 2.0 | CA certificates |
| [undetected-chromedriver](https://github.com/ultrafunkamsterdam/undetected-chromedriver) | GPL v3 | Headless Chrome for `--browser` |
| [setuptools](https://github.com/pypa/setuptools) | MIT | `distutils` shim `undetected-chromedriver` needs on Python 3.12+ |

`undetected-chromedriver` also needs Google Chrome or Chromium installed
separately — pip can't install the browser itself. Everything else works
with no browser installed; `--browser` is the only thing that needs one.

---

## Installation (Kali Linux)

```bash
git clone https://github.com/arif-offsec/captcharecon.git
cd captcharecon
sudo bash install.sh
```

The installer:
- Updates apt package lists
- Installs and upgrades all Python dependencies to their latest versions
- Installs the `captcharecon` command system-wide
- Installs the man page (`man captcharecon`)
- Creates a config file at `/etc/captcharecon/captcharecon.conf`

To uninstall:

```bash
sudo bash uninstall.sh
```

---

## Usage

### Full scan — all modules

```bash
captcharecon -u https://target.com/login
```

### Specific modules

```bash
captcharecon -u https://target.com/login --modules detect antibot
```

### Route through Burp Suite / Caido / ZAP

```bash
captcharecon -u https://target.com/login --proxy http://127.0.0.1:8080
```

### Get past a basic JS/redirect wall with headless Chrome

```bash
captcharecon -u https://target.com/login --browser
```

Loads the target once in headless Chrome (undetected-chromedriver) before
the modules run, then hands the resulting cookies to every module. See
[Browser-Assisted Fetch (`--browser`)](#browser-assisted-fetch---browser)
below for what this does and doesn't do.

### Deep rate limit probe

```bash
captcharecon -u https://target.com/login --ratelimit-requests 30 --delay 0.3
```

### Save JSON report

```bash
captcharecon -u https://target.com/login --full --output report.json
```

### Full options

```
-u, --url URL                Target URL (required)
--modules [...]              Modules: detect resilience ratelimit antibot
--full                       Run all modules with extended checks
--output FILE                Save JSON report to FILE
--proxy URL                  Proxy URL (Burp / Caido / ZAP)
-b, --browser                Fetch with headless Chrome first, reuse its cookies
--delay SECS                 Delay between requests (default: 1.0)
--timeout SECS               Request timeout (default: 10)
--ratelimit-requests N       Requests for rate limit probing (default: 10)
--user-agent UA              Custom User-Agent string
--no-banner                  Suppress ASCII banner
-v, --verbose                Verbose output
```

---

## Manual Page

```bash
man captcharecon
```

The man page covers all options, modules, output format, proxy integration,
open-source dependency licences, and ethical use requirements.

---

## CAPTCHA Providers Detected

- reCAPTCHA v2 (Checkbox)
- reCAPTCHA v3 (Invisible / Enterprise)
- hCaptcha
- Cloudflare Turnstile
- FunCaptcha / Arkose Labs
- GeeTest (Slide Puzzle)
- KeyCAPTCHA
- Math / Text CAPTCHA (custom implementations)

---

## WAF / Bot Management Detected

**WAF / CDN:** Cloudflare, Akamai, AWS WAF/CloudFront, Imperva Incapsula,
F5 BIG-IP ASM, ModSecurity, Sucuri

**Bot Management:** DataDome, PerimeterX/HUMAN Security, Cloudflare Bot Management,
Kasada, Akamai Bot Manager, Radware Bot Manager, Shape Security/F5

**Fingerprinting:** FingerprintJS, ThreatMetrix, Sift Science, Mouseflow,
Hotjar, FullStory

---

## Output

### Terminal
Rich-formatted tables with colour-coded severity — HIGH, MEDIUM, LOW, INFO.

### JSON

```bash
captcharecon -u https://target.com/login --output findings.json
```

```json
{
  "tool": "CaptchaRecon",
  "version": "1.0.0",
  "license": "GPL v3",
  "timestamp": "2025-04-26T10:00:00Z",
  "target": "https://target.com/login",
  "modules": {
    "detect":     { "captcha_found": true, "findings": [] },
    "resilience": { "forms_tested": 1,     "findings": [] },
    "ratelimit":  { "rate_limited": false,  "bypass_findings": [] },
    "antibot":    { "waf": [],             "security_headers": {} }
  }
}
```

---

## Proxy Integration

Works with Burp Suite, Caido, and OWASP ZAP out of the box.

```bash
# Burp Suite / Caido
captcharecon -u https://target.com/login --proxy http://127.0.0.1:8080

# OWASP ZAP
captcharecon -u https://target.com/login --proxy http://127.0.0.1:8090
```

---

## Browser-Assisted Fetch (`--browser`)

Every module normally talks to the target with plain HTTP requests. That's
fast, but some targets sit behind a JS challenge or redirect check that
never even shows a plain HTTP client the real page — the requests-based
modules would then be fingerprinting a challenge page, not the target.

`--browser` adds one step before the modules run: it loads the target once
in headless Chrome via
[undetected-chromedriver](https://github.com/ultrafunkamsterdam/undetected-chromedriver),
then hands the resulting cookies to the same `requests` session every
module already uses. `detect` and `antibot` also reuse that browser-loaded
page directly instead of fetching the target a second time. `resilience`
and `ratelimit` still make their own requests — they're testing exact,
often deliberately malformed request bodies, which needs raw control a
browser doesn't give you — but they benefit from the cookies.

```bash
captcharecon -u https://target.com/login --browser
```

### What it needs

Google Chrome or Chromium installed on the system running captcharecon.
`pip install undetected-chromedriver` installs the Python driver, not the
browser itself — `install.sh` tries to install Chromium via apt as an
optional step, but not every apt mirror carries it (Ubuntu 24.04's default
repos, for one, only ship a snap-based `chromium-browser` stub). If no
browser is available, or `undetected-chromedriver` can't start it for any
other reason, `--browser` prints a warning and the scan continues exactly
as if `--browser` had never been passed — it never crashes the scan.

### Temp files

Everything the browser instance creates — its Chrome profile, disk cache,
crash dumps — is written to one private temp directory made just for that
instance, and deleted the moment the fetch finishes, whether it succeeded
or failed. `undetected-chromedriver` does not do this cleanup on its own:
by default it makes a temp profile and removes it at exit, but that
auto-removal turns off the moment you hand it an explicit profile path —
which captcharecon always does, specifically so it can guarantee where
that data goes and that it's actually removed. See
`captcharecon/utils/browser.py` for the implementation.

### What this does not do

- **It does not solve, bypass, or interact with any CAPTCHA** — same as
  every other module. It only gets the page to load.
- **It does not hide your IP.** undetected-chromedriver defeats
  browser/JS fingerprinting, not network-level identification — running
  from a datacenter or a flagged residential IP can still get you blocked
  even with `--browser` on.
- **Headless is explicitly the more detectable mode.** The library's own
  docs describe headless as lowering undetectability and "not fully
  supported." If a target blocks `--browser` but not a real browser, that
  matches expectations rather than indicating a bug — some teams instead
  run this kind of tooling headed, under a virtual display like Xvfb, for
  that reason.
- **The underlying package is not fast-moving.** The latest
  `undetected-chromedriver` release on PyPI is 3.5.5 (Feb 2024). Bot
  detection techniques don't stand still, so treat `--browser` as another
  data point, not a guarantee.

---

## Project Structure

```
captcharecon/
├── captcharecon/
│   ├── __init__.py
│   ├── cli.py              ← entry point, arg parsing, ethics prompt
│   ├── core/
│   │   ├── detector.py     ← CAPTCHA fingerprinting (8 providers)
│   │   ├── resilience.py   ← 5 implementation weakness checks
│   │   ├── ratelimit.py    ← header scan + rapid probe + 9 bypass headers
│   │   ├── antibot.py      ← WAF/bot mgmt/fingerprinting/security headers
│   │   └── reporter.py     ← summary table + JSON export
│   └── utils/
│       ├── http.py         ← shared session, throttle, proxy support
│       └── browser.py      ← headless Chrome session for --browser
├── man/
│   └── captcharecon.1      ← man page source
├── install.sh              ← system-wide installer
├── uninstall.sh            ← clean uninstaller
├── setup.py
├── requirements.txt        ← all open-source dependencies with licences
├── LICENSE                 ← GPL v3
└── README.md
```

---

## Ethical Use

This tool is designed for:

- Authorised web application penetration tests
- Bug bounty hunting within defined scope
- Security research on systems you own or have permission to test
- Defensive security — understanding your own application's exposure

Misuse may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse
Act, and equivalent legislation in other jurisdictions. The ethics acknowledgement
prompt at startup is mandatory.

---

## Contributing

Pull requests are welcome. If you find a new CAPTCHA provider, WAF signature,
or bot management platform not covered, open an issue or PR.

---

## License

GPL v3 — Free and open-source forever. See [LICENSE](LICENSE).
