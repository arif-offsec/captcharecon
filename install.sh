#!/usr/bin/env bash
# =============================================================================
# CaptchaRecon — Installer
# Installs the tool system-wide and ensures all dependencies are up to date.
# Must be run as root or with sudo.
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
info() { echo -e "${CYAN}[→]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
fail() { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

INSTALL_DIR="/opt/captcharecon"
BIN_LINK="/usr/local/bin/captcharecon"
MAN_DIR="/usr/local/share/man/man1"
CONF_DIR="/etc/captcharecon"
LOG_FILE="/var/log/captcharecon_install.log"

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  fail "Run as root: sudo bash install.sh"
fi

echo ""
echo -e "${BOLD}${CYAN}Installing CaptchaRecon...${RESET}"
echo "Log: $LOG_FILE"
echo ""

exec > >(tee -a "$LOG_FILE") 2>&1

# ── OS check ─────────────────────────────────────────────────────────────────
if ! command -v apt-get &>/dev/null; then
  fail "This installer requires a Debian/Ubuntu-based system (apt-get not found)."
fi

# ── System dependencies ───────────────────────────────────────────────────────
info "Updating apt package lists..."
apt-get update -qq

info "Installing system dependencies..."
apt-get install -y -qq \
  python3 \
  python3-pip \
  python3-venv \
  curl \
  git \
  man-db \
  gzip \
  2>/dev/null
ok "System packages ready"

# ── Chromium (optional — only needed for --browser) ──────────────────────────
# undetected-chromedriver drives an existing Chrome/Chromium install; pip
# cannot install the browser itself. Not every apt mirror carries a real
# chromium package (some Debian/Ubuntu releases only ship a snap stub), so
# this step is best-effort and never fails the install.
info "Installing Chromium for --browser (optional, best-effort)..."
if apt-get install -y -qq chromium 2>/dev/null || apt-get install -y -qq chromium-browser 2>/dev/null; then
  ok "Chromium installed — captcharecon --browser is ready to use"
else
  warn "Could not install Chromium from apt. captcharecon still works fully"
  warn "without it — --browser just won't be available until Chrome or"
  warn "Chromium is installed separately."
fi

# ── Remove EXTERNALLY-MANAGED restriction if present ─────────────────────────
EXTERN_FILE=""
for f in /usr/lib/python3*/EXTERNALLY-MANAGED; do
  [[ -f "$f" ]] && EXTERN_FILE="$f" && break
done
if [[ -n "$EXTERN_FILE" ]]; then
  mv "$EXTERN_FILE" "${EXTERN_FILE}.bak"
  info "Removed pip system restriction (backed up to ${EXTERN_FILE}.bak)"
fi

# ── Python open-source dependencies ───────────────────────────────────────────
info "Installing and upgrading Python dependencies (all open-source)..."

PYTHON_DEPS=(
  "requests>=2.31.0"                  # Apache 2.0 — HTTP library
  "beautifulsoup4>=4.12.0"            # MIT — HTML parsing
  "rich>=13.0.0"                      # MIT — terminal formatting
  "urllib3>=2.0.0"                    # MIT — HTTP client
  "lxml>=5.0.0"                       # BSD — fast HTML/XML parser
  "certifi>=2024.0.0"                 # MPL 2.0 — CA certificates
  "undetected-chromedriver>=3.5.5"    # GPL v3 — powers --browser
)

for dep in "${PYTHON_DEPS[@]}"; do
  pkg_name=$(echo "$dep" | sed 's/[>=].*//')
  info "  Installing/upgrading: $pkg_name"
  pip3 install --upgrade "$dep" --quiet
  ok "  $pkg_name — up to date"
done

# setuptools ships the distutils shim undetected-chromedriver needs on
# Python 3.12+ (the stdlib dropped distutils; uc still imports it).
if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; then
  info "  Installing/upgrading: setuptools (distutils shim for Python 3.12+)"
  pip3 install --upgrade "setuptools>=70.0.0" --quiet
  ok "  setuptools — up to date"
fi

# ── Install CaptchaRecon itself ───────────────────────────────────────────────
info "Installing CaptchaRecon to $INSTALL_DIR..."

# Clean previous install
[[ -d "$INSTALL_DIR" ]] && rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Copy source
cp -r captcharecon/  "$INSTALL_DIR/captcharecon/"
cp    setup.py       "$INSTALL_DIR/"
cp    requirements.txt "$INSTALL_DIR/"
cp    README.md      "$INSTALL_DIR/"
cp    LICENSE        "$INSTALL_DIR/"

# Install package
pip3 install --quiet "$INSTALL_DIR/"
ok "CaptchaRecon package installed"

# ── CLI symlink ───────────────────────────────────────────────────────────────
[[ -L "$BIN_LINK" || -f "$BIN_LINK" ]] && rm -f "$BIN_LINK"

cat > "$BIN_LINK" << 'WRAPPER'
#!/usr/bin/env python3
import sys
from captcharecon.cli import main
if __name__ == '__main__':
    sys.exit(main())
WRAPPER

chmod +x "$BIN_LINK"
ok "CLI symlink created: $BIN_LINK"

# ── Man page ──────────────────────────────────────────────────────────────────
info "Installing man page..."
mkdir -p "$MAN_DIR"
gzip -c man/captcharecon.1 > "$MAN_DIR/captcharecon.1.gz"
mandb -q 2>/dev/null || true
ok "Man page installed — run: man captcharecon"

# ── Config ────────────────────────────────────────────────────────────────────
mkdir -p "$CONF_DIR"
if [[ ! -f "$CONF_DIR/captcharecon.conf" ]]; then
  cat > "$CONF_DIR/captcharecon.conf" << 'CONF'
# CaptchaRecon Configuration
# Edit these values to change default behaviour.

# Default request delay in seconds
DEFAULT_DELAY=1.0

# Default request timeout in seconds
DEFAULT_TIMEOUT=10

# Default number of requests for rate limit probing
DEFAULT_RATELIMIT_REQUESTS=10

# Default modules to run (space-separated)
DEFAULT_MODULES="detect resilience ratelimit antibot"
CONF
  ok "Config written to $CONF_DIR/captcharecon.conf"
else
  warn "Existing config preserved at $CONF_DIR/captcharecon.conf"
fi

# ── Verify installation ───────────────────────────────────────────────────────
echo ""
info "Verifying installation..."

if command -v captcharecon &>/dev/null; then
  ok "captcharecon command is available"
else
  fail "Installation verification failed — captcharecon command not found"
fi

if python3 -c "from captcharecon.cli import main" 2>/dev/null; then
  ok "Python module imports correctly"
else
  fail "Python module import failed"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}Installation complete.${RESET}"
echo ""
echo -e "  Run a scan:   ${CYAN}captcharecon -u https://target.com${RESET}"
echo -e "  All options:  ${CYAN}captcharecon --help${RESET}"
echo -e "  Manual page:  ${CYAN}man captcharecon${RESET}"
echo -e "  Uninstall:    ${CYAN}sudo bash uninstall.sh${RESET}"
echo ""
echo -e "${YELLOW}Always test only against systems you have explicit permission to test.${RESET}"
echo ""
