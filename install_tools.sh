#!/usr/bin/env bash
# =============================================================================
# Offensive Security MCP Agent — Tool Preflight + Installer (Kali)
# Cybermarks Solutions // Daniyal Ahmed
# =============================================================================
# Purpose:
# - Install common CLI dependencies used by the MCP tool registry
# - Provide a deterministic preflight report for missing tools
#
# Notes:
# - Prefer using the project's Python venv (./mcp) for Python deps.
# - Avoid `pip --break-system-packages` unless you intentionally want system-wide installs.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${ROOT_DIR}/logs"
mkdir -p "$LOG_DIR"
LOGFILE="${LOG_DIR}/install_$(date +%Y%m%d_%H%M%S).log"

log()     { echo -e "${GREEN}[+]${NC} $*" | tee -a "$LOGFILE"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOGFILE"; }
err()     { echo -e "${RED}[-]${NC} $*" | tee -a "$LOGFILE"; }
section() { echo -e "\n${BLUE}${BOLD}━━━ $* ━━━${NC}" | tee -a "$LOGFILE"; }
info()    { echo -e "${CYAN}[*]${NC} $*" | tee -a "$LOGFILE"; }

check_installed() { command -v "$1" &>/dev/null; }

apt_install() {
  local pkg="$1"
  info "apt install $pkg"
  apt-get install -y "$pkg" >>"$LOGFILE" 2>&1 \
    && log "$pkg installed" \
    || warn "apt failed: $pkg (repo/package name may differ)"
}

ensure_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "Run as root (or with sudo): sudo $0"
    exit 1
  fi
}

banner() {
cat << 'EOF'

  ╔═══════════════════════════════════════════════════════════════╗
  ║     OFFENSIVE SECURITY MCP AGENT — TOOL INSTALLER            ║
  ║     Kali Linux — Full Offensive Toolkit Setup                 ║
  ╚═══════════════════════════════════════════════════════════════╝

EOF
}

banner
ensure_root

info "Log file: $LOGFILE"
info "Starting installation..."
sleep 1

section "APT — core tools"
apt-get update -qq >>"$LOGFILE" 2>&1 || true

# IMPORTANT:
# - Some items in the original script were COMMAND NAMES, not apt package names
#   (e.g., airodump-ng/aireplay-ng are provided by aircrack-ng).
# - Keep this list to real Debian/Kali package names.
APT_PACKAGES=(
  # Base utils
  curl wget git jq tmux socat netcat-openbsd

  # Recon/scanning
  nmap masscan amass whois dnsutils
  nikto gobuster wfuzz whatweb enum4linux smbclient ldap-utils snmp
  sqlmap commix
  seclists

  # Password/cracking
  hydra hashcat john responder

  # Post
  proxychains4 evil-winrm

  # Wireless (commands come from these packages)
  aircrack-ng hcxdumptool hcxtools wifite

  # Metasploit / ExploitDB
  metasploit-framework exploitdb

  # Go toolchain (for some ProjectDiscovery tools)
  golang
)

for pkg in "${APT_PACKAGES[@]}"; do
  apt_install "$pkg"
done

section "Python venv (recommended) + Python packages"
if [[ ! -d "${ROOT_DIR}/mcp" ]]; then
  warn "Python venv not found at ${ROOT_DIR}/mcp. Create it first if desired:"
  warn "  python3 -m venv mcp && source mcp/bin/activate && pip install -U pip"
fi

info "Installing Python packages (will use system pip unless you activate venv first)."
PYTHON_PKGS=(
  mcp
  fastapi
  "uvicorn[standard]"
  websockets
  pydantic
  aiohttp
  impacket
  ldapdomaindump
  adidnsdump
  certipy-ad
  bloodhound
  netexec
)

python3 -m pip install -q --upgrade pip >>"$LOGFILE" 2>&1 || true
for pkg in "${PYTHON_PKGS[@]}"; do
  info "pip install ${pkg}"
  python3 -m pip install -q "${pkg}" >>"$LOGFILE" 2>&1 || warn "pip failed: ${pkg}"
done

section "Go-based tools (optional)"
export GOPATH="${HOME}/go"
export PATH="${PATH}:${GOPATH}/bin"

if check_installed go; then
  info "Installing a few Go tools..."
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest >>"$LOGFILE" 2>&1 || warn "go install subfinder failed"
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest >>"$LOGFILE" 2>&1 || warn "go install nuclei failed"
  go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest >>"$LOGFILE" 2>&1 || warn "go install dnsx failed"
  go install github.com/ropnop/kerbrute@latest >>"$LOGFILE" 2>&1 || warn "go install kerbrute failed"
else
  warn "Go not installed; skipping Go tools."
fi

section "Verification — command presence"
TOOLS=(
  # Recon/scanning
  nmap masscan amass subfinder dnsx whois dig
  nikto gobuster wfuzz whatweb enum4linux snmpwalk ldapsearch smbclient
  sqlmap commix

  # Exploit framework
  msfconsole msfvenom searchsploit

  # Password/cracking
  hydra hashcat john responder kerbrute

  # Post
  evil-winrm proxychains4

  # NetExec (CME successor)
  nxc

  # Wireless
  airmon-ng airodump-ng aireplay-ng aircrack-ng hcxdumptool wifite

  # Python-based tools
  bloodhound-python certipy
)

PASS=0; FAIL=0
for tool in "${TOOLS[@]}"; do
  if check_installed "$tool"; then
    echo -e "  ${GREEN}✓${NC} $tool"
    ((PASS++))
  else
    echo -e "  ${RED}✗${NC} $tool"
    ((FAIL++))
  fi
done

echo ""
echo -e "${BOLD}━━━ SUMMARY ━━━${NC}"
echo -e "  ${GREEN}Installed : $PASS${NC}"
echo -e "  ${RED}Missing   : $FAIL${NC}"
echo -e "  Log file  : $LOGFILE"
echo ""

if [[ $FAIL -gt 0 ]]; then
  warn "$FAIL commands missing. Some are optional depending on which MCP tools you use."
fi

log "Done."

