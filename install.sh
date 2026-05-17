#!/usr/bin/env bash
# OSCP AutoPwn Framework - Installer
# Run as root on Kali Linux or Parrot OS
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✘]${NC} $*"; exit 1; }

echo -e "${RED}"
cat << 'EOF'
╔══════════════════════════════════════════════════════════╗
║     OSCP AutoPwn Framework - Installation Script        ║
║     ⚠ FOR AUTHORIZED LAB ENVIRONMENTS ONLY ⚠            ║
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

[[ $EUID -ne 0 ]] && error "Please run as root"

info "Updating package lists..."
apt-get update -qq

info "Installing system dependencies..."
apt-get install -y -qq \
  nmap \
  gobuster \
  ffuf \
  nikto \
  whatweb \
  enum4linux \
  smbclient \
  crackmapexec \
  exploitdb \
  metasploit-framework \
  hydra \
  hashcat \
  john \
  netcat-traditional \
  curl \
  wget \
  python3 \
  python3-pip \
  rlwrap \
  redis-tools \
  2>/dev/null || warn "Some packages may not be available"

# enum4linux-ng
if ! command -v enum4linux-ng &>/dev/null; then
  info "Installing enum4linux-ng..."
  pip3 install enum4linux-ng -q 2>/dev/null || true
fi

# nuclei
if ! command -v nuclei &>/dev/null; then
  info "Installing nuclei..."
  if command -v go &>/dev/null; then
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true
  else
    warn "Go not found - install nuclei manually from https://github.com/projectdiscovery/nuclei"
  fi
fi

info "Installing Python dependencies..."
pip3 install -r "$(dirname "$0")/requirements.txt" -q

info "Setting up wordlists..."
if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
  if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    info "Decompressing rockyou.txt..."
    gunzip -k /usr/share/wordlists/rockyou.txt.gz
  else
    warn "rockyou.txt not found - download from: https://github.com/brannondorsey/naive-hashcat/releases"
  fi
fi

# Install SecLists
if [ ! -d /usr/share/seclists ]; then
  info "Installing SecLists..."
  apt-get install -y -qq seclists 2>/dev/null || \
    git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists 2>/dev/null || \
    warn "SecLists installation failed - install manually"
fi

# Make main script executable
chmod +x "$(dirname "$0")/main.py"

# Create output directory
mkdir -p "$(dirname "$0")/output"

echo ""
info "Installation complete!"
echo ""
echo -e "${GREEN}Usage Examples:${NC}"
echo "  python3 main.py 10.10.10.5"
echo "  python3 main.py 10.10.10.5 --lhost 10.10.14.1 --lport 4444"
echo "  python3 main.py 10.10.10.0/24 --phases recon,exploit"
echo "  python3 main.py targets.txt --config config/default.yaml --resume"
echo "  python3 main.py 10.10.10.5 --dry-run"
echo ""
echo -e "${YELLOW}⚠ Remember: Only use against systems you are authorized to test!${NC}"
