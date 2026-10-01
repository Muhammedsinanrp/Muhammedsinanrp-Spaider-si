#!/usr/bin/env bash
# =============================================================================
#  SPAIDER Linux Tool Installer
#  AI-Powered Cybersecurity Command Platform — RED · BLUE · PURPLE
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
cat << "EOF"
 ███████╗██████╗  █████╗ ██╗██████╗ ███████╗██████╗ 
 ██╔════╝██╔══██╗██╔══██╗██║██╔══██╗██╔════╝██╔══██╗
 ███████╗██████╔╝███████║██║██║  ██║█████╗  ██████╔╝
 ╚════██║██╔═══╝ ██╔══██║██║██║  ██║██╔══╝  ██╔══██╗
 ███████║██║     ██║  ██║██║██████╔╝███████╗██║  ██║
 ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
EOF
echo -e "${NC}"
echo -e "${GREEN}${BOLD}=== SPAIDER Linux Tool Installer ===${NC}"
echo -e "Target OS: Ubuntu / Debian / Kali Linux / Parrot OS / Arch / Fedora\n"

# 1. Check Root / Sudo
SUDO=""
if [ "$EUID" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
        echo -e "${YELLOW}[!] Non-root user detected. Using sudo for system installations.${NC}"
    else
        echo -e "${RED}[✘] Error: Please run this script as root or install sudo.${NC}"
        exit 1
    fi
fi

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="/usr/local/bin/spaider"

echo -e "${CYAN}[*] Step 1: Installing system dependencies...${NC}"
if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -y
    $SUDO apt-get install -y python3 python3-pip python3-venv git curl nmap libmagic1
elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y python3 python3-pip git curl nmap file-libs
elif command -v pacman >/dev/null 2>&1; then
    $SUDO pacman -Sy --noconfirm python python-pip git curl nmap file
else
    echo -e "${YELLOW}[!] Warning: Unknown package manager. Please ensure python3, nmap, and curl are installed.${NC}"
fi

echo -e "${CYAN}[*] Step 2: Setting up Python virtual environment...${NC}"
cd "$INSTALL_DIR"

if [ ! -d "$INSTALL_DIR/.venv" ]; then
    python3 -m venv "$INSTALL_DIR/.venv"
fi

source "$INSTALL_DIR/.venv/bin/activate"

echo -e "${CYAN}[*] Step 3: Installing Python dependencies & CLI...${NC}"
python3 -m pip install --upgrade pip
if [ -f "$INSTALL_DIR/backend/requirements.txt" ]; then
    python3 -m pip install -r "$INSTALL_DIR/backend/requirements.txt" || true
fi
python3 -m pip install -e . || true

echo -e "${CYAN}[*] Step 4: Configuring CLI executable symlink...${NC}"
chmod +x "$INSTALL_DIR/bin/spaider"
chmod +x "$INSTALL_DIR/backend/app/cli.py"

$SUDO ln -sf "$INSTALL_DIR/bin/spaider" "$BIN_PATH"
echo -e "${GREEN}[✔] Symlinked $INSTALL_DIR/bin/spaider -> $BIN_PATH${NC}"

# Optional .env creation
if [ ! -f "$INSTALL_DIR/.env" ] && [ -f "$INSTALL_DIR/.env.example" ]; then
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    echo -e "${GREEN}[✔] Created .env configuration file.${NC}"
fi

# Optional Systemd Service
if [ -d "/etc/systemd/system" ]; then
    echo -e "${CYAN}[*] Step 5: Installing systemd service...${NC}"
    $SUDO tee /etc/systemd/system/spaider.service > /dev/null << EOF
[Unit]
Description=SPAIDER AI Cybersecurity Platform Service
After=network.target

[Service]
Type=simple
User=${USER:-root}
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/.venv/bin:/usr/local/bin:/usr/bin"
ExecStart=$INSTALL_DIR/.venv/bin/python $INSTALL_DIR/backend/app/cli.py serve --host 0.0.0.0 --port 8001
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    $SUDO systemctl daemon-reload || true
    echo -e "${GREEN}[✔] Systemd service created: /etc/systemd/system/spaider.service${NC}"
    echo -e "    Start with:  ${BOLD}sudo systemctl start spaider${NC}"
    echo -e "    Enable with: ${BOLD}sudo systemctl enable spaider${NC}"
fi

# Verification
echo -e "\n${GREEN}${BOLD}=== Installation Complete! ===${NC}"
echo -e "You can now run ${BOLD}spaider${NC} from anywhere in your Linux terminal!\n"
echo -e "Quick commands:"
echo -e "  ${CYAN}spaider --help${NC}                   - View all commands"
echo -e "  ${CYAN}spaider scan <target>${NC}            - Scan target for ports & services"
echo -e "  ${CYAN}spaider ai \"<query>\"${NC}             - Ask the AI Security Analyst"
echo -e "  ${CYAN}spaider malware <file>${NC}           - Analyze a binary or sample"
echo -e "  ${CYAN}spaider console${NC}                  - Launch interactive cyber shell"
echo -e "  ${CYAN}spaider serve${NC}                    - Start backend API daemon (0.0.0.0:8001)"
echo -e "  ${CYAN}spaider web${NC}                      - Serve SPAIDER Web Dashboard UI\n"
