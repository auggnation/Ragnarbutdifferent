#!/bin/bash
# Mild-Viking Network Monitor — Install Script
# Usage:
#   wget https://raw.githubusercontent.com/auggnation/Ragnarbutdifferent/main/install_ragnar.sh
#   sudo chmod +x install_ragnar.sh && sudo ./install_ragnar.sh

set -e
[ -z "$BASH_VERSION" ] && exec /bin/bash "$0" "$@"

# ── Colours ───────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

# ── Config ────────────────────────────────────────────────────────
RAGNAR_USER="mild-viking"
RAGNAR_PATH="/home/${RAGNAR_USER}/mild-viking"
GITHUB_REPO="https://github.com/auggnation/Ragnarbutdifferent"
GITHUB_RAW="https://raw.githubusercontent.com/auggnation/Ragnarbutdifferent/main"
BRANCH="main"
SERVICE_NAME="mild-viking"
WEB_PORT=8000
LOG_DIR="/var/log/mild-viking_install"
LOG_FILE="${LOG_DIR}/install_$(date +%Y%m%d_%H%M%S).log"
GIT_WORKS=true

mkdir -p "$LOG_DIR"

# ── Helpers ───────────────────────────────────────────────────────
log()     { local l=$1; shift; echo -e "[$(date '+%H:%M:%S')] [$l] $*" | tee -a "$LOG_FILE"; }
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; log INFO "$*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; log SUCCESS "$*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; log WARNING "$*"; }
err()     { echo -e "${RED}[ERROR]${NC} $*"; log ERROR "$*"; }
die()     { err "$*"; exit 1; }
header()  { echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${WHITE} $* ${NC}"; echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"; }

# Require root
[ "$(id -u)" -ne 0 ] && die "Run as root: sudo $0"

# ── Platform detect ───────────────────────────────────────────────
PKG_MGR="apt"; UPDATE_CMD="apt-get update -y"; INSTALL_CMD="apt-get install -y"
IS_ARM=false; ARCH=$(uname -m 2>/dev/null || echo "unknown")
case "$ARCH" in arm*|aarch64) IS_ARM=true ;; esac
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "${ID:-}" in
        fedora|rhel|centos|rocky|almalinux)
            PKG_MGR="dnf"; UPDATE_CMD="dnf makecache -y"; INSTALL_CMD="dnf install -y" ;;
        arch|manjaro)
            PKG_MGR="pacman"; UPDATE_CMD="pacman -Sy --noconfirm"; INSTALL_CMD="pacman -S --noconfirm" ;;
    esac
fi

check_git() {
    git --version >/dev/null 2>&1 && GIT_WORKS=true || { GIT_WORKS=false; warn "git unavailable — will use wget tarball"; }
}

clone_or_download() {
    local url=$1 target=${2:-$(basename "${1%.git}")} branch=${3:-main}
    if [ "$GIT_WORKS" = true ]; then
        git clone --depth 1 --branch "$branch" "$url" "$target" 2>/dev/null && return 0
        warn "git clone failed, trying tarball..."
    fi
    local path="${url#https://github.com/}"; path="${path%.git}"
    local tarball="https://github.com/${path}/archive/refs/heads/${branch}.tar.gz"
    local tmp; tmp=$(mktemp /tmp/ragnar-XXXXXX.tar.gz)
    if wget -q --timeout=60 -O "$tmp" "$tarball" 2>/dev/null || \
       curl -fsSL --connect-timeout 30 -o "$tmp" "$tarball" 2>/dev/null; then
        mkdir -p "$target"
        tar xzf "$tmp" -C "$target" --strip-components=1
        rm -f "$tmp"
        return 0
    fi
    rm -f "$tmp"; return 1
}

# ── Welcome banner ────────────────────────────────────────────────
clear
echo -e "${CYAN}"
cat << 'EOF'
 ███╗   ███╗██╗██╗      ██████╗       ██╗   ██╗██╗██╗  ██╗██╗███╗   ██╗ ██████╗
 ████╗ ████║██║██║      ██╔══██╗      ██║   ██║██║██║ ██╔╝██║████╗  ██║██╔════╝
 ██╔████╔██║██║██║      ██║  ██║█████╗██║   ██║██║█████╔╝ ██║██╔██╗ ██║██║  ███╗
 ██║╚██╔╝██║██║██║      ██║  ██║╚════╝╚██╗ ██╔╝██║██╔═██╗ ██║██║╚██╗██║██║   ██║
 ██║ ╚═╝ ██║██║███████╗ ██████╔╝       ╚████╔╝ ██║██║  ██╗██║██║ ╚████║╚██████╔╝
 ╚═╝     ╚═╝╚═╝╚══════╝ ╚═════╝         ╚═══╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝
                      NETWORK MONITOR  //  auggnation
EOF
echo -e "${NC}"
echo -e "${WHITE}Platform:${NC} $(uname -m) / $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME}" || echo "Linux")"
echo -e "${WHITE}Install path:${NC} ${RAGNAR_PATH}"
echo -e "${WHITE}Web interface:${NC} http://<IP>:${WEB_PORT}"
echo

# ═══════════════════════════════════════════════════════════════════
header "STEP 1 / 7  System packages"
# ═══════════════════════════════════════════════════════════════════

info "Updating package lists..."
$UPDATE_CMD >> "$LOG_FILE" 2>&1 || warn "Package update had warnings (continuing)"

SYSTEM_PKGS=(
    python3 python3-pip python3-venv python3-dev
    git wget curl
    network-manager iproute2 net-tools iputils-ping
    arp-scan nmap
    hostapd dnsmasq
    libjpeg-dev zlib1g-dev libfreetype6-dev liblcms2-dev
    libopenjp2-7 libtiff5-dev libffi-dev libssl-dev
    build-essential
)

# ARM/Pi-specific packages
if [ "$IS_ARM" = true ]; then
    SYSTEM_PKGS+=(python3-rpi.gpio python3-spidev raspi-config)
fi

info "Installing system packages..."
$INSTALL_CMD "${SYSTEM_PKGS[@]}" >> "$LOG_FILE" 2>&1 || warn "Some packages may not have installed (continuing)"
ok "System packages installed"

# ═══════════════════════════════════════════════════════════════════
header "STEP 2 / 7  Create user and install directory"
# ═══════════════════════════════════════════════════════════════════

if ! id "$RAGNAR_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$RAGNAR_USER"
    ok "Created user: $RAGNAR_USER"
else
    info "User $RAGNAR_USER already exists"
fi

# Add to required groups
usermod -aG sudo,netdev,dialout "$RAGNAR_USER" 2>/dev/null || true
[ "$IS_ARM" = true ] && usermod -aG gpio,spi,i2c "$RAGNAR_USER" 2>/dev/null || true

# Backup existing install if present
if [ -d "$RAGNAR_PATH" ] && [ -f "$RAGNAR_PATH/Ragnar.py" ]; then
    BACKUP="${RAGNAR_PATH}_backup_$(date +%Y%m%d_%H%M%S)"
    info "Backing up existing installation to $BACKUP"
    # Preserve config and data
    if [ -f "$RAGNAR_PATH/config/shared_config.json" ]; then
        cp -f "$RAGNAR_PATH/config/shared_config.json" /tmp/mild-viking_config_backup.json 2>/dev/null || true
    fi
    mv "$RAGNAR_PATH" "$BACKUP" || true
fi

mkdir -p "$RAGNAR_PATH"
ok "Install directory ready: $RAGNAR_PATH"

# ═══════════════════════════════════════════════════════════════════
header "STEP 3 / 7  Download Mild-Viking"
# ═══════════════════════════════════════════════════════════════════

check_git
cd /tmp

TEMP_CLONE="/tmp/mild-viking_src_$$"
info "Downloading from ${GITHUB_REPO}..."
if ! clone_or_download "$GITHUB_REPO" "$TEMP_CLONE" "$BRANCH"; then
    die "Failed to download Mild-Viking. Check your internet connection."
fi

info "Copying files to $RAGNAR_PATH..."
rsync -a --exclude='.git' "${TEMP_CLONE}/" "${RAGNAR_PATH}/" 2>/dev/null || \
    cp -r "${TEMP_CLONE}/." "${RAGNAR_PATH}/"
rm -rf "$TEMP_CLONE"

# Restore config if backed up
if [ -f /tmp/mild-viking_config_backup.json ]; then
    mkdir -p "$RAGNAR_PATH/config"
    cp -f /tmp/mild-viking_config_backup.json "$RAGNAR_PATH/config/shared_config.json"
    info "Restored previous configuration"
fi

chown -R "${RAGNAR_USER}:${RAGNAR_USER}" "$RAGNAR_PATH"
ok "Mild-Viking downloaded and installed"

# ═══════════════════════════════════════════════════════════════════
header "STEP 4 / 7  Python virtual environment and dependencies"
# ═══════════════════════════════════════════════════════════════════

VENV_PATH="${RAGNAR_PATH}/venv"

info "Creating Python virtual environment..."
python3 -m venv --system-site-packages "$VENV_PATH" >> "$LOG_FILE" 2>&1
ok "Virtual environment created: $VENV_PATH"

info "Installing Python packages..."
"${VENV_PATH}/bin/pip" install --upgrade pip setuptools wheel >> "$LOG_FILE" 2>&1

PYTHON_PKGS=(
    "flask>=3.0.0"
    "flask-socketio>=5.3.0"
    "flask-cors>=4.0.0"
    "psutil>=5.9.0"
    "Pillow>=10.0.0"
    "requests>=2.31.0"
    "python-dotenv>=1.0.0"
    "bcrypt>=4.0.0"
    "cryptography>=41.0.0"
    "netifaces>=0.11.0"
    "speedtest-cli>=2.1.3"
)

for pkg in "${PYTHON_PKGS[@]}"; do
    info "  Installing $pkg..."
    "${VENV_PATH}/bin/pip" install "$pkg" >> "$LOG_FILE" 2>&1 || warn "  $pkg install had warnings"
done

# ARM/Pi specific
if [ "$IS_ARM" = true ]; then
    for pkg in RPi.GPIO spidev luma.led_matrix; do
        info "  Installing $pkg (ARM)..."
        "${VENV_PATH}/bin/pip" install "$pkg" >> "$LOG_FILE" 2>&1 || warn "  $pkg not available (may not matter)"
    done
fi

chown -R "${RAGNAR_USER}:${RAGNAR_USER}" "$VENV_PATH"
ok "Python packages installed"

# ═══════════════════════════════════════════════════════════════════
header "STEP 5 / 7  WiFi management service"
# ═══════════════════════════════════════════════════════════════════

# Install WiFi management if script exists
WIFI_SCRIPT="${RAGNAR_PATH}/install_wifi_management.sh"
if [ -f "$WIFI_SCRIPT" ]; then
    info "Running WiFi management installer..."
    chmod +x "$WIFI_SCRIPT"
    bash "$WIFI_SCRIPT" >> "$LOG_FILE" 2>&1 || warn "WiFi management installer had warnings (continuing)"
    ok "WiFi management configured"
else
    warn "WiFi management installer not found — configure WiFi manually via the web interface"
fi

# Ensure NetworkManager is running
systemctl enable NetworkManager 2>/dev/null || true
systemctl start  NetworkManager 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════════
header "STEP 6 / 7  Systemd service"
# ═══════════════════════════════════════════════════════════════════

# Write service unit
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=Mild-Viking Network Monitor
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RAGNAR_USER}
WorkingDirectory=${RAGNAR_PATH}
ExecStart=${VENV_PATH}/bin/python3 ${RAGNAR_PATH}/Ragnar.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mild-viking
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=${RAGNAR_PATH}

# Allow network operations
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

# Create env file template if missing
if [ ! -f "${RAGNAR_PATH}/.env" ]; then
    cat > "${RAGNAR_PATH}/.env" << 'ENVEOF'
# Mild-Viking Network Monitor — environment config
# No secrets required for basic operation
MILD_VIKING_DEBUG=false
ENVEOF
    chown "${RAGNAR_USER}:${RAGNAR_USER}" "${RAGNAR_PATH}/.env"
fi

# Allow arp-scan to run without root (setuid or capability)
ARP_SCAN_BIN=$(which arp-scan 2>/dev/null || true)
if [ -n "$ARP_SCAN_BIN" ]; then
    setcap cap_net_raw+ep "$ARP_SCAN_BIN" 2>/dev/null || \
        chmod u+s "$ARP_SCAN_BIN" 2>/dev/null || \
        warn "Could not setcap arp-scan — device scan may need root"
fi

# Set up nmap to work without root
NMAP_BIN=$(which nmap 2>/dev/null || true)
if [ -n "$NMAP_BIN" ]; then
    setcap cap_net_raw,cap_net_admin+eip "$NMAP_BIN" 2>/dev/null || true
fi

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"
ok "Systemd service installed: ${SERVICE_NAME}.service"

# ═══════════════════════════════════════════════════════════════════
header "STEP 7 / 7  Firewall and final setup"
# ═══════════════════════════════════════════════════════════════════

# Open port 8000
if command -v ufw &>/dev/null; then
    ufw allow "${WEB_PORT}/tcp" >> "$LOG_FILE" 2>&1 && info "UFW: opened port $WEB_PORT" || true
fi
if command -v iptables &>/dev/null; then
    iptables -C INPUT -p tcp --dport "$WEB_PORT" -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -p tcp --dport "$WEB_PORT" -j ACCEPT 2>/dev/null || true
fi

# Ensure data directories exist
for dir in config data data/logs data/networks web; do
    mkdir -p "${RAGNAR_PATH}/${dir}"
done
chown -R "${RAGNAR_USER}:${RAGNAR_USER}" "$RAGNAR_PATH"

# Pi-specific: enable SPI and I2C for e-paper display
if [ "$IS_ARM" = true ] && command -v raspi-config &>/dev/null; then
    raspi-config nonint do_spi 0    2>/dev/null || true
    raspi-config nonint do_i2c 0   2>/dev/null || true
    info "Enabled SPI and I2C interfaces"
fi

# Start the service
info "Starting Mild-Viking service..."
systemctl start "${SERVICE_NAME}.service" || warn "Service start failed — check: journalctl -u ${SERVICE_NAME}"

ok "Mild-Viking service started"

# ═══════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════

IP_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-pi-ip")

echo
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         MILD-VIKING INSTALLATION COMPLETE             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo
echo -e "${WHITE}Web dashboard:${NC}  http://${IP_ADDR}:${WEB_PORT}"
echo -e "${WHITE}Service status:${NC} sudo systemctl status mild-viking"
echo -e "${WHITE}View logs:${NC}      sudo journalctl -u mild-viking -f"
echo -e "${WHITE}Restart:${NC}        sudo systemctl restart mild-viking"
echo -e "${WHITE}Install log:${NC}    ${LOG_FILE}"
echo
echo -e "${CYAN}The dashboard will be available at http://${IP_ADDR}:${WEB_PORT}${NC}"
echo -e "${CYAN}Open this URL in a browser on any device on the same network.${NC}"
echo

# Prompt for reboot on Raspberry Pi
if [ "$IS_ARM" = true ]; then
    echo -e "${YELLOW}A reboot is recommended on Raspberry Pi to activate all settings.${NC}"
    read -rp "Reboot now? [y/N] " REBOOT_CHOICE
    [[ "${REBOOT_CHOICE,,}" == "y" ]] && reboot
fi
