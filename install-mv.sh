#!/bin/bash
# Mild-Viking Network Monitor — Install Script
# Usage:
#   wget https://raw.githubusercontent.com/auggnation/Ragnarbutdifferent/main/install-mv.sh
#   sudo bash install-mv.sh

set -e
[ -z "$BASH_VERSION" ] && exec /bin/bash "$0" "$@"
[ "$(id -u)" -ne 0 ] && { echo "Run as root: sudo $0"; exit 1; }

# ── Colours ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

# ── Config ────────────────────────────────────────────────────────────
MV_USER="mild-viking"
MV_PATH="/home/${MV_USER}/mild-viking"
GITHUB_REPO="https://github.com/auggnation/Ragnarbutdifferent"
BRANCH="main"
SERVICE_NAME="mild-viking"
WEB_PORT=8000
LOG_DIR="/var/log/mild-viking"
LOG_FILE="${LOG_DIR}/install_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "$LOG_DIR"

# ── Helpers ───────────────────────────────────────────────────────────
log()    { echo "[$(date '+%H:%M:%S')] $*" >> "$LOG_FILE"; }
info()   { echo -e "${BLUE}[INFO]${NC}  $*"; log "INFO  $*"; }
ok()     { echo -e "${GREEN}[ OK ]${NC}  $*"; log "OK    $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC}  $*"; log "WARN  $*"; }
die()    { echo -e "${RED}[FAIL]${NC}  $*"; log "FAIL  $*"; exit 1; }
header() { echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; \
           echo -e "${WHITE}  $*  ${NC}"; \
           echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"; }

# Detect Raspberry Pi / ARM
IS_ARM=false
case "$(uname -m 2>/dev/null)" in arm*|aarch64) IS_ARM=true ;; esac

# ── Banner ────────────────────────────────────────────────────────────
clear
echo -e "${CYAN}"
cat << 'BANNER'
 ███╗   ███╗██╗██╗      ██████╗       ██╗   ██╗██╗██╗  ██╗██╗███╗   ██╗ ██████╗
 ████╗ ████║██║██║      ██╔══██╗      ██║   ██║██║██║ ██╔╝██║████╗  ██║██╔════╝
 ██╔████╔██║██║██║      ██║  ██║█████╗██║   ██║██║█████╔╝ ██║██╔██╗ ██║██║  ███╗
 ██║╚██╔╝██║██║██║      ██║  ██║╚════╝╚██╗ ██╔╝██║██╔═██╗ ██║██║╚██╗██║██║   ██║
 ██║ ╚═╝ ██║██║███████╗ ██████╔╝       ╚████╔╝ ██║██║  ██╗██║██║ ╚████║╚██████╔╝
 ╚═╝     ╚═╝╚═╝╚══════╝ ╚═════╝         ╚═══╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝
                    NETWORK MONITOR  //  auggnation
BANNER
echo -e "${NC}"
echo -e "${WHITE}Platform:${NC}    $(uname -m) / $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME}" || echo "Linux")"
echo -e "${WHITE}Install path:${NC} ${MV_PATH}"
echo -e "${WHITE}Web interface:${NC} http://<your-pi-ip>:${WEB_PORT}"
echo -e "${WHITE}Log file:${NC}     ${LOG_FILE}"
echo

# ═══════════════════════════════════════════════════════════════════════
header "STEP 1 / 6  System packages"
# ═══════════════════════════════════════════════════════════════════════

info "Updating package lists..."
DEBIAN_FRONTEND=noninteractive apt-get update -y >> "$LOG_FILE" 2>&1 \
    || warn "Package update had warnings (continuing)"

SYSTEM_PKGS=(
    # Python runtime
    python3 python3-pip python3-venv python3-dev

    # Download / version control
    git wget curl

    # Network tools (WiFi management, AP mode, device scanning)
    network-manager iproute2 net-tools iputils-ping
    arp-scan nmap

    # AP mode (hotspot when no WiFi is configured)
    hostapd dnsmasq

    # Pillow image library build dependencies (e-paper display)
    libjpeg-dev zlib1g-dev libfreetype6-dev liblcms2-dev
    libopenjp2-7 libtiff-dev

    # Cryptography build dependencies
    libffi-dev libssl-dev build-essential
)

# Raspberry Pi hardware packages
if [ "$IS_ARM" = true ]; then
    SYSTEM_PKGS+=(python3-rpi.gpio python3-spidev raspi-config)
fi

warn "Installing system packages — may take 5-10 min on a fresh Pi..."
DEBIAN_FRONTEND=noninteractive apt-get install -y "${SYSTEM_PKGS[@]}" >> "$LOG_FILE" 2>&1 \
    || warn "Some packages may not have installed — check $LOG_FILE"

ok "System packages done"

# ═══════════════════════════════════════════════════════════════════════
header "STEP 2 / 6  User and install directory"
# ═══════════════════════════════════════════════════════════════════════

if ! id "$MV_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$MV_USER"
    ok "Created user: $MV_USER"
else
    info "User $MV_USER already exists"
fi

# Group membership
usermod -aG sudo,netdev,dialout "$MV_USER" 2>/dev/null || true
[ "$IS_ARM" = true ] && usermod -aG gpio,spi,i2c "$MV_USER" 2>/dev/null || true

# Back up any existing install but preserve config/data
if [ -d "$MV_PATH" ] && [ -f "$MV_PATH/mildviking.py" ]; then
    BACKUP="${MV_PATH}_backup_$(date +%Y%m%d_%H%M%S)"
    info "Backing up existing install to $BACKUP"
    [ -f "$MV_PATH/data/config.json" ] && \
        cp "$MV_PATH/data/config.json" /tmp/mv_config_backup.json 2>/dev/null || true
    mv "$MV_PATH" "$BACKUP" || true
fi

mkdir -p "$MV_PATH"
ok "Install directory: $MV_PATH"

# ═══════════════════════════════════════════════════════════════════════
header "STEP 3 / 6  Download Mild-Viking"
# ═══════════════════════════════════════════════════════════════════════

info "Cloning from ${GITHUB_REPO}..."
TEMP_SRC="/tmp/mild-viking_src_$$"

if git --version >/dev/null 2>&1; then
    git clone --depth 1 --branch "$BRANCH" "$GITHUB_REPO" "$TEMP_SRC" >> "$LOG_FILE" 2>&1 \
    || {
        warn "git clone failed, trying tarball..."
        TARBALL="${GITHUB_REPO}/archive/refs/heads/${BRANCH}.tar.gz"
        TMP_TGZ=$(mktemp /tmp/mv-XXXXXX.tar.gz)
        wget -q --timeout=60 -O "$TMP_TGZ" "$TARBALL" >> "$LOG_FILE" 2>&1 \
            || curl -fsSL --connect-timeout 30 -o "$TMP_TGZ" "$TARBALL" >> "$LOG_FILE" 2>&1 \
            || die "Could not download Mild-Viking. Check your internet connection."
        mkdir -p "$TEMP_SRC"
        tar xzf "$TMP_TGZ" -C "$TEMP_SRC" --strip-components=1
        rm -f "$TMP_TGZ"
    }
else
    warn "git not found, using tarball..."
    TARBALL="${GITHUB_REPO}/archive/refs/heads/${BRANCH}.tar.gz"
    TMP_TGZ=$(mktemp /tmp/mv-XXXXXX.tar.gz)
    wget -q --timeout=60 -O "$TMP_TGZ" "$TARBALL" >> "$LOG_FILE" 2>&1 \
        || curl -fsSL --connect-timeout 30 -o "$TMP_TGZ" "$TARBALL" >> "$LOG_FILE" 2>&1 \
        || die "Could not download Mild-Viking. Check your internet connection."
    mkdir -p "$TEMP_SRC"
    tar xzf "$TMP_TGZ" -C "$TEMP_SRC" --strip-components=1
    rm -f "$TMP_TGZ"
fi

rsync -a --exclude='.git' "${TEMP_SRC}/" "${MV_PATH}/" 2>/dev/null \
    || cp -r "${TEMP_SRC}/." "${MV_PATH}/"
rm -rf "$TEMP_SRC"

# Restore saved config
if [ -f /tmp/mv_config_backup.json ]; then
    mkdir -p "${MV_PATH}/data"
    cp /tmp/mv_config_backup.json "${MV_PATH}/data/config.json"
    ok "Restored previous configuration"
fi

chown -R "${MV_USER}:${MV_USER}" "$MV_PATH"
ok "Mild-Viking downloaded"

# ═══════════════════════════════════════════════════════════════════════
header "STEP 4 / 6  Python virtual environment"
# ═══════════════════════════════════════════════════════════════════════

VENV="${MV_PATH}/venv"
info "Creating Python virtual environment..."
python3 -m venv --system-site-packages "$VENV" >> "$LOG_FILE" 2>&1
ok "Virtual environment: $VENV"

info "Upgrading pip..."
"${VENV}/bin/pip" install --upgrade pip setuptools wheel >> "$LOG_FILE" 2>&1

info "Installing Python dependencies from requirements.txt..."
"${VENV}/bin/pip" install -r "${MV_PATH}/requirements.txt" >> "$LOG_FILE" 2>&1 \
    || warn "Some Python packages failed — check $LOG_FILE"

# ARM-only packages that can't always be listed in requirements.txt
if [ "$IS_ARM" = true ]; then
    for pkg in RPi.GPIO spidev smbus2; do
        "${VENV}/bin/pip" install "$pkg" >> "$LOG_FILE" 2>&1 \
            || warn "$pkg not available (may not matter if not using GPIO/SPI)"
    done
fi

chown -R "${MV_USER}:${MV_USER}" "$VENV"
ok "Python dependencies installed"

# ═══════════════════════════════════════════════════════════════════════
header "STEP 5 / 6  System configuration"
# ═══════════════════════════════════════════════════════════════════════

# ── NetworkManager ────────────────────────────────────────────────────
systemctl enable NetworkManager 2>/dev/null || true
systemctl start  NetworkManager 2>/dev/null || true
ok "NetworkManager enabled"

# ── sudoers ───────────────────────────────────────────────────────────
SUDOERS_FILE="/etc/sudoers.d/mild-viking"
cat > "$SUDOERS_FILE" << 'SUDOEOF'
# Mild-Viking — allow network management without password prompts

# WiFi management via NetworkManager
mild-viking ALL=(ALL) NOPASSWD: /usr/bin/nmcli
mild-viking ALL=(ALL) NOPASSWD: /usr/sbin/nmcli

# AP mode — interface configuration
mild-viking ALL=(ALL) NOPASSWD: /usr/sbin/ip
mild-viking ALL=(ALL) NOPASSWD: /sbin/ip

# AP mode — start/stop hostapd and dnsmasq
mild-viking ALL=(ALL) NOPASSWD: /usr/sbin/hostapd
mild-viking ALL=(ALL) NOPASSWD: /usr/sbin/dnsmasq
mild-viking ALL=(ALL) NOPASSWD: /usr/bin/pkill
mild-viking ALL=(ALL) NOPASSWD: /bin/pkill

# AP mode — stop system dnsmasq that may conflict
mild-viking ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop dnsmasq
mild-viking ALL=(ALL) NOPASSWD: /usr/bin/systemctl start dnsmasq
mild-viking ALL=(ALL) NOPASSWD: /bin/systemctl stop dnsmasq

# Device scanning
mild-viking ALL=(ALL) NOPASSWD: /usr/sbin/arp-scan
mild-viking ALL=(ALL) NOPASSWD: /usr/bin/arp-scan

# Time management
mild-viking ALL=(ALL) NOPASSWD: /usr/bin/timedatectl
mild-viking ALL=(ALL) NOPASSWD: /usr/sbin/timedatectl
mild-viking ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart systemd-timesyncd
SUDOEOF

chmod 440 "$SUDOERS_FILE"
visudo -c -f "$SUDOERS_FILE" >> "$LOG_FILE" 2>&1 \
    && ok "sudoers rules installed" \
    || { warn "sudoers syntax error — removing"; rm -f "$SUDOERS_FILE"; }

# ── Capabilities (run arp-scan and nmap without root) ─────────────────
ARP_SCAN=$(command -v arp-scan 2>/dev/null || true)
[ -n "$ARP_SCAN" ] && \
    setcap cap_net_raw+ep "$ARP_SCAN" 2>/dev/null && ok "arp-scan: raw socket capability set"

NMAP_BIN=$(command -v nmap 2>/dev/null || true)
[ -n "$NMAP_BIN" ] && \
    setcap cap_net_raw,cap_net_admin+eip "$NMAP_BIN" 2>/dev/null && ok "nmap: raw socket capability set"

# ── Pi-specific: enable SPI and I2C for e-paper display ───────────────
if [ "$IS_ARM" = true ] && command -v raspi-config &>/dev/null; then
    raspi-config nonint do_spi 0 2>/dev/null || true
    raspi-config nonint do_i2c 0 2>/dev/null || true
    ok "SPI and I2C interfaces enabled"
fi

# ── Data directories ──────────────────────────────────────────────────
for dir in data data/logs web; do
    mkdir -p "${MV_PATH}/${dir}"
done
chown -R "${MV_USER}:${MV_USER}" "$MV_PATH"

# ── update-viking command ─────────────────────────────────────────────
# Creates a real executable so it works from any shell (not just bash)
cat > /usr/local/bin/update-viking << EOF
#!/bin/bash
echo "Pulling latest Mild-Viking from GitHub..."
sudo git -C "${MV_PATH}" pull
echo "Restarting service..."
sudo systemctl restart "${SERVICE_NAME}"
echo "Done. Check status: sudo journalctl -u ${SERVICE_NAME} -n 30"
EOF
chmod +x /usr/local/bin/update-viking
ok "update-viking command installed at /usr/local/bin/update-viking"

# Also add the alias to the invoking user's .bashrc (convenience — same result as the command)
REAL_USER="${SUDO_USER:-${USER:-pi}}"
REAL_HOME=$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6 || echo "/home/$REAL_USER")
if [ -d "$REAL_HOME" ]; then
    BASHRC="${REAL_HOME}/.bashrc"
    ALIAS_LINE="alias update-viking='sudo git -C ${MV_PATH} pull && sudo systemctl restart ${SERVICE_NAME}'"
    if ! grep -q "update-viking" "$BASHRC" 2>/dev/null; then
        echo "" >> "$BASHRC"
        echo "# Mild-Viking — pull latest code and restart" >> "$BASHRC"
        echo "${ALIAS_LINE}" >> "$BASHRC"
        ok "update-viking alias added to ${BASHRC}"
    else
        info "update-viking alias already in ${BASHRC}"
    fi
fi

# ── Open web port ─────────────────────────────────────────────────────
command -v ufw &>/dev/null && ufw allow "${WEB_PORT}/tcp" >> "$LOG_FILE" 2>&1 && \
    info "UFW: opened port $WEB_PORT"

# ═══════════════════════════════════════════════════════════════════════
header "STEP 6 / 6  Systemd service"
# ═══════════════════════════════════════════════════════════════════════

cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=Mild-Viking Network Monitor
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${MV_USER}
WorkingDirectory=${MV_PATH}
ExecStart=${VENV}/bin/python3 ${MV_PATH}/mildviking.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mild-viking
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=${MV_PATH}
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"

info "Starting Mild-Viking..."
systemctl start "${SERVICE_NAME}.service" \
    && ok "Service started" \
    || warn "Service failed to start — check: sudo journalctl -u ${SERVICE_NAME} -n 50"

# ═══════════════════════════════════════════════════════════════════════
# Done
# ═══════════════════════════════════════════════════════════════════════

IP_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-pi-ip")

echo
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       MILD-VIKING INSTALLATION COMPLETE          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo
echo -e "${WHITE}Dashboard:${NC}      http://${IP_ADDR}:${WEB_PORT}"
echo -e "${WHITE}Settings:${NC}       http://${IP_ADDR}:${WEB_PORT}/settings"
echo -e "${WHITE}Status:${NC}         sudo systemctl status mild-viking"
echo -e "${WHITE}Logs:${NC}           sudo journalctl -u mild-viking -f"
echo -e "${WHITE}Restart:${NC}        sudo systemctl restart mild-viking"
echo -e "${WHITE}Update:${NC}         update-viking"
echo -e "${WHITE}Install log:${NC}    ${LOG_FILE}"
echo
echo -e "${CYAN}If no WiFi is configured the Pi will broadcast a setup hotspot.${NC}"
echo -e "${CYAN}Connect to it and open http://192.168.1.2:8000/settings to configure WiFi.${NC}"
echo

if [ "$IS_ARM" = true ]; then
    echo -e "${YELLOW}A reboot is recommended to activate SPI/I2C for the e-paper display.${NC}"
    read -rp "Reboot now? [y/N] " REBOOT_CHOICE
    [[ "${REBOOT_CHOICE,,}" == "y" ]] && reboot
fi
