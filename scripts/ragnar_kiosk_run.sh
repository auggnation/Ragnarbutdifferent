#!/bin/bash
# Ragnar kiosk wrapper — auto-detects environment:
#   * Already inside a Wayland/X session (autostart mode): just launch
#     chromium in --kiosk pointed at the configured URL.
#   * No session present (systemd service mode on Pi OS Lite): spawn our
#     own Xorg on vt7, xauth cookie, openbox WM, then chromium.
#
# Reads live config from the running Ragnar instance via /api/config so
# rotation / URL changes only require re-running the wrapper.

set -euo pipefail

REPO_ROOT="${RAGNAR_REPO:-$(cd "$(dirname "$0")/.." && pwd -P 2>/dev/null || echo /opt/ragnar)}"
CONFIG_API="http://127.0.0.1:8000/api/config"
BROWSER="${RAGNAR_BROWSER:-chromium-browser}"
if ! command -v "$BROWSER" >/dev/null 2>&1; then
    for bin in chromium-browser chromium firefox-esr; do
        if command -v "$bin" >/dev/null 2>&1; then BROWSER="$bin"; break; fi
    done
fi

LOG_DIR="${RAGNAR_KIOSK_LOG_DIR:-/var/log/ragnar}"
mkdir -p "$LOG_DIR" 2>/dev/null || true
WRAPPER_LOG="$LOG_DIR/kiosk-wrapper.log"
if : > >(tee -a "$WRAPPER_LOG" 2>/dev/null) 2>/dev/null; then
    exec > >(tee -a "$WRAPPER_LOG") 2>&1
fi
echo "[kiosk-run] start $(date -Iseconds) user=$(id -un) HOME=${HOME:-unset} DISPLAY=${DISPLAY:-unset} WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-unset} XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-unset}"

# Default config values (mirror shared.py defaults)
KIOSK_URL="http://localhost:8000"
KIOSK_ROTATION="0"
KIOSK_HIDE_CURSOR="true"
WARDRIVING_ENABLED="false"

if command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    cfg="$(curl -fsS --max-time 5 "$CONFIG_API" 2>/dev/null || true)"
    if [[ -n "$cfg" ]]; then
        parsed="$(printf '%s' "$cfg" | python3 -c '
import json, shlex, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
print("KIOSK_URL=" + shlex.quote(str(d.get("kiosk_url", "http://localhost:8000"))))
print("KIOSK_ROTATION=" + shlex.quote(str(d.get("kiosk_rotation", 0))))
print("KIOSK_HIDE_CURSOR=" + ("true" if d.get("kiosk_hide_cursor", True) else "false"))
print("WARDRIVING_ENABLED=" + ("true" if d.get("wardriving_enabled", False) else "false"))
' 2>/dev/null || true)"
        if [[ -n "$parsed" ]]; then eval "$parsed"; fi
    fi
fi

QS_SEP="?"
if [[ "$KIOSK_URL" == *"?"* ]]; then QS_SEP="&"; fi
FINAL_URL="${KIOSK_URL}${QS_SEP}kiosk=1"
if [[ "$WARDRIVING_ENABLED" == "true" ]]; then
    FINAL_URL="${FINAL_URL}#wardriving"
fi
echo "[kiosk-run] target URL: $FINAL_URL"

# Per-kiosk chromium profile so we don't trip "restore tabs" prompts.
PROFILE_DIR="$HOME/.config/ragnar-kiosk-chromium"
mkdir -p "$PROFILE_DIR" 2>/dev/null || true

CHROMIUM_ARGS=(
    --kiosk
    --noerrdialogs
    --disable-infobars
    --disable-translate
    --disable-features=TranslateUI,Translate
    --no-first-run
    --check-for-update-interval=31536000
    --user-data-dir="$PROFILE_DIR"
    --app="$FINAL_URL"
)

# Wait for Ragnar's web server to actually answer (max 60s).
for i in $(seq 1 60); do
    if curl -fsS --max-time 2 "$KIOSK_URL" >/dev/null 2>&1; then break; fi
    sleep 1
done

# ---------------------------------------------------------------------------
# MODE A: existing session — just launch chromium into it.
# Triggered when WAYLAND_DISPLAY or DISPLAY is already set (XDG autostart
# always sets these for us; the user can also invoke manually from a
# terminal inside their session).
# ---------------------------------------------------------------------------
if [[ -n "${WAYLAND_DISPLAY:-}" || -n "${DISPLAY:-}" ]]; then
    echo "[kiosk-run] running inside existing session — launching chromium directly"

    # Apply rotation via wlr-randr (labwc/wlroots) or xrandr (X session).
    case "$KIOSK_ROTATION" in
        90|180|270)
            if [[ -n "${WAYLAND_DISPLAY:-}" ]] && command -v wlr-randr >/dev/null 2>&1; then
                # wlr-randr's --transform takes: normal|90|180|270|flipped|flipped-90|...
                OUTPUT="$(wlr-randr 2>/dev/null | awk '/^[^ ]/ {print $1; exit}')"
                if [[ -n "$OUTPUT" ]]; then
                    echo "[kiosk-run] wlr-randr: rotating $OUTPUT to $KIOSK_ROTATION"
                    wlr-randr --output "$OUTPUT" --transform "$KIOSK_ROTATION" 2>&1 || true
                fi
            elif [[ -n "${DISPLAY:-}" ]] && command -v xrandr >/dev/null 2>&1; then
                case "$KIOSK_ROTATION" in
                    90) XROT=left ;; 180) XROT=inverted ;; 270) XROT=right ;;
                esac
                PRIMARY="$(xrandr --query 2>/dev/null | awk '/ connected/ {print $1; exit}')"
                if [[ -n "$PRIMARY" ]]; then
                    echo "[kiosk-run] xrandr: rotating $PRIMARY to $XROT"
                    xrandr --output "$PRIMARY" --rotate "$XROT" 2>&1 || true
                fi
            else
                echo "[kiosk-run] WARN: rotation requested but neither wlr-randr nor xrandr available"
            fi
            ;;
        *) : ;;  # 0 = no rotation
    esac

    exec "$BROWSER" "${CHROMIUM_ARGS[@]}"
fi

# ---------------------------------------------------------------------------
# MODE B: no session — start our own Xorg, then chromium under it.
# This is the Pi OS Lite / systemd-service path.
# ---------------------------------------------------------------------------
echo "[kiosk-run] no session env — spinning up own X server"

XORG_LOG="$LOG_DIR/kiosk-Xorg.log"
mkdir -p "$HOME/.local/share/xorg" 2>/dev/null || true
rm -f /tmp/.X0-lock 2>/dev/null || true
rm -f /tmp/.X11-unix/X0 2>/dev/null || true

export XAUTHORITY="$HOME/.Xauthority"
touch "$XAUTHORITY" 2>/dev/null || true
chmod 600 "$XAUTHORITY" 2>/dev/null || true
if command -v xauth >/dev/null 2>&1; then
    COOKIE=""
    if command -v mcookie >/dev/null 2>&1; then
        COOKIE="$(mcookie)"
    elif [[ -r /dev/urandom ]] && command -v xxd >/dev/null 2>&1; then
        COOKIE="$(head -c 16 /dev/urandom | xxd -p)"
    else
        COOKIE="$(od -An -tx1 -N16 /dev/urandom 2>/dev/null | tr -d ' \n')"
    fi
    if [[ -n "$COOKIE" ]]; then
        xauth -f "$XAUTHORITY" add ":0" . "$COOKIE" 2>/dev/null || true
    fi
fi

SESSION_SCRIPT="$(mktemp --tmpdir ragnar-kiosk-XXXXXX.sh)"
trap 'rm -f "$SESSION_SCRIPT"' EXIT
cat > "$SESSION_SCRIPT" <<EOF
#!/bin/bash
xset s off || true
xset s noblank || true
xset -dpms || true

case "$KIOSK_ROTATION" in
    90)  ROT=left ;;
    180) ROT=inverted ;;
    270) ROT=right ;;
    *)   ROT=normal ;;
esac
PRIMARY="\$(xrandr --query 2>/dev/null | awk '/ connected/ {print \$1; exit}')"
if [[ -n "\$PRIMARY" && "\$ROT" != "normal" ]]; then
    xrandr --output "\$PRIMARY" --rotate "\$ROT" || true
fi

if command -v openbox-session >/dev/null 2>&1; then
    openbox-session &
elif command -v openbox >/dev/null 2>&1; then
    openbox &
fi

if [[ "$KIOSK_HIDE_CURSOR" == "true" ]] && command -v unclutter >/dev/null 2>&1; then
    unclutter -idle 0 -root &
fi

exec "$BROWSER" \\
    --kiosk \\
    --noerrdialogs \\
    --disable-infobars \\
    --disable-translate \\
    --disable-features=TranslateUI,Translate \\
    --no-first-run \\
    --check-for-update-interval=31536000 \\
    --user-data-dir="\$HOME/.config/ragnar-kiosk-chromium" \\
    --app="$FINAL_URL"
EOF
chmod +x "$SESSION_SCRIPT"

exec xinit "$SESSION_SCRIPT" -- /usr/bin/X :0 vt7 -nolisten tcp -auth "$XAUTHORITY" -logfile "$XORG_LOG" -keeptty
