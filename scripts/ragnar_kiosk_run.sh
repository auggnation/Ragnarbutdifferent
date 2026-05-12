#!/bin/bash
# Ragnar kiosk wrapper — launches X + browser in fullscreen kiosk mode.
# Reads live config from the running Ragnar instance via /api/config so
# rotation / URL changes only require `systemctl restart ragnar-kiosk`.

set -euo pipefail

REPO_ROOT="${RAGNAR_REPO:-$(cd "$(dirname "$0")/.." && pwd -P 2>/dev/null || echo /opt/ragnar)}"
CONFIG_API="http://127.0.0.1:8000/api/config"
BROWSER="${RAGNAR_BROWSER:-chromium-browser}"

# Default config values (mirror shared.py defaults)
KIOSK_URL="http://localhost:8000"
KIOSK_ROTATION="0"
KIOSK_HIDE_CURSOR="true"
WARDRIVING_ENABLED="false"

# Try to pull live config — non-fatal if Ragnar isn't up yet.
if command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    cfg="$(curl -fsS --max-time 5 "$CONFIG_API" 2>/dev/null || true)"
    if [[ -n "$cfg" ]]; then
        # Pipe JSON to Python over stdin (avoids heredoc/quoting hazards).
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
        if [[ -n "$parsed" ]]; then
            eval "$parsed"
        fi
    fi
fi

# Tag the URL so the SPA can render kiosk layout + skip auth via loopback.
QS_SEP="?"
if [[ "$KIOSK_URL" == *"?"* ]]; then
    QS_SEP="&"
fi
FINAL_URL="${KIOSK_URL}${QS_SEP}kiosk=1"
# Route wardriving rigs straight to the wardriving live view.
if [[ "$WARDRIVING_ENABLED" == "true" ]]; then
    FINAL_URL="${FINAL_URL}#wardriving"
fi

# xinitrc-style session script
SESSION_SCRIPT="$(mktemp --tmpdir ragnar-kiosk-XXXXXX.sh)"
trap 'rm -f "$SESSION_SCRIPT"' EXIT
cat > "$SESSION_SCRIPT" <<EOF
#!/bin/bash
# Disable screen blanking / DPMS
xset s off || true
xset s noblank || true
xset -dpms || true

# Apply rotation if requested
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

# Window manager (lightweight, just for fullscreen handling)
if command -v openbox-session >/dev/null 2>&1; then
    openbox-session &
elif command -v openbox >/dev/null 2>&1; then
    openbox &
fi

# Hide the cursor when idle
if [[ "$KIOSK_HIDE_CURSOR" == "true" ]] && command -v unclutter >/dev/null 2>&1; then
    unclutter -idle 0 -root &
fi

# Wait for Ragnar's web server to actually answer (max 60s) before launching.
for i in \$(seq 1 60); do
    if curl -fsS --max-time 2 "$KIOSK_URL" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Per-kiosk profile dir so a crashed session doesn't trip "restore tabs" prompts.
PROFILE_DIR="\$HOME/.config/ragnar-kiosk-chromium"
mkdir -p "\$PROFILE_DIR"

exec "$BROWSER" \\
    --kiosk \\
    --noerrdialogs \\
    --disable-infobars \\
    --disable-translate \\
    --disable-features=TranslateUI,Translate \\
    --no-first-run \\
    --check-for-update-interval=31536000 \\
    --user-data-dir="\$PROFILE_DIR" \\
    --app="$FINAL_URL"
EOF
chmod +x "$SESSION_SCRIPT"

exec xinit "$SESSION_SCRIPT" -- :0 vt7 -nolisten tcp
