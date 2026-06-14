# webapp.py
# Mild-Viking Network Monitor — web server on port 8000
# Replaces webapp_modern.py; serves traffic dashboard only

import os
import threading
import time
import logging
from datetime import datetime

from flask import Flask, jsonify, send_from_directory, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS

logger = logging.getLogger("webapp")

# ── App setup ────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR  = os.path.join(BASE_DIR, 'web')

app = Flask(__name__, static_folder=WEB_DIR, static_url_path='/web')
app.config['SECRET_KEY'] = 'mild-viking-network-monitor-2025'

socketio = SocketIO(
    app,
    cors_allowed_origins='*',
    async_mode='threading',
    logger=False,
    engineio_logger=False,
)
CORS(app)

# ── Shared state (set by run_server) ─────────────────────────────────
_shared_data     = None
_traffic_monitor = None


def _monitor():
    global _traffic_monitor
    if _traffic_monitor:
        return _traffic_monitor
    if _shared_data and hasattr(_shared_data, 'traffic_monitor'):
        _traffic_monitor = _shared_data.traffic_monitor
    return _traffic_monitor


def _default_status():
    return {
        'sent_rate': 0, 'recv_rate': 0, 'total_rate': 0,
        'sent_rate_human': '0 B/s', 'recv_rate_human': '0 B/s',
        'bytes_sent': 0, 'bytes_recv': 0,
        'sent_history': [], 'recv_history': [],
        'animation_mode': 'idle', 'animation_style': 0,
        'animation_intensity': 0,
        'level': 1, 'level_progress': 0,
        'uptime_seconds': 0, 'uptime_human': '0s',
        'current_ip': '', 'current_ssid': '',
        'gateway_ip': '', 'interface': '',
        'connection_type': 'unknown',
        'device_count': 0, 'subnet': '',
        'vlan_subnets': [], 'devices': [],
        'timestamp': datetime.now().isoformat(),
    }


# ── HTML / static routes ─────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(WEB_DIR, 'index.html')


@app.route('/web/<path:path>')
def web_static(path):
    return send_from_directory(WEB_DIR, path)


@app.route('/css/<path:path>')
def css_files(path):
    return send_from_directory(WEB_DIR, path)


@app.route('/settings')
def settings_page():
    return send_from_directory(WEB_DIR, 'settings.html')


# ── API routes ───────────────────────────────────────────────────────

@app.route('/api/status')
def api_status():
    mon = _monitor()
    data = mon.get_status() if mon else _default_status()
    data['timestamp'] = datetime.now().isoformat()
    resp = jsonify(data)
    resp.headers['Cache-Control'] = 'no-cache'
    return resp


@app.route('/api/devices')
def api_devices():
    mon = _monitor()
    if mon:
        s = mon.get_status()
        return jsonify({
            'devices':  s.get('devices', []),
            'count':    s.get('device_count', 0),
            'subnets':  s.get('vlan_subnets', []),
            'subnet':   s.get('subnet', ''),
            'scanned_at': datetime.now().isoformat(),
        })
    return jsonify({'devices': [], 'count': 0, 'subnets': [], 'subnet': ''})


@app.route('/api/scan', methods=['POST'])
def api_scan():
    mon = _monitor()
    if mon:
        mon.trigger_scan()
        return jsonify({'status': 'scan triggered'})
    return jsonify({'status': 'monitor unavailable'}), 503


_CONFIG_SAFE_KEYS = {
    'websrv', 'epd_type', 'screen_reversed',
    'wifi_ap_ssid', 'wifi_ap_password',
    'ethernet_prefer_over_wifi',
    'wifi_known_networks', 'wifi_default_interface',
    # Time
    'timezone', 'ntp_server',
    # Speed test settings
    'speedtest_enabled', 'speedtest_interval_min',
    # Email notifications
    'notify_enabled', 'notify_email',
    'smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass',
    'notify_on_disconnect', 'notify_on_reconnect',
    # Monthly device report
    'monthly_report_enabled', 'monthly_report_email', 'monthly_report_last',
    # Manual VLAN IDs and extra subnets
    'manual_vlan_ids', 'manual_subnets',
    'manual_vlans',   # legacy — kept for backward compat
    # Display preferences
    'mac_format', 'ip_format',
    # Firewall integration (OPNsense / pfSense)
    'firewall_type', 'firewall_url', 'firewall_api_key',
    'firewall_api_secret', 'firewall_verify_ssl',
}


@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    if _shared_data is None:
        return jsonify({})
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        for k, v in data.items():
            if k in _CONFIG_SAFE_KEYS:
                _shared_data.config[k] = v
        try:
            _shared_data.save_config()
        except Exception:
            pass
        return jsonify({'status': 'saved'})
    return jsonify({k: _shared_data.config.get(k) for k in _CONFIG_SAFE_KEYS})


@app.route('/api/wifi/networks')
def api_wifi_networks():
    """Return known WiFi networks from config."""
    if _shared_data is None:
        return jsonify({'networks': []})
    return jsonify({'networks': _shared_data.config.get('wifi_known_networks', [])})


def _get_wifi_iface():
    """Return the first wireless interface name (wlan0, wlan1, etc.)."""
    import subprocess, os
    try:
        for name in os.listdir('/sys/class/net'):
            if os.path.exists(f'/sys/class/net/{name}/wireless'):
                return name
    except Exception:
        pass
    try:
        r = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            if 'Interface' in line:
                return line.split()[-1]
    except Exception:
        pass
    return 'wlan0'   # sensible default


@app.route('/api/wifi/connect', methods=['POST'])
def api_wifi_connect():
    """Change the Pi's WiFi network at the OS level, trying NM then wpa_supplicant."""
    import subprocess, shutil, os, re as _re
    data = request.get_json(silent=True) or {}
    ssid = data.get('ssid', '').strip()
    password = data.get('password', '').strip()
    if not ssid:
        return jsonify({'error': 'ssid required'}), 400

    # Save credentials to app config
    if _shared_data:
        networks = _shared_data.config.get('wifi_known_networks', [])
        networks = [n for n in networks if n.get('ssid') != ssid]
        networks.append({'ssid': ssid, 'password': password})
        _shared_data.config['wifi_known_networks'] = networks
        _shared_data.save_config()

    iface  = _get_wifi_iface()
    errors = []

    # ── Method 1: nmcli (NetworkManager, default on Bookworm) ────────
    if shutil.which('nmcli'):
        try:
            subprocess.run(['sudo', 'nmcli', 'device', 'set', iface, 'managed', 'yes'],
                           capture_output=True, timeout=5)
            cmd = ['sudo', 'nmcli', 'device', 'wifi', 'connect', ssid]
            if password:
                cmd += ['password', password]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                return jsonify({'status': 'connected', 'ssid': ssid})
            errors.append((r.stderr or r.stdout).strip()[:120])
        except Exception as exc:
            errors.append(str(exc)[:80])

    # ── Method 2: raspi-config (works on all Pi OS versions) ─────────
    if shutil.which('raspi-config'):
        try:
            r = subprocess.run(
                ['sudo', 'raspi-config', 'nonint', 'do_wifi_ssid_passphrase', ssid, password],
                capture_output=True, text=True, timeout=20
            )
            if r.returncode == 0:
                return jsonify({'status': 'connected', 'ssid': ssid})
            errors.append('raspi-config: ' + (r.stderr or r.stdout).strip()[:80])
        except Exception as exc:
            errors.append('raspi-config: ' + str(exc)[:60])

    # ── Method 3: edit wpa_supplicant.conf directly ───────────────────
    wpa_conf = '/etc/wpa_supplicant/wpa_supplicant.conf'
    try:
        r = subprocess.run(['sudo', 'cat', wpa_conf],
                           capture_output=True, text=True, timeout=5)
        existing = r.stdout if r.returncode == 0 else \
                   'ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\nupdate_config=1\ncountry=US\n'

        # Generate a proper network block (hash password if wpa_passphrase available)
        if password and shutil.which('wpa_passphrase'):
            pr = subprocess.run(['wpa_passphrase', ssid, password],
                                capture_output=True, text=True, timeout=5)
            net_block = pr.stdout if pr.returncode == 0 else \
                        f'network={{\n\tssid="{ssid}"\n\tpsk="{password}"\n}}\n'
        elif password:
            net_block = f'network={{\n\tssid="{ssid}"\n\tpsk="{password}"\n\tkey_mgmt=WPA-PSK\n}}\n'
        else:
            net_block = f'network={{\n\tssid="{ssid}"\n\tkey_mgmt=NONE\n}}\n'

        # Remove any existing block for this SSID then append new one
        cleaned = _re.sub(
            r'network=\{[^}]*?ssid="' + _re.escape(ssid) + r'".*?\}',
            '', existing, flags=_re.DOTALL
        ).rstrip()
        new_conf = cleaned + '\n' + net_block

        write = subprocess.run(['sudo', 'tee', wpa_conf],
                               input=new_conf, capture_output=True, text=True, timeout=5)
        if write.returncode == 0:
            # Reload config then force reassociation with best available network
            subprocess.run(['sudo', 'wpa_cli', '-i', iface, 'reconfigure'],
                           capture_output=True, timeout=10)
            subprocess.run(['sudo', 'wpa_cli', '-i', iface, 'reassociate'],
                           capture_output=True, timeout=10)
            # Renew DHCP lease on new network
            for dhcp_cmd in (['sudo', 'dhclient', '-r', iface],
                             ['sudo', 'dhclient', iface],
                             ['sudo', 'systemctl', 'restart', 'dhcpcd']):
                try:
                    subprocess.run(dhcp_cmd, capture_output=True, timeout=8)
                except Exception:
                    break
            return jsonify({'status': 'connected', 'ssid': ssid,
                            'note': 'via wpa_supplicant'})
        errors.append('wpa_supplicant write failed')
    except Exception as exc:
        errors.append('wpa_supplicant: ' + str(exc)[:80])

    return jsonify({'status': 'saved',
                    'warning': ' | '.join(errors) or 'Saved — may need reboot to connect'})


@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    """Device name and dashboard password settings."""
    if _shared_data is None:
        return jsonify({})
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        current_pw = _shared_data.config.get('dashboard_password', '')
        # Require current password if one is set
        if current_pw and data.get('current_password', '') != current_pw:
            return jsonify({'error': 'wrong password'}), 403
        if 'device_name' in data:
            name = str(data['device_name']).strip() or 'MILD-VIKING'
            _shared_data.config['device_name'] = name
        if 'dashboard_password' in data:
            _shared_data.config['dashboard_password'] = str(data['dashboard_password'])
        try:
            _shared_data.save_config()
        except Exception:
            pass
        return jsonify({'status': 'saved'})
    pw_set = bool(_shared_data.config.get('dashboard_password', ''))
    return jsonify({
        'device_name': _shared_data.config.get('device_name', 'MILD-VIKING'),
        'password_set': pw_set,
        'ip_format':   _shared_data.config.get('ip_format', 'full'),
        'mac_format':  _shared_data.config.get('mac_format', 'full'),
    })


@app.route('/api/auth', methods=['POST'])
def api_auth():
    """Validate dashboard password. Returns ok/error."""
    if _shared_data is None:
        return jsonify({'status': 'ok'})
    pw = _shared_data.config.get('dashboard_password', '')
    if not pw:
        return jsonify({'status': 'ok'})
    data = request.get_json(silent=True) or {}
    if data.get('password', '') == pw:
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'error'}), 403


@app.route('/api/wifi/network', methods=['DELETE'])
def api_wifi_network_delete():
    """Remove a saved WiFi network by SSID."""
    data = request.get_json(silent=True) or {}
    ssid = data.get('ssid', '').strip()
    if not ssid:
        return jsonify({'error': 'ssid required'}), 400
    if _shared_data:
        nets = _shared_data.config.get('wifi_known_networks', [])
        _shared_data.config['wifi_known_networks'] = [n for n in nets if n.get('ssid') != ssid]
        try:
            _shared_data.save_config()
        except Exception:
            pass
    return jsonify({'status': 'removed'})


def _parse_nmcli_terse(line):
    """Split an nmcli terse line on ':' but treat '\\:' as a literal colon in the value."""
    parts, cur, i = [], [], 0
    while i < len(line):
        if line[i] == '\\' and i + 1 < len(line) and line[i + 1] == ':':
            cur.append(':'); i += 2
        elif line[i] == ':':
            parts.append(''.join(cur)); cur = []; i += 1
        else:
            cur.append(line[i]); i += 1
    parts.append(''.join(cur))
    return parts


@app.route('/api/wifi/scan')
def api_wifi_scan():
    """Scan for nearby WiFi networks. Forces a fresh scan via nmcli, falls back to iwlist."""
    import subprocess, shutil
    networks = []
    seen     = set()

    # ── Method 1: nmcli with forced rescan ───────────────────────────
    if shutil.which('nmcli'):
        try:
            out = subprocess.check_output(
                ['sudo', 'nmcli', '--rescan', 'yes', '-t', '-e', 'yes',
                 '-f', 'SSID,SECURITY,SIGNAL', 'device', 'wifi', 'list'],
                stderr=subprocess.DEVNULL, timeout=15, text=True
            )
            for line in out.strip().splitlines():
                parts = _parse_nmcli_terse(line)
                ssid  = parts[0].strip() if parts else ''
                if ssid and ssid not in seen:
                    seen.add(ssid)
                    networks.append({
                        'ssid':     ssid,
                        'security': parts[1].strip() if len(parts) > 1 else '',
                        'signal':   (parts[2].strip() + '%') if len(parts) > 2 else '',
                    })
        except Exception:
            pass

    # ── Method 2: iwlist fallback (works even when NM isn't managing the iface) ──
    if not networks:
        iface = _get_wifi_iface()
        try:
            subprocess.run(['sudo', 'iwlist', iface, 'scan'],
                           capture_output=True, timeout=12)
            out = subprocess.check_output(
                ['sudo', 'iwlist', iface, 'scan'],
                stderr=subprocess.DEVNULL, timeout=15, text=True
            )
            import re as _re
            for m in _re.finditer(r'ESSID:"([^"]*)"', out):
                ssid = m.group(1)
                if ssid and ssid not in seen:
                    seen.add(ssid)
                    networks.append({'ssid': ssid, 'security': '', 'signal': ''})
        except Exception:
            pass

    return jsonify({'networks': networks})


@app.route('/api/speedtest', methods=['POST'])
def api_speedtest_run():
    """Blocking speed test — runs in thread, waits up to 120s for result."""
    import threading
    mon = _monitor()
    if not mon:
        return jsonify({'error': 'monitor unavailable'}), 503
    if getattr(mon, 'speedtest_running', False):
        return jsonify({'error': 'already running'}), 409

    done = threading.Event()
    mon.trigger_speedtest()

    def _wait():
        for _ in range(120):
            time.sleep(1)
            if not getattr(mon, 'speedtest_running', False):
                break
        done.set()

    threading.Thread(target=_wait, daemon=True).start()
    done.wait(timeout=125)

    return jsonify({
        'dl':   getattr(mon, 'speedtest_dl',   None),
        'ul':   getattr(mon, 'speedtest_ul',   None),
        'ping': getattr(mon, 'speedtest_ping', None),
        'at':   getattr(mon, 'speedtest_at',   None),
    })


@app.route('/api/settings/test-email', methods=['POST'])
def api_test_email():
    """Send a test email using configured SMTP settings."""
    if _shared_data is None:
        return jsonify({'error': 'server not ready'}), 503
    cfg = _shared_data.config
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText('This is a test notification from your Mild-Viking network monitor.')
        msg['Subject'] = '[Mild-Viking] Test notification'
        msg['From']    = cfg.get('smtp_user', '')
        msg['To']      = cfg.get('notify_email', '')
        with smtplib.SMTP(cfg.get('smtp_host', ''), int(cfg.get('smtp_port', 587))) as s:
            s.starttls()
            s.login(cfg.get('smtp_user', ''), cfg.get('smtp_pass', ''))
            s.send_message(msg)
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})


@app.route('/api/time', methods=['POST'])
def api_time():
    """Save timezone + NTP server; apply timezone/NTP to the OS if possible."""
    import subprocess
    if _shared_data is None:
        return jsonify({'error': 'server not ready'}), 503
    data = request.get_json(silent=True) or {}
    tz  = data.get('timezone', '').strip()
    ntp = data.get('ntp_server', '').strip()
    if tz:
        _shared_data.config['timezone'] = tz
        try:
            subprocess.run(['sudo', 'timedatectl', 'set-timezone', tz],
                           timeout=5, check=False)
        except Exception:
            pass
    if ntp:
        _shared_data.config['ntp_server'] = ntp
        try:
            # Write NTP= line to /etc/systemd/timesyncd.conf if writable
            subprocess.run(
                ['sudo', 'bash', '-c',
                 f'grep -q "^NTP=" /etc/systemd/timesyncd.conf && '
                 f'sed -i "s/^NTP=.*/NTP={ntp}/" /etc/systemd/timesyncd.conf || '
                 f'echo "NTP={ntp}" >> /etc/systemd/timesyncd.conf'],
                timeout=5, check=False)
            subprocess.run(['sudo', 'systemctl', 'restart', 'systemd-timesyncd'],
                           timeout=5, check=False)
        except Exception:
            pass
    try:
        _shared_data.save_config()
    except Exception:
        pass
    return jsonify({'status': 'saved'})


@app.route('/api/report/monthly', methods=['POST'])
def api_monthly_report():
    """Generate and email the monthly device usage report immediately."""
    from datetime import datetime as _dt
    if _shared_data is None:
        return jsonify({'error': 'server not ready'}), 503
    cfg = _shared_data.config
    mon = _monitor()
    try:
        from notifier import send_monthly_report
        devices = mon.get_monthly_report() if mon and hasattr(mon, 'get_monthly_report') else []
        send_monthly_report(cfg, devices)
        sent_at = _dt.now().strftime('%Y-%m-%d %H:%M')
        _shared_data.config['monthly_report_last'] = sent_at
        try:
            _shared_data.save_config()
        except Exception:
            pass
        return jsonify({'status': 'ok', 'sent_at': sent_at})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})


@app.route('/api/devices/all')
def api_devices_all():
    """Return the full persistent device registry (all ever-seen devices)."""
    mon = _monitor()
    if mon and hasattr(mon, 'get_known_devices'):
        return jsonify({'devices': mon.get_known_devices()})
    return jsonify({'devices': []})


@app.route('/api/highscores')
def api_highscores():
    """Return Hall of Records — device categories + speed test leaderboards."""
    mon = _monitor()
    if mon and hasattr(mon, 'get_hall_of_records'):
        try:
            return jsonify(mon.get_hall_of_records())
        except Exception as e:
            logger.warning(f"Hall of Records error: {e}")
    return jsonify({'categories': [], 'top_dl': [], 'top_ul': []})


@app.route('/api/firewall/test', methods=['POST'])
def api_firewall_test():
    """Test connectivity to the configured firewall API."""
    try:
        from firewall_integration import test_firewall_connection
        data = request.get_json(silent=True) or {}
        fw_type  = data.get('firewall_type', '')
        fw_url   = data.get('firewall_url', '')
        fw_key   = data.get('firewall_api_key', '')
        fw_sec   = data.get('firewall_api_secret', '')
        fw_ssl   = data.get('firewall_verify_ssl', False)
        if not fw_type or not fw_url:
            return jsonify({'ok': False, 'error': 'Firewall type and URL are required'})
        ok, msg = test_firewall_connection(fw_type, fw_url, fw_key, fw_sec, fw_ssl)
        if ok:
            return jsonify({'ok': True, 'message': msg})
        else:
            return jsonify({'ok': False, 'error': msg})
    except ImportError as e:
        return jsonify({'ok': False, 'error': f'Missing dependency: {e} — run: pip install requests'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


# ── WebSocket ─────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    logger.debug("WebSocket client connected")
    mon = _monitor()
    data = mon.get_status() if mon else _default_status()
    data['timestamp'] = datetime.now().isoformat()
    emit('status_update', data)


@socketio.on('request_scan')
def on_request_scan():
    mon = _monitor()
    if mon:
        mon.trigger_scan()
        emit('scan_triggered', {'status': 'ok'})


@socketio.on('request_speedtest')
def on_request_speedtest():
    mon = _monitor()
    if not mon:
        emit('speedtest_result', {'error': 'monitor unavailable'})
        return
    if mon.speedtest_running:
        emit('speedtest_result', {'running': True})
        return
    emit('speedtest_result', {'running': True})

    def _run_and_emit():
        mon.trigger_speedtest()
        # Wait up to 5 s for the thread to actually set speedtest_running=True
        for _ in range(5):
            time.sleep(1)
            if mon.speedtest_running:
                break
        # Now wait up to 120 s for it to finish
        for _ in range(120):
            time.sleep(1)
            if not mon.speedtest_running:
                break
        socketio.emit('speedtest_result', {
            'running': False,
            'dl':   mon.speedtest_dl,
            'ul':   mon.speedtest_ul,
            'ping': mon.speedtest_ping,
            'at':   mon.speedtest_at,
        })

    threading.Thread(target=_run_and_emit, daemon=True, name="speedtest-emit").start()


def _broadcast_loop():
    """Push status to all connected WebSocket clients every second."""
    while True:
        try:
            mon = _monitor()
            data = mon.get_status() if mon else _default_status()
            data['timestamp'] = datetime.now().isoformat()
            socketio.emit('status_update', data)
        except Exception as exc:
            logger.debug(f"Broadcast error: {exc}")
        time.sleep(1)


# ── Server entry point ───────────────────────────────────────────────

def run_server(shared_data=None, host='0.0.0.0', port=8000):
    global _shared_data, _traffic_monitor
    _shared_data = shared_data

    if shared_data and hasattr(shared_data, 'traffic_monitor'):
        _traffic_monitor = shared_data.traffic_monitor

    threading.Thread(
        target=_broadcast_loop, daemon=True, name="ws-broadcast"
    ).start()

    logger.info(f"Mild-Viking web server starting → http://{host}:{port}")
    socketio.run(
        app,
        host=host,
        port=port,
        allow_unsafe_werkzeug=True,
    )
