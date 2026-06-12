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


@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    if _shared_data is None:
        return jsonify({})
    safe_keys = [
        'websrv', 'epd_type', 'screen_reversed',
        'wifi_ap_ssid', 'wifi_ap_password',
        'ethernet_prefer_over_wifi',
        'wifi_known_networks', 'wifi_default_interface',
    ]
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        for k, v in data.items():
            if k in safe_keys:
                _shared_data.config[k] = v
        try:
            _shared_data.save_config()
        except Exception:
            pass
        return jsonify({'status': 'saved'})
    return jsonify({k: _shared_data.config.get(k) for k in safe_keys})


@app.route('/api/wifi/networks')
def api_wifi_networks():
    """Return known WiFi networks from config."""
    if _shared_data is None:
        return jsonify({'networks': []})
    return jsonify({'networks': _shared_data.config.get('wifi_known_networks', [])})


@app.route('/api/wifi/connect', methods=['POST'])
def api_wifi_connect():
    """Add a WiFi network and trigger reconnect."""
    data = request.get_json(silent=True) or {}
    ssid = data.get('ssid', '').strip()
    password = data.get('password', '').strip()
    if not ssid:
        return jsonify({'error': 'ssid required'}), 400
    if _shared_data:
        networks = _shared_data.config.get('wifi_known_networks', [])
        # Remove existing entry with same SSID
        networks = [n for n in networks if n.get('ssid') != ssid]
        networks.append({'ssid': ssid, 'password': password})
        _shared_data.config['wifi_known_networks'] = networks
        _shared_data.save_config()
    return jsonify({'status': 'network saved'})


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
