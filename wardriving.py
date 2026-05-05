# wardriving.py
# High-performance wardriving engine for Ragnar.
# Captures WiFi networks with GPS coordinates using external antennas.
# Supports multiple WiFi adapters, exports to WiGLE CSV and KML.

import os
import re
import csv
import json
import time
import uuid
import sqlite3
import threading
import subprocess
import logging
from datetime import datetime, timezone

logger = logging.getLogger("Wardriving")

# WiGLE CSV header
WIGLE_HEADER = [
    'MAC', 'SSID', 'AuthMode', 'FirstSeen', 'Channel', 'RSSI',
    'CurrentLatitude', 'CurrentLongitude', 'AltitudeMeters', 'AccuracyMeters', 'Type'
]

# Encryption mapping
_SECURITY_MAP = {
    'WPA3': '[WPA3][ESS]',
    'WPA2': '[WPA2-PSK-CCMP][ESS]',
    'WPA1 WPA2': '[WPA-PSK-TKIP+CCMP][WPA2-PSK-CCMP][ESS]',
    'WPA2 802.1X': '[WPA2-EAP-CCMP][ESS]',
    'WPA1': '[WPA-PSK-TKIP][ESS]',
    'WEP': '[WEP][ESS]',
    '': '[ESS]',
    '--': '[ESS]',
}


def _map_security(security_str):
    """Map nmcli security string to WiGLE-compatible auth mode."""
    if not security_str:
        return '[ESS]'
    s = security_str.strip()
    return _SECURITY_MAP.get(s, f'[{s}][ESS]')


def _freq_to_channel(freq_mhz):
    """Convert WiFi frequency (MHz) to channel number."""
    try:
        freq = int(freq_mhz)
    except (ValueError, TypeError):
        return 0
    # 2.4 GHz
    if 2412 <= freq <= 2484:
        if freq == 2484:
            return 14
        return (freq - 2407) // 5
    # 5 GHz
    if 5170 <= freq <= 5825:
        return (freq - 5000) // 5
    # 6 GHz (WiFi 6E)
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return 0


class WardrivingSession:
    """Represents a single wardriving session with its own SQLite DB."""

    def __init__(self, data_dir, session_id=None):
        self.session_id = session_id or datetime.now().strftime('%Y%m%d_%H%M%S')
        self.data_dir = os.path.join(data_dir, 'wardriving')
        os.makedirs(self.data_dir, exist_ok=True)
        self.db_path = os.path.join(self.data_dir, f'session_{self.session_id}.db')
        self.start_time = time.time()
        self.end_time = None
        self.network_count = 0
        self.unique_bssids = set()
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        """Create the session database tables."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS networks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bssid TEXT NOT NULL,
                    ssid TEXT DEFAULT '',
                    security TEXT DEFAULT '',
                    channel INTEGER DEFAULT 0,
                    frequency INTEGER DEFAULT 0,
                    rssi INTEGER DEFAULT -100,
                    latitude REAL,
                    longitude REAL,
                    altitude REAL,
                    speed_kmh REAL,
                    hdop REAL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    best_rssi INTEGER DEFAULT -100,
                    best_lat REAL,
                    best_lon REAL,
                    scan_count INTEGER DEFAULT 1,
                    interface TEXT DEFAULT '',
                    band TEXT DEFAULT '2.4GHz'
                )
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_bssid ON networks(bssid)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS gps_track (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    altitude REAL,
                    speed_kmh REAL,
                    satellites INTEGER,
                    hdop REAL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS session_info (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            conn.execute(
                "INSERT OR REPLACE INTO session_info (key, value) VALUES (?, ?)",
                ('start_time', datetime.now(timezone.utc).isoformat())
            )

    def upsert_network(self, bssid, ssid, security, channel, frequency,
                       rssi, lat, lon, alt, speed, hdop, interface=''):
        """Insert or update a discovered network (thread-safe)."""
        # Sanitize SSID: strip null bytes and non-printable control characters
        if ssid:
            ssid = ssid.replace('\x00', '')
            if ssid and all(ord(c) < 32 for c in ssid):
                ssid = ''
        now = datetime.now(timezone.utc).isoformat()
        band = '5GHz' if (frequency and int(frequency) > 4900) else '2.4GHz'
        if frequency and int(frequency) > 5925:
            band = '6GHz'

        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    existing = conn.execute(
                        "SELECT rssi, best_rssi, scan_count FROM networks WHERE bssid = ?",
                        (bssid,)
                    ).fetchone()

                    if existing:
                        old_best = existing[1] or -100
                        count = (existing[2] or 0) + 1
                        if rssi > old_best:
                            conn.execute("""
                                UPDATE networks SET
                                    ssid = COALESCE(NULLIF(?, ''), ssid),
                                    security = COALESCE(NULLIF(?, ''), security),
                                    channel = ?, frequency = ?, rssi = ?,
                                    latitude = ?, longitude = ?, altitude = ?,
                                    speed_kmh = ?, hdop = ?,
                                    last_seen = ?, best_rssi = ?,
                                    best_lat = ?, best_lon = ?,
                                    scan_count = ?, interface = ?, band = ?
                                WHERE bssid = ?
                            """, (ssid, security, channel, frequency, rssi,
                                  lat, lon, alt, speed, hdop,
                                  now, rssi, lat, lon, count, interface, band, bssid))
                        else:
                            conn.execute("""
                                UPDATE networks SET
                                    ssid = COALESCE(NULLIF(?, ''), ssid),
                                    security = COALESCE(NULLIF(?, ''), security),
                                    rssi = ?, last_seen = ?, scan_count = ?
                                WHERE bssid = ?
                            """, (ssid, security, rssi, now, count, bssid))
                    else:
                        conn.execute("""
                            INSERT INTO networks
                                (bssid, ssid, security, channel, frequency, rssi,
                                 latitude, longitude, altitude, speed_kmh, hdop,
                                 first_seen, last_seen, best_rssi, best_lat, best_lon,
                                 scan_count, interface, band)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                        """, (bssid, ssid, security, channel, frequency, rssi,
                              lat, lon, alt, speed, hdop,
                              now, now, rssi, lat, lon, interface, band))
                        self.unique_bssids.add(bssid)
                        self.network_count = len(self.unique_bssids)

            except Exception as e:
                logger.error(f"DB upsert error: {e}")

    def log_gps_track(self, lat, lon, alt, speed, satellites, hdop):
        """Log a GPS trackpoint."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        "INSERT INTO gps_track (timestamp, latitude, longitude, altitude, speed_kmh, satellites, hdop) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (time.time(), lat, lon, alt, speed, satellites, hdop)
                    )
            except Exception as e:
                logger.debug(f"GPS track log error: {e}")

    def get_stats(self):
        """Return session statistics."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    total = conn.execute("SELECT COUNT(*) FROM networks").fetchone()[0]
                    open_nets = conn.execute("SELECT COUNT(*) FROM networks WHERE security IN ('', '--', 'OWE')").fetchone()[0]
                    wep_nets = conn.execute("SELECT COUNT(*) FROM networks WHERE security LIKE '%WEP%'").fetchone()[0]
                    wpa_nets = conn.execute("SELECT COUNT(*) FROM networks WHERE security LIKE '%WPA%'").fetchone()[0]
                    band_24 = conn.execute("SELECT COUNT(*) FROM networks WHERE band = '2.4GHz'").fetchone()[0]
                    band_5 = conn.execute("SELECT COUNT(*) FROM networks WHERE band = '5GHz'").fetchone()[0]
                    band_6 = conn.execute("SELECT COUNT(*) FROM networks WHERE band = '6GHz'").fetchone()[0]
                    strongest = conn.execute("SELECT bssid, ssid, best_rssi FROM networks ORDER BY best_rssi DESC LIMIT 1").fetchone()
                    trackpoints = conn.execute("SELECT COUNT(*) FROM gps_track").fetchone()[0]

                    return {
                        'session_id': self.session_id,
                        'total_networks': total,
                        'unique_bssids': total,
                        'open_networks': open_nets,
                        'wep_networks': wep_nets,
                        'wpa_networks': wpa_nets,
                        'band_2_4ghz': band_24,
                        'band_5ghz': band_5,
                        'band_6ghz': band_6,
                        'gps_trackpoints': trackpoints,
                        'strongest': dict(strongest) if strongest else None,
                        'duration_seconds': (self.end_time or time.time()) - self.start_time,
                        'start_time': self.start_time,
                        'db_path': self.db_path
                    }
            except Exception as e:
                logger.error(f"Stats error: {e}")
                return {'error': str(e)}

    def get_networks(self, limit=500, offset=0, sort_by='best_rssi', order='DESC'):
        """Get paginated network list."""
        allowed_sort = {'best_rssi', 'ssid', 'channel', 'first_seen', 'last_seen', 'scan_count', 'band'}
        if sort_by not in allowed_sort:
            sort_by = 'best_rssi'
        if order.upper() not in ('ASC', 'DESC'):
            order = 'DESC'
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(
                        f"SELECT * FROM networks ORDER BY {sort_by} {order} LIMIT ? OFFSET ?",
                        (limit, offset)
                    ).fetchall()
                    return [dict(r) for r in rows]
            except Exception as e:
                logger.error(f"Get networks error: {e}")
                return []

    def get_gps_track(self):
        """Return GPS track as list of [lat, lon] points."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    rows = conn.execute(
                        "SELECT latitude, longitude FROM gps_track ORDER BY timestamp"
                    ).fetchall()
                    return [[r[0], r[1]] for r in rows]
            except Exception:
                return []

    def export_wigle_csv(self):
        """Export session to WiGLE CSV format string."""
        lines = []
        lines.append('WigleWifi-1.4,appRelease=Ragnar,model=RaspberryPi,release=1.0,device=Ragnar,display=EPD,board=RPi,brand=Ragnar')
        lines.append(','.join(WIGLE_HEADER))

        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute("SELECT * FROM networks ORDER BY first_seen").fetchall()
                    for row in rows:
                        r = dict(row)
                        lines.append(','.join([
                            r.get('bssid', ''),
                            r.get('ssid', '').replace(',', '\\,'),
                            _map_security(r.get('security', '')),
                            r.get('first_seen', ''),
                            str(r.get('channel', 0)),
                            str(r.get('best_rssi', -100)),
                            str(r.get('best_lat', '') or ''),
                            str(r.get('best_lon', '') or ''),
                            str(r.get('altitude', '') or ''),
                            str(r.get('hdop', '') or ''),
                            'WIFI'
                        ]))
            except Exception as e:
                logger.error(f"WiGLE export error: {e}")

        return '\n'.join(lines)

    def export_kml(self):
        """Export session to KML format for Google Earth."""
        kml_parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<kml xmlns="http://www.opengis.net/kml/2.2">',
            '<Document>',
            f'<name>Ragnar Wardriving - {self.session_id}</name>',
            '<Style id="open"><IconStyle><color>ff00ff00</color><scale>0.8</scale></IconStyle></Style>',
            '<Style id="wep"><IconStyle><color>ff00ffff</color><scale>0.8</scale></IconStyle></Style>',
            '<Style id="wpa"><IconStyle><color>ff0000ff</color><scale>0.8</scale></IconStyle></Style>',
        ]

        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute("SELECT * FROM networks WHERE best_lat IS NOT NULL").fetchall()
                    for row in rows:
                        r = dict(row)
                        sec = r.get('security', '')
                        style = '#open' if not sec or sec in ('', '--') else ('#wep' if 'WEP' in sec else '#wpa')
                        ssid = (r.get('ssid') or '<hidden>').replace('&', '&amp;').replace('<', '&lt;')
                        kml_parts.append(f'''<Placemark>
<name>{ssid}</name>
<description>BSSID: {r.get("bssid","")}\nSecurity: {sec}\nChannel: {r.get("channel",0)}\nSignal: {r.get("best_rssi",-100)} dBm</description>
<styleUrl>{style}</styleUrl>
<Point><coordinates>{r.get("best_lon",0)},{r.get("best_lat",0)},{r.get("altitude",0) or 0}</coordinates></Point>
</Placemark>''')
            except Exception as e:
                logger.error(f"KML export error: {e}")

        # Add GPS track
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    track = conn.execute("SELECT latitude, longitude, altitude FROM gps_track ORDER BY timestamp").fetchall()
                    if track:
                        coords = ' '.join(f'{r[1]},{r[0]},{r[2] or 0}' for r in track)
                        kml_parts.append(f'''<Placemark>
<name>GPS Track</name>
<Style><LineStyle><color>ff0088ff</color><width>3</width></LineStyle></Style>
<LineString><tessellate>1</tessellate><coordinates>{coords}</coordinates></LineString>
</Placemark>''')
            except Exception:
                pass

        kml_parts.extend(['</Document>', '</kml>'])
        return '\n'.join(kml_parts)

    def close(self):
        """Finalize session."""
        self.end_time = time.time()
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO session_info (key, value) VALUES (?, ?)",
                        ('end_time', datetime.now(timezone.utc).isoformat())
                    )
                    conn.execute(
                        "INSERT OR REPLACE INTO session_info (key, value) VALUES (?, ?)",
                        ('total_networks', str(self.network_count))
                    )
            except Exception:
                pass


class WardrivingEngine:
    """Main wardriving engine that coordinates WiFi scanning and GPS."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.data_dir = getattr(shared_data, 'data_dir', 'data')
        self._running = False
        self._thread = None
        self._gps = None
        self.session = None
        self.scan_interval = 2  # seconds between scans (fast!)
        self.interfaces = []     # WiFi interfaces to use
        self.networks_per_scan = 0
        self.total_networks = 0
        self.scans_completed = 0
        self.last_scan_time = 0
        self.error = None
        self._gps_track_interval = 5  # log GPS position every 5 seconds
        self._last_gps_track = 0

    def start(self, interfaces=None, gps_port=None):
        """Start a wardriving session.
        
        Args:
            interfaces: List of WiFi interface names to scan with.
                       If None, auto-detects all WiFi interfaces.
            gps_port: Serial port for GPS. If None, auto-detects.
        """
        if self._running:
            return {'error': 'Already running'}

        # Detect/validate interfaces
        self.interfaces = interfaces or self._detect_wifi_interfaces()
        if not self.interfaces:
            return {'error': 'No WiFi interfaces found'}

        # Start GPS
        from gps_manager import GPSManager
        self._gps = GPSManager(port=gps_port)
        gps_ok = self._gps.start()
        if not gps_ok:
            logger.warning(f"GPS not available: {self._gps.error}. Wardriving without GPS.")

        # Create session
        self.session = WardrivingSession(self.data_dir)
        self._running = True
        self.error = None
        self.scans_completed = 0

        # Start scanning thread
        self._thread = threading.Thread(target=self._scan_loop, daemon=True, name="wardriving")
        self._thread.start()

        logger.info(f"Wardriving started: interfaces={self.interfaces}, GPS={gps_ok}")
        return {
            'success': True,
            'session_id': self.session.session_id,
            'interfaces': self.interfaces,
            'gps_available': gps_ok,
            'gps_port': self._gps.port if gps_ok else None
        }

    def stop(self):
        """Stop the current wardriving session."""
        if not self._running:
            return {'error': 'Not running'}

        self._running = False
        if self.session:
            self.session.close()
        if self._gps:
            self._gps.stop()

        stats = self.session.get_stats() if self.session else {}
        logger.info(f"Wardriving stopped. Networks: {stats.get('total_networks', 0)}")
        return {'success': True, 'stats': stats}

    def is_running(self):
        return self._running

    def get_status(self):
        """Get current wardriving status."""
        result = {
            'running': self._running,
            'session_id': self.session.session_id if self.session else None,
            'interfaces': self.interfaces,
            'scans_completed': self.scans_completed,
            'networks_this_scan': self.networks_per_scan,
            'total_networks': self.total_networks,
            'last_scan_time': self.last_scan_time,
            'error': self.error,
            'gps': self._gps.get_status() if self._gps else {'connected': False},
        }
        if self.session:
            result['stats'] = self.session.get_stats()
        return result

    def get_session_list(self):
        """List all saved wardriving sessions."""
        wd_dir = os.path.join(self.data_dir, 'wardriving')
        if not os.path.isdir(wd_dir):
            return []
        sessions = []
        for f in sorted(os.listdir(wd_dir), reverse=True):
            if f.startswith('session_') and f.endswith('.db'):
                sid = f[8:-3]  # strip 'session_' and '.db'
                db_path = os.path.join(wd_dir, f)
                size = os.path.getsize(db_path)
                try:
                    with sqlite3.connect(db_path) as conn:
                        conn.row_factory = sqlite3.Row
                        total = conn.execute("SELECT COUNT(*) FROM networks").fetchone()[0]
                        info = {}
                        for row in conn.execute("SELECT key, value FROM session_info").fetchall():
                            info[row[0]] = row[1]
                    sessions.append({
                        'session_id': sid,
                        'db_path': db_path,
                        'file_size': size,
                        'total_networks': total,
                        'start_time': info.get('start_time', ''),
                        'end_time': info.get('end_time', ''),
                    })
                except Exception:
                    sessions.append({'session_id': sid, 'error': 'corrupt'})
        return sessions

    def _detect_wifi_interfaces(self):
        """Detect all available WiFi interfaces (including external USB adapters)."""
        interfaces = []
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'DEVICE,TYPE,STATE', 'device'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    parts = line.split(':')
                    if len(parts) >= 3 and parts[1] == 'wifi':
                        interfaces.append(parts[0])
        except Exception as e:
            logger.debug(f"nmcli detection failed: {e}")

        # Fallback: check sysfs
        if not interfaces:
            try:
                import os
                for name in sorted(os.listdir('/sys/class/net')):
                    if os.path.isdir(f'/sys/class/net/{name}/wireless'):
                        interfaces.append(name)
            except Exception:
                pass

        return interfaces

    def _scan_loop(self):
        """Main scanning loop — runs fast continuous scans."""
        logger.info(f"Scan loop started with {len(self.interfaces)} interface(s)")

        while self._running:
            scan_start = time.time()

            try:
                # Get GPS position
                pos = self._gps.get_position() if self._gps else None
                lat = pos['lat'] if pos else None
                lon = pos['lon'] if pos else None
                alt = pos['alt'] if pos else None
                speed = pos['speed_kmh'] if pos else None
                hdop = pos['hdop'] if pos else None

                # Log GPS track periodically
                if pos and (time.time() - self._last_gps_track) >= self._gps_track_interval:
                    self.session.log_gps_track(
                        lat, lon, alt, speed,
                        pos.get('satellites', 0), hdop
                    )
                    self._last_gps_track = time.time()

                # Scan each interface
                total_found = 0
                for iface in self.interfaces:
                    networks = self._scan_interface(iface)
                    for net in networks:
                        self.session.upsert_network(
                            bssid=net['bssid'],
                            ssid=net['ssid'],
                            security=net['security'],
                            channel=net['channel'],
                            frequency=net['frequency'],
                            rssi=net['rssi'],
                            lat=lat, lon=lon, alt=alt,
                            speed=speed, hdop=hdop,
                            interface=iface
                        )
                        total_found += 1

                self.networks_per_scan = total_found
                self.scans_completed += 1
                self.total_networks = self.session.network_count
                self.last_scan_time = time.time()

            except Exception as e:
                self.error = str(e)
                logger.error(f"Scan error: {e}")

            # Wait for next scan (adaptive: faster if moving)
            elapsed = time.time() - scan_start
            wait = max(0.5, self.scan_interval - elapsed)
            # If we have GPS speed data, scan faster when moving
            if self._gps and self._gps.speed_kmh and self._gps.speed_kmh > 5:
                wait = min(wait, 1.0)  # Scan every second when moving

            time.sleep(wait)

        logger.info("Scan loop stopped")

    def _scan_interface(self, interface):
        """Scan a single WiFi interface for networks using iw (fastest method)."""
        networks = []

        # Method 1: iw scan dump (fastest — reads cached scan results)
        try:
            result = subprocess.run(
                ['sudo', 'iw', 'dev', interface, 'scan', 'dump'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                networks = self._parse_iw_scan(result.stdout, interface)
                if networks:
                    return networks
        except Exception as e:
            logger.debug(f"iw scan dump failed on {interface}: {e}")

        # Method 2: Trigger new scan + dump
        try:
            subprocess.run(
                ['sudo', 'iw', 'dev', interface, 'scan', 'trigger'],
                capture_output=True, text=True, timeout=5
            )
            time.sleep(0.5)
            result = subprocess.run(
                ['sudo', 'iw', 'dev', interface, 'scan', 'dump'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                networks = self._parse_iw_scan(result.stdout, interface)
                if networks:
                    return networks
        except Exception as e:
            logger.debug(f"iw scan trigger+dump failed on {interface}: {e}")

        # Method 3: nmcli fallback
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'BSSID,SSID,SIGNAL,SECURITY,FREQ,CHAN', 'dev', 'wifi', 'list',
                 'ifname', interface, '--rescan', 'auto'],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                networks = self._parse_nmcli_scan(result.stdout)
        except Exception as e:
            logger.debug(f"nmcli scan failed on {interface}: {e}")

        return networks

    def _parse_iw_scan(self, output, interface):
        """Parse iw scan dump output into network dicts."""
        networks = []
        current = None

        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('BSS '):
                if current and current.get('bssid'):
                    # Sanitize SSID: remove null bytes and control chars
                    ssid = current.get('ssid', '')
                    if ssid and (('\x00' in ssid) or all(c < ' ' for c in ssid if c != ' ')):
                        current['ssid'] = ''
                    networks.append(current)
                # BSS aa:bb:cc:dd:ee:ff(on wlan0) -- associated
                bssid_match = re.match(r'BSS\s+([0-9a-fA-F:]{17})', line)
                current = {
                    'bssid': bssid_match.group(1).upper() if bssid_match else '',
                    'ssid': '',
                    'security': '',
                    'channel': 0,
                    'frequency': 0,
                    'rssi': -100,
                    'interface': interface
                }
            elif current:
                if line.startswith('SSID:'):
                    current['ssid'] = line[5:].strip()
                elif line.startswith('signal:'):
                    try:
                        current['rssi'] = int(float(line.split(':')[1].strip().split(' ')[0]))
                    except (ValueError, IndexError):
                        pass
                elif line.startswith('freq:'):
                    try:
                        # Handle formats: "freq: 2437", "freq: 2437 MHz", etc.
                        freq_str = re.search(r'(\d+)', line.split(':', 1)[1])
                        if freq_str:
                            freq = int(freq_str.group(1))
                            current['frequency'] = freq
                            current['channel'] = _freq_to_channel(freq)
                    except (ValueError, IndexError):
                        pass
                elif line.startswith('DS Parameter set:'):
                    # "DS Parameter set: channel 6" — fallback for channel
                    try:
                        ch_match = re.search(r'channel\s+(\d+)', line)
                        if ch_match and current['channel'] == 0:
                            ch = int(ch_match.group(1))
                            current['channel'] = ch
                            # Estimate frequency from channel if not set
                            if current['frequency'] == 0 and 1 <= ch <= 14:
                                current['frequency'] = 2407 + ch * 5 if ch < 14 else 2484
                    except (ValueError, IndexError):
                        pass
                elif line.startswith('* primary channel:'):
                    # HT/VHT operation: "* primary channel: 36"
                    try:
                        ch_match = re.search(r'(\d+)', line.split(':', 1)[1])
                        if ch_match and current['channel'] == 0:
                            current['channel'] = int(ch_match.group(1))
                    except (ValueError, IndexError):
                        pass
                elif line.startswith('* center freq segment 1:') or line.startswith('center freq 1:'):
                    # VHT/HE operation center frequency
                    try:
                        freq_match = re.search(r'(\d{4,5})', line)
                        if freq_match and current['frequency'] == 0:
                            freq = int(freq_match.group(1))
                            current['frequency'] = freq
                            if current['channel'] == 0:
                                current['channel'] = _freq_to_channel(freq)
                    except (ValueError, IndexError):
                        pass
                elif 'RSN:' == line or line.startswith('RSN:'):
                    current['security'] = 'WPA2'
                elif 'WPA:' == line or line.startswith('WPA:'):
                    if current['security'] != 'WPA2':
                        current['security'] = 'WPA1'
                elif line.startswith('capability:') and 'Privacy' in line:
                    if not current['security']:
                        current['security'] = 'WEP'

        if current and current.get('bssid'):
            ssid = current.get('ssid', '')
            if ssid and (('\x00' in ssid) or all(c < ' ' for c in ssid if c != ' ')):
                current['ssid'] = ''
            networks.append(current)

        return networks

    def _parse_nmcli_scan(self, output):
        """Parse nmcli terse WiFi scan output."""
        networks = []
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            # nmcli terse: BSSID:SSID:SIGNAL:SECURITY:FREQ:CHAN
            # Handle escaped colons in BSSID
            parts = line.replace('\\:', '\x00').split(':')
            parts = [p.replace('\x00', ':') for p in parts]
            if len(parts) >= 6:
                try:
                    freq = int(parts[4]) if parts[4] else 0
                except ValueError:
                    freq = 0
                try:
                    chan = int(parts[5]) if parts[5] else _freq_to_channel(freq)
                except ValueError:
                    chan = _freq_to_channel(freq)
                try:
                    signal = int(parts[2]) if parts[2] else -100
                    # nmcli gives 0-100 signal, convert to approximate dBm
                    if signal >= 0:
                        rssi = max(-100, min(-20, -100 + signal))
                    else:
                        rssi = signal
                except ValueError:
                    rssi = -100

                networks.append({
                    'bssid': parts[0].upper(),
                    'ssid': parts[1],
                    'rssi': rssi,
                    'security': parts[3],
                    'frequency': freq,
                    'channel': chan,
                })

        return networks
