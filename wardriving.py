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

# Common camera manufacturer MAC OUI prefixes (first 3 bytes)
_CAMERA_OUI = {
    '00:80:F0', '00:62:6E', 'C0:56:E3', '28:57:BE', 'AC:CC:8E',  # Axis
    '00:0F:7C', 'B0:C5:54', '7C:11:CB', '30:71:B2', '4C:BD:8F',  # ACTi, Hikvision
    '44:47:CC', '54:C4:15', 'E0:50:8B', 'C0:06:0C',               # Hikvision
    'A0:BD:1D', '3C:EF:8C', '48:EA:63', 'BC:AD:28', 'DC:B8:08',  # Dahua
    '00:30:53', '00:04:7D', '00:E0:8F', '60:38:E0',               # Vivotek, Bosch
    '78:A5:04', '78:B2:13', 'CC:2D:21', '00:18:AE',               # Samsung, TVT
    '00:09:89', '00:12:9B', '00:14:95',                            # Geovision, Arecont
    '00:1A:07', '00:1C:F0', '00:24:B5', '64:16:66',               # Reolink, Amcrest
    '9C:8E:CD', 'D4:6D:6D', 'EC:71:DB',                            # TP-Link cameras, Foscam
}

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
                    band TEXT DEFAULT '2.4GHz',
                    is_camera INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_bssid ON networks(bssid)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS bluetooth_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT NOT NULL,
                    name TEXT DEFAULT '',
                    rssi INTEGER DEFAULT -100,
                    device_type TEXT DEFAULT '',
                    latitude REAL,
                    longitude REAL,
                    altitude REAL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    scan_count INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_bt_mac ON bluetooth_devices(mac)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cell_towers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cell_id TEXT NOT NULL,
                    mcc TEXT DEFAULT '',
                    mnc TEXT DEFAULT '',
                    lac TEXT DEFAULT '',
                    tech TEXT DEFAULT '',
                    provider TEXT DEFAULT '',
                    signal_dbm INTEGER DEFAULT -120,
                    band_freq TEXT DEFAULT '',
                    latitude REAL,
                    longitude REAL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    scan_count INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_cell ON cell_towers(cell_id)
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
        # Sanitize SSID: strip null bytes, hex escape sequences, and non-printable chars
        if ssid:
            ssid = ssid.replace('\x00', '')
            # iw outputs literal \x00 sequences (backslash + x + hex) for non-printable SSIDs
            ssid = re.sub(r'\\x[0-9a-fA-F]{2}', '', ssid)
            ssid = ssid.strip()
            # If nothing printable remains, treat as hidden
            if not ssid or all(ord(c) < 32 for c in ssid):
                ssid = ''
        now = datetime.now(timezone.utc).isoformat()
        band = '5GHz' if (frequency and int(frequency) > 4900) else '2.4GHz'
        if frequency and int(frequency) > 5925:
            band = '6GHz'
        # Check if MAC matches known camera OUI
        is_camera = 1 if bssid and bssid[:8].upper() in _CAMERA_OUI else 0

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
                            # Update GPS if we have coords now but didn't before
                            if lat and lon:
                                conn.execute("""
                                    UPDATE networks SET
                                        ssid = COALESCE(NULLIF(?, ''), ssid),
                                        security = COALESCE(NULLIF(?, ''), security),
                                        rssi = ?, last_seen = ?, scan_count = ?,
                                        latitude = COALESCE(latitude, ?),
                                        longitude = COALESCE(longitude, ?),
                                        altitude = COALESCE(altitude, ?),
                                        best_lat = COALESCE(best_lat, ?),
                                        best_lon = COALESCE(best_lon, ?)
                                    WHERE bssid = ?
                                """, (ssid, security, rssi, now, count,
                                      lat, lon, alt, lat, lon, bssid))
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
                                 scan_count, interface, band, is_camera)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                        """, (bssid, ssid, security, channel, frequency, rssi,
                              lat, lon, alt, speed, hdop,
                              now, now, rssi, lat, lon, interface, band, is_camera))
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

    def upsert_bluetooth(self, mac, name, rssi, device_type, lat, lon, alt):
        """Insert or update a discovered Bluetooth device."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    existing = conn.execute(
                        "SELECT scan_count FROM bluetooth_devices WHERE mac = ?", (mac,)
                    ).fetchone()
                    if existing:
                        count = (existing[0] or 0) + 1
                        conn.execute("""
                            UPDATE bluetooth_devices SET
                                name = COALESCE(NULLIF(?, ''), name),
                                rssi = MAX(rssi, ?), device_type = COALESCE(NULLIF(?, ''), device_type),
                                latitude = COALESCE(?, latitude), longitude = COALESCE(?, longitude),
                                altitude = COALESCE(?, altitude),
                                last_seen = ?, scan_count = ?
                            WHERE mac = ?
                        """, (name, rssi, device_type, lat, lon, alt, now, count, mac))
                    else:
                        conn.execute("""
                            INSERT INTO bluetooth_devices
                                (mac, name, rssi, device_type, latitude, longitude, altitude,
                                 first_seen, last_seen, scan_count)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                        """, (mac, name, rssi, device_type, lat, lon, alt, now, now))
            except Exception as e:
                logger.debug(f"BT upsert error: {e}")

    def upsert_cell_tower(self, cell_id, mcc, mnc, lac, tech, provider,
                          signal_dbm, band_freq, lat, lon):
        """Insert or update a detected cell tower."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    existing = conn.execute(
                        "SELECT scan_count FROM cell_towers WHERE cell_id = ?", (cell_id,)
                    ).fetchone()
                    if existing:
                        count = (existing[0] or 0) + 1
                        conn.execute("""
                            UPDATE cell_towers SET
                                signal_dbm = MAX(signal_dbm, ?), last_seen = ?, scan_count = ?,
                                latitude = COALESCE(?, latitude), longitude = COALESCE(?, longitude)
                            WHERE cell_id = ?
                        """, (signal_dbm, now, count, lat, lon, cell_id))
                    else:
                        conn.execute("""
                            INSERT INTO cell_towers
                                (cell_id, mcc, mnc, lac, tech, provider, signal_dbm, band_freq,
                                 latitude, longitude, first_seen, last_seen, scan_count)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                        """, (cell_id, mcc, mnc, lac, tech, provider, signal_dbm, band_freq,
                              lat, lon, now, now))
            except Exception as e:
                logger.debug(f"Cell upsert error: {e}")

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

                    # Bluetooth and cell counts (tables may not exist in old DBs)
                    bt_count = 0
                    cell_count = 0
                    camera_count = 0
                    try:
                        bt_count = conn.execute("SELECT COUNT(*) FROM bluetooth_devices").fetchone()[0]
                    except Exception:
                        pass
                    try:
                        cell_count = conn.execute("SELECT COUNT(*) FROM cell_towers").fetchone()[0]
                    except Exception:
                        pass
                    try:
                        camera_count = conn.execute("SELECT COUNT(*) FROM networks WHERE is_camera = 1").fetchone()[0]
                    except Exception:
                        pass

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
                        'bluetooth_devices': bt_count,
                        'cell_towers': cell_count,
                        'cameras': camera_count,
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

    def get_bluetooth_devices(self):
        """Get all discovered Bluetooth devices."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(
                        "SELECT * FROM bluetooth_devices ORDER BY rssi DESC"
                    ).fetchall()
                    return [dict(r) for r in rows]
            except Exception:
                return []

    def get_cell_towers(self):
        """Get all discovered cell towers."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(
                        "SELECT * FROM cell_towers ORDER BY signal_dbm DESC"
                    ).fetchall()
                    return [dict(r) for r in rows]
            except Exception:
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

    def export_wigle_csv(self, device_name='Ragnar'):
        """Export session to WiGLE CSV format string including WiFi, BT, and cell."""
        lines = []
        dn = device_name or 'Ragnar'
        lines.append(f'WigleWifi-1.4,appRelease=Ragnar,model=RaspberryPi,release=1.0,device={dn},display=EPD,board=RPi,brand=Ragnar')
        lines.append(','.join(WIGLE_HEADER))

        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    # WiFi networks
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
                    # Bluetooth devices
                    try:
                        bt_rows = conn.execute("SELECT * FROM bluetooth_devices ORDER BY first_seen").fetchall()
                        for row in bt_rows:
                            r = dict(row)
                            lines.append(','.join([
                                r.get('mac', ''),
                                r.get('name', '').replace(',', '\\,'),
                                '[BT]',
                                r.get('first_seen', ''),
                                '0',
                                str(r.get('rssi', -100)),
                                str(r.get('latitude', '') or ''),
                                str(r.get('longitude', '') or ''),
                                str(r.get('altitude', '') or ''),
                                '',
                                'BT'
                            ]))
                    except Exception:
                        pass
                    # Cell towers
                    try:
                        cell_rows = conn.execute("SELECT * FROM cell_towers ORDER BY first_seen").fetchall()
                        for row in cell_rows:
                            r = dict(row)
                            lines.append(','.join([
                                r.get('cell_id', ''),
                                f"{r.get('provider', '')} {r.get('tech', '')}".strip().replace(',', '\\,'),
                                f"[{r.get('tech', 'GSM')}]",
                                r.get('first_seen', ''),
                                str(r.get('band_freq', '')),
                                str(r.get('signal_dbm', -120)),
                                str(r.get('latitude', '') or ''),
                                str(r.get('longitude', '') or ''),
                                '',
                                '',
                                'GSM'
                            ]))
                    except Exception:
                        pass
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
            '<Style id="bt"><IconStyle><color>ffff8800</color><scale>0.6</scale></IconStyle></Style>',
            '<Style id="cell"><IconStyle><color>ff8800ff</color><scale>0.7</scale></IconStyle></Style>',
            '<Style id="camera"><IconStyle><color>ffff0088</color><scale>0.9</scale></IconStyle></Style>',
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

        # Add Bluetooth devices
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    bt_rows = conn.execute("SELECT * FROM bluetooth_devices WHERE latitude IS NOT NULL").fetchall()
                    for row in bt_rows:
                        r = dict(row)
                        name = (r.get('name') or r.get('mac', 'Unknown')).replace('&', '&amp;').replace('<', '&lt;')
                        kml_parts.append(f'''<Placemark>
<name>BT: {name}</name>
<description>MAC: {r.get("mac","")}\nType: {r.get("device_type","")}\nRSSI: {r.get("rssi",-100)} dBm</description>
<styleUrl>#bt</styleUrl>
<Point><coordinates>{r.get("longitude",0)},{r.get("latitude",0)},0</coordinates></Point>
</Placemark>''')
            except Exception:
                pass

        # Add Cell towers
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cell_rows = conn.execute("SELECT * FROM cell_towers WHERE latitude IS NOT NULL").fetchall()
                    for row in cell_rows:
                        r = dict(row)
                        kml_parts.append(f'''<Placemark>
<name>Cell: {r.get("provider","")} {r.get("tech","")}</name>
<description>CellID: {r.get("cell_id","")}\nMCC/MNC: {r.get("mcc","")}/{r.get("mnc","")}\nSignal: {r.get("signal_dbm",-120)} dBm</description>
<styleUrl>#cell</styleUrl>
<Point><coordinates>{r.get("longitude",0)},{r.get("latitude",0)},0</coordinates></Point>
</Placemark>''')
            except Exception:
                pass

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

    def import_wigle_csv(self, csv_path_or_stream):
        """Import a WiGLE-format CSV file into this session.

        Supports Piglet, GhostESP, and standard WiGLE CSV exports.
        Returns dict with counts of imported records.
        """
        imported_wifi = 0
        imported_bt = 0
        imported_cell = 0
        skipped = 0

        try:
            # Handle both file path and file-like objects
            if isinstance(csv_path_or_stream, str):
                fh = open(csv_path_or_stream, 'r', encoding='utf-8', errors='replace')
            else:
                fh = csv_path_or_stream

            lines = fh.readlines()
            if hasattr(csv_path_or_stream, 'close') and isinstance(csv_path_or_stream, str):
                fh.close()

            # Skip WiGLE metadata line(s) starting with WigleWifi
            data_lines = []
            header_line = None
            for line in lines:
                stripped = line.strip()
                if stripped.lower().startswith('wigle') or stripped.lower().startswith('#'):
                    continue
                if header_line is None:
                    header_line = stripped
                    continue
                data_lines.append(stripped)

            if not header_line:
                return {'error': 'No CSV header found', 'imported': 0}

            # Parse header - normalize to lowercase
            headers = [h.strip().lower() for h in header_line.split(',')]

            # Map common WiGLE column names
            col_map = {}
            for i, h in enumerate(headers):
                if h in ('mac', 'bssid'):
                    col_map['mac'] = i
                elif h in ('ssid', 'name'):
                    col_map['ssid'] = i
                elif h in ('authmode', 'security', 'encryption'):
                    col_map['auth'] = i
                elif h in ('firstseen', 'first_seen', 'time'):
                    col_map['firstseen'] = i
                elif h in ('channel',):
                    col_map['channel'] = i
                elif h in ('rssi', 'signal', 'level'):
                    col_map['rssi'] = i
                elif h in ('currentlatitude', 'latitude', 'lat'):
                    col_map['lat'] = i
                elif h in ('currentlongitude', 'longitude', 'lon', 'long'):
                    col_map['lon'] = i
                elif h in ('altitudemeters', 'altitude', 'alt'):
                    col_map['alt'] = i
                elif h in ('type',):
                    col_map['type'] = i

            if 'mac' not in col_map:
                return {'error': 'CSV missing MAC/BSSID column', 'imported': 0}

            for line in data_lines:
                if not line:
                    continue
                # CSV parse (handles quoted fields)
                try:
                    row = next(csv.reader([line]))
                except Exception:
                    skipped += 1
                    continue

                if len(row) <= col_map.get('mac', 0):
                    skipped += 1
                    continue

                mac = row[col_map['mac']].strip().upper()
                if not mac or len(mac) < 12:
                    skipped += 1
                    continue

                ssid = row[col_map['ssid']].strip() if 'ssid' in col_map and col_map['ssid'] < len(row) else ''
                auth = row[col_map['auth']].strip() if 'auth' in col_map and col_map['auth'] < len(row) else ''
                channel = 0
                if 'channel' in col_map and col_map['channel'] < len(row):
                    try:
                        channel = int(row[col_map['channel']])
                    except (ValueError, TypeError):
                        pass
                rssi = -80
                if 'rssi' in col_map and col_map['rssi'] < len(row):
                    try:
                        rssi = int(row[col_map['rssi']])
                    except (ValueError, TypeError):
                        pass
                lat = None
                lon = None
                alt = None
                if 'lat' in col_map and col_map['lat'] < len(row):
                    try:
                        lat = float(row[col_map['lat']])
                    except (ValueError, TypeError):
                        pass
                if 'lon' in col_map and col_map['lon'] < len(row):
                    try:
                        lon = float(row[col_map['lon']])
                    except (ValueError, TypeError):
                        pass
                if 'alt' in col_map and col_map['alt'] < len(row):
                    try:
                        alt = float(row[col_map['alt']])
                    except (ValueError, TypeError):
                        pass

                # Determine type
                record_type = ''
                if 'type' in col_map and col_map['type'] < len(row):
                    record_type = row[col_map['type']].strip().upper()

                if record_type in ('BT', 'BLE', 'BLUETOOTH'):
                    self.upsert_bluetooth(mac, ssid, rssi, '', lat, lon, alt)
                    imported_bt += 1
                elif record_type in ('GSM', 'CDMA', 'LTE', 'UMTS', 'CELL', '5G', 'NR'):
                    self.upsert_cell_tower(
                        cell_id=mac, tech=record_type, provider=ssid,
                        signal_dbm=rssi, lat=lat, lon=lon
                    )
                    imported_cell += 1
                else:
                    # WiFi network
                    freq = 0
                    if channel:
                        if channel <= 14:
                            freq = 2407 + channel * 5
                        elif channel >= 36:
                            freq = 5000 + channel * 5
                    self.upsert_network(
                        bssid=mac, ssid=ssid, security=auth,
                        channel=channel, frequency=freq, rssi=rssi,
                        lat=lat, lon=lon, alt=alt, speed=None, hdop=None,
                        interface='import'
                    )
                    imported_wifi += 1

        except Exception as e:
            logger.error(f"WiGLE CSV import error: {e}")
            return {'error': str(e), 'imported': 0}

        total = imported_wifi + imported_bt + imported_cell
        logger.info(f"WiGLE CSV imported: {imported_wifi} WiFi, {imported_bt} BT, {imported_cell} Cell, {skipped} skipped")
        return {
            'success': True,
            'imported_wifi': imported_wifi,
            'imported_bluetooth': imported_bt,
            'imported_cell': imported_cell,
            'total_imported': total,
            'skipped': skipped
        }

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
        self._bt_thread = None
        self._cell_thread = None
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
        self.bt_count = 0
        self.cell_count = 0
        self.device_name = ''
        self._serial_thread = None
        self._serial_port = None
        self.serial_connected = False
        self.serial_networks = 0
        self._serial_entry_buffer = {}  # Buffer for multi-line GhostESP entries

    def start(self, interfaces=None, gps_port=None, device_name=None):
        """Start a wardriving session."""
        if self._running:
            return {'error': 'Already running'}

        # Device name from param or config
        self.device_name = device_name or self.shared_data.config.get('wardriving_device_name', '') or ''

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
        self.bt_count = 0
        self.cell_count = 0

        # Save device name and session info
        if self.device_name:
            try:
                with sqlite3.connect(self.session.db_path) as conn:
                    conn.execute("INSERT OR REPLACE INTO session_info (key, value) VALUES (?, ?)",
                                 ('device_name', self.device_name))
            except Exception:
                pass

        # Start scanning threads
        self._thread = threading.Thread(target=self._scan_loop, daemon=True, name="wardriving")
        self._thread.start()

        # Start Bluetooth scanning thread
        self._bt_thread = threading.Thread(target=self._bt_scan_loop, daemon=True, name="wardriving-bt")
        self._bt_thread.start()

        # Start cell scanning thread
        self._cell_thread = threading.Thread(target=self._cell_scan_loop, daemon=True, name="wardriving-cell")
        self._cell_thread.start()

        # Start serial ESP32 listener (Piglet/GhostESP) - auto-detect or use configured port
        serial_port = self.shared_data.config.get('wardriving_serial_port', '')
        if not serial_port:
            serial_port = self._detect_esp32_serial()
        if serial_port:
            self._serial_port = serial_port
            self.shared_data.config['wardriving_serial_port'] = serial_port
            self._serial_thread = threading.Thread(target=self._serial_listen_loop, daemon=True, name="wardriving-serial")
            self._serial_thread.start()
            logger.info(f"GhostESP/Piglet auto-detected on {serial_port}")

        logger.info(f"Wardriving started: interfaces={self.interfaces}, GPS={gps_ok}, device={self.device_name}")
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

    def start_serial(self, port):
        """Start serial listener on the given port."""
        if self._serial_thread and self._serial_thread.is_alive():
            return {'error': 'Serial already running'}
        self._serial_port = port
        self._running_serial = True
        self._serial_thread = threading.Thread(target=self._serial_listen_loop, daemon=True, name="wardriving-serial")
        self._serial_thread.start()
        return {'success': True, 'port': port}

    def stop_serial(self):
        """Stop the serial listener."""
        self._serial_port = None
        self.serial_connected = False
        return {'success': True}

    def _detect_esp32_serial(self):
        """Auto-detect an Espressif ESP32 on /dev/ttyACM* or /dev/ttyUSB*."""
        import glob
        candidates = glob.glob('/dev/ttyACM*') + glob.glob('/dev/ttyUSB*')
        for port in sorted(candidates):
            try:
                result = subprocess.run(
                    ['udevadm', 'info', '-a', port],
                    capture_output=True, text=True, timeout=3
                )
                if 'Espressif' in result.stdout or 'espressif' in result.stdout.lower():
                    logger.info(f"ESP32 detected on {port}")
                    return port
            except Exception:
                continue
        return None

    def is_running(self):
        return self._running

    def get_status(self):
        """Get current wardriving status."""
        # GPS status: use live GPS if running, otherwise probe for device (cached)
        if self._gps:
            gps_status = self._gps.get_status()
        else:
            now = time.time()
            if not hasattr(self, '_gps_probe_cache') or now - self._gps_probe_time > 15:
                from gps_manager import detect_gps_device
                try:
                    detected = detect_gps_device()
                except Exception:
                    detected = None
                self._gps_probe_cache = detected
                self._gps_probe_time = now
            detected = self._gps_probe_cache
            gps_status = {
                'connected': bool(detected),
                'port': detected,
                'has_fix': False,
                'error': None if detected else 'No GPS device detected',
            }

        result = {
            'running': self._running,
            'session_id': self.session.session_id if self.session else None,
            'interfaces': self.interfaces,
            'scans_completed': self.scans_completed,
            'networks_this_scan': self.networks_per_scan,
            'total_networks': self.total_networks,
            'last_scan_time': self.last_scan_time,
            'error': self.error,
            'gps': gps_status,
            'bluetooth_count': self.bt_count,
            'cell_count': self.cell_count,
            'device_name': self.device_name,
            'serial_connected': self.serial_connected,
            'serial_port': self._serial_port or '',
            'serial_networks': self.serial_networks,
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

        def _sanitize_ssid(ssid):
            """Clean up SSID: remove hex escapes, null bytes, control chars."""
            if not ssid:
                return ''
            ssid = ssid.replace('\x00', '')
            # iw outputs literal \xNN for non-printable bytes
            ssid = re.sub(r'\\x[0-9a-fA-F]{2}', '', ssid)
            ssid = ssid.strip()
            if not ssid or all(ord(c) < 32 for c in ssid):
                return ''
            return ssid

        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('BSS '):
                if current and current.get('bssid'):
                    current['ssid'] = _sanitize_ssid(current.get('ssid', ''))
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
            current['ssid'] = _sanitize_ssid(current.get('ssid', ''))
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

    # ------------------------------------------------------------------
    # Bluetooth scanning
    # ------------------------------------------------------------------

    def _bt_scan_loop(self):
        """Background loop: scan for Bluetooth devices every ~15 seconds."""
        logger.info("Bluetooth scan loop started")
        while self._running:
            try:
                pos = self._gps.get_position() if self._gps else None
                lat = pos['lat'] if pos else None
                lon = pos['lon'] if pos else None
                alt = pos['alt'] if pos else None

                devices = self._scan_bluetooth()
                for dev in devices:
                    self.session.upsert_bluetooth(
                        mac=dev['mac'], name=dev['name'], rssi=dev.get('rssi', -100),
                        device_type=dev.get('type', ''), lat=lat, lon=lon, alt=alt
                    )
                self.bt_count = len(devices)
            except Exception as e:
                logger.debug(f"BT scan error: {e}")
            time.sleep(15)
        logger.info("Bluetooth scan loop stopped")

    def _scan_bluetooth(self):
        """Scan for Bluetooth Classic + BLE devices."""
        devices = []
        seen_macs = set()

        # Method 1: bluetoothctl (Classic + BLE)
        try:
            # Power on + scan for 8 seconds
            subprocess.run(['sudo', 'bluetoothctl', 'power', 'on'],
                           capture_output=True, timeout=5)
            proc = subprocess.run(
                ['sudo', 'bluetoothctl', '--timeout', '8', 'scan', 'on'],
                capture_output=True, text=True, timeout=12
            )
            # List discovered devices
            result = subprocess.run(
                ['sudo', 'bluetoothctl', 'devices'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    # Format: "Device AA:BB:CC:DD:EE:FF DeviceName"
                    m = re.match(r'Device\s+([0-9A-Fa-f:]{17})\s+(.*)', line.strip())
                    if m:
                        mac = m.group(1).upper()
                        name = m.group(2).strip()
                        if mac not in seen_macs:
                            seen_macs.add(mac)
                            devices.append({'mac': mac, 'name': name, 'rssi': -80, 'type': 'Classic/BLE'})
        except Exception as e:
            logger.debug(f"bluetoothctl scan failed: {e}")

        # Method 2: hcitool lescan for BLE (if available)
        try:
            result = subprocess.run(
                ['sudo', 'timeout', '5', 'hcitool', 'lescan', '--duplicates'],
                capture_output=True, text=True, timeout=8
            )
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    m = re.match(r'([0-9A-Fa-f:]{17})\s+(.*)', line.strip())
                    if m:
                        mac = m.group(1).upper()
                        name = m.group(2).strip()
                        if mac not in seen_macs and name != '(unknown)':
                            seen_macs.add(mac)
                            devices.append({'mac': mac, 'name': name, 'rssi': -85, 'type': 'BLE'})
        except Exception as e:
            logger.debug(f"hcitool lescan failed: {e}")

        return devices

    # ------------------------------------------------------------------
    # Cell network scanning
    # ------------------------------------------------------------------

    def _cell_scan_loop(self):
        """Background loop: scan for cell towers every ~30 seconds."""
        logger.info("Cell network scan loop started")
        while self._running:
            try:
                pos = self._gps.get_position() if self._gps else None
                lat = pos['lat'] if pos else None
                lon = pos['lon'] if pos else None

                towers = self._scan_cell_networks()
                for t in towers:
                    self.session.upsert_cell_tower(
                        cell_id=t['cell_id'], mcc=t.get('mcc', ''), mnc=t.get('mnc', ''),
                        lac=t.get('lac', ''), tech=t.get('tech', ''),
                        provider=t.get('provider', ''), signal_dbm=t.get('signal', -120),
                        band_freq=t.get('band', ''), lat=lat, lon=lon
                    )
                self.cell_count = len(towers)
            except Exception as e:
                logger.debug(f"Cell scan error: {e}")
            time.sleep(30)
        logger.info("Cell network scan loop stopped")

    def _scan_cell_networks(self):
        """Scan for cell networks using ModemManager (mmcli)."""
        towers = []

        # Find modem index
        try:
            result = subprocess.run(
                ['mmcli', '-L'], capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0 or not result.stdout.strip():
                return towers
            # Parse modem number: "/org/freedesktop/ModemManager1/Modem/0"
            modem_match = re.search(r'/Modem/(\d+)', result.stdout)
            if not modem_match:
                return towers
            modem_idx = modem_match.group(1)
        except Exception:
            return towers

        # Get modem info
        try:
            result = subprocess.run(
                ['mmcli', '-m', modem_idx, '--output-json'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                modem = data.get('modem', {})
                generic = modem.get('generic', {})
                thr = modem.get('3gpp', {})

                provider = generic.get('operator-name', '') or thr.get('operator-name', '')
                tech_list = generic.get('access-technologies', [])
                tech = tech_list[0] if tech_list else ''
                signal_raw = generic.get('signal-quality', {}).get('value', 0)
                signal_dbm = int(-120 + (signal_raw * 0.9)) if signal_raw else -120

                mcc = thr.get('operator-code', '')[:3] if thr.get('operator-code') else ''
                mnc = thr.get('operator-code', '')[3:] if thr.get('operator-code') else ''

                # Get cell info from scan
                cell_id_str = thr.get('registration', {}).get('cell-id', '') or str(modem_idx)

                if cell_id_str:
                    towers.append({
                        'cell_id': cell_id_str,
                        'mcc': mcc,
                        'mnc': mnc,
                        'lac': thr.get('registration', {}).get('lac', ''),
                        'tech': tech,
                        'provider': provider,
                        'signal': signal_dbm,
                        'band': '',
                    })
        except Exception as e:
            logger.debug(f"mmcli modem info failed: {e}")

        # Try network scan for nearby towers
        try:
            result = subprocess.run(
                ['mmcli', '-m', modem_idx, '--3gpp-scan', '--output-json'],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                scan_results = data.get('modem', {}).get('3gpp', {}).get('scan', [])
                for net in scan_results:
                    cid = f"{net.get('operator-code', '')}-{net.get('operator-long', '')}"
                    if cid and not any(t['cell_id'] == cid for t in towers):
                        towers.append({
                            'cell_id': cid,
                            'mcc': net.get('operator-code', '')[:3] if net.get('operator-code') else '',
                            'mnc': net.get('operator-code', '')[3:] if net.get('operator-code') else '',
                            'lac': '',
                            'tech': net.get('access-technology', ''),
                            'provider': net.get('operator-long', ''),
                            'signal': -100,
                            'band': '',
                        })
        except Exception as e:
            logger.debug(f"mmcli 3gpp scan failed: {e}")

        return towers

    # ------------------------------------------------------------------
    # Serial ESP32 listener (Piglet / GhostESP)
    # ------------------------------------------------------------------

    def _serial_listen_loop(self):
        """Listen for wardriving data from a USB-connected ESP32 (Piglet/GhostESP).

        Parses two formats:
        1. WiGLE CSV lines: MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,Lat,Lon,Alt,Acc,Type
        2. JSON lines: {"mac":"...","ssid":"...","rssi":...,"channel":...,"lat":...,"lon":...}
        """
        logger.info(f"Serial ESP32 listener starting on {self._serial_port}")
        try:
            import serial as pyserial
        except ImportError:
            logger.error("pyserial not installed - serial listener disabled")
            return

        while self._running:
            try:
                ser = pyserial.Serial(self._serial_port, 115200, timeout=2)
                self.serial_connected = True
                logger.info(f"Serial connected: {self._serial_port}")

                # Send scanap command to start WiFi scanning
                ser.write(b"scanap\r\n")
                last_scan_time = time.time()

                while self._running:
                    try:
                        raw = ser.readline()
                        if not raw:
                            # Periodically re-trigger scan every 30s
                            if time.time() - last_scan_time > 30:
                                ser.write(b"scanap\r\n")
                                last_scan_time = time.time()
                            continue
                        line = raw.decode('utf-8', errors='replace').strip()
                        if not line:
                            continue
                        self._parse_serial_line(line)
                    except Exception as e:
                        logger.debug(f"Serial read error: {e}")
                        break

                ser.close()
            except Exception as e:
                self.serial_connected = False
                logger.debug(f"Serial connect failed ({self._serial_port}): {e}")
                # Retry every 5 seconds
                for _ in range(5):
                    if not self._running:
                        break
                    time.sleep(1)

        self.serial_connected = False
        logger.info("Serial ESP32 listener stopped")

    def _parse_serial_line(self, line):
        """Parse a single line from ESP32 serial output."""
        if not self.session:
            return

        pos = self._gps.get_position() if self._gps else None
        gps_lat = pos['lat'] if pos else None
        gps_lon = pos['lon'] if pos else None
        gps_alt = pos.get('alt') if pos else None

        # Skip GhostESP prompt and status lines
        if line.startswith('ghost-cli>') or line.startswith('Wardrive:') or line.startswith('Registered') or line.startswith('Unsupported'):
            return

        # Try JSON format first (GhostESP style)
        if line.startswith('{'):
            try:
                data = json.loads(line)
                mac = data.get('mac', data.get('bssid', '')).upper()
                if not mac or len(mac) < 12:
                    return
                ssid = data.get('ssid', data.get('name', ''))
                rssi = int(data.get('rssi', data.get('signal', -80)))
                channel = int(data.get('channel', 0))
                auth = data.get('auth', data.get('security', data.get('encryption', '')))
                lat = data.get('lat', data.get('latitude', gps_lat))
                lon = data.get('lon', data.get('longitude', gps_lon))
                alt = data.get('alt', data.get('altitude', gps_alt))
                record_type = data.get('type', 'WIFI').upper()

                if lat:
                    lat = float(lat)
                if lon:
                    lon = float(lon)
                if alt:
                    alt = float(alt)

                if record_type in ('BT', 'BLE', 'BLUETOOTH'):
                    self.session.upsert_bluetooth(mac, ssid, rssi, '', lat, lon, alt)
                else:
                    freq = 0
                    if channel:
                        freq = (2407 + channel * 5) if channel <= 14 else (5000 + channel * 5)
                    self.session.upsert_network(
                        bssid=mac, ssid=ssid, security=auth,
                        channel=channel, frequency=freq, rssi=rssi,
                        lat=lat, lon=lon, alt=alt, speed=None, hdop=None,
                        interface='esp32-serial'
                    )
                    self.serial_networks += 1
                return
            except (json.JSONDecodeError, ValueError):
                pass

        # Try GhostESP multi-line text format:
        # [N] SSID: Name,
        #      BSSID: AA:BB:CC:DD:EE:FF,
        #      RSSI: -70,
        #      Channel: 6,
        #      Band: 2.4GHz,
        #      Security: WPA2
        entry_start = re.match(r'^\[(\d+)\]\s*SSID:\s*(.*?)(?:,\s*)?$', line)
        if entry_start:
            # Flush previous buffered entry if exists
            if self._serial_entry_buffer.get('bssid'):
                self._flush_serial_entry(gps_lat, gps_lon, gps_alt)
            self._serial_entry_buffer = {'ssid': entry_start.group(2).strip().rstrip(',')}
            return

        # Parse continuation lines of a multi-line entry
        if self._serial_entry_buffer is not None and 'ssid' in self._serial_entry_buffer:
            kv = re.match(r'^\s*(BSSID|RSSI|Channel|Band|Security|Vendor|PMF):\s*(.*?)(?:,\s*)?$', line)
            if kv:
                key = kv.group(1).lower()
                val = kv.group(2).strip().rstrip(',')
                self._serial_entry_buffer[key] = val
                return
            else:
                # Non-matching line means entry is complete
                if self._serial_entry_buffer.get('bssid'):
                    self._flush_serial_entry(gps_lat, gps_lon, gps_alt)
                self._serial_entry_buffer = {}

        # Try WiGLE CSV format (Piglet style)
        # MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,Lat,Lon,Alt,Acc,Type
        parts = line.split(',')
        if len(parts) >= 8:
            mac = parts[0].strip().upper()
            # Validate MAC format
            if re.match(r'^[0-9A-F]{2}(:[0-9A-F]{2}){5}$', mac):
                ssid = parts[1].strip() if len(parts) > 1 else ''
                auth = parts[2].strip() if len(parts) > 2 else ''
                channel = 0
                try:
                    channel = int(parts[4].strip()) if len(parts) > 4 else 0
                except (ValueError, TypeError):
                    pass
                rssi = -80
                try:
                    rssi = int(parts[5].strip()) if len(parts) > 5 else -80
                except (ValueError, TypeError):
                    pass
                lat = None
                lon = None
                alt = None
                try:
                    lat = float(parts[6].strip()) if len(parts) > 6 and parts[6].strip() else gps_lat
                    lon = float(parts[7].strip()) if len(parts) > 7 and parts[7].strip() else gps_lon
                    alt = float(parts[8].strip()) if len(parts) > 8 and parts[8].strip() else gps_alt
                except (ValueError, TypeError):
                    lat = gps_lat
                    lon = gps_lon

                record_type = parts[10].strip().upper() if len(parts) > 10 else 'WIFI'

                if record_type in ('BT', 'BLE'):
                    self.session.upsert_bluetooth(mac, ssid, rssi, '', lat, lon, alt)
                elif record_type in ('GSM', 'CDMA', 'LTE', 'UMTS', 'CELL'):
                    self.session.upsert_cell_tower(
                        cell_id=mac, tech=record_type, provider=ssid,
                        signal_dbm=rssi, lat=lat, lon=lon
                    )
                else:
                    freq = 0
                    if channel:
                        freq = (2407 + channel * 5) if channel <= 14 else (5000 + channel * 5)
                    self.session.upsert_network(
                        bssid=mac, ssid=ssid, security=auth,
                        channel=channel, frequency=freq, rssi=rssi,
                        lat=lat, lon=lon, alt=alt, speed=None, hdop=None,
                        interface='esp32-serial'
                    )
                    self.serial_networks += 1

    def _flush_serial_entry(self, gps_lat, gps_lon, gps_alt):
        """Flush a buffered GhostESP multi-line entry to the session."""
        buf = self._serial_entry_buffer
        bssid = buf.get('bssid', '').upper()
        if not bssid or len(bssid) < 12:
            return

        ssid = buf.get('ssid', '')
        if ssid == '(Hidden)':
            ssid = ''
        security = buf.get('security', '')
        channel = 0
        try:
            channel = int(buf.get('channel', 0))
        except (ValueError, TypeError):
            pass
        rssi = -80
        try:
            rssi = int(buf.get('rssi', -80))
        except (ValueError, TypeError):
            pass

        freq = 0
        if channel:
            freq = (2407 + channel * 5) if channel <= 14 else (5000 + channel * 5)

        self.session.upsert_network(
            bssid=bssid, ssid=ssid, security=security,
            channel=channel, frequency=freq, rssi=rssi,
            lat=gps_lat, lon=gps_lon, alt=gps_alt, speed=None, hdop=None,
            interface='esp32-serial'
        )
        self.serial_networks += 1
