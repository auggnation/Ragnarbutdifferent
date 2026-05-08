# gps_manager.py
# USB GPS module support for Ragnar wardriving.
# Supports any NMEA-compatible USB GPS (u-blox, BN-220, VK-162, etc.)
# Reads NMEA sentences from serial port and provides lat/lon/alt/speed/fix data.

import os
import re
import time
import glob
import threading
import logging

logger = logging.getLogger("GPSManager")

# NMEA sentence parsers
_NMEA_GGA = re.compile(
    r'^\$(?:GP|GN|GL)GGA,'
    r'(?P<time>\d{6}(?:\.\d+)?),'
    r'(?P<lat>\d{2,4}\.\d+)?,(?P<lat_dir>[NS])?,'
    r'(?P<lon>\d{3,5}\.\d+)?,(?P<lon_dir>[EW])?,'
    r'(?P<fix>\d),'
    r'(?P<sats>\d+),'
    r'(?P<hdop>[^,]*),'
    r'(?P<alt>[^,]*),(?P<alt_unit>[^,]*),'
)

_NMEA_RMC = re.compile(
    r'^\$(?:GP|GN|GL)RMC,'
    r'(?P<time>\d{6}(?:\.\d+)?),'
    r'(?P<status>[AV]),'
    r'(?P<lat>\d{2,4}\.\d+)?,(?P<lat_dir>[NS])?,'
    r'(?P<lon>\d{3,5}\.\d+)?,(?P<lon_dir>[EW])?,'
    r'(?P<speed_knots>[^,]*),'
    r'(?P<course>[^,]*),'
)


def _nmea_to_decimal(raw, direction):
    """Convert NMEA lat/lon (ddmm.mmmm) to decimal degrees."""
    if not raw or not direction:
        return None
    try:
        if direction in ('N', 'S'):
            degrees = int(raw[:2])
            minutes = float(raw[2:])
        else:
            degrees = int(raw[:3])
            minutes = float(raw[3:])
        decimal = degrees + minutes / 60.0
        if direction in ('S', 'W'):
            decimal = -decimal
        return round(decimal, 7)
    except (ValueError, IndexError):
        return None


def detect_gps_device():
    """Auto-detect USB GPS serial device.
    
    Checks common paths:
    - /dev/ttyUSB* (FTDI/PL2303/CP210x USB-serial adapters)
    - /dev/ttyACM* (CDC-ACM devices like u-blox)
    - /dev/serial/by-id/*GPS* or *gps* or *u-blox*
    """
    # Check by-id symlinks first (most reliable)
    by_id = '/dev/serial/by-id'
    if os.path.isdir(by_id):
        for entry in os.listdir(by_id):
            lower = entry.lower()
            if any(kw in lower for kw in ('gps', 'u-blox', 'ublox', 'nmea', 'gnss', 'bn-', 'vk-')):
                path = os.path.realpath(os.path.join(by_id, entry))
                if os.path.exists(path):
                    return path

    # Fall back to ttyACM/ttyUSB (prefer ACM for u-blox)
    for pattern in ('/dev/ttyACM*', '/dev/ttyUSB*'):
        devices = sorted(glob.glob(pattern))
        for dev in devices:
            # Quick probe: try reading a few bytes to see if it sends NMEA
            try:
                import serial as pyserial
                with pyserial.Serial(dev, 9600, timeout=2) as ser:
                    data = ser.read(512).decode('ascii', errors='ignore')
                    if '$GP' in data or '$GN' in data or '$GL' in data:
                        return dev
            except Exception:
                continue

    return None


class GPSManager:
    """Manages a USB GPS module, providing real-time position data."""

    def __init__(self, port=None, baudrate=9600):
        self.port = port
        self.baudrate = baudrate
        self._serial = None
        self._running = False
        self._thread = None
        self._lock = threading.Lock()

        # Current GPS state
        self.latitude = None
        self.longitude = None
        self.altitude = None
        self.speed_kmh = None
        self.course = None
        self.fix_quality = 0       # 0=no fix, 1=GPS, 2=DGPS
        self.satellites = 0
        self.hdop = None
        self.last_update = 0
        self.connected = False
        self.error = None

    def start(self):
        """Start GPS reading thread."""
        if self._running:
            return

        if not self.port:
            self.port = detect_gps_device()
        if not self.port:
            self.error = "No GPS device detected"
            logger.warning(self.error)
            return False

        try:
            import serial as pyserial
            self._serial = pyserial.Serial(self.port, self.baudrate, timeout=1)
            self._running = True
            self.connected = True
            self.error = None
            self._thread = threading.Thread(target=self._read_loop, daemon=True, name="gps-reader")
            self._thread.start()
            logger.info(f"GPS started on {self.port} @ {self.baudrate} baud")
            return True
        except ImportError:
            self.error = "pyserial not installed (pip install pyserial)"
            logger.error(self.error)
            return False
        except Exception as e:
            self.error = f"GPS init failed: {e}"
            logger.error(self.error)
            return False

    def stop(self):
        """Stop GPS reading."""
        self._running = False
        self.connected = False
        if self._serial:
            try:
                self._serial.close()
            except Exception:
                pass
            self._serial = None
        logger.info("GPS stopped")

    def has_fix(self):
        """Return True if GPS has a valid position fix (not stale)."""
        if self.fix_quality <= 0 or self.latitude is None or self.longitude is None:
            return False
        # Consider fix stale after 10 seconds without update
        if self.last_update and (time.time() - self.last_update) > 10:
            return False
        return True

    def get_position(self):
        """Return current position dict (or None if no fix)."""
        if not self.has_fix():
            return None
        with self._lock:
            return {
                'lat': self.latitude,
                'lon': self.longitude,
                'alt': self.altitude,
                'speed_kmh': self.speed_kmh,
                'course': self.course,
                'fix': self.fix_quality,
                'satellites': self.satellites,
                'hdop': self.hdop,
                'timestamp': self.last_update
            }

    def get_status(self):
        """Return full GPS status dict."""
        with self._lock:
            return {
                'connected': self.connected,
                'port': self.port,
                'has_fix': self.has_fix(),
                'fix_quality': self.fix_quality,
                'satellites': self.satellites,
                'hdop': self.hdop,
                'latitude': self.latitude,
                'longitude': self.longitude,
                'altitude': self.altitude,
                'speed_kmh': self.speed_kmh,
                'course': self.course,
                'last_update': self.last_update,
                'error': self.error
            }

    def _read_loop(self):
        """Background thread: read NMEA sentences and parse position."""
        buffer = ''
        while self._running:
            try:
                if not self._serial or not self._serial.is_open:
                    self._reconnect()
                    continue

                raw = self._serial.readline()
                if not raw:
                    continue

                line = raw.decode('ascii', errors='ignore').strip()
                if not line.startswith('$'):
                    continue

                self._parse_nmea(line)

            except Exception as e:
                if self._running:
                    logger.debug(f"GPS read error: {e}")
                    self._reconnect()

    def _reconnect(self):
        """Attempt to reconnect to GPS device."""
        try:
            if self._serial:
                self._serial.close()
        except Exception:
            pass

        with self._lock:
            self.connected = False

        time.sleep(3)

        if not self._running:
            return

        # Try to reopen — use cached port first, re-detect only every 30 s
        try:
            import serial as pyserial
            now = time.time()
            if self.port:
                port = self.port
            elif hasattr(self, '_detect_cache_time') and now - self._detect_cache_time < 30:
                port = self._detect_cache_port
            else:
                port = detect_gps_device()
                self._detect_cache_port = port
                self._detect_cache_time = now
            if port:
                self._serial = pyserial.Serial(port, self.baudrate, timeout=1)
                self.port = port
                with self._lock:
                    self.connected = True
                    self.error = None
                logger.info(f"GPS reconnected on {port}")
            else:
                with self._lock:
                    self.error = "GPS device lost"
                time.sleep(5)
        except Exception as e:
            with self._lock:
                self.error = f"GPS reconnect failed: {e}"
            time.sleep(5)

    def _parse_nmea(self, line):
        """Parse a single NMEA sentence."""
        # GGA — position + fix quality + satellites + altitude
        m = _NMEA_GGA.match(line)
        if m:
            lat = _nmea_to_decimal(m.group('lat'), m.group('lat_dir'))
            lon = _nmea_to_decimal(m.group('lon'), m.group('lon_dir'))
            with self._lock:
                if lat is not None and lon is not None:
                    self.latitude = lat
                    self.longitude = lon
                try:
                    self.fix_quality = int(m.group('fix'))
                except (ValueError, TypeError):
                    self.fix_quality = 0
                try:
                    self.satellites = int(m.group('sats'))
                except (ValueError, TypeError):
                    pass
                try:
                    self.hdop = float(m.group('hdop')) if m.group('hdop') else None
                except (ValueError, TypeError):
                    pass
                try:
                    self.altitude = float(m.group('alt')) if m.group('alt') else None
                except (ValueError, TypeError):
                    pass
                self.last_update = time.time()
            return

        # RMC — position + speed + course
        m = _NMEA_RMC.match(line)
        if m:
            if m.group('status') == 'A':  # Active (valid fix)
                lat = _nmea_to_decimal(m.group('lat'), m.group('lat_dir'))
                lon = _nmea_to_decimal(m.group('lon'), m.group('lon_dir'))
                with self._lock:
                    if lat is not None and lon is not None:
                        self.latitude = lat
                        self.longitude = lon
                    try:
                        knots = float(m.group('speed_knots')) if m.group('speed_knots') else None
                        self.speed_kmh = round(knots * 1.852, 1) if knots is not None else None
                    except (ValueError, TypeError):
                        pass
                    try:
                        self.course = float(m.group('course')) if m.group('course') else None
                    except (ValueError, TypeError):
                        pass
                    self.last_update = time.time()
            else:
                # RMC 'V' (void) — don't reset fix_quality here.
                # GGA is the authoritative source for fix quality.
                # Many GPS modules send brief RMC 'V' during movement.
                pass
