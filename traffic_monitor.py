# traffic_monitor.py
# Real-time network traffic monitoring, uptime-based leveling, and device discovery

import threading
import time
import subprocess
import re
import logging
from collections import deque

logger = logging.getLogger("traffic_monitor")


def _fmt_bps(bps):
    if bps >= 1_000_000_000:
        return f"{bps/1_000_000_000:.1f} GB/s"
    if bps >= 1_000_000:
        return f"{bps/1_000_000:.1f} MB/s"
    if bps >= 1_000:
        return f"{bps/1_000:.1f} KB/s"
    return f"{int(bps)} B/s"


def _fmt_uptime(seconds):
    s = int(seconds)
    h = s // 3600
    m = (s % 3600) // 60
    sec = s % 60
    if h:
        return f"{h}h {m:02d}m"
    if m:
        return f"{m}m {sec:02d}s"
    return f"{sec}s"


class TrafficMonitor:
    """
    Monitors network traffic, uptime-based levels, and local device discovery.

    Animation modes based on total traffic rate:
      idle   < THRESH_ACTIVE  (default 100 KB/s)
      active < THRESH_ATTACK  (default 5 MB/s)
      attack >= THRESH_ATTACK
    """

    THRESH_ACTIVE = 100_000      # 100 KB/s
    THRESH_ATTACK = 5_000_000    # 5 MB/s

    def __init__(self, shared_data=None):
        self.shared_data = shared_data
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._traffic_thread = None
        self._scan_thread = None

        # Traffic counters
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.sent_rate = 0.0
        self.recv_rate = 0.0
        self.total_rate = 0.0
        self._prev_sent = 0
        self._prev_recv = 0
        self._prev_time = 0.0

        # Rate history (last 60 samples) for sparklines
        self.sent_history = deque(maxlen=60)
        self.recv_history = deque(maxlen=60)

        # Animation state
        self.animation_mode = "idle"      # idle | active | attack
        self.animation_style = 0          # 0-3, cycles every 45s
        self.animation_intensity = 0.0    # 0.0-1.0

        # Leveling (1 level per hour of uptime)
        self.start_time = time.time()
        self.uptime_seconds = 0.0
        self.level = 1
        self.level_progress = 0.0         # 0.0-1.0 fraction into current level hour

        # Network identity
        self.current_ip = ""
        self.current_ssid = ""
        self.gateway_ip = ""
        self.interface_name = ""
        self.connection_type = "unknown"  # ethernet | wifi | ap | none

        # Discovered devices
        self.devices = []
        self.device_count = 0
        self.subnet = ""
        self.vlan_subnets = []

        # Speed test results
        self.speedtest_dl   = 0.0   # Mbps download
        self.speedtest_ul   = 0.0   # Mbps upload
        self.speedtest_ping = 0.0   # ms
        self.speedtest_at   = ""    # ISO timestamp of last test
        self._speedtest_thread = None

        # Refresh timers
        self._last_info_update = 0.0
        self._last_style_cycle = 0.0
        self._last_scan_time = 0.0
        self._INFO_INTERVAL  = 15.0        # seconds
        self._STYLE_INTERVAL = 45.0        # seconds per animation style
        self._SCAN_INTERVAL  = 120.0       # seconds between device scans
        self._SPEED_INTERVAL = 1800.0      # 30 min between speed tests

        # Do initial probe so data is available immediately
        self._probe_network_info()

    # ── Lifecycle ─────────────────────────────────────────────────────

    def start(self):
        self._stop.clear()
        self._prev_sent, self._prev_recv = self._read_counters()
        self._prev_time = time.time()

        self._traffic_thread = threading.Thread(
            target=self._traffic_loop, daemon=True, name="traffic-monitor"
        )
        self._traffic_thread.start()

        self._scan_thread = threading.Thread(
            target=self._scan_loop, daemon=True, name="device-scanner"
        )
        self._scan_thread.start()

        self._speedtest_thread = threading.Thread(
            target=self._speedtest_loop, daemon=True, name="speedtest"
        )
        self._speedtest_thread.start()

        logger.info("Traffic monitor started")

    def stop(self):
        self._stop.set()
        for t in (self._traffic_thread, self._scan_thread, self._speedtest_thread):
            if t and t.is_alive():
                t.join(timeout=5)
        logger.info("Traffic monitor stopped")

    # ── Main monitoring loop ──────────────────────────────────────────

    def _traffic_loop(self):
        while not self._stop.wait(1.0):
            try:
                now = time.time()
                sent, recv = self._read_counters()
                elapsed = now - self._prev_time

                if elapsed > 0:
                    sr = max(0.0, (sent - self._prev_sent) / elapsed)
                    rr = max(0.0, (recv - self._prev_recv) / elapsed)
                else:
                    sr = rr = 0.0

                self._prev_sent, self._prev_recv, self._prev_time = sent, recv, now

                mode, intensity = self._calc_mode(sr + rr)

                with self._lock:
                    self.bytes_sent = sent
                    self.bytes_recv = recv
                    self.sent_rate = sr
                    self.recv_rate = rr
                    self.total_rate = sr + rr
                    self.sent_history.append(sr)
                    self.recv_history.append(rr)
                    self.animation_mode = mode
                    self.animation_intensity = intensity
                    self.uptime_seconds = now - self.start_time
                    hours = self.uptime_seconds / 3600.0
                    self.level = max(1, int(hours) + 1)
                    self.level_progress = hours - int(hours)

                # Cycle animation style
                if now - self._last_style_cycle >= self._STYLE_INTERVAL:
                    with self._lock:
                        self.animation_style = (self.animation_style + 1) % 4
                    self._last_style_cycle = now

                # Refresh network info
                if now - self._last_info_update >= self._INFO_INTERVAL:
                    self._probe_network_info()
                    self._last_info_update = now

            except Exception as exc:
                logger.error(f"Traffic loop error: {exc}")

    def _scan_loop(self):
        # Initial scan after a short delay to let the network settle
        self._stop.wait(12)
        while not self._stop.is_set():
            try:
                self._scan_devices()
            except Exception as exc:
                logger.error(f"Device scan error: {exc}")
            self._stop.wait(self._SCAN_INTERVAL)

    # ── Traffic counters ──────────────────────────────────────────────

    def _read_counters(self):
        try:
            import psutil
            c = psutil.net_io_counters()
            return c.bytes_sent, c.bytes_recv
        except ImportError:
            pass
        # Fallback: /proc/net/dev
        try:
            sent = recv = 0
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    cols = line.split()
                    if len(cols) < 10 or ':' not in cols[0]:
                        continue
                    iface = cols[0].rstrip(':')
                    if iface in ('lo',) or iface.startswith(('docker', 'veth', 'br-')):
                        continue
                    recv += int(cols[1])
                    sent += int(cols[9])
            return sent, recv
        except Exception:
            return 0, 0

    # ── Animation mode ─────────────────────────────────────────────────

    def _calc_mode(self, total_bps):
        if total_bps >= self.THRESH_ATTACK:
            intensity = min(1.0, total_bps / (self.THRESH_ATTACK * 2))
            return "attack", intensity
        if total_bps >= self.THRESH_ACTIVE:
            span = self.THRESH_ATTACK - self.THRESH_ACTIVE
            intensity = (total_bps - self.THRESH_ACTIVE) / span
            return "active", min(1.0, intensity)
        intensity = total_bps / self.THRESH_ACTIVE
        return "idle", min(1.0, intensity)

    # ── Network identity probe ────────────────────────────────────────

    def _probe_network_info(self):
        ip = self._get_ip()
        ssid, iface, is_eth, conn_type = self._get_connection()
        gw = self._get_gateway()
        subnet = self._get_subnet(iface)

        with self._lock:
            if ip:
                self.current_ip = ip
            if iface:
                self.interface_name = iface
            if gw:
                self.gateway_ip = gw
            if subnet:
                self.subnet = subnet
            # Always update SSID (might become empty if disconnected)
            self.current_ssid = ssid
            self.connection_type = conn_type

        if self.shared_data:
            try:
                if ip:
                    self.shared_data.current_ip = ip
                if ssid:
                    self.shared_data.current_ssid = ssid
            except Exception:
                pass

    def _get_ip(self):
        try:
            r = subprocess.run(
                ['hostname', '-I'], capture_output=True, text=True, timeout=3
            )
            for ip in r.stdout.strip().split():
                if not ip.startswith(('127.', '169.254.')):
                    return ip
        except Exception:
            pass
        try:
            r = subprocess.run(
                ['ip', 'route', 'get', '1.1.1.1'],
                capture_output=True, text=True, timeout=3
            )
            m = re.search(r'src (\S+)', r.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
        return ""

    def _get_connection(self):
        """Returns (ssid, iface, is_ethernet, conn_type)."""
        # Ethernet first
        try:
            r = subprocess.run(
                ['ip', '-o', '-4', 'addr', 'show'],
                capture_output=True, text=True, timeout=3
            )
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                iface = parts[1]
                if iface == 'lo':
                    continue
                if re.match(r'^(eth|en)', iface):
                    # Has an IPv4 address → ethernet connected
                    return "", iface, True, "ethernet"
        except Exception:
            pass

        # WiFi via nmcli
        try:
            r = subprocess.run(
                ['nmcli', '-t', '-f', 'active,ssid,device', 'dev', 'wifi'],
                capture_output=True, text=True, timeout=3
            )
            for line in r.stdout.splitlines():
                parts = line.split(':')
                if len(parts) >= 3 and parts[0] == 'yes':
                    return parts[1], parts[2], False, "wifi"
        except Exception:
            pass

        # iwgetid fallback
        try:
            r = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True, timeout=2)
            ssid = r.stdout.strip()
            r2 = subprocess.run(['iwgetid'], capture_output=True, text=True, timeout=2)
            m = re.match(r'(\S+)\s+', r2.stdout)
            iface = m.group(1) if m else 'wlan0'
            if ssid:
                return ssid, iface, False, "wifi"
        except Exception:
            pass

        # Check if we're in AP mode
        try:
            r = subprocess.run(
                ['hostapd_cli', 'status'], capture_output=True, text=True, timeout=2
            )
            if 'state=ENABLED' in r.stdout:
                return "", "wlan0", False, "ap"
        except Exception:
            pass

        return "", "wlan0", False, "none"

    def _get_gateway(self):
        try:
            r = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=3
            )
            m = re.search(r'default via (\S+)', r.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
        return ""

    def _get_subnet(self, iface):
        if not iface:
            return ""
        try:
            r = subprocess.run(
                ['ip', '-o', '-4', 'addr', 'show', iface],
                capture_output=True, text=True, timeout=3
            )
            m = re.search(r'inet (\S+)', r.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
        return ""

    # ── Device discovery ──────────────────────────────────────────────

    def _scan_devices(self):
        with self._lock:
            iface = self.interface_name
            subnet = self.subnet

        subnets = self._discover_subnets() if not subnet else [subnet]
        all_devices = []

        for sn in subnets:
            devices = self._scan_subnet(sn, iface)
            all_devices.extend(devices)

        with self._lock:
            self.devices = all_devices[:100]
            self.device_count = len(all_devices)
            self.vlan_subnets = subnets
            self._last_scan_time = time.time()

        logger.info(f"Scan found {len(all_devices)} devices on {subnets}")

    def _discover_subnets(self):
        """Enumerate all active IPv4 subnets."""
        subnets = []
        try:
            r = subprocess.run(
                ['ip', '-o', '-4', 'addr', 'show'],
                capture_output=True, text=True, timeout=3
            )
            for line in r.stdout.splitlines():
                cols = line.split()
                if len(cols) < 4 or cols[1] == 'lo':
                    continue
                for col in cols:
                    if re.match(r'\d+\.\d+\.\d+\.\d+/\d+', col):
                        subnets.append(col)
        except Exception:
            pass
        return subnets or ['192.168.1.0/24']

    def _scan_subnet(self, subnet, iface=""):
        # 1. arp-scan (fastest, needs root or setuid)
        try:
            cmd = ['arp-scan', '--localnet', '--quiet']
            if iface:
                cmd.extend(['--interface', iface])
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                devices = []
                for line in r.stdout.splitlines():
                    m = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)', line)
                    if m:
                        devices.append({
                            'ip': m.group(1),
                            'mac': m.group(2).upper(),
                            'hostname': m.group(3).strip()
                        })
                if devices:
                    return devices
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"arp-scan failed: {e}")

        # 2. Read ARP cache (no privileges needed)
        try:
            r = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=5)
            devices = []
            for line in r.stdout.splitlines()[1:]:
                cols = line.split()
                if len(cols) >= 3 and cols[2] != '<incomplete>' and cols[2] != '<incplt>':
                    devices.append({'ip': cols[0], 'mac': cols[2].upper(), 'hostname': ''})
            if devices:
                return devices
        except Exception:
            pass

        # 3. nmap ping scan (slower fallback)
        try:
            r = subprocess.run(
                ['nmap', '-sn', '-T4', '--host-timeout', '2s', subnet],
                capture_output=True, text=True, timeout=90
            )
            devices = []
            current_host = {}
            for line in r.stdout.splitlines():
                m = re.search(r'Nmap scan report for (.+)', line)
                if m:
                    host_str = m.group(1).strip()
                    ip_m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', host_str)
                    if ip_m:
                        hostname = re.sub(r'\s*\(.*\)', '', host_str).strip()
                        current_host = {'ip': ip_m.group(1), 'hostname': hostname, 'mac': ''}
                    else:
                        current_host = {'ip': host_str, 'hostname': '', 'mac': ''}
                mac_m = re.search(r'MAC Address: ([0-9A-F:]+)', line)
                if mac_m and current_host:
                    current_host['mac'] = mac_m.group(1)
                if current_host and ('ip' in current_host):
                    devices.append(current_host)
                    current_host = {}
            return devices
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"nmap scan failed: {e}")

        return []

    # ── Speed test ────────────────────────────────────────────────────

    def _speedtest_loop(self):
        # Wait 90 s at startup so the network is settled before first test
        self._stop.wait(90)
        while not self._stop.is_set():
            try:
                self._run_speedtest()
            except Exception as exc:
                logger.error(f"Speed test error: {exc}")
            self._stop.wait(self._SPEED_INTERVAL)

    def _run_speedtest(self):
        """Run speedtest-cli and store results. Non-fatal on any failure."""
        try:
            r = subprocess.run(
                ['speedtest-cli', '--simple', '--secure'],
                capture_output=True, text=True, timeout=90
            )
            dl = ul = ping = 0.0
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith('Download:'):
                    m = re.search(r'([\d.]+)', line)
                    if m:
                        dl = float(m.group(1))
                elif line.startswith('Upload:'):
                    m = re.search(r'([\d.]+)', line)
                    if m:
                        ul = float(m.group(1))
                elif line.startswith('Ping:'):
                    m = re.search(r'([\d.]+)', line)
                    if m:
                        ping = float(m.group(1))
            if dl > 0 or ul > 0:
                with self._lock:
                    self.speedtest_dl   = dl
                    self.speedtest_ul   = ul
                    self.speedtest_ping = ping
                    self.speedtest_at   = time.strftime('%H:%M')
                logger.info(f"Speed test: ↓{dl:.1f} ↑{ul:.1f} Mbps  ping {ping:.0f}ms")
            else:
                logger.warning(f"Speed test returned no results: {r.stdout!r} {r.stderr!r}")
        except FileNotFoundError:
            logger.warning("speedtest-cli not found — skipping speed test")
        except Exception as exc:
            logger.warning(f"Speed test failed: {exc}")

    # ── Public API ────────────────────────────────────────────────────

    def get_status(self):
        with self._lock:
            return {
                'sent_rate': round(self.sent_rate, 1),
                'recv_rate': round(self.recv_rate, 1),
                'total_rate': round(self.total_rate, 1),
                'sent_rate_human': _fmt_bps(self.sent_rate),
                'recv_rate_human': _fmt_bps(self.recv_rate),
                'bytes_sent': self.bytes_sent,
                'bytes_recv': self.bytes_recv,
                'sent_history': list(self.sent_history),
                'recv_history': list(self.recv_history),
                'animation_mode': self.animation_mode,
                'animation_style': self.animation_style,
                'animation_intensity': round(self.animation_intensity, 4),
                'level': self.level,
                'level_progress': round(self.level_progress, 4),
                'uptime_seconds': round(self.uptime_seconds, 1),
                'uptime_human': _fmt_uptime(self.uptime_seconds),
                'current_ip': self.current_ip,
                'current_ssid': self.current_ssid,
                'gateway_ip': self.gateway_ip,
                'interface': self.interface_name,
                'connection_type': self.connection_type,
                'device_count': self.device_count,
                'subnet': self.subnet,
                'vlan_subnets': list(self.vlan_subnets),
                'devices': self.devices[:50],
                'speedtest_dl': self.speedtest_dl,
                'speedtest_ul': self.speedtest_ul,
                'speedtest_ping': self.speedtest_ping,
                'speedtest_at': self.speedtest_at,
            }

    def trigger_scan(self):
        """Force an immediate device scan in a background thread."""
        threading.Thread(target=self._scan_devices, daemon=True, name="scan-on-demand").start()
