# traffic_monitor.py
# Real-time network traffic monitoring, uptime-based leveling, and device discovery

import os
import json as _json
import threading
import time
import subprocess
import re
import logging
import socket
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

        # Persistent device registry: ip → {ip, mac, hostname, first_seen, last_seen}
        self._known_devices = {}

        # Hostname resolution cache: ip → (hostname, expiry_timestamp)
        self._hostname_cache = {}

        # Per-device traffic attribution (ip → {connections, rate_in, rate_out})
        self._dev_traffic = {}

        # Monthly per-device totals (ip → {bytes_in, bytes_out}); resets each month
        self._monthly_traffic = {}
        self._monthly_month   = time.strftime('%Y-%m')

        # Daily per-device totals — resets at midnight, history kept 30 days
        self._today_str      = time.strftime('%Y-%m-%d')
        self._daily_traffic  = {}   # ip → {bytes_in, bytes_out}
        self._daily_history  = []   # [{date, traffic: {ip: {bytes_in, bytes_out}}}]

        # Persistence
        self._stats_path  = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'data', 'device_stats.json'
        )
        self._last_save   = 0.0
        self._SAVE_INTERVAL = 300.0  # save every 5 min

        # Speed test results
        self.speedtest_dl   = 0.0   # Mbps download
        self.speedtest_ul   = 0.0   # Mbps upload
        self.speedtest_ping = 0.0   # ms
        self.speedtest_at   = ""    # ISO timestamp of last test
        self.speedtest_running = False
        self._speedtest_thread = None

        # Speed test history — kept for Hall of Records (top 10 by dl / ul)
        self._speedtest_history = []   # [{dl, ul, ping, at}], max 50 entries

        # Refresh timers
        self._last_info_update = 0.0
        self._last_style_cycle = 0.0
        self._last_scan_time = 0.0
        self._INFO_INTERVAL  = 15.0        # seconds
        self._STYLE_INTERVAL = 45.0        # seconds per animation style
        self._SCAN_INTERVAL  = 30.0        # seconds between device scans
        self._SPEED_INTERVAL = 1800.0      # 30 min between speed tests

        # Do initial probe so data is available immediately
        self._probe_network_info()
        self._load_stats()

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

                # Persist traffic stats periodically
                if now - self._last_save >= self._SAVE_INTERVAL:
                    self._save_stats()
                    self._last_save = now

                # Attribute traffic to devices every 5 s
                if int(now) % 5 == 0:
                    self._attribute_device_traffic(sr, rr)

            except Exception as exc:
                logger.error(f"Traffic loop error: {exc}")

    def _scan_loop(self):
        # Brief initial delay to let network settle, then scan constantly
        self._stop.wait(5)
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

    def _resolve_hostname(self, ip):
        """Try multiple methods to resolve a hostname for an IP. Returns '' on failure."""
        now = time.time()
        cached = self._hostname_cache.get(ip)
        if cached and now < cached[1]:
            return cached[0]

        hostname = ''

        # 1. DNS PTR reverse lookup (fast, works on most networks)
        try:
            result = socket.gethostbyaddr(ip)
            h = result[0].split('.')[0]  # short name only
            if h and h != ip:
                hostname = h
        except Exception:
            pass

        # 2. avahi-resolve (mDNS/Bonjour — works for .local devices)
        if not hostname:
            try:
                r = subprocess.run(
                    ['avahi-resolve', '-a', ip],
                    capture_output=True, text=True, timeout=2
                )
                m = re.search(r'\S+\.local', r.stdout)
                if m:
                    hostname = m.group(0).replace('.local', '')
            except Exception:
                pass

        # 3. nmblookup (NetBIOS — works for Windows/Samba devices)
        if not hostname:
            try:
                r = subprocess.run(
                    ['nmblookup', '-A', ip],
                    capture_output=True, text=True, timeout=3
                )
                for line in r.stdout.splitlines():
                    m = re.match(r'\s+(\S+)\s+<00>', line)
                    if m and m.group(1) not in ('<01>', '__MSBROWSE__'):
                        hostname = m.group(1).strip()
                        break
            except Exception:
                pass

        # Cache result for 5 minutes (or 30s for empty results to retry sooner)
        ttl = 300 if hostname else 30
        self._hostname_cache[ip] = (hostname, now + ttl)
        return hostname

    def _scan_devices(self):
        with self._lock:
            iface = self.interface_name
            subnet = self.subnet

        subnets = self._discover_subnets() if not subnet else [subnet]
        # Merge manually configured subnets from settings
        cfg = getattr(self.shared_data, 'config', {}) if self.shared_data else {}
        for extra in cfg.get('manual_vlans', []):
            if extra not in subnets:
                subnets.append(extra)
        all_devices = []

        for sn in subnets:
            devices = self._scan_subnet(sn, iface)
            all_devices.extend(devices)

        # Enrich hostnames from firewall API (OPNsense / pfSense) if configured
        _fw_map: dict = {}
        cfg = getattr(self.shared_data, 'config', {}) if self.shared_data else {}
        _fw_type = cfg.get('firewall_type', '')
        _fw_url  = cfg.get('firewall_url', '')
        if _fw_type and _fw_url:
            try:
                from firewall_integration import fetch_hostnames as _fw_fetch
                _fw_map = _fw_fetch(
                    _fw_type, _fw_url,
                    cfg.get('firewall_api_key', ''),
                    cfg.get('firewall_api_secret', ''),
                    bool(cfg.get('firewall_verify_ssl', False)),
                )
            except Exception as _e:
                logger.debug(f"Firewall hostname enrichment skipped: {_e}")

        # Enrich hostnames — firewall map first, then local DNS/mDNS/NetBIOS
        for dev in all_devices:
            mac = (dev.get('mac') or '').lower().replace('-', ':').strip()
            if _fw_map and mac and not dev.get('hostname'):
                dev['hostname'] = _fw_map.get(mac, '')
            if not dev.get('hostname'):
                dev['hostname'] = self._resolve_hostname(dev['ip'])

        # Update persistent device registry
        now_str = time.strftime('%Y-%m-%dT%H:%M:%S')
        with self._lock:
            for dev in all_devices:
                ip = dev['ip']
                known = self._known_devices.get(ip, {})
                # Prefer non-empty values for each field
                mac = dev.get('mac') or known.get('mac', '')
                hostname = dev.get('hostname') or known.get('hostname', '')
                self._known_devices[ip] = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname,
                    'first_seen': known.get('first_seen', now_str),
                    'last_seen': now_str,
                }
                dev['mac'] = mac
                dev['hostname'] = hostname

            self.devices = all_devices[:100]
            self.device_count = len(all_devices)
            self.vlan_subnets = subnets
            self._last_scan_time = time.time()

        logger.info(f"Scan found {len(all_devices)} devices on {subnets}")

    def _discover_subnets(self):
        """Enumerate all active IPv4 subnets via interfaces, routes, and ARP."""
        import ipaddress
        subnets = set()

        def _add_net(cidr):
            try:
                net = str(ipaddress.IPv4Network(cidr, strict=False))
                if not (net.startswith('127.') or net.startswith('169.254.')):
                    subnets.add(net)
            except Exception:
                pass

        # Method 1: local interface addresses
        try:
            r = subprocess.run(['ip', '-o', '-4', 'addr', 'show'],
                               capture_output=True, text=True, timeout=3)
            for line in r.stdout.splitlines():
                cols = line.split()
                if len(cols) < 4 or cols[1] == 'lo':
                    continue
                for col in cols:
                    if re.match(r'\d+\.\d+\.\d+\.\d+/\d+', col):
                        try:
                            _add_net(str(ipaddress.IPv4Interface(col).network))
                        except Exception:
                            _add_net(col)
        except Exception:
            pass

        # Method 2: connected routes from routing table
        try:
            r = subprocess.run(['ip', '-o', 'route', 'show'],
                               capture_output=True, text=True, timeout=3)
            for line in r.stdout.splitlines():
                parts = line.split()
                if parts and re.match(r'\d+\.\d+\.\d+\.\d+/\d+', parts[0]):
                    _add_net(parts[0])
        except Exception:
            pass

        # Method 3: ARP table — cross-subnet entries reveal VLANs/routed nets
        try:
            r = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=3)
            for line in r.stdout.splitlines():
                parts = line.split()
                if parts and re.match(r'\d+\.\d+\.\d+\.\d+$', parts[0]):
                    _add_net(f"{parts[0]}/24")
        except Exception:
            pass

        result = sorted(subnets)
        return result or ['192.168.1.0/24']

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

    # ── Per-device traffic attribution ───────────────────────────────

    def _get_active_connections(self):
        """Return {remote_ip: connection_count} for active TCP connections."""
        counts = {}
        # Try ss first (fast, available on most Linux)
        try:
            r = subprocess.run(
                ['ss', '-tn', 'state', 'established'],
                capture_output=True, text=True, timeout=3
            )
            for line in r.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    peer = parts[4]
                    ip = re.sub(r':\d+$', '', peer)
                    ip = ip.strip('[]')  # strip IPv6 brackets
                    if ip and not ip.startswith('127.') and ip != '::1':
                        counts[ip] = counts.get(ip, 0) + 1
            return counts
        except Exception:
            pass
        # Fallback: parse /proc/net/tcp
        try:
            for fname in ('/proc/net/tcp', '/proc/net/tcp6'):
                try:
                    with open(fname) as f:
                        for line in f.readlines()[1:]:
                            cols = line.split()
                            if len(cols) < 4 or cols[3] != '01':  # 01 = ESTABLISHED
                                continue
                            remote_hex = cols[2]
                            if ':' in remote_hex:
                                ip_hex, port_hex = remote_hex.rsplit(':', 1)
                            else:
                                continue
                            try:
                                ip_int = int(ip_hex, 16)
                                ip = f"{ip_int & 0xff}.{(ip_int >> 8) & 0xff}.{(ip_int >> 16) & 0xff}.{(ip_int >> 24) & 0xff}"
                                if not ip.startswith('127.') and ip != '0.0.0.0':
                                    counts[ip] = counts.get(ip, 0) + 1
                            except Exception:
                                pass
                except FileNotFoundError:
                    pass
        except Exception:
            pass
        return counts

    def _attribute_device_traffic(self, recv_rate, sent_rate):
        """Distribute current interface rates across known devices by connection count."""
        conn_counts = self._get_active_connections()
        with self._lock:
            known_ips = {d['ip'] for d in self.devices}

        # Merge: known devices get at least 0 connections
        all_ips = known_ips | set(conn_counts.keys())
        if not all_ips:
            return

        total_conns = sum(conn_counts.get(ip, 0) for ip in all_ips) or 1
        uniform_share = 1.0 / len(all_ips)

        updated = {}
        for ip in all_ips:
            conns = conn_counts.get(ip, 0)
            # Weight: 70% by connection share, 30% uniform — so idle devices get a tiny slice
            weight = 0.7 * (conns / total_conns) + 0.3 * uniform_share
            prev = self._dev_traffic.get(ip, {})
            # Smooth with simple EMA (α=0.3)
            alpha = 0.3
            prev_in  = prev.get('rate_in', 0.0)
            prev_out = prev.get('rate_out', 0.0)
            updated[ip] = {
                'connections': conns,
                'rate_in':  alpha * recv_rate * weight + (1 - alpha) * prev_in,
                'rate_out': alpha * sent_rate * weight + (1 - alpha) * prev_out,
            }
        self._dev_traffic = updated

        # Accumulate monthly totals; reset at month boundary
        cur_month = time.strftime('%Y-%m')
        if cur_month != self._monthly_month:
            self._monthly_traffic = {}
            self._monthly_month = cur_month
        for ip, t in updated.items():
            entry = self._monthly_traffic.setdefault(ip, {'bytes_in': 0, 'bytes_out': 0})
            entry['bytes_in']  += t.get('rate_in',  0.0)
            entry['bytes_out'] += t.get('rate_out', 0.0)

        # Accumulate daily totals; archive and reset at day boundary
        cur_day = time.strftime('%Y-%m-%d')
        if cur_day != self._today_str:
            self._daily_history.append({
                'date':    self._today_str,
                'traffic': dict(self._daily_traffic),
            })
            self._daily_history = self._daily_history[-30:]
            self._daily_traffic = {}
            self._today_str = cur_day
            self._save_stats()
        for ip, t in updated.items():
            entry = self._daily_traffic.setdefault(ip, {'bytes_in': 0, 'bytes_out': 0})
            entry['bytes_in']  += t.get('rate_in',  0.0)
            entry['bytes_out'] += t.get('rate_out', 0.0)

    # ── Speed test ────────────────────────────────────────────────────

    def _speedtest_loop(self):
        # Wait 90 s at startup so the network is settled before first test
        self._stop.wait(90)
        while not self._stop.is_set():
            cfg = getattr(self.shared_data, 'config', {}) if self.shared_data else {}
            if cfg.get('speedtest_enabled', True) is not False:
                try:
                    self._run_speedtest()
                except Exception as exc:
                    logger.error(f"Speed test error: {exc}")
            interval = float(cfg.get('speedtest_interval_min', 30) or 30) * 60
            interval = max(300.0, interval)  # floor at 5 min
            self._stop.wait(interval)

    def _run_speedtest(self):
        """Run a speed test. Tries speedtest module, CLI, then urllib fallback."""
        dl = ul = ping = 0.0

        # Method 1: Python speedtest module
        try:
            import speedtest as _st
            s = _st.Speedtest(secure=True)
            s.get_best_server()
            dl   = s.download() / 1_000_000
            ul   = s.upload()   / 1_000_000
            ping = s.results.ping
        except ImportError:
            # Method 2: speedtest-cli / python3 -m speedtest subprocess
            for cmd in (['speedtest-cli', '--simple', '--secure'],
                        ['python3', '-m', 'speedtest', '--simple', '--secure']):
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
                    for line in r.stdout.splitlines():
                        line = line.strip()
                        if line.startswith('Download:'):
                            m = re.search(r'([\d.]+)', line)
                            if m: dl = float(m.group(1))
                        elif line.startswith('Upload:'):
                            m = re.search(r'([\d.]+)', line)
                            if m: ul = float(m.group(1))
                        elif line.startswith('Ping:'):
                            m = re.search(r'([\d.]+)', line)
                            if m: ping = float(m.group(1))
                    if dl > 0 or ul > 0:
                        break
                except FileNotFoundError:
                    continue
                except Exception:
                    continue

            # Method 3: urllib download timing — no external deps needed
            if not (dl > 0 or ul > 0):
                import urllib.request, ssl as _ssl
                _ctx = _ssl.create_default_context()
                _ctx.check_hostname = False
                _ctx.verify_mode    = _ssl.CERT_NONE
                # Try plain HTTP first (no SSL issues), then HTTPS fallback
                _test_urls = [
                    'http://proof.ovh.net/files/10Mb.dat',
                    'http://speedtest.tele2.net/10MB.zip',
                    'https://speed.cloudflare.com/__down?bytes=10000000',
                ]
                for _url in _test_urls:
                    try:
                        _req = urllib.request.Request(
                            _url, headers={'User-Agent': 'mild-viking-speedtest/1.0'})
                        _kw  = {'context': _ctx} if _url.startswith('https') else {}
                        t0   = time.monotonic()
                        _rcv = 0
                        with urllib.request.urlopen(_req, timeout=40, **_kw) as _resp:
                            while True:
                                _chunk = _resp.read(65536)
                                if not _chunk:
                                    break
                                _rcv += len(_chunk)
                        _el = time.monotonic() - t0
                        if _el > 0 and _rcv > 100_000:   # at least 100 KB received
                            dl = (_rcv * 8) / _el / 1_000_000
                            logger.info(f"Speed test (urllib {_url}): ↓{dl:.1f} Mbps")
                            break
                    except Exception as _exc:
                        logger.debug(f"urllib speedtest {_url}: {_exc}")
                        continue
        except Exception as exc:
            logger.warning(f"Speed test failed: {exc}")

        if dl > 0 or ul > 0:
            ts = time.strftime('%Y-%m-%dT%H:%M:%S')
            with self._lock:
                self.speedtest_dl   = dl
                self.speedtest_ul   = ul
                self.speedtest_ping = ping
                self.speedtest_at   = time.strftime('%H:%M')
                self._speedtest_history.append({'dl': round(dl, 1), 'ul': round(ul, 1),
                                                'ping': round(ping, 1), 'at': ts})
                self._speedtest_history = self._speedtest_history[-50:]
            self._save_stats()
            logger.info(f"Speed test: ↓{dl:.1f} ↑{ul:.1f} Mbps  ping {ping:.0f}ms")
        else:
            logger.warning("Speed test returned zero results")

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
                'devices': self._enrich_devices(self.devices[:50]),
                'speedtest_dl': self.speedtest_dl,
                'speedtest_ul': self.speedtest_ul,
                'speedtest_ping': self.speedtest_ping,
                'speedtest_at': self.speedtest_at,
                'speedtest_running': self.speedtest_running,
            }

    def _enrich_devices(self, devices):
        """Attach per-device traffic data to the device list."""
        result = []
        for d in devices:
            ip = d.get('ip', '')
            t = self._dev_traffic.get(ip, {})
            result.append({**d,
                'connections': t.get('connections', 0),
                'rate_in':  round(t.get('rate_in', 0.0), 1),
                'rate_out': round(t.get('rate_out', 0.0), 1),
                'rate_in_human':  _fmt_bps(t.get('rate_in', 0.0)),
                'rate_out_human': _fmt_bps(t.get('rate_out', 0.0)),
            })
        return result

    def trigger_scan(self):
        """Force an immediate device scan in a background thread."""
        threading.Thread(target=self._scan_devices, daemon=True, name="scan-on-demand").start()

    def trigger_speedtest(self):
        """Run a speed test immediately in a background thread. No-op if one is running."""
        if self.speedtest_running:
            return
        def _run():
            self.speedtest_running = True
            try:
                self._run_speedtest()
            finally:
                self.speedtest_running = False
        threading.Thread(target=_run, daemon=True, name="speedtest-on-demand").start()

    def get_known_devices(self):
        """Return the full persistent device registry."""
        with self._lock:
            return list(self._known_devices.values())

    def get_monthly_report(self):
        """Return per-device traffic totals for the current month, merged with device registry."""
        with self._lock:
            known = dict(self._known_devices)
            monthly = dict(self._monthly_traffic)
        result = []
        all_ips = set(known) | set(monthly)
        for ip in all_ips:
            d = dict(known.get(ip, {'ip': ip, 'mac': '', 'hostname': ''}))
            m = monthly.get(ip, {})
            d['bytes_in']  = int(m.get('bytes_in',  0))
            d['bytes_out'] = int(m.get('bytes_out', 0))
            result.append(d)
        return result

    # ── Stats persistence ─────────────────────────────────────────────

    def _load_stats(self):
        try:
            if not os.path.exists(self._stats_path):
                return
            with open(self._stats_path, 'r') as f:
                data = _json.load(f)
            self._daily_history     = data.get('daily_history', [])
            self._speedtest_history = data.get('speedtest_history', [])
            if data.get('today_date') == self._today_str:
                self._daily_traffic = data.get('today_traffic', {})
            logger.info(f"Loaded device stats ({len(self._daily_history)} days, "
                        f"{len(self._speedtest_history)} speed tests)")
        except Exception as e:
            logger.warning(f"Stats load error: {e}")

    def _save_stats(self):
        try:
            os.makedirs(os.path.dirname(self._stats_path), exist_ok=True)
            with self._lock:
                data = {
                    'today_date':        self._today_str,
                    'today_traffic':     dict(self._daily_traffic),
                    'daily_history':     list(self._daily_history),
                    'speedtest_history': list(self._speedtest_history),
                }
            with open(self._stats_path, 'w') as f:
                _json.dump(data, f)
        except Exception as e:
            logger.warning(f"Stats save error: {e}")

    # ── Hall of Records ───────────────────────────────────────────────

    def get_hall_of_records(self):
        """Return 4-category Hall of Records: uptime, today, 7d, 30d data leaders."""
        now = time.time()

        with self._lock:
            known         = dict(self._known_devices)
            today_traffic = dict(self._daily_traffic)
            history       = list(self._daily_history)
            current_ips   = {d['ip'] for d in self.devices}

        def _label(ip):
            d = known.get(ip, {})
            return d.get('hostname') or d.get('mac') or ip

        def _fmt_bytes(b):
            b = int(b)
            if b >= 1_000_000_000: return f"{b/1_000_000_000:.1f} GB"
            if b >= 1_000_000:     return f"{b/1_000_000:.1f} MB"
            if b >= 1_000:         return f"{b/1_000:.1f} KB"
            return f"{b} B"

        def _fmt_dur(s):
            s = int(s)
            d = s // 86400
            h = (s % 86400) // 3600
            m = (s % 3600) // 60
            if d: return f"{d}d {h}h"
            if h: return f"{h}h {m:02d}m"
            return f"{m}m"

        categories = []

        # ── Longest time up (device currently on network, earliest first_seen) ──
        uptime_winner, uptime_secs = None, 0.0
        for ip, dev in known.items():
            if ip not in current_ips:
                continue
            try:
                fs = time.mktime(time.strptime(dev.get('first_seen', ''), '%Y-%m-%dT%H:%M:%S'))
                secs = now - fs
            except Exception:
                continue
            if secs > uptime_secs:
                uptime_secs, uptime_winner = secs, ip
        if uptime_winner:
            categories.append({
                'category': 'longest_up',
                'title':    'LONGEST TIME UP',
                'icon':     '⏱',
                'device':   _label(uptime_winner),
                'ip':       uptime_winner,
                'value':    _fmt_dur(uptime_secs),
                'raw':      int(uptime_secs),
            })

        # ── Most data today ──────────────────────────────────────────
        if today_traffic:
            top = max(today_traffic, key=lambda ip:
                today_traffic[ip].get('bytes_in', 0) + today_traffic[ip].get('bytes_out', 0))
            total = today_traffic[top].get('bytes_in', 0) + today_traffic[top].get('bytes_out', 0)
            if total > 0:
                categories.append({
                    'category': 'today',
                    'title':    'MOST DATA TODAY',
                    'icon':     '📅',
                    'device':   _label(top),
                    'ip':       top,
                    'value':    _fmt_bytes(total),
                    'raw':      int(total),
                })

        # ── Most data — last 7 days ──────────────────────────────────
        cutoff_7 = time.strftime('%Y-%m-%d', time.localtime(now - 7 * 86400))
        agg_7: dict = {}
        for day in history:
            if day.get('date', '') >= cutoff_7:
                for ip, t in day.get('traffic', {}).items():
                    agg_7[ip] = agg_7.get(ip, 0) + t.get('bytes_in', 0) + t.get('bytes_out', 0)
        for ip, t in today_traffic.items():
            agg_7[ip] = agg_7.get(ip, 0) + t.get('bytes_in', 0) + t.get('bytes_out', 0)
        if agg_7:
            top7 = max(agg_7, key=lambda ip: agg_7[ip])
            if agg_7[top7] > 0:
                categories.append({
                    'category': 'week',
                    'title':    'MOST DATA — 7 DAYS',
                    'icon':     '📊',
                    'device':   _label(top7),
                    'ip':       top7,
                    'value':    _fmt_bytes(agg_7[top7]),
                    'raw':      int(agg_7[top7]),
                })

        # ── Most data — last 30 days ─────────────────────────────────
        cutoff_30 = time.strftime('%Y-%m-%d', time.localtime(now - 30 * 86400))
        agg_30: dict = {}
        for day in history:
            if day.get('date', '') >= cutoff_30:
                for ip, t in day.get('traffic', {}).items():
                    agg_30[ip] = agg_30.get(ip, 0) + t.get('bytes_in', 0) + t.get('bytes_out', 0)
        for ip, t in today_traffic.items():
            agg_30[ip] = agg_30.get(ip, 0) + t.get('bytes_in', 0) + t.get('bytes_out', 0)
        if agg_30:
            top30 = max(agg_30, key=lambda ip: agg_30[ip])
            if agg_30[top30] > 0:
                categories.append({
                    'category': 'month',
                    'title':    'MOST DATA — 30 DAYS',
                    'icon':     '📈',
                    'device':   _label(top30),
                    'ip':       top30,
                    'value':    _fmt_bytes(agg_30[top30]),
                    'raw':      int(agg_30[top30]),
                })

        # ── Speed test leaderboards ──────────────────────────────────
        with self._lock:
            st_history = list(self._speedtest_history)

        def _fmt_ts(iso):
            try:
                t = time.strptime(iso, '%Y-%m-%dT%H:%M:%S')
                return time.strftime('%b %d  %H:%M', t)
            except Exception:
                return iso

        top_dl = sorted(st_history, key=lambda r: r.get('dl', 0), reverse=True)[:10]
        top_ul = sorted(st_history, key=lambda r: r.get('ul', 0), reverse=True)[:10]

        speed_rows_dl = [
            {'dl': r['dl'], 'ul': r['ul'], 'ping': r['ping'], 'at': _fmt_ts(r['at'])}
            for r in top_dl
        ]
        speed_rows_ul = [
            {'dl': r['dl'], 'ul': r['ul'], 'ping': r['ping'], 'at': _fmt_ts(r['at'])}
            for r in top_ul
        ]

        return {
            'categories':  categories,
            'top_dl':      speed_rows_dl,
            'top_ul':      speed_rows_ul,
        }
