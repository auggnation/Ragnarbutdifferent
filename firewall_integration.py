# firewall_integration.py
# Mild-Viking: OPNsense / pfSense hostname enrichment
#
# OPNsense API reference: https://docs.opnsense.org/development/api.html
#   Auth:  HTTP Basic — key as username, secret as password
#   Base:  https://<ip>/api/<module>/<controller>/<command>
#
# pfSense API reference: https://github.com/jaredhendrickson13/pfsense-api
#   Auth:  Bearer token in Authorization header (or basic auth depending on version)
#   Base:  https://<ip>/api/v1/<endpoint>

import logging
import requests
from urllib3.exceptions import InsecureRequestWarning
import urllib3

urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger("firewall_integration")


# ── Helpers ───────────────────────────────────────────────────────────

def _make_base_url(url: str) -> str:
    """Normalize the firewall URL — strip trailing slash, ensure https."""
    url = url.strip().rstrip('/')
    if not url.startswith('http'):
        url = 'https://' + url
    return url


def _session(verify_ssl: bool) -> requests.Session:
    s = requests.Session()
    s.verify = verify_ssl
    return s


# ── OPNsense ──────────────────────────────────────────────────────────
#
# Endpoints (all under /api/):
#   GET  /api/core/firmware/info                 — version / connectivity test
#   GET  /api/dhcpv4/leases/search_lease         — DHCP lease list
#   GET  /api/diagnostics/interface/get_arp      — ARP table
#   GET  /api/diagnostics/interface/search_arp   — searchable ARP table
#   GET  /api/diagnostics/dns/reverse_lookup     — reverse DNS lookup

def _opnsense_get(s: requests.Session, base: str, path: str, auth: tuple, **kwargs):
    url = f"{base}/api/{path.lstrip('/')}"
    r = s.get(url, auth=auth, timeout=8, **kwargs)
    r.raise_for_status()
    return r.json()


def _opnsense_post(s: requests.Session, base: str, path: str, auth: tuple, body=None):
    url = f"{base}/api/{path.lstrip('/')}"
    r = s.post(url, auth=auth, json=body or {}, timeout=8)
    r.raise_for_status()
    return r.json()


def _opnsense_hostnames(base_url: str, key: str, secret: str, verify_ssl: bool) -> dict:
    """Return {mac: hostname} from OPNsense DHCP leases + ARP table."""
    base = _make_base_url(base_url)
    s    = _session(verify_ssl)
    auth = (key, secret)
    mac_host: dict[str, str] = {}

    # 1. DHCP leases — most reliable source of hostname
    try:
        data = _opnsense_get(s, base, 'dhcpv4/leases/search_lease', auth)
        for row in data.get('rows', []):
            mac  = (row.get('mac')      or '').lower().replace('-', ':').strip()
            host = (row.get('hostname') or '').strip()
            if mac and host:
                mac_host[mac] = host
        logger.debug(f"OPNsense DHCP leases: {len(mac_host)} hostnames")
    except Exception as e:
        logger.warning(f"OPNsense DHCP lease fetch failed: {e}")

    # 2. ARP table — fills in devices not in DHCP (static IPs, etc.)
    try:
        data = _opnsense_get(s, base, 'diagnostics/interface/get_arp', auth)
        for row in data.get('rows', []):
            mac  = (row.get('mac')      or '').lower().replace('-', ':').strip()
            host = (row.get('hostname') or '').strip()
            if mac and host and mac not in mac_host:
                mac_host[mac] = host
        logger.debug(f"OPNsense ARP enriched to: {len(mac_host)} total hostnames")
    except Exception as e:
        logger.warning(f"OPNsense ARP fetch failed: {e}")

    return mac_host


def _opnsense_test(base_url: str, key: str, secret: str, verify_ssl: bool):
    base = _make_base_url(base_url)
    s    = _session(verify_ssl)
    auth = (key, secret)
    data = _opnsense_get(s, base, 'core/firmware/info', auth)
    ver  = data.get('product_version') or data.get('firmware_version') or '?'
    return True, f"OPNsense {ver} — connected to {base}"


# ── pfSense ───────────────────────────────────────────────────────────
#
# Requires pfSense-API package: https://github.com/jaredhendrickson13/pfsense-api
# Endpoints:
#   GET  /api/v1/system/version              — version / connectivity test
#   GET  /api/v1/services/dhcpd/lease        — DHCP lease list
#   GET  /api/v1/diagnostics/arp             — ARP table
#
# Auth: Bearer token (API key) in Authorization header.
# In pfSense-API v2+, basic auth with client-id/client-token is also supported.

def _pfsense_get(s: requests.Session, base: str, path: str, key: str, secret: str):
    url  = f"{base}/{path.lstrip('/')}"
    # Support both v1 (Bearer) and v2 (Basic) auth
    if secret:
        r = s.get(url, auth=(key, secret), timeout=8)
    else:
        r = s.get(url, headers={'Authorization': f'Bearer {key}'}, timeout=8)
    r.raise_for_status()
    return r.json()


def _pfsense_hostnames(base_url: str, key: str, secret: str, verify_ssl: bool) -> dict:
    """Return {mac: hostname} from pfSense DHCP leases + ARP table."""
    base = _make_base_url(base_url)
    s    = _session(verify_ssl)
    mac_host: dict[str, str] = {}

    # 1. DHCP leases
    try:
        data = _pfsense_get(s, base, 'api/v1/services/dhcpd/lease', key, secret)
        for row in (data.get('data') or []):
            mac  = (row.get('mac')      or '').lower().replace('-', ':').strip()
            host = (row.get('hostname') or '').strip()
            if mac and host:
                mac_host[mac] = host
        logger.debug(f"pfSense DHCP leases: {len(mac_host)} hostnames")
    except Exception as e:
        logger.warning(f"pfSense DHCP lease fetch failed: {e}")

    # 2. ARP table
    try:
        data = _pfsense_get(s, base, 'api/v1/diagnostics/arp', key, secret)
        for row in (data.get('data') or []):
            mac  = (row.get('mac')      or '').lower().replace('-', ':').strip()
            host = (row.get('hostname') or '').strip()
            if mac and host and mac not in mac_host:
                mac_host[mac] = host
        logger.debug(f"pfSense ARP enriched to: {len(mac_host)} total hostnames")
    except Exception as e:
        logger.warning(f"pfSense ARP fetch failed: {e}")

    return mac_host


def _pfsense_test(base_url: str, key: str, secret: str, verify_ssl: bool):
    base = _make_base_url(base_url)
    s    = _session(verify_ssl)
    data = _pfsense_get(s, base, 'api/v1/system/version', key, secret)
    ver  = (data.get('data') or {}).get('version', '?')
    return True, f"pfSense {ver} — connected to {base}"


# ── Public API ────────────────────────────────────────────────────────

def fetch_hostnames(fw_type: str, base_url: str, key: str, secret: str,
                    verify_ssl: bool) -> dict:
    """Return {mac: hostname}. Called by traffic_monitor on each scan."""
    if not fw_type or not base_url:
        return {}
    try:
        if fw_type == 'opnsense':
            return _opnsense_hostnames(base_url, key, secret, verify_ssl)
        if fw_type == 'pfsense':
            return _pfsense_hostnames(base_url, key, secret, verify_ssl)
    except Exception as e:
        logger.warning(f"Firewall hostname fetch failed ({fw_type}): {e}")
    return {}


def test_firewall_connection(fw_type: str, base_url: str, key: str, secret: str,
                             verify_ssl: bool):
    """Returns (ok: bool, message: str). Called by /api/firewall/test endpoint."""
    if not base_url:
        return False, "Firewall URL is required"
    try:
        if fw_type == 'opnsense':
            return _opnsense_test(base_url, key, secret, verify_ssl)
        if fw_type == 'pfsense':
            return _pfsense_test(base_url, key, secret, verify_ssl)
        return False, f"Unknown firewall type: {fw_type!r}"
    except requests.exceptions.SSLError:
        return False, "SSL certificate error — try disabling 'Verify SSL' in settings"
    except requests.exceptions.ConnectionError:
        return False, f"Cannot reach {_make_base_url(base_url)} — check IP/URL"
    except requests.exceptions.Timeout:
        return False, "Connection timed out — check IP/URL and firewall rules"
    except requests.exceptions.HTTPError as e:
        code = e.response.status_code if e.response is not None else '?'
        if code == 401:
            return False, "Authentication failed — check API key / secret"
        if code == 403:
            return False, "Access denied — check user privileges on the firewall"
        return False, f"HTTP {code} error from firewall"
    except Exception as e:
        return False, str(e)
