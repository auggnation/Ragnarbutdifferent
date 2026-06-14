# firewall_integration.py
# Mild-Viking: OPNsense / pfSense hostname enrichment

import logging
import requests

logger = logging.getLogger("firewall_integration")

# ── Helpers ──────────────────────────────────────────────────────────

def _session(verify_ssl: bool) -> requests.Session:
    s = requests.Session()
    s.verify = verify_ssl
    s.timeout = 8
    return s


# ── OPNsense ──────────────────────────────────────────────────────────

def _opnsense_hostnames(base_url: str, key: str, secret: str, verify_ssl: bool) -> dict:
    """Return {mac: hostname} from OPNsense DHCP leases + ARP table."""
    s = _session(verify_ssl)
    auth = (key, secret)
    mac_host: dict[str, str] = {}

    try:
        url = base_url.rstrip('/') + '/api/dhcpv4/leases/searchLease'
        r = s.post(url, auth=auth, json={}, timeout=8)
        r.raise_for_status()
        for row in r.json().get('rows', []):
            mac = (row.get('mac') or '').lower().strip()
            host = (row.get('hostname') or '').strip()
            if mac and host:
                mac_host[mac] = host
    except Exception as e:
        logger.debug(f"OPNsense DHCP leases error: {e}")

    try:
        url = base_url.rstrip('/') + '/api/diagnostics/interface/getArp'
        r = s.get(url, auth=auth, timeout=8)
        r.raise_for_status()
        for row in r.json().get('rows', []):
            mac = (row.get('mac') or '').lower().strip()
            host = (row.get('hostname') or '').strip()
            if mac and host and mac not in mac_host:
                mac_host[mac] = host
    except Exception as e:
        logger.debug(f"OPNsense ARP error: {e}")

    return mac_host


def _opnsense_test(base_url: str, key: str, secret: str, verify_ssl: bool):
    s = _session(verify_ssl)
    url = base_url.rstrip('/') + '/api/core/firmware/status'
    r = s.get(url, auth=(key, secret), timeout=8)
    r.raise_for_status()
    return True, f"OPNsense connected (HTTP {r.status_code})"


# ── pfSense ──────────────────────────────────────────────────────────

def _pfsense_hostnames(base_url: str, key: str, secret: str, verify_ssl: bool) -> dict:
    """Return {mac: hostname} from pfSense-API DHCP leases + ARP."""
    s = _session(verify_ssl)
    headers = {'Authorization': f'Bearer {key}'} if key else {}
    mac_host: dict[str, str] = {}

    try:
        url = base_url.rstrip('/') + '/api/v1/services/dhcpd/lease'
        r = s.get(url, headers=headers, timeout=8)
        r.raise_for_status()
        for row in (r.json().get('data') or []):
            mac = (row.get('mac') or '').lower().strip()
            host = (row.get('hostname') or '').strip()
            if mac and host:
                mac_host[mac] = host
    except Exception as e:
        logger.debug(f"pfSense DHCP error: {e}")

    try:
        url = base_url.rstrip('/') + '/api/v1/diagnostics/arp'
        r = s.get(url, headers=headers, timeout=8)
        r.raise_for_status()
        for row in (r.json().get('data') or []):
            mac = (row.get('mac') or '').lower().strip()
            host = (row.get('hostname') or '').strip()
            if mac and host and mac not in mac_host:
                mac_host[mac] = host
    except Exception as e:
        logger.debug(f"pfSense ARP error: {e}")

    return mac_host


def _pfsense_test(base_url: str, key: str, secret: str, verify_ssl: bool):
    s = _session(verify_ssl)
    headers = {'Authorization': f'Bearer {key}'} if key else {}
    url = base_url.rstrip('/') + '/api/v1/system/version'
    r = s.get(url, headers=headers, timeout=8)
    r.raise_for_status()
    ver = r.json().get('data', {}).get('version', '?')
    return True, f"pfSense connected (version {ver})"


# ── Public API ────────────────────────────────────────────────────────

def fetch_hostnames(fw_type: str, base_url: str, key: str, secret: str,
                    verify_ssl: bool) -> dict:
    """Return {mac: hostname} dict. Returns {} on error."""
    try:
        if fw_type == 'opnsense':
            return _opnsense_hostnames(base_url, key, secret, verify_ssl)
        if fw_type == 'pfsense':
            return _pfsense_hostnames(base_url, key, secret, verify_ssl)
    except Exception as e:
        logger.warning(f"Firewall hostname fetch failed: {e}")
    return {}


def test_firewall_connection(fw_type: str, base_url: str, key: str, secret: str,
                             verify_ssl: bool):
    """Returns (ok: bool, message: str)."""
    try:
        if fw_type == 'opnsense':
            return _opnsense_test(base_url, key, secret, verify_ssl)
        if fw_type == 'pfsense':
            return _pfsense_test(base_url, key, secret, verify_ssl)
        return False, f"Unknown firewall type: {fw_type}"
    except requests.exceptions.SSLError as e:
        return False, f"SSL error (try disabling SSL verify): {e}"
    except requests.exceptions.ConnectionError as e:
        return False, f"Cannot reach {base_url}: {e}"
    except requests.exceptions.HTTPError as e:
        return False, f"HTTP {e.response.status_code}: check API credentials"
    except Exception as e:
        return False, str(e)
