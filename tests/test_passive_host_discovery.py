"""Tests for passive host discovery via TrafficAnalyzer.

Covers:
- ARP reply parsing -> IP↔MAC mapping
- LAN-network derivation and is_lan_ip
- Listening-port detection from observed service ports
- _passive_sync_to_db merge semantics:
  * existing host gets new ports added (no replace)
  * new LAN IP creates a host
  * non-LAN traffic does not touch the DB
  * host without MAC and few packets is below threshold
"""

import ipaddress
from unittest.mock import MagicMock, patch

import pytest

from traffic_analyzer import TrafficAnalyzer


@pytest.fixture
def analyzer():
    with patch.object(TrafficAnalyzer, '_detect_interface', return_value='lo'), \
         patch.object(TrafficAnalyzer, '_detect_local_ips',
                      return_value={'127.0.0.1', '192.168.1.10'}), \
         patch.object(TrafficAnalyzer, '_detect_gateway_ips',
                      return_value={'192.168.1.1'}):
        a = TrafficAnalyzer(shared_data=None, interface='lo')
    a.MAX_ALERTS_PER_MINUTE = 10_000
    a._alert_dedup_window = 0
    return a


# ---------------------------------------------------------------------------
# _is_lan_ip / LAN-network derivation
# ---------------------------------------------------------------------------

def test_lan_networks_include_gateway_and_local_subnet(analyzer):
    nets = analyzer._lan_networks
    assert any(ipaddress.IPv4Address('192.168.1.50') in n for n in nets)


@pytest.mark.parametrize("ip,expected", [
    ('192.168.1.50', True),       # same /24 as gateway + local
    ('192.168.1.255', True),      # boundary still in subnet
    ('192.168.2.50', False),      # other /24
    ('10.0.0.5', False),          # different RFC1918 block
    ('8.8.8.8', False),           # public
    ('127.0.0.1', False),         # loopback
    ('169.254.1.1', False),       # link-local
    ('224.0.0.1', False),         # multicast
    ('', False),
    ('not-an-ip', False),
])
def test_is_lan_ip(analyzer, ip, expected):
    assert analyzer._is_lan_ip(ip) is expected


# ---------------------------------------------------------------------------
# ARP parsing
# ---------------------------------------------------------------------------

def test_arp_reply_extracts_mac(analyzer):
    line = ('2026-05-28 01:00:00.000000 ARP, Reply 192.168.1.50 '
            'is-at aa:bb:cc:dd:ee:ff, length 28')
    analyzer._parse_and_record_packet(line)

    assert analyzer._mac_by_ip['192.168.1.50'] == 'aa:bb:cc:dd:ee:ff'
    assert analyzer.host_stats['192.168.1.50'].mac == 'aa:bb:cc:dd:ee:ff'


def test_arp_reply_outside_lan_ignored(analyzer):
    line = ('2026-05-28 01:00:00.000000 ARP, Reply 10.0.0.50 '
            'is-at aa:bb:cc:dd:ee:ff, length 28')
    analyzer._parse_and_record_packet(line)

    assert '10.0.0.50' not in analyzer._mac_by_ip


def test_arp_request_does_not_record_mac(analyzer):
    # "tell" lines don't include the requester's MAC in -q output.
    line = ('2026-05-28 01:00:00.000000 ARP, Request who-has 192.168.1.1 '
            'tell 192.168.1.50, length 28')
    analyzer._parse_and_record_packet(line)
    assert '192.168.1.50' not in analyzer._mac_by_ip


# ---------------------------------------------------------------------------
# Listening-port detection
# ---------------------------------------------------------------------------

def test_listening_port_recorded_when_well_known_dst(analyzer):
    base_ts = '2026-05-28 01:00:00.000000'
    line = f'{base_ts} IP 192.168.1.20.50000 > 192.168.1.50.443: tcp 0'
    analyzer._parse_and_record_packet(line)

    assert 443 in analyzer._listening_ports['192.168.1.50']


def test_listening_port_recorded_for_high_value_high_port(analyzer):
    base_ts = '2026-05-28 01:00:00.000000'
    line = f'{base_ts} IP 192.168.1.20.50000 > 192.168.1.50.6379: tcp 0'
    analyzer._parse_and_record_packet(line)

    assert 6379 in analyzer._listening_ports['192.168.1.50']


def test_listening_port_not_recorded_for_ephemeral(analyzer):
    base_ts = '2026-05-28 01:00:00.000000'
    # Random ephemeral; should NOT be considered a listening port.
    line = f'{base_ts} IP 192.168.1.20.50000 > 192.168.1.50.40000: tcp 0'
    analyzer._parse_and_record_packet(line)

    assert 192_168_1_50 != 0  # sanity
    listening = analyzer._listening_ports.get('192.168.1.50', set())
    assert 40000 not in listening


def test_listening_port_not_recorded_for_non_lan(analyzer):
    base_ts = '2026-05-28 01:00:00.000000'
    line = f'{base_ts} IP 192.168.1.20.50000 > 8.8.8.8.443: tcp 0'
    analyzer._parse_and_record_packet(line)

    assert '8.8.8.8' not in analyzer._listening_ports


# ---------------------------------------------------------------------------
# Pseudo-MAC helper
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip,expected", [
    ('192.168.1.50', '00:00:c0:a8:01:32'),
    ('10.0.0.1', '00:00:0a:00:00:01'),
    ('255.255.255.255', '00:00:ff:ff:ff:ff'),
    ('not.an.ip.addr', ''),
    ('1.2.3', ''),
])
def test_ip_to_pseudo_mac(ip, expected):
    assert TrafficAnalyzer._ip_to_pseudo_mac(ip) == expected


# ---------------------------------------------------------------------------
# _passive_sync_to_db
# ---------------------------------------------------------------------------

def _build_db(existing_by_ip=None):
    db = MagicMock()
    db.get_host_by_ip.side_effect = lambda ip: (existing_by_ip or {}).get(ip)
    db.upsert_host.return_value = True
    return db


def test_passive_sync_creates_new_host_with_real_mac(analyzer):
    db = _build_db()
    analyzer.shared_data = MagicMock(db=db)

    # Seed: ARP reply + a packet to a service port.
    base_ts = '2026-05-28 01:00:00.000000'
    analyzer._parse_and_record_packet(
        f'{base_ts} ARP, Reply 192.168.1.50 is-at aa:bb:cc:dd:ee:ff, length 28')
    analyzer._parse_and_record_packet(
        f'{base_ts} IP 192.168.1.20.50000 > 192.168.1.50.443: tcp 0')

    analyzer._passive_sync_to_db()

    db.upsert_host.assert_called()
    call = db.upsert_host.call_args
    assert call.kwargs['mac'] == 'aa:bb:cc:dd:ee:ff'
    assert call.kwargs['ip'] == '192.168.1.50'
    assert '443' in (call.kwargs['ports'] or '')
    services = call.kwargs.get('services') or {}
    assert services.get('443') == 'https'


def test_passive_sync_merges_ports_with_existing_host(analyzer):
    existing = {
        '192.168.1.50': {
            'mac': 'aa:bb:cc:dd:ee:ff',
            'ports': '80,22',
            'services': '{"22": "ssh", "80": "http"}',
        }
    }
    db = _build_db(existing)
    analyzer.shared_data = MagicMock(db=db)

    base_ts = '2026-05-28 01:00:00.000000'
    # Observed listening on 443 and 6379 (new ports).
    analyzer._parse_and_record_packet(
        f'{base_ts} ARP, Reply 192.168.1.50 is-at aa:bb:cc:dd:ee:ff, length 28')
    analyzer._parse_and_record_packet(
        f'{base_ts} IP 192.168.1.20.50000 > 192.168.1.50.443: tcp 0')
    analyzer._parse_and_record_packet(
        f'{base_ts} IP 192.168.1.20.50001 > 192.168.1.50.6379: tcp 0')

    analyzer._passive_sync_to_db()

    call = db.upsert_host.call_args
    ports = set(call.kwargs['ports'].split(','))
    # All four ports (old + new) should be present.
    assert ports == {'22', '80', '443', '6379'}
    services = call.kwargs['services']
    # Existing service descriptions are preserved.
    assert services['22'] == 'ssh'
    assert services['80'] == 'http'
    # New ports got inferred labels.
    assert services['443'] == 'https'
    assert services['6379'] == 'redis'


def test_passive_sync_skips_host_without_mac_below_threshold(analyzer):
    db = _build_db()
    analyzer.shared_data = MagicMock(db=db)

    # Only ONE packet — below PASSIVE_MIN_PACKETS (5), no ARP.
    line = '2026-05-28 01:00:00.000000 IP 192.168.1.20.50000 > 192.168.1.99.443: tcp 0'
    analyzer._parse_and_record_packet(line)

    analyzer._passive_sync_to_db()

    # 192.168.1.99 should NOT be upserted (no MAC, <5 packets).
    upserted_ips = [c.kwargs.get('ip') for c in db.upsert_host.call_args_list]
    assert '192.168.1.99' not in upserted_ips


def test_passive_sync_upserts_host_with_pseudo_mac_when_threshold_met(analyzer):
    db = _build_db()
    analyzer.shared_data = MagicMock(db=db)

    base_ts = '2026-05-28 01:00:00.000000'
    # Five packets to 192.168.1.77, no ARP — should use pseudo-MAC.
    for i in range(5):
        line = (f'{base_ts} IP 192.168.1.20.{50000 + i} '
                f'> 192.168.1.77.443: tcp 0')
        analyzer._parse_and_record_packet(line)

    analyzer._passive_sync_to_db()

    call = next((c for c in db.upsert_host.call_args_list
                 if c.kwargs.get('ip') == '192.168.1.77'), None)
    assert call is not None
    assert call.kwargs['mac'] == '00:00:c0:a8:01:4d'


def test_passive_sync_does_not_touch_non_lan_hosts(analyzer):
    db = _build_db()
    analyzer.shared_data = MagicMock(db=db)

    base_ts = '2026-05-28 01:00:00.000000'
    for i in range(10):
        line = f'{base_ts} IP 192.168.1.20.{50000 + i} > 8.8.8.8.443: tcp 0'
        analyzer._parse_and_record_packet(line)

    analyzer._passive_sync_to_db()

    upserted_ips = [c.kwargs.get('ip') for c in db.upsert_host.call_args_list]
    assert '8.8.8.8' not in upserted_ips


def test_passive_sync_skips_ragnar_own_ip(analyzer):
    db = _build_db()
    analyzer.shared_data = MagicMock(db=db)

    # 192.168.1.10 is in _local_ips per the fixture.
    base_ts = '2026-05-28 01:00:00.000000'
    analyzer._parse_and_record_packet(
        f'{base_ts} ARP, Reply 192.168.1.10 is-at 11:22:33:44:55:66, length 28')
    for i in range(10):
        line = (f'{base_ts} IP 192.168.1.10.{50000 + i} > '
                f'192.168.1.50.443: tcp 0')
        analyzer._parse_and_record_packet(line)

    analyzer._passive_sync_to_db()

    upserted_ips = [c.kwargs.get('ip') for c in db.upsert_host.call_args_list]
    assert '192.168.1.10' not in upserted_ips


def test_passive_sync_no_op_when_db_unavailable(analyzer):
    analyzer.shared_data = None
    base_ts = '2026-05-28 01:00:00.000000'
    analyzer._parse_and_record_packet(
        f'{base_ts} ARP, Reply 192.168.1.50 is-at aa:bb:cc:dd:ee:ff, length 28')
    # Should not raise.
    analyzer._passive_sync_to_db()


def test_passive_sync_skips_when_existing_host_and_no_new_ports(analyzer):
    """Existing host with all our observed ports — no DB write needed."""
    existing = {
        '192.168.1.50': {
            'mac': 'aa:bb:cc:dd:ee:ff',
            'ports': '443',
            'services': '{"443": "https"}',
        }
    }
    db = _build_db(existing)
    analyzer.shared_data = MagicMock(db=db)

    base_ts = '2026-05-28 01:00:00.000000'
    analyzer._parse_and_record_packet(
        f'{base_ts} ARP, Reply 192.168.1.50 is-at aa:bb:cc:dd:ee:ff, length 28')
    analyzer._parse_and_record_packet(
        f'{base_ts} IP 192.168.1.20.50000 > 192.168.1.50.443: tcp 0')

    analyzer._passive_sync_to_db()

    # upsert_host should be called but with ports=None to avoid clobbering.
    call = db.upsert_host.call_args
    assert call.kwargs.get('ports') is None
    assert call.kwargs.get('services') is None


# ---------------------------------------------------------------------------
# Liveness from passive observation: resurrects 'degraded' hosts
# ---------------------------------------------------------------------------

def test_passive_sync_calls_update_ping_status_for_observed_hosts(analyzer):
    """Every passively-synced host should also get a liveness ping update."""
    db = _build_db()
    analyzer.shared_data = MagicMock(db=db)

    base_ts = '2026-05-28 01:00:00.000000'
    analyzer._parse_and_record_packet(
        f'{base_ts} ARP, Reply 192.168.1.50 is-at aa:bb:cc:dd:ee:ff, length 28')
    analyzer._parse_and_record_packet(
        f'{base_ts} IP 192.168.1.20.50000 > 192.168.1.50.443: tcp 0')

    analyzer._passive_sync_to_db()

    # update_ping_status should be called with the real MAC and success=True.
    db.update_ping_status.assert_called()
    call = db.update_ping_status.call_args
    assert call.args[0] == 'aa:bb:cc:dd:ee:ff'
    assert call.kwargs.get('success') is True


def test_passive_sync_resurrects_degraded_host_with_pseudo_mac(analyzer):
    """A host whose only known MAC is pseudo still gets liveness."""
    db = _build_db()
    analyzer.shared_data = MagicMock(db=db)

    base_ts = '2026-05-28 01:00:00.000000'
    for i in range(5):
        line = (f'{base_ts} IP 192.168.1.20.{50000 + i} > '
                f'192.168.1.77.443: tcp 0')
        analyzer._parse_and_record_packet(line)

    analyzer._passive_sync_to_db()

    # Pseudo-MAC should still receive a liveness signal.
    macs_pinged = [c.args[0] for c in db.update_ping_status.call_args_list]
    assert '00:00:c0:a8:01:4d' in macs_pinged


def test_passive_sync_update_ping_failure_does_not_crash(analyzer):
    """If update_ping_status raises, sync continues."""
    db = _build_db()
    db.update_ping_status.side_effect = RuntimeError("DB locked")
    analyzer.shared_data = MagicMock(db=db)

    base_ts = '2026-05-28 01:00:00.000000'
    analyzer._parse_and_record_packet(
        f'{base_ts} ARP, Reply 192.168.1.50 is-at aa:bb:cc:dd:ee:ff, length 28')
    analyzer._parse_and_record_packet(
        f'{base_ts} IP 192.168.1.20.50000 > 192.168.1.50.443: tcp 0')

    # Should not raise.
    analyzer._passive_sync_to_db()
    db.upsert_host.assert_called()
