# Mild-Viking — Network Traffic Monitor

A Raspberry Pi network traffic monitor running on a 2.13" e-Paper HAT with a real-time web dashboard.

Forked from [Ragnar](https://github.com/PierreGode/Ragnar) — all offensive security tooling removed; rebuilt as a pure passive network observer.

## Install

```bash
wget https://raw.githubusercontent.com/auggnation/Ragnarbutdifferent/main/install_ragnar.sh
sudo chmod +x install_ragnar.sh && sudo ./install_ragnar.sh
```

## Web dashboard

Access at `http://<device-ip>:8000`

## Features

- Real-time network traffic in/out (B/s → GB/s auto-scaling)
- Animation modes: idle (blue), active (green), storm/attack (red/orange) based on traffic intensity
- Level system — gains 1 level per hour of uptime
- Displays IP address and connected network name
- Device discovery every 30 seconds (arp-scan → ARP cache → nmap fallback)
- VLAN/subnet scanning — discovers all reachable subnets
- Speed test (speedtest-cli) runs at boot + every 30 minutes
- E-paper display auto-scrolls every 15 seconds: stats → devices → VLANs
- WiFi AP fallback — creates `MILD-VIKING WIFI` hotspot if no network found
- LAN-first: prefers ethernet, manages WiFi as fallback

## Service

```bash
sudo systemctl status mild-viking
sudo systemctl restart mild-viking
sudo journalctl -u mild-viking -f
```

## Credits

- [PierreGode/Ragnar](https://github.com/PierreGode/Ragnar) — original project
- [infinition/Bjorn](https://github.com/infinition/Bjorn) — upstream ancestor
- auggnation — this fork
