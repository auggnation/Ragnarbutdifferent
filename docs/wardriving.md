# Wardriving — Ragnar + HuginnESP

## Overview

Ragnar's wardriving engine collects WiFi networks, BLE devices, cell towers, and GPS positions while driving. Data is stored in SQLite per session and can be exported to WiGLE CSV or KML.

The system has two data sources:
- **WiFi adapters (wlan)** — Linux adapters in monitor/managed mode, scanning directly via `iw`
- **HuginnESP** — ESP32-S3 via USB serial, scanning WiFi + BLE + threat detection

Everything logged automatically receives GPS coordinates if a GPS receiver is connected.

---

## Hardware

### HuginnESP (ESP32-S3)

| Property | Value |
|----------|-------|
| Board | Waveshare ESP32-S3 Smart 86 Box |
| Display | 4" 480×480 RGB IPS, GT911 touch (I2C) |
| Processor | ESP32-S3, 240 MHz |
| Flash | 16 MB |
| PSRAM | 8 MB OPI |
| Serial | USB CDC, 115200 baud |
| Firmware | [HuginnESP](https://github.com/PierreGode/HuginnESP) (PlatformIO Arduino) |
| Libraries | LovyanGFX 1.1.16, NimBLE-Arduino 1.4.1 |

### GPS

Optional USB GPS receiver (NMEA via pyserial). Auto-detected at startup.

---

## Architecture

```
┌─────────────────────┐     USB Serial      ┌──────────────────┐
│  Raspberry Pi / PC  │◄───────────────────►│   HuginnESP      │
│                     │   115200 baud        │   ESP32-S3       │
│  Ragnar             │                      │                  │
│  ├─ wardriving.py   │   JSON + alerts      │  ├─ WiFi scan    │
│  ├─ webapp_modern.py│◄────────────────────│  ├─ BLE scan     │
│  └─ web UI          │                      │  ├─ AirTag det.  │
│                     │   Commands           │  ├─ Flipper det. │
│  GPS ◄──────────┐   │──────────────────►  │  ├─ Skimmer det. │
│  (USB NMEA)     │   │   scanap, blescan   │  └─ Pineapple    │
│                 ▼   │                      │                  │
│  SQLite session DB  │                      │  480×480 display │
└─────────────────────┘                      └──────────────────┘
```

---

## HuginnESP Serial Protocol

### Commands (Ragnar → ESP)

| Command | Description |
|---------|-------------|
| `scanap` | Start WiFi scanning |
| `blescan -f` | BLE filtered (Flipper + AirTag) |
| `blescan -a` | BLE all (all devices + threat detection) |
| `capture -skimmer` | BLE skimmer detection |
| `pineap` | Pineapple/Evil Twin detection |
| `stop` | Stop active scan, return to auto-cycle |
| `capture -stop` | Stop BLE capture |
| `status` | Get current mode (JSON) |

### Scan Cycle

Ragnar rotates through these steps:

| Step | Command | Duration | Mode label |
|------|---------|----------|------------|
| 1 | `scanap` | 15s | wifi |
| 2 | `blescan -f` | 8s | ble-filtered |
| 3 | `scanap` | 15s | wifi |
| 4 | `blescan -a` | 8s | ble-all |
| 5 | `scanap` | 15s | wifi |
| 6 | `capture -skimmer` | 8s | ble-skimmer |
| 7 | `scanap` | 15s | wifi |
| 8 | `pineap` | 10s | pineap |

Total cycle: ~94 seconds.

### Serial Output (ESP → Ragnar)

#### WiFi Networks (JSON, one line per AP)
```json
{"type":"WIFI","mac":"38:E1:F4:F6:79:26","ssid":"Tele2_F67926","rssi":-84,"channel":1,"auth":"WPA2"}
```

#### BLE Devices (JSON, ALL mode, one line per device)
```json
{"type":"BLE","mac":"AA:BB:CC:DD:EE:FF","name":"DeviceName","rssi":-60}
```

#### AirTag (multi-line, FILTERED + ALL mode)
```
AirTag found!
Tag: 1
MAC Address: D3:59:9B:E4:2C:3A
RSSI: -89
```

#### Flipper Zero (multi-line, FILTERED + ALL mode)
```
Found White Flipper Device:
MAC: AA:BB:CC:DD:EE:FF,
Name: Flipper-X,
RSSI: -70
```

#### Skimmer (multi-line, SKIMMER + ALL mode)
```
POTENTIAL SKIMMER DETECTED!
Device Name: HC-05
MAC Address: 11:22:33:44:55:66
RSSI: -55
Reason: Suspicious BLE module near payment terminal
```

Known skimmer names: `HC-05`, `HC-06`, `HC-08`, `BT05`, `BT06`, `JDY-30`, `JDY-31`, `JDY-33`, `SPP-CA`

#### Pineapple/Evil Twin (multi-line)
```
Pineapple detected: NetworkName
BSSID: AA:BB:CC:DD:EE:FF
Channel: 6
```

#### BLE Spam (single line)
```
BLE Spam detected from AA:BB:CC:DD:EE:FF
```
Triggered at 20+ advertisements from the same MAC within 5 seconds.

#### Status (JSON, response to `status` command)
```json
{"mode":"auto","wifi_count":5,"ble_count":12}
```

#### Boot Messages
```
[BOOT] HuginnESP starting...
[BOOT] Free heap: 234567
[BOOT] PSRAM: 8388608
[BOOT] Init WiFi...
[BOOT] WiFi OK
[BOOT] Init BLE...
[BOOT] BLE OK
[BOOT] All tasks started — entering main loop
```

---

## Ragnar Parser

`wardriving.py → _parse_serial_line()` handles all output:

| Data type | Detection | Storage | GPS |
|-----------|-----------|---------|-----|
| WiFi JSON | `line.startswith('{')` → `type == WIFI` | `upsert_network()` | ✅ |
| BLE JSON | `line.startswith('{')` → `type == BLE` | `upsert_bluetooth()` | ✅ |
| AirTag | `line.startswith('AirTag found')` → buffer | `upsert_bluetooth('AirTag')` | ✅ |
| Flipper | `re.match('Found .* Flipper')` → buffer | `upsert_bluetooth('Flipper')` | ✅ |
| Skimmer | `'POTENTIAL SKIMMER' in line` → buffer | `upsert_bluetooth('Skimmer')` | ✅ |
| Pineapple | `'Pineapple detected' in line` | `_esp_alerts` list | ✅ |
| BLE Spam | `'BLE Spam detected' in line` | `_esp_alerts` list | ✅ |
| WiGLE CSV | Comma-separated with MAC format | `upsert_network()` / `upsert_bluetooth()` | ✅ |
| Multi-line WiFi | `[N] SSID: ...` → buffer | `upsert_network()` | ✅ |

Ignored lines:
- `huginn>`, `Wardrive:`, `Registered`, `Unsupported`
- `WiFi scan`, `Started`, `Stopped`, `Usage:`, `BLE initialized`, etc.
- `[BOOT]` prefix (not explicitly filtered but matches no parser)

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/wardriving/status` | Full status incl. GPS, serial, counters |
| POST | `/api/wardriving/start` | Start wardriving session |
| POST | `/api/wardriving/stop` | Stop session |
| GET | `/api/wardriving/networks` | List captured WiFi networks |
| GET | `/api/wardriving/bluetooth` | List BLE devices |
| GET | `/api/wardriving/cells` | List cell towers |
| GET | `/api/wardriving/sessions` | List sessions |
| GET | `/api/wardriving/export/<id>` | Export session (WiGLE CSV / KML) |
| POST | `/api/wardriving/import` | Import WiGLE CSV |
| GET | `/api/wardriving/gps` | GPS status |
| GET | `/api/wardriving/interfaces` | Available WiFi interfaces |
| GET | `/api/wardriving/serial/detect` | Auto-detect ESP32 port |
| GET/POST | `/api/wardriving/serial` | Serial status / start/stop listener |
| GET | `/api/wardriving/track` | GPS track (lat/lon history) |
| POST | `/api/wardriving/device_name` | Set device name |
| GET/POST | `/api/wardriving/on_boot` | Auto-start on boot |

---

## Status Object

`GET /api/wardriving/status` returns:

```json
{
  "running": true,
  "session_id": "uuid",
  "interfaces": ["wlan1"],
  "scans_completed": 42,
  "total_networks": 156,
  "gps": {
    "connected": true,
    "port": "/dev/ttyACM0",
    "has_fix": true
  },
  "serial_connected": true,
  "serial_port": "/dev/ttyACM1",
  "serial_networks": 23,
  "esp_mode": "wifi",
  "esp_ble_count": 87,
  "esp_alerts": [
    {"time": 1683456789, "alert": "AirTag found!"}
  ],
  "serial_unique": 12,
  "bluetooth_count": 87,
  "cell_count": 3,
  "stats": { ... }
}
```

---

## Data Storage

Each session creates a SQLite database in `data/networks/`.

### Table: networks
| Column | Type | Description |
|--------|------|-------------|
| bssid | TEXT | MAC address (primary key) |
| ssid | TEXT | Network name |
| security | TEXT | WPA2, WPA3, Open, etc. |
| channel | INT | WiFi channel |
| frequency | INT | Frequency in MHz |
| rssi | INT | Signal strength (dBm) |
| lat | REAL | GPS latitude |
| lon | REAL | GPS longitude |
| alt | REAL | GPS altitude |
| interface | TEXT | `wlan1`, `esp32-serial`, etc. |

### Table: bluetooth
| Column | Type | Description |
|--------|------|-------------|
| mac | TEXT | BLE MAC address |
| name | TEXT | Device name |
| rssi | INT | Signal strength |
| device_type | TEXT | `BLE`, `AirTag`, `Flipper`, `Skimmer` |
| lat/lon/alt | REAL | GPS position |

---

## Export

### WiGLE CSV
Standard format for uploading to wigle.net. Contains MAC, SSID, AuthMode, channel, RSSI, GPS coordinates.

### KML
Google Earth format with network positions as markers.

---

## Setup

### 1. Flash HuginnESP

```bash
cd HuginnESP
pio run --target upload     # COM8 on Windows, /dev/ttyACM* on Linux
```

### 2. Connect to Ragnar

**Auto-detect (Linux):**
Click 🔍 Search in the web UI — finds the ESP32 automatically via `udevadm`.

**Manual:**
Enter the port (`/dev/ttyACM0` or `COM8`) in the serial field and click Connect.

### 3. GPS (optional)

Connect a USB GPS receiver. Ragnar auto-detects NMEA devices.

### 4. Start Wardriving

Click **Start Wardriving** in the web UI. Ragnar begins scanning with all active interfaces + ESP32 serial.

---

## Camera Recognition

Ragnar identifies surveillance cameras based on MAC OUI prefixes (manufacturers):
Axis, Hikvision, Dahua, Vivotek, Bosch, Samsung, Reolink, Amcrest, Foscam, and more.

Cameras are marked in the network list with type and manufacturer.
