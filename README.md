# WiFi Scanner

A real-time WiFi diagnostics tool with a radar-style visualization. Scans nearby networks, displays signal quality metrics with sparkline graphs, and includes a built-in speed test.

![WiFi Scanner Screenshot](https://github.com/vmadhuvarshi/wifiscanner/blob/main/screenshot.png)

## Features

- **2D Radar View** — Nearby networks displayed as blips on a circular radar, positioned by signal strength. Connected network highlighted with a distinct marker.
- **Live Diagnostics Panel** — Signal quality, SNR, RSSI, noise floor, Rx/Tx rates, router & internet ping/jitter/loss, DNS lookup time, and TCP connection counts.
- **Sparkline Graphs** — Rolling ~2-minute history for every metric, color-coded by health (green/yellow/red).
- **Speed Test** — On-demand download and upload speed measurement via Cloudflare.
- **Auto-updating** — Network scan every 5s, diagnostics every 2s. Connection changes reflected automatically.

## Requirements

- **Windows** — Uses `netsh` and `netstat` for WiFi data (no Linux/macOS support yet)
- **Python 3.10+**

## Quick Start

```bash
pip install -r requirements.txt
python server.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

## How It Works

| Component | Details |
|-----------|---------|
| Backend | FastAPI + background threads polling `netsh wlan`, `ping`, `netstat`, `socket` |
| Frontend | Vanilla HTML/CSS/JS, Canvas 2D radar, inline SVG sparklines |
| Speed Test | Downloads ~10 MB / uploads ~5 MB via `speed.cloudflare.com` |
| Metrics | Signal %, RSSI (derived), SNR (estimated), ping, jitter, loss, DNS, TCP states |

## Project Structure

```
wifiscanner/
  server.py            # FastAPI backend — network scanning, diagnostics, speed test
  static/
    index.html         # Single-page frontend — radar + diagnostics panel
  requirements.txt
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/networks` | GET | List of nearby WiFi networks (SSID, BSSID, RSSI, channel) |
| `/api/diagnostics` | GET | Connected network metrics + rolling history for sparklines |
| `/api/speedtest` | POST | Run download + upload speed test, returns Mbps |

## Limitations

- Windows-only (relies on `netsh`, `netstat`, `ping`)
- Must run locally — WiFi scanning requires OS-level access
- Noise floor is estimated at -90 dBm (Windows doesn't expose this natively)
- Speed test accuracy depends on network conditions and Cloudflare endpoint proximity
