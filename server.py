"""WiFi Scanner Backend — serves nearby network data, diagnostics, and speed test."""

import collections
import platform
import re
import socket
import subprocess
import threading
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI()

# ---------------------------------------------------------------------------
# Shared state — updated by background threads
# ---------------------------------------------------------------------------
_networks: list[dict] = []
_networks_lock = threading.Lock()

_diagnostics: dict = {}
_diagnostics_history: dict[str, collections.deque] = {}
_diagnostics_lock = threading.Lock()

NETWORK_POLL_INTERVAL = 5  # seconds
DIAG_POLL_INTERVAL = 2  # seconds
HISTORY_SIZE = 60  # ~2 minutes at 2s intervals

# Metrics to track in rolling history
HISTORY_KEYS = [
    "signal_percent", "rssi", "snr", "noise", "rx_rate", "tx_rate",
    "router_ping", "internet_ping", "router_jitter", "internet_jitter",
    "router_loss", "internet_loss", "dns_lookup", "tcp_established",
    "tcp_close_wait",
]

for _k in HISTORY_KEYS:
    _diagnostics_history[_k] = collections.deque(maxlen=HISTORY_SIZE)

# Track previous ping values for jitter calculation
_prev_router_ping: float | None = None
_prev_internet_ping: float | None = None
# Rolling windows for loss calculation
_router_ping_results: collections.deque = collections.deque(maxlen=30)
_internet_ping_results: collections.deque = collections.deque(maxlen=30)


# ---------------------------------------------------------------------------
# WiFi scanning helpers (unchanged)
# ---------------------------------------------------------------------------

def _parse_windows(raw: str) -> list[dict]:
    """Parse output of `netsh wlan show networks mode=bssid`.

    Each SSID can have multiple BSSIDs (access points). We emit one entry
    per BSSID so every AP shows up as its own radar blip.
    """
    networks: list[dict] = []
    current_ssid = "Hidden"
    current_bssid: dict | None = None

    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("SSID") and "BSSID" not in line:
            # Flush previous BSSID entry
            if current_bssid and current_bssid.get("bssid"):
                networks.append(current_bssid)
                current_bssid = None
            match = re.match(r"SSID\s+\d+\s*:\s*(.*)", line)
            current_ssid = match.group(1).strip() if match else "Hidden"
        elif line.startswith("BSSID"):
            # Flush previous BSSID entry (multiple BSSIDs under same SSID)
            if current_bssid and current_bssid.get("bssid"):
                networks.append(current_bssid)
            match = re.match(r"BSSID\s+\d+\s*:\s*(.*)", line)
            current_bssid = {
                "ssid": current_ssid,
                "bssid": match.group(1).strip() if match else "",
                "rssi": -100,
                "signal_percent": 0,
                "channel": 0,
            }
        elif line.startswith("Signal") and current_bssid is not None:
            match = re.match(r"Signal\s*:\s*(\d+)%", line)
            if match:
                pct = int(match.group(1))
                current_bssid["rssi"] = int(pct / 2 - 100)
                current_bssid["signal_percent"] = pct
        elif line.startswith("Channel") and current_bssid is not None:
            match = re.match(r"Channel\s*:\s*(\d+)", line)
            if match:
                current_bssid["channel"] = int(match.group(1))

    if current_bssid and current_bssid.get("bssid"):
        networks.append(current_bssid)
    return networks


def _dedup_by_ssid(networks: list[dict]) -> list[dict]:
    """Keep only the strongest-signal entry per SSID.

    Routers often broadcast multiple BSSIDs (2.4 GHz, 5 GHz, mesh nodes).
    We show one blip per logical network, using the best signal and its BSSID.
    """
    best: dict[str, dict] = {}
    for net in networks:
        ssid = net.get("ssid") or "Hidden"
        prev = best.get(ssid)
        if prev is None or net.get("rssi", -100) > prev.get("rssi", -100):
            best[ssid] = net
    return list(best.values())


def scan_networks() -> list[dict]:
    """Run an OS-native WiFi scan and return parsed results."""
    system = platform.system()
    try:
        if system == "Windows":
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True, text=True, timeout=10,
            )
            return _dedup_by_ssid(_parse_windows(result.stdout))
        else:
            return []
    except Exception as exc:
        print(f"[scanner] Error: {exc}")
        return []


# ---------------------------------------------------------------------------
# Diagnostics helpers
# ---------------------------------------------------------------------------

def _get_interface_info() -> dict:
    """Parse `netsh wlan show interfaces` for connected network info."""
    info = {
        "connected": False, "ssid": "", "bssid": "", "channel": 0,
        "band": "", "rx_rate": 0.0, "tx_rate": 0.0, "signal_percent": 0,
        "rssi": -100, "snr": 0, "noise": -90, "auth": "", "radio_type": "",
    }
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=5,
        )
        raw = result.stdout
        if not raw:
            return info

        state_match = re.search(r"State\s*:\s*(.*)", raw)
        if state_match and "connected" in state_match.group(1).lower() and "disconnected" not in state_match.group(1).lower():
            info["connected"] = True

        ssid_match = re.search(r"^\s*SSID\s*:\s*(.+)$", raw, re.MULTILINE)
        if ssid_match:
            info["ssid"] = ssid_match.group(1).strip()

        bssid_match = re.search(r"BSSID\s*:\s*([0-9a-fA-F:]+)", raw)
        if bssid_match:
            info["bssid"] = bssid_match.group(1).strip()

        ch_match = re.search(r"Channel\s*:\s*(\d+)", raw)
        if ch_match:
            info["channel"] = int(ch_match.group(1))

        radio_match = re.search(r"Radio type\s*:\s*(.*)", raw)
        if radio_match:
            rt = radio_match.group(1).strip()
            info["radio_type"] = rt
            if "802.11a" in rt or "802.11ac" in rt or "802.11ax" in rt or "802.11be" in rt:
                info["band"] = "5 GHz"
            else:
                info["band"] = "2.4 GHz"
            # Refine: channels > 14 are 5 GHz
            if info["channel"] > 14:
                info["band"] = "5 GHz"

        rx_match = re.search(r"Receive rate\s*\(Mbps\)\s*:\s*([\d.]+)", raw)
        if rx_match:
            info["rx_rate"] = float(rx_match.group(1))

        tx_match = re.search(r"Transmit rate\s*\(Mbps\)\s*:\s*([\d.]+)", raw)
        if tx_match:
            info["tx_rate"] = float(tx_match.group(1))

        sig_match = re.search(r"Signal\s*:\s*(\d+)%", raw)
        if sig_match:
            pct = int(sig_match.group(1))
            info["signal_percent"] = pct
            info["rssi"] = int(pct / 2 - 100)
            info["noise"] = -90  # assumed
            info["snr"] = info["rssi"] - info["noise"]

        auth_match = re.search(r"Authentication\s*:\s*(.*)", raw)
        if auth_match:
            info["auth"] = auth_match.group(1).strip()

    except Exception as exc:
        print(f"[diagnostics] Interface info error: {exc}")
    return info


def _get_gateway() -> str:
    """Get the default gateway IP for the WiFi interface."""
    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "addresses"],
            capture_output=True, text=True, timeout=5,
        )
        # Find the Wi-Fi section and its gateway
        sections = re.split(r"Configuration for interface\s+", result.stdout)
        for section in sections:
            if re.match(r'"?(Wi-Fi|WiFi|Wireless|WLAN)', section, re.IGNORECASE):
                gw_match = re.search(r"Default Gateway:\s+([\d.]+)", section)
                if gw_match:
                    return gw_match.group(1)
        # Fallback: try ipconfig
        result2 = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=5,
        )
        # Find Wireless adapter section
        sections2 = re.split(r"(?=Wireless LAN adapter|Wi-Fi)", result2.stdout)
        for section in sections2:
            if "Wi-Fi" in section or "Wireless" in section:
                gw_match = re.search(r"Default Gateway.*?:\s+([\d.]+)", section)
                if gw_match:
                    return gw_match.group(1)
    except Exception as exc:
        print(f"[diagnostics] Gateway detection error: {exc}")
    return ""


def _ping(host: str) -> float | None:
    """Ping a host once, return round-trip time in ms or None on failure."""
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "1500", host],
            capture_output=True, text=True, timeout=5,
        )
        # Parse "time=Xms" or "time<1ms"
        time_match = re.search(r"time[=<](\d+)ms", result.stdout)
        if time_match:
            return float(time_match.group(1))
        # Check for "time<1ms"
        if "time<1ms" in result.stdout:
            return 0.5
    except Exception as exc:
        print(f"[diagnostics] Ping error ({host}): {exc}")
    return None


def _dns_lookup_time() -> float | None:
    """Measure DNS lookup time for google.com in ms."""
    try:
        start = time.perf_counter()
        socket.getaddrinfo("google.com", 80)
        elapsed = (time.perf_counter() - start) * 1000
        return round(elapsed, 1)
    except Exception:
        return None


def _tcp_connections() -> dict:
    """Count TCP connections by state."""
    counts = {"established": 0, "close_wait": 0, "time_wait": 0, "total": 0}
    try:
        result = subprocess.run(
            ["netstat", "-n", "-p", "tcp"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            upper = line.upper()
            if "ESTABLISHED" in upper:
                counts["established"] += 1
            elif "CLOSE_WAIT" in upper:
                counts["close_wait"] += 1
            elif "TIME_WAIT" in upper:
                counts["time_wait"] += 1
        counts["total"] = counts["established"] + counts["close_wait"] + counts["time_wait"]
    except Exception as exc:
        print(f"[diagnostics] TCP connections error: {exc}")
    return counts


# ---------------------------------------------------------------------------
# Diagnostics polling
# ---------------------------------------------------------------------------

def _collect_diagnostics() -> dict:
    """Collect all diagnostic metrics."""
    global _prev_router_ping, _prev_internet_ping

    info = _get_interface_info()
    gateway = _get_gateway() if info["connected"] else ""

    # Ping measurements
    router_ping = _ping(gateway) if gateway else None
    internet_ping = _ping("1.1.1.1") if info["connected"] else None

    # Jitter (abs diff from previous)
    router_jitter = None
    if router_ping is not None and _prev_router_ping is not None:
        router_jitter = round(abs(router_ping - _prev_router_ping), 1)
    _prev_router_ping = router_ping

    internet_jitter = None
    if internet_ping is not None and _prev_internet_ping is not None:
        internet_jitter = round(abs(internet_ping - _prev_internet_ping), 1)
    _prev_internet_ping = internet_ping

    # Loss tracking
    _router_ping_results.append(1 if router_ping is not None else 0)
    _internet_ping_results.append(1 if internet_ping is not None else 0)

    router_loss = 0
    if len(_router_ping_results) > 0:
        router_loss = round((1 - sum(_router_ping_results) / len(_router_ping_results)) * 100, 1)
    internet_loss = 0
    if len(_internet_ping_results) > 0:
        internet_loss = round((1 - sum(_internet_ping_results) / len(_internet_ping_results)) * 100, 1)

    # DNS
    dns_time = _dns_lookup_time() if info["connected"] else None

    # TCP
    tcp = _tcp_connections()

    diag = {
        **info,
        "gateway": gateway,
        "router_ping": router_ping,
        "internet_ping": internet_ping,
        "router_jitter": router_jitter,
        "internet_jitter": internet_jitter,
        "router_loss": router_loss,
        "internet_loss": internet_loss,
        "dns_lookup": dns_time,
        "tcp_established": tcp["established"],
        "tcp_close_wait": tcp["close_wait"],
        "tcp_time_wait": tcp["time_wait"],
        "tcp_total": tcp["total"],
    }

    # Update rolling history
    with _diagnostics_lock:
        for key in HISTORY_KEYS:
            val = diag.get(key)
            _diagnostics_history[key].append(val)

    return diag


def _diag_poll_loop() -> None:
    global _diagnostics
    while True:
        data = _collect_diagnostics()
        with _diagnostics_lock:
            _diagnostics = data
        time.sleep(DIAG_POLL_INTERVAL)


# ---------------------------------------------------------------------------
# Speed test
# ---------------------------------------------------------------------------

def _run_speed_test() -> dict:
    """Download and upload test files to measure throughput."""
    import urllib.request

    result: dict = {"success": False, "download_mbps": 0, "upload_mbps": 0}

    # --- Download test (~10 MB from Cloudflare) ---
    dl_url = "https://speed.cloudflare.com/__down?bytes=10000000"
    try:
        print("[speedtest] Starting download test...")
        req = urllib.request.Request(dl_url, headers={"User-Agent": "WiFiScanner/1.0"})
        start = time.perf_counter()
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
        elapsed = time.perf_counter() - start

        dl_bytes = len(data)
        result["download_mbps"] = round((dl_bytes * 8) / (elapsed * 1_000_000), 2)
        result["download_bytes"] = dl_bytes
        result["download_duration_s"] = round(elapsed, 2)
        result["success"] = True
        print(f"[speedtest] Download: {result['download_mbps']} Mbps ({elapsed:.2f}s)")
    except Exception as exc:
        print(f"[speedtest] Download error: {exc}")
        result["download_error"] = str(exc)

    # --- Upload test (~5 MB to Cloudflare) ---
    ul_url = "https://speed.cloudflare.com/__up"
    ul_size = 5_000_000
    try:
        print("[speedtest] Starting upload test...")
        payload = b"\x00" * ul_size
        req = urllib.request.Request(
            ul_url, data=payload,
            headers={
                "User-Agent": "WiFiScanner/1.0",
                "Content-Type": "application/octet-stream",
            },
            method="POST",
        )
        start = time.perf_counter()
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
        elapsed = time.perf_counter() - start

        result["upload_mbps"] = round((ul_size * 8) / (elapsed * 1_000_000), 2)
        result["upload_bytes"] = ul_size
        result["upload_duration_s"] = round(elapsed, 2)
        result["success"] = True
        print(f"[speedtest] Upload: {result['upload_mbps']} Mbps ({elapsed:.2f}s)")
    except Exception as exc:
        print(f"[speedtest] Upload error: {exc}")
        result["upload_error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Background polling threads
# ---------------------------------------------------------------------------

def _network_poll_loop() -> None:
    global _networks
    while True:
        data = scan_networks()
        with _networks_lock:
            _networks = data
        time.sleep(NETWORK_POLL_INTERVAL)


_net_thread = threading.Thread(target=_network_poll_loop, daemon=True)
_net_thread.start()

_diag_thread = threading.Thread(target=_diag_poll_loop, daemon=True)
_diag_thread.start()


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.get("/api/networks")
def get_networks():
    with _networks_lock:
        return {"networks": list(_networks)}


@app.get("/api/diagnostics")
def get_diagnostics():
    with _diagnostics_lock:
        history = {k: list(v) for k, v in _diagnostics_history.items()}
        return {
            "current": dict(_diagnostics),
            "history": history,
        }


@app.post("/api/speedtest")
def run_speedtest():
    return _run_speed_test()


# ---------------------------------------------------------------------------
# Serve frontend
# ---------------------------------------------------------------------------

STATIC_DIR = Path(__file__).parent / "static"


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
