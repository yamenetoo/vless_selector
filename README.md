# 🚀 Vless Selector – Massively Parallel V2Ray Config Selector

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Vless Selector** is a powerful, multi‑threaded tool that automatically discovers, tests, and continuously optimizes the fastest VLESS configurations from a subscription. It runs a stable VPN tunnel while constantly probing for better servers – and seamlessly upgrades when a significantly better one is found.

![Demo](demo.gif) *<– replace with an actual screenshot or animated demo*

## ✨ Features

- **Massively parallel discovery** – Tests dozens of configs simultaneously using isolated ports.
- **Lightweight pre‑filter** – Quickly checks reachability before full testing.
- **Continuous background testing** – Keeps evaluating untested and older configs without interrupting your stable connection.
- **Auto‑upgrade** – Automatically switches to a better server when it exceeds your current one by a configurable threshold.
- **Self‑contained** – Automatically downloads the latest **Xray‑core** Windows executable if missing.
- **Detailed status display** – Shows live test results, connected programs, and performance metrics.
- **Interactive commands** – Press keys to view status, manually test, or quit.
- **Test history logging** – Saves recent results to `test_history.json` for later analysis.

## 📋 Requirements

- **Windows** (the script uses Windows‑specific commands like `taskkill`; Xray is downloaded for Windows)
- **Python 3.6+**
- Python packages: `requests`, `pysocks`, `urllib3`

## 🔧 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yamenetoo/vless_selector.git
   cd vless_selector
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
   *(Create a `requirements.txt` with: `requests`, `pysocks`)*

3. **Run the script**
   ```bash
   python vless_selector.py
   ```
   On first run, it will automatically download `xray.exe` into the `vendor/` folder.

## ⚙️ Configuration

All settings are at the top of the script. You can adjust:

| Variable | Description | Default |
|----------|-------------|---------|
| `SUBSCRIPTION_URL` | Your VLESS subscription URL (plain text or base64) | *your URL* |
| `SOCKS5_PORT` | Stable VPN port for apps | `10808` |
| `DISCOVERY_BATCH_SIZE` | Parallel tests during initial discovery | `50` |
| `PRE_FILTER_WORKERS` | Parallel connections for lightweight pre‑filter | `50` |
| `CONTINUOUS_TEST_ENABLED` | Enable background testing | `True` |
| `CONTINUOUS_TEST_INTERVAL` | Seconds between continuous test rounds | `30` |
| `AUTO_UPGRADE_ENABLED` | Automatically switch to a better config | `True` |
| `MIN_SPEED_MBPS` | Minimum acceptable speed | `0.5` |
| `MAX_LATENCY_MS` | Maximum acceptable latency | `500` |

## 🎮 Usage

Run the script and let it work:

```
python vless_selector.py
```

Once the stable VPN is established, you can use these **interactive commands** (press the key and Enter, or just the key if on Windows):

- `s` – Show current status
- `t` – Manually test the stable connection
- `c` – Display continuous testing stats
- `q` – Quit and stop VPN

The terminal will continuously update with discovery and test results.

### Example Output

```
📡 Fetching subscription...
✅ Parsed 250 valid configs

🔍 Pre-filtering 250 configs (50 workers)...
   ✅ server-a.com:443                    123.4ms (50/250)
   ❌ slow-server.net:443                  timeout (51/250)
...
✅ Pre-filter: 180/250 reachable

🚀 PHASE 1: PARALLEL DISCOVERY (50 configs in parallel)
   ✅ us-node-01                           ⏱️ 45ms 🚀12.3Mbps  (50/50)
✅ Discovery complete: 32/50 working

🚀 PHASE 2: LOCKING BEST CONFIG FOR STABLE VPN
🏆 Best config: sg-optimized.net:443
   ⏱️  Latency: 38.2ms
   🚀 Speed:    18.7Mbps
   📊 Score:    87.4
✅ Stable VPN running on 127.0.0.1:10808

💡 VPN is stable! Configure apps to use: 127.0.0.1:10808
   Commands: 's'=status, 't'=test, 'c'=continuous, 'q'=quit
```

## 🔄 How It Works

1. **Fetch & Parse** – Downloads the subscription, decodes base64 if needed, and parses VLESS URIs.
2. **Pre‑filter** – Quickly tests reachability (TCP/TLS handshake) to discard dead servers.
3. **Parallel Discovery** – Runs full tests on the first batch of configs (each on a different local port) to find working ones.
4. **Stable VPN** – Locks the best working config and starts a persistent SOCKS5 proxy on the main port.
5. **Continuous Testing** – In the background, repeatedly tests new and older configs. If a significantly better one is found, it automatically upgrades the stable tunnel.

## 🧪 Auto‑upgrade Logic

A new config is considered better if:

- Its **score** exceeds the current stable score by at least `AUTO_UPGRADE_THRESHOLD` (default 30%), **or**
- Its speed is above `MIN_SPEED_FOR_UPGRADE` (2.0 Mbps) **and** the stable score is low (<50).

The upgrade will not happen more often than `UPGRADE_COOLDOWN` (300 seconds).

## 🛠️ Troubleshooting

| Problem | Possible Solution |
|---------|-------------------|
| **No working configs found** | Check your subscription URL. Try reducing `DISCOVERY_BATCH_SIZE` to 20. Run as Administrator (Windows). Allow Xray through firewall. |
| **Xray fails to start** | Manually download Xray from [XTLS/Xray-core releases](https://github.com/XTLS/Xray-core/releases) and place `xray.exe` in `vendor/`. |
| **Port already in use** | Kill any lingering Xray processes: `taskkill /F /IM xray.exe`. The script attempts this automatically. |
| **Slow performance** | The continuous testing uses extra system resources. Lower `CONTINUOUS_WORKERS` or increase `CONTINUOUS_TEST_INTERVAL`. |

## 📄 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) for the proxy core.
- The V2Ray community for VLESS protocol.

 

