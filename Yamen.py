#!/usr/bin/env python3
"""
V2Ray MASSIVELY PARALLEL Config Selector + CONTINUOUS OPTIMIZATION
====================================================================
Requirements: pip install requests pysocks
Add Proxy SwitchyOmega 3 (ZeroOmega) to chrome :
https://chromewebstore.google.com/detail/proxy-switchyomega-3-zero/pfnededegaaopdmhkdmcofjmoldfiped
"""

import os
import sys
import time
import json
import base64
import re
import socket
import ssl
import tempfile
import subprocess
import concurrent.futures
import atexit
import threading
from pathlib import Path
from urllib.parse import parse_qs
from datetime import datetime
from collections import deque

import requests
import socks
import zipfile
import io
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ==================== 📦 AUTO-DOWNLOAD XRAY ====================
def download_xray(target_dir: str = "vendor", version: str = "latest"):
    """Download official Xray-core Windows executable."""
    target_path = Path(target_dir)
    target_path.mkdir(parents=True, exist_ok=True)
    
    exe_path = target_path / "xray.exe"
    if exe_path.exists() and exe_path.stat().st_size > 10_000_000:  # >10MB = likely valid
        print(f"✅ xray.exe already exists: {exe_path}")
        return str(exe_path)
    
    print(f"📦 Downloading Xray-core ({version})...")
    
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    # ✅ FIXED: Stripped trailing spaces from URL
    if version.lower() == "latest":
        download_url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip".strip()
    else:
        download_url = f"https://github.com/XTLS/Xray-core/releases/download/{version}/Xray-windows-64.zip".strip()
    
    try:
        r = session.get(download_url, timeout=120, stream=True)  # Increased timeout
        r.raise_for_status()
        
        print("📦 Extracting xray.exe...")
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            for file_info in z.infolist():
                if file_info.filename.endswith("xray.exe"):
                    with z.open(file_info) as source, open(exe_path, "wb") as target:
                        target.write(source.read())
                    # Make executable (Windows doesn't need chmod, but good practice)
                    if os.name != 'nt':
                        os.chmod(exe_path, 0o755)
                    print(f"✅ xray.exe saved to {exe_path}")
                    return str(exe_path)
        print("❌ xray.exe not found in archive")
        return None
    except Exception as e:
        print(f"❌ Download failed: {e}")
        return None


# ==================== 🎛️ USER CONFIGURATION ====================
# ✅ FIXED: Auto-download Xray and set correct path
Model_Path = r"D:/proxy/vendor"
xray_exe = download_xray(target_dir=Model_Path)
if not xray_exe:
    print("❌ Failed to download Xray. Please download manually from:")
    print("   https://github.com/XTLS/Xray-core/releases")
    sys.exit(1)

# ✅ FIXED: XRAY_PATH now points to the EXE file, not folder
XRAY_PATH = Path(xray_exe)
print(f"🔧 Using Xray: {XRAY_PATH}")

# ✅ FIXED: All URLs stripped of trailing spaces
SUBSCRIPTION_URL = "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/refs/heads/main/configs/vless_sub.txt".strip()

# Main stable VPN port
SOCKS5_HOST = "127.0.0.1"
SOCKS5_PORT = 10808

# Parallel test ports
TEST_PORT_START = 20808
TEST_PORT_COUNT = 100

# ===== DISCOVERY SETTINGS =====
# ✅ FIXED: Reduced to safer defaults (adjust up if your system can handle it)
DISCOVERY_BATCH_SIZE = 50           # Test 50 configs in parallel initially
DISCOVERY_TIMEOUT = 10              # Seconds per discovery test
PRE_FILTER_TIMEOUT = 3.0            # Lightweight pre-check timeout
PRE_FILTER_WORKERS = 50             # Parallel pre-filter workers

# ===== CONTINUOUS TESTING =====
CONTINUOUS_TEST_ENABLED = True
CONTINUOUS_TEST_INTERVAL = 30
CONTINUOUS_BATCH_SIZE = 20
CONTINUOUS_WORKERS = 20

# ===== AUTO-UPGRADE =====
AUTO_UPGRADE_ENABLED = True
AUTO_UPGRADE_THRESHOLD = 0.3
MIN_SPEED_FOR_UPGRADE = 2.0
UPGRADE_COOLDOWN = 300

# ===== TEST THRESHOLDS =====
MIN_SPEED_MBPS = 0.5
MAX_LATENCY_MS = 500
# ✅ FIXED: Stripped trailing space
VALIDATION_URL = "https://www.google.com".strip()
SPEED_TEST_URL = "http://speedtest.tele2.net/1MB.zip".strip()
SPEED_TEST_TIMEOUT = 20
DOWNLOAD_LIMIT = 512 * 1024

# ===== LOGGING =====
TEST_HISTORY_SIZE = 100
SAVE_TEST_LOG = True
TEST_LOG_FILE = "test_history.json"

# ===== DISPLAY =====
SHOW_TOP_N = 30
XRAY_STARTUP_DELAY = 1.5  # Increased for reliability

# ==================== 🔚 END CONFIGURATION ====================


# ==================== 🌍 GLOBAL STATE ====================
class VPNState:
    def __init__(self):
        self.stable_vpn_proc = None
        self.stable_config = None
        self.stable_test_results = None
        self.all_configs = []
        self.tested_configs = []
        self.best_config = None
        self.is_running = True
        self.continuous_thread = None
        self.lock = threading.Lock()
        self.test_port_index = 0
        self.discovery_complete = False
        self.last_upgrade_time = 0
        self.test_history = deque(maxlen=TEST_HISTORY_SIZE)
        self.continuous_round = 0
        self.config_test_count = {}
        self.config_last_tested = {}

state = VPNState()


# ==================== 🔐 PORT MANAGEMENT ====================
def is_port_in_use(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def kill_xray_processes():
    try:
        subprocess.run(f'taskkill /F /IM xray.exe', shell=True, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                      creationflags=subprocess.CREATE_NO_WINDOW)
        time.sleep(0.5)
    except:
        pass


def ensure_port_free(host, port):
    if not is_port_in_use(host, port):
        return True
    kill_xray_processes()
    time.sleep(0.5)
    return not is_port_in_use(host, port)


def get_next_test_port():
    with state.lock:
        port = TEST_PORT_START + state.test_port_index
        state.test_port_index = (state.test_port_index + 1) % TEST_PORT_COUNT
        return port


# ==================== 📡 SUBSCRIPTION & PARSING ====================
def fetch_subscription(url):
    print(f"📡 Fetching subscription...")
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        content = resp.text.strip()
        try:
            content = base64.b64decode(content).decode('utf-8')
        except:
            pass
        return content.splitlines()
    except Exception as e:
        print(f"❌ Fetch failed: {e}")
        return []


def parse_vless_uri(uri):
    if not uri.startswith('vless://'):
        return None
    try:
        without_scheme = uri[8:]
        if '#' in without_scheme:
            config_part, tag = without_scheme.split('#', 1)
        else:
            config_part, tag = without_scheme, ''
        if '@' in config_part:
            uuid, host_part = config_part.split('@', 1)
        else:
            return None
        if '?' in host_part:
            authority, query = host_part.split('?', 1)
            params = {k: v[0] if v else '' for k, v in parse_qs(query).items()}
        else:
            authority, params = host_part, {}
        if ':' in authority:
            host, port_str = authority.rsplit(':', 1)
            port = int(re.match(r'\d+', port_str).group()) if re.match(r'\d+', port_str) else 443
        else:
            host, port = authority, 443
        
        return {
            'uri': uri,
            'tag': tag or f"{host}:{port}",
            'address': host,
            'port': port,
            'id': uuid,
            'security': params.get('security', 'none'),
            'sni': params.get('sni', params.get('host', host)),
            'network': params.get('type', 'tcp'),
            'path': params.get('path', '/'),
            'fp': params.get('fp', 'chrome'),
            'host': params.get('host', ''),
            'flow': params.get('flow', ''),
        }
    except Exception as e:
        print(f"⚠️ Parse error: {e}")
        return None


# ==================== 🔍 LIGHTWEIGHT PRE-FILTER ====================
def pre_filter_config(cfg):
    host, port = cfg['address'], cfg['port']
    security = cfg['security']
    
    try:
        start = time.time()
        socket.getaddrinfo(host, port)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PRE_FILTER_TIMEOUT)
        sock.connect((host, port))
        
        if security == 'tls':
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=cfg['sni'], do_handshake_on_connect=True)
        
        latency_ms = (time.time() - start) * 1000
        sock.close()
        return (cfg, latency_ms, None)
    except socket.timeout:
        return (cfg, None, 'timeout')
    except socket.gaierror:
        return (cfg, None, 'dns_fail')
    except ssl.SSLError as e:
        return (cfg, None, f'tls:{str(e)[:20]}')
    except ConnectionRefusedError:
        return (cfg, None, 'conn_refused')
    except Exception as e:
        return (cfg, None, str(e)[:30])


def run_pre_filter(configs):
    print(f"🔍 Pre-filtering {len(configs)} configs ({PRE_FILTER_WORKERS} workers)...")
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=PRE_FILTER_WORKERS) as executor:
        futures = {executor.submit(pre_filter_config, cfg): cfg for cfg in configs}
        
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            cfg, latency, error = future.result()
            if latency:
                results.append({'config': cfg, 'pre_latency': latency})
                tag = cfg['tag'][:30] + '...' if len(cfg['tag']) > 30 else cfg['tag']
                print(f"\r   ✅ {tag:<33} {latency:6.1f}ms ({i}/{len(configs)})", end='', flush=True)
            else:
                tag = cfg['tag'][:30] + '...' if len(cfg['tag']) > 30 else cfg['tag']
                print(f"\r   ❌ {tag:<33} {error:<15} ({i}/{len(configs)})", end='', flush=True)
    
    print(f"\n✅ Pre-filter: {len(results)}/{len(configs)} reachable")
    return sorted(results, key=lambda x: x['pre_latency'])


# ==================== ⚙️ XRAY CONFIG ====================
def create_xray_config(parsed_config, socks_port):
    stream = {"network": parsed_config['network'], "security": parsed_config['security']}
    if parsed_config['security'] == 'tls':
        stream['tlsSettings'] = {
            "serverName": parsed_config['sni'],
            "fingerprint": parsed_config.get('fp', 'chrome'),
        }
    if parsed_config['network'] == 'ws':
        stream['wsSettings'] = {
            "path": parsed_config['path'],
            "headers": {"Host": parsed_config.get('host', parsed_config['address'])}
        }
    outbound = {
        "protocol": "vless",
        "settings": {"vnext": [{"address": parsed_config['address'], "port": parsed_config['port'],
            "users": [{"id": parsed_config['id'], "encryption": "none", "flow": parsed_config.get('flow', '')}]}]},
        "streamSettings": stream
    }
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"port": socks_port, "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}]
    }


def start_xray_instance(cfg, socks_port, config_file=None):
    """Start Xray instance. Returns (proc, config_file) or (None, config_file)."""
    config_json = create_xray_config(cfg, socks_port)
    
    if config_file:
        with open(config_file, 'w') as f:
            json.dump(config_json, f, indent=2)
        cmd = [str(XRAY_PATH), '-c', config_file]
    else:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_json, f)
            config_file = f.name
        cmd = [str(XRAY_PATH), '-c', config_file]
    
    try:
        # ✅ FIXED: Better process startup with error capture
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        time.sleep(XRAY_STARTUP_DELAY)
        
        # Check if process is still running
        if proc.poll() is not None:
            # Process exited – get error output
            stdout, stderr = proc.communicate(timeout=2)
            error_msg = stderr.decode('utf-8', errors='ignore').strip()[:200] if stderr else "unknown error"
            print(f"⚠️  Xray failed to start: {error_msg}")
            return None, config_file
        
        print(f"   🟢 Xray started (PID: {proc.pid}) on port {socks_port}")
        return proc, config_file
    except FileNotFoundError:
        print(f"❌ Xray executable not found: {XRAY_PATH}")
        return None, config_file
    except PermissionError:
        print(f"❌ Permission denied to run: {XRAY_PATH}")
        return None, config_file
    except Exception as e:
        print(f"❌ Failed to start Xray: {e}")
        return None, config_file


def stop_xray_instance(proc, config_file=None):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
    if config_file and os.path.exists(config_file):
        try:
            os.unlink(config_file)
        except:
            pass


# ==================== 🧪 FULL CONFIG TEST (WITH BETTER DEBUG) ====================
def test_config_full(cfg, test_port):
    results = {
        'config': cfg,
        'test_port': test_port,
        'valid': False,
        'latency': None,
        'speed': None,
        'score': 0,
        'error': None,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'debug': []
    }
    
    proc, config_file = None, None
    try:
        # Start Xray
        results['debug'].append("Starting Xray...")
        proc, config_file = start_xray_instance(cfg, test_port)
        if not proc:
            results['error'] = 'xray_start_failed'
            results['debug'].append("Xray failed to start")
            return results
        
        results['debug'].append("Xray running, testing validity...")
        
        # Test 1: Validity
        try:
            proxies = {'http': f'socks5h://127.0.0.1:{test_port}', 
                       'https': f'socks5h://127.0.0.1:{test_port}'}
            start = time.time()
            resp = requests.get(VALIDATION_URL, proxies=proxies, timeout=5)
            results['valid'] = (resp.status_code == 200)
            results['latency'] = (time.time() - start) * 1000
            results['debug'].append(f"Validity: {resp.status_code}")
        except requests.exceptions.ProxyError as e:
            results['error'] = f'proxy_error:{str(e)[:30]}'
            results['debug'].append(f"Proxy error: {e}")
            return results
        except requests.exceptions.Timeout:
            results['error'] = 'validation_timeout'
            results['debug'].append("Validation timeout")
            return results
        except Exception as e:
            results['error'] = f'validity:{str(e)[:30]}'
            results['debug'].append(f"Validity error: {e}")
            return results
        
        if not results['valid']:
            results['error'] = 'cannot_reach_internet'
            results['debug'].append("Cannot reach internet")
            return results
        
        # Test 2: Speed
        results['debug'].append("Testing speed...")
        try:
            start = time.time()
            downloaded = 0
            resp = requests.get(SPEED_TEST_URL, proxies=proxies, stream=True, timeout=SPEED_TEST_TIMEOUT)
            for chunk in resp.iter_content(chunk_size=1024*1024):
                if chunk:
                    downloaded += len(chunk)
                    if downloaded >= DOWNLOAD_LIMIT:
                        break
            elapsed = time.time() - start
            if elapsed > 0 and downloaded > 0:
                results['speed'] = (downloaded * 8) / (elapsed * 1024 * 1024)
            results['debug'].append(f"Downloaded {downloaded} bytes in {elapsed:.2f}s")
        except Exception as e:
            results['speed'] = 0.0
            results['debug'].append(f"Speed test error: {e}")
        
        # Calculate score
        speed_score = min(results['speed'] or 0, 50) * 2
        latency_score = max(0, (500 - results['latency']) / 5) if results['latency'] else 0
        results['score'] = (speed_score * 0.7) + (latency_score * 0.3)
        
    except Exception as e:
        results['error'] = str(e)[:50]
        results['debug'].append(f"Unexpected error: {e}")
    finally:
        stop_xray_instance(proc, config_file)
        results['debug'].append("Xray stopped")
    
    return results


# ==================== 🔄 CONTINUOUS PARALLEL TESTING ====================
def get_configs_for_continuous_testing():
    with state.lock:
        tested_uris = {r['config']['uri'] for r in state.tested_configs}
        now = time.time()
        
        untested = [c for c in state.all_configs if c['uri'] not in tested_uris]
        
        old_tested = []
        for cfg in state.all_configs:
            uri = cfg['uri']
            last_tested = state.config_last_tested.get(uri, 0)
            if last_tested > 0 and (now - last_tested) > 300:
                old_tested.append(cfg)
        
        if len(untested) >= CONTINUOUS_BATCH_SIZE:
            candidates = untested[:CONTINUOUS_BATCH_SIZE]
        elif len(untested) + len(old_tested) >= CONTINUOUS_BATCH_SIZE:
            candidates = (untested + old_tested)[:CONTINUOUS_BATCH_SIZE]
        else:
            candidates = state.all_configs[:CONTINUOUS_BATCH_SIZE]
        
        filtered = []
        for cfg in candidates:
            uri = cfg['uri']
            count = state.config_test_count.get(uri, 0)
            last_tested = state.config_last_tested.get(uri, 0)
            if count > 5 and (now - last_tested) < 600:
                continue
            filtered.append(cfg)
        
        return filtered[:CONTINUOUS_BATCH_SIZE]


def run_continuous_test_round():
    if not state.is_running or not CONTINUOUS_TEST_ENABLED:
        return []
    
    with state.lock:
        state.continuous_round += 1
        round_num = state.continuous_round
    
    candidates = get_configs_for_continuous_testing()
    if not candidates:
        return []
    
    print(f"\n🔍 Continuous Test Round #{round_num} ({len(candidates)} configs)...")
    
    test_ports = [get_next_test_port() for _ in candidates]
    new_results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONTINUOUS_WORKERS) as executor:
        futures = {
            executor.submit(test_config_full, cfg, test_ports[i]): i 
            for i, cfg in enumerate(candidates)
        }
        
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            completed += 1
            state.test_history.append(result)
            
            if result['valid']:
                new_results.append(result)
                uri = result['config']['uri']
                with state.lock:
                    state.config_test_count[uri] = state.config_test_count.get(uri, 0) + 1
                    state.config_last_tested[uri] = time.time()
                
                existing = next((r for r in state.tested_configs if r['config']['uri'] == uri), None)
                if existing:
                    existing.update(result)
                else:
                    state.tested_configs.append(result)
                
                tag = result['config']['tag'][:25] + '...' if len(result['config']['tag']) > 25 else result['config']['tag']
                print(f"\r   ✅ {tag:<28} ⏱️{result['latency']:6.0f}ms 🚀{result['speed']:6.2f}Mbps ({completed}/{len(candidates)})", end='', flush=True)
            else:
                tag = result['config']['tag'][:25] + '...' if len(result['config']['tag']) > 25 else result['config']['tag']
                error_short = result.get('error', 'failed')[:15]
                print(f"\r   ❌ {tag:<28} {error_short:<15} ({completed}/{len(candidates)})", end='', flush=True)
    
    print(f"\n✅ Round #{round_num}: {len(new_results)}/{len(candidates)} working")
    
    if new_results and AUTO_UPGRADE_ENABLED and state.stable_config:
        check_for_auto_upgrade(new_results)
    
    if SAVE_TEST_LOG:
        save_test_log()
    
    return new_results


def check_for_auto_upgrade(new_results):
    with state.lock:
        if time.time() - state.last_upgrade_time < UPGRADE_COOLDOWN:
            return
        
        stable_score = state.stable_test_results.get('score', 0) if state.stable_test_results else 0
        best_new = max(new_results, key=lambda x: x.get('score', 0))
        new_score = best_new.get('score', 0)
        new_speed = best_new.get('speed', 0) or 0
        
        should_upgrade = (
            (new_score > stable_score * (1 + AUTO_UPGRADE_THRESHOLD)) or
            (new_speed >= MIN_SPEED_FOR_UPGRADE and stable_score < 50)
        )
        
        if should_upgrade:
            print(f"\n🎯 BETTER CONFIG FOUND!")
            print(f"   Current: {state.stable_config['tag'][:30]} (score: {stable_score:.1f})")
            print(f"   New:     {best_new['config']['tag'][:30]} (score: {new_score:.1f})")
            print(f"   Improvement: {((new_score - stable_score) / stable_score * 100):.1f}%")
            
            if switch_to_config(best_new['config'], best_new):
                state.last_upgrade_time = time.time()
                print(f"✅ Auto-upgrade successful!")
            else:
                print(f"❌ Auto-upgrade failed")


def continuous_test_thread():
    print(f"\n🔄 Continuous testing started (interval: {CONTINUOUS_TEST_INTERVAL}s)")
    
    while state.is_running:
        time.sleep(CONTINUOUS_TEST_INTERVAL)
        if not state.is_running:
            break
        
        if not state.stable_vpn_proc or state.stable_vpn_proc.poll() is not None:
            print(f"\n⚠️  Stable VPN died! Attempting recovery...")
            if state.tested_configs:
                working = [r for r in state.tested_configs if r.get('valid')]
                if working:
                    best = max(working, key=lambda x: x.get('score', 0))
                    print(f"   Recovering with: {best['config']['tag'][:40]}")
                    proc, _ = start_xray_instance(best['config'], SOCKS5_PORT, "stable_config.json")
                    if proc:
                        state.stable_vpn_proc = proc
                        state.stable_config = best['config']
                        state.stable_test_results = best
                        print(f"   ✅ VPN recovered!")
                    else:
                        print(f"   ❌ Recovery failed")
            continue
        
        run_continuous_test_round()
        
        if state.continuous_round % 3 == 0:
            display_status()


# ==================== 🔄 SEAMLESS CONFIG SWITCH ====================
def switch_to_config(new_config, new_results):
    with state.lock:
        print(f"\n🔄 Switching to better config...")
        
        new_proc, new_config_file = start_xray_instance(new_config, SOCKS5_PORT, "stable_config.json")
        if not new_proc:
            print(f"❌ Failed to start new config")
            return False
        
        success, _ = test_proxy_connection(SOCKS5_PORT, timeout=5)
        if success:
            if state.stable_vpn_proc:
                stop_xray_instance(state.stable_vpn_proc)
            state.stable_vpn_proc = new_proc
            state.stable_config = new_config
            state.stable_test_results = new_results
            print(f"✅ Switched to: {new_config['tag'][:40]}")
            return True
        else:
            stop_xray_instance(new_proc, new_config_file)
            print(f"❌ New config failed validation")
            return False


def test_proxy_connection(socks_port, timeout=10):
    try:
        proxies = {'http': f'socks5h://127.0.0.1:{socks_port}', 
                   'https': f'socks5h://127.0.0.1:{socks_port}'}
        resp = requests.get(VALIDATION_URL, proxies=proxies, timeout=timeout)
        return (resp.status_code == 200, None)
    except Exception as e:
        return (False, str(e))


# ==================== 📝 TEST LOGGING ====================
def save_test_log():
    try:
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'stable_config': state.stable_config['tag'] if state.stable_config else None,
            'total_tested': len(state.tested_configs),
            'working_count': sum(1 for t in state.tested_configs if t.get('valid')),
            'recent_tests': list(state.test_history)[-20:]
        }
        existing = []
        if os.path.exists(TEST_LOG_FILE):
            try:
                with open(TEST_LOG_FILE, 'r') as f:
                    existing = json.load(f)
            except:
                existing = []
        existing.append(log_data)
        existing = existing[-100:]
        with open(TEST_LOG_FILE, 'w') as f:
            json.dump(existing, f, indent=2, default=str)
    except Exception as e:
        print(f"⚠️  Failed to save test log: {e}")


# ==================== 📊 STATUS DISPLAY ====================
def display_status():
    print("\n" + "=" * 70)
    print("📊 VPN STATUS")
    print("=" * 70)
    
    with state.lock:
        if state.stable_vpn_proc and state.stable_vpn_proc.poll() is None:
            print(f"✅ VPN: RUNNING (PID: {state.stable_vpn_proc.pid})")
        else:
            print(f"❌ VPN: STOPPED")
        
        if state.stable_config:
            print(f"📝 Config: {state.stable_config['tag']}")
            uri = state.stable_config['uri']
            print(f"🔗 URI: {uri[:70]}...")
        
        if state.stable_test_results:
            r = state.stable_test_results
            print(f"\n📈 Performance:")
            print(f"   ⏱️  Latency: {r.get('latency', 'N/A')}ms")
            print(f"   🚀 Speed:    {r.get('speed', 'N/A')}Mbps")
            print(f"   📊 Score:    {r.get('score', 'N/A'):.1f}")
        
        print(f"\n📋 Testing Stats:")
        print(f"   Total configs: {len(state.all_configs)}")
        print(f"   Tested: {len(state.tested_configs)}")
        working = sum(1 for t in state.tested_configs if t.get('valid'))
        print(f"   ✅ Working: {working}")
        print(f"   🏆 Best score: {max((t.get('score', 0) for t in state.tested_configs), default=0):.1f}")
        print(f"   🔄 Continuous rounds: {state.continuous_round}")
        print(f"   ⏱️  Last upgrade: {time.time() - state.last_upgrade_time:.0f}s ago")
    
    show_connected_programs()
    print("=" * 70)


def show_connected_programs():
    if os.name != 'nt':
        return
    print(f"\n📡 Programs Using Proxy @ {SOCKS5_HOST}:{SOCKS5_PORT}")
    print(f"   {'PROGRAM':<28} {'PID':<10} {'TIME'}")
    print("   " + "-" * 48)
    try:
        cmd = f'netstat -ano | findstr :{SOCKS5_PORT} | findstr ESTABLISHED'
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, 
                                        creationflags=subprocess.CREATE_NO_WINDOW)
        lines = output.decode('cp437', errors='ignore').strip().split('\n')
        pids = set()
        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                try:
                    pids.add(int(parts[-1]))
                except:
                    pass
        for pid in pids:
            try:
                cmd = f'wmic process where "ProcessId={pid}" get Name /value'
                output = subprocess.check_output(cmd, shell=True, creationflags=subprocess.CREATE_NO_WINDOW, 
                                                stderr=subprocess.DEVNULL)
                text = output.decode('cp437', errors='ignore')
                match = re.search(r'Name=(\S+)', text)
                exe = match.group(1) if match else 'unknown.exe'
                print(f"   {exe:<28} {pid:<10} {time.strftime('%H:%M:%S')}")
            except:
                pass
        if not pids:
            print(f"   {'(no active connections)':<28} {'-':<10} {time.strftime('%H:%M:%S')}")
    except:
        pass


# ==================== 🎯 MAIN ====================
def run_parallel_discovery(configs, batch_size=DISCOVERY_BATCH_SIZE):
    print(f"\n🚀 PHASE 1: PARALLEL DISCOVERY ({min(batch_size, len(configs))} configs in parallel)")
    print(f"   Using ports {TEST_PORT_START}-{TEST_PORT_START + min(batch_size, len(configs)) - 1}")
    
    candidates = configs[:batch_size]
    test_ports = list(range(TEST_PORT_START, TEST_PORT_START + len(candidates)))
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(candidates)) as executor:
        futures = {
            executor.submit(test_config_full, item['config'], test_ports[i]): item 
            for i, item in enumerate(candidates)
        }
        
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            completed += 1
            results.append(result)
            
            tag = result['config']['tag'][:30] + '...' if len(result['config']['tag']) > 30 else result['config']['tag']
            status = "✅" if result['valid'] else "❌"
            speed_str = f"{result['speed']:.2f}Mbps" if result['speed'] else "N/A"
            latency_str = f"{result['latency']:.0f}ms" if result['latency'] else "N/A"
            error_str = result.get('error', '')[:10] if not result['valid'] else ''
            print(f"\r   {status} {tag:<30} ⏱️{latency_str:<8} 🚀{speed_str:<10} {error_str:<10} ({completed}/{len(candidates)})", end='', flush=True)
    
    print(f"\n✅ Discovery complete: {sum(1 for r in results if r['valid'])}/{len(results)} working")
    return results


def main():
    print("=" * 70)
    print("🚀 V2Ray MASSIVELY PARALLEL Config Selector [FIXED]")
    print("   ✅ XRAY_PATH fixed | ✅ URLs stripped | ✅ Better error reporting")
    print("=" * 70)
    print(f"📍 Stable Proxy: {SOCKS5_HOST}:{SOCKS5_PORT}")
    print(f"🔧 Xray: {XRAY_PATH}")
    print(f"⚡ Discovery: {DISCOVERY_BATCH_SIZE} workers | 🔄 Continuous: {CONTINUOUS_WORKERS} workers")
    print()

    # === Cleanup & Port Check ===
    print("🧹 Cleaning up old Xray processes...")
    kill_xray_processes()
    time.sleep(0.5)
    
    if not ensure_port_free(SOCKS5_HOST, SOCKS5_PORT):
        print(f"❌ Port {SOCKS5_HOST}:{SOCKS5_PORT} still in use")
        sys.exit(1)

    # === Check Xray ===
    if not XRAY_PATH.exists():
        print(f"❌ Xray not found: {XRAY_PATH}")
        print("💡 The auto-downloader should have fetched it. Try running as Administrator.")
        sys.exit(1)
    
    # Verify it's executable
    if not os.access(XRAY_PATH, os.X_OK) and os.name != 'nt':
        print(f"⚠️  Xray not executable, fixing permissions...")
        os.chmod(XRAY_PATH, 0o755)

    # === Fetch & Parse ===
    lines = fetch_subscription(SUBSCRIPTION_URL)
    if not lines:
        sys.exit(1)
    
    state.all_configs = [parse_vless_uri(line.strip()) for line in lines if line.strip().startswith('vless://')]
    state.all_configs = [c for c in state.all_configs if c]
    print(f"✅ Parsed {len(state.all_configs)} valid configs\n")
    
    if not state.all_configs:
        print("❌ No valid configs")
        sys.exit(1)

    # === Pre-Filter ===
    pre_filtered = run_pre_filter(state.all_configs)
    if not pre_filtered:
        print("\n❌ No configs passed pre-filter")
        print("💡 Check your internet connection or subscription URL")
        sys.exit(1)

    # === PHASE 1: Parallel Discovery ===
    discovery_results = run_parallel_discovery(pre_filtered, DISCOVERY_BATCH_SIZE)
    state.tested_configs = [r for r in discovery_results if r['valid']]
    
    if not state.tested_configs:
        print("\n❌ No working configs found in discovery")
        print("\n🔍 Debug info for first 3 failed configs:")
        for r in discovery_results[:3]:
            print(f"   • {r['config']['tag'][:40]}")
            print(f"     Error: {r.get('error', 'unknown')}")
            if r.get('debug'):
                for d in r['debug'][-3:]:
                    print(f"     → {d}")
        print("\n💡 Tips:")
        print("   1. Run CMD as Administrator")
        print("   2. Allow Xray through Windows Firewall")
        print("   3. Try reducing DISCOVERY_BATCH_SIZE to 20")
        print("   4. Check if your subscription configs are still valid")
        sys.exit(1)

    # === PHASE 2: Lock Best Config ===
    print(f"\n" + "=" * 70)
    print("🚀 PHASE 2: LOCKING BEST CONFIG FOR STABLE VPN")
    print("=" * 70)
    
    state.tested_configs.sort(key=lambda x: x.get('score', 0), reverse=True)
    best = state.tested_configs[0]
    
    print(f"\n🏆 Best config: {best['config']['tag']}")
    print(f"   ⏱️  Latency: {best['latency']:.1f}ms")
    print(f"   🚀 Speed:    {best['speed']:.2f}Mbps")
    print(f"   📊 Score:    {best['score']:.1f}")
    
    print(f"\n🔒 Starting stable VPN on port {SOCKS5_PORT}...")
    proc, config_file = start_xray_instance(best['config'], SOCKS5_PORT, "stable_config.json")
    
    if not proc:
        print("❌ Failed to start stable VPN")
        sys.exit(1)
    
    success, _ = test_proxy_connection(SOCKS5_PORT)
    if not success:
        print("❌ Stable config failed validation, trying backups...")
        for backup in state.tested_configs[1:5]:
            stop_xray_instance(proc)
            proc, config_file = start_xray_instance(backup['config'], SOCKS5_PORT, "stable_config.json")
            success, _ = test_proxy_connection(SOCKS5_PORT)
            if success:
                best = backup
                break
        if not success:
            print("❌ No backup configs working")
            sys.exit(1)
    
    state.stable_vpn_proc = proc
    state.stable_config = best['config']
    state.stable_test_results = best
    
    print(f"✅ Stable VPN running on {SOCKS5_HOST}:{SOCKS5_PORT}")
    display_status()

    # === PHASE 3: Continuous Testing ===
    if CONTINUOUS_TEST_ENABLED:
        print(f"\n" + "=" * 70)
        print("🔄 PHASE 3: CONTINUOUS PARALLEL TESTING STARTED")
        print("=" * 70)
        state.continuous_thread = threading.Thread(target=continuous_test_thread, daemon=True)
        state.continuous_thread.start()

    # === Keep Alive ===
    atexit.register(lambda: stop_xray_instance(state.stable_vpn_proc, "stable_config.json"))
    
    print(f"\n💡 VPN is stable! Configure apps to use: {SOCKS5_HOST}:{SOCKS5_PORT}")
    print("   Commands: 's'=status, 't'=test, 'c'=continuous, 'q'=quit, Ctrl+C=exit\n")
    
    try:
        while state.is_running:
            if os.name == 'nt':
                import msvcrt
                if msvcrt.kbhit():
                    cmd = msvcrt.getch().decode('utf-8').strip().lower()
                    if cmd == 's':
                        display_status()
                    elif cmd == 't':
                        print("\n🧪 Manual test...")
                        success, _ = test_proxy_connection(SOCKS5_PORT)
                        print(f"   Result: {'✅ PASS' if success else '❌ FAIL'}")
                    elif cmd == 'c':
                        print(f"\n📊 Continuous: Round {state.continuous_round}, {len(state.tested_configs)} tested")
                    elif cmd == 'q':
                        state.is_running = False
                        break
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n\n🛑 Interrupted")
        state.is_running = False

    print("\n🛑 Stopping VPN...")
    stop_xray_instance(state.stable_vpn_proc, "stable_config.json")
    kill_xray_processes()
    if SAVE_TEST_LOG:
        save_test_log()
        print(f"📝 Log saved to {TEST_LOG_FILE}")
    print("✅ Done")


if __name__ == "__main__":
    if os.name == 'nt':
        os.system('')
    main()
