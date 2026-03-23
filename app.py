import os
import time
import subprocess
from flask import Flask, render_template, jsonify, request, send_from_directory
from scanner import ScannerController, _load_events, EVENTS_FILE
import platform
import shutil
from datetime import datetime
import psutil
import wmi
import win32serviceutil
import win32service
import win32security
import win32api
import win32con
import socket
import uuid
import re
import json
from pathlib import Path
import getpass


app = Flask(__name__)

# ── In-process scanner fallback (used only if service is not installed) ───────
_fallback_scanner = None

# ── Service name must match scanner_service.py ────────────────────────────────
_SERVICE_NAME        = "FileScannerService"
_SCANNER_SERVICE_PY  = os.path.join(os.path.dirname(__file__), 'scanner_service.py')
_SERVICE_STATUS_FILE = os.path.join(os.path.dirname(__file__), 'scanner_service_status.json')


# ═════════════════════════════════════════════════════════════════════════════
# Service helpers
# ═════════════════════════════════════════════════════════════════════════════

def _service_installed() -> bool:
    """Return True if FileScannerService is registered with the SCM."""
    try:
        win32serviceutil.QueryServiceStatus(_SERVICE_NAME)
        return True
    except Exception:
        return False


def _service_running() -> bool:
    """Return True if the Windows Service is currently in RUNNING state."""
    try:
        status = win32serviceutil.QueryServiceStatus(_SERVICE_NAME)
        return status[1] == win32service.SERVICE_RUNNING
    except Exception:
        return False


def _start_service() -> dict:
    """
    Start FileScannerService via SCM.
    Returns {'ok': True} or {'ok': False, 'error': '...'}.
    """
    try:
        win32serviceutil.StartService(_SERVICE_NAME)
        # Wait up to 5 s for SERVICE_RUNNING
        for _ in range(10):
            time.sleep(0.5)
            if _service_running():
                return {'ok': True}
        return {'ok': False, 'error': 'Service did not reach RUNNING state in time.'}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def _stop_service() -> dict:
    """
    Stop FileScannerService via SCM.
    Returns {'ok': True} or {'ok': False, 'error': '...'}.
    """
    try:
        win32serviceutil.StopService(_SERVICE_NAME)
        # Wait up to 5 s for SERVICE_STOPPED
        for _ in range(10):
            time.sleep(0.5)
            status = win32serviceutil.QueryServiceStatus(_SERVICE_NAME)
            if status[1] == win32service.SERVICE_STOPPED:
                return {'ok': True}
        return {'ok': False, 'error': 'Service did not reach STOPPED state in time.'}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def is_clamav_available():
    try:
        clamscan_path = r"C:\ClamAV\clamav-1.5.1.win.x64\clamscan.exe"
        result = subprocess.run([clamscan_path, "--version"], capture_output=True, text=True)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError):
        return False

CLAMAV_AVAILABLE = is_clamav_available()
try:
    import clamd
    CLAMAV_AVAILABLE = True
except ImportError:
    CLAMAV_AVAILABLE = False

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

QUARANTINE_DIR = os.path.join(os.path.dirname(__file__), 'quarantine')
os.makedirs(QUARANTINE_DIR, exist_ok=True)
MANUAL_SCAN_REPORTS_FILE = os.path.join(os.path.dirname(__file__), 'manual_scan_reports.json')

_DEFENDER_KEYWORDS = {
    'windows defender', 'microsoft defender',
    'windows firewall', 'microsoft security essentials'
}


def get_active_antivirus():
    """
    Returns only antivirus products that are CURRENTLY ACTIVE.

    How productState works (Windows Security Center):
      productState is a 3-byte hex integer, e.g. 0x1E2100
      Byte 1 (bits 16-23): product type   (0x10 = AV, 0x20 = Firewall, etc.)
      Byte 2 (bits 8-15):  engine state   (0x10 = enabled, 0x00 = disabled)
      Byte 3 (bits 0-7):   definition state (0x00 = up to date, 0x10 = out of date)

      So engine byte = (productState >> 8) & 0xFF
      0x10 = enabled/ON  →  active AV
      0x00 = disabled    →  inactive (e.g. expired/uninstalled McAfee)

    We ALSO confirm the AV brand has a running Windows service as a second check.
    """
    active_av = []

    # ── Step 1: Query Windows Security Center ─────────────────────────
    try:
        sc = subprocess.run(
            ["powershell", "-Command",
             "Get-CimInstance -Namespace root/SecurityCenter2 "
             "-ClassName AntiVirusProduct "
             "| Select-Object displayName, productState "
             "| ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=15
        )

        if sc.returncode == 0 and sc.stdout.strip():
            raw = sc.stdout.strip()
            if raw.startswith('{'):
                raw = '[' + raw + ']'
            products = json.loads(raw)

            for product in products:
                name = (product.get('displayName') or '').strip()
                if not name:
                    continue

                name_lower = name.lower()

                if any(kw in name_lower for kw in _DEFENDER_KEYWORDS):
                    continue

                try:
                    state_val = int(product.get('productState', 0))
                    engine_byte = (state_val >> 8) & 0xFF
                    if engine_byte != 0x10:
                        print(f"AV '{name}' has engine_byte=0x{engine_byte:02X} — not active, skipping")
                        continue
                except (TypeError, ValueError):
                    continue

                if name not in active_av:
                    active_av.append(name)

    except Exception as e:
        print(f"Security Center AV query failed: {e}")

    # ── Step 2: Cross-check with running services ──────────────────────
    if active_av:
        try:
            svc_result = subprocess.run(
                ["powershell", "-Command",
                 "Get-Service | Where-Object {$_.Status -eq 'Running'} "
                 "| Select-Object -ExpandProperty DisplayName"],
                capture_output=True, text=True, timeout=10
            )
            running_services = svc_result.stdout.lower() if svc_result.returncode == 0 else ""

            confirmed = []
            for av_name in active_av:
                brand = av_name.lower().split()[0]
                if brand in running_services:
                    confirmed.append(av_name)
                else:
                    print(f"AV '{av_name}' brand '{brand}' not found in running services — skipping")

            if confirmed:
                active_av = confirmed

        except Exception as e:
            print(f"Service cross-check failed: {e}")

    return active_av if active_av else ["No antivirus detected"]


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/events')
def get_events():
    events = _load_events()
    return jsonify(events)

@app.route('/api/events/clear', methods=['POST'])
def clear_events():
    try:
        with open(EVENTS_FILE, 'w') as f:
            json.dump([], f)
        return jsonify({'status': 'success', 'message': 'Events cleared successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'detail': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'detail': 'No selected file'}), 400
    temp_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(temp_path)
    try:
        clamscan_path = r"C:\ClamAV\clamav-1.5.1.win.x64\clamscan.exe"
        result = subprocess.run([clamscan_path, temp_path], capture_output=True, text=True)
        if 'FOUND' in result.stdout or 'Infected files: 1' in result.stdout:
            return jsonify({'status': 'infected', 'detail': result.stdout})
        elif result.returncode == 0:
            return jsonify({'status': 'clean', 'detail': 'No threats found'})
        else:
            return jsonify({'status': 'error', 'detail': result.stderr or 'Scan failed'})
    except Exception as e:
        return jsonify({'status': 'error', 'detail': str(e)})
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# ═════════════════════════════════════════════════════════════════════════════
# Scanner start / stop / status  —  Windows Service edition
# ═════════════════════════════════════════════════════════════════════════════

@app.route('/api/start', methods=['POST'])
def start_scanner():
    """
    Start the background scanner.
    Priority: Windows Service → in-process fallback (if service not installed).
    """
    global _fallback_scanner

    if _service_installed():
        if _service_running():
            return jsonify({'status': 'already_running', 'mode': 'service'})
        result = _start_service()
        if result['ok']:
            return jsonify({'status': 'started', 'mode': 'service'})
        else:
            return jsonify({'status': 'error', 'mode': 'service', 'message': result['error']}), 500
    else:
        # Service not installed — fall back to in-process scanner
        if not _fallback_scanner:
            _fallback_scanner = ScannerController()
            _fallback_scanner.start()
        return jsonify({
            'status': 'started',
            'mode': 'in_process',
            'warning': (
                'Running in-process because FileScannerService is not installed. '
                'The scanner will stop when you close the terminal. '
                'Install the service with: python scanner_service.py --startup auto install'
            )
        })


@app.route('/api/stop', methods=['POST'])
def stop_scanner():
    """
    Stop the background scanner (service or in-process fallback).
    """
    global _fallback_scanner

    if _service_installed():
        if not _service_running():
            return jsonify({'status': 'already_stopped', 'mode': 'service'})
        result = _stop_service()
        if result['ok']:
            return jsonify({'status': 'stopped', 'mode': 'service'})
        else:
            return jsonify({'status': 'error', 'mode': 'service', 'message': result['error']}), 500
    else:
        if _fallback_scanner:
            _fallback_scanner.stop()
            _fallback_scanner = None
        return jsonify({'status': 'stopped', 'mode': 'in_process'})


@app.route('/api/status')
def scanner_status():
    """
    Return scanner running state + which mode it's operating in.
    Also surfaces the last message written by the service itself.
    """
    if _service_installed():
        running = _service_running()
        payload = {'running': running, 'mode': 'service'}

        # Read the internal status file written by scanner_service.py
        if os.path.exists(_SERVICE_STATUS_FILE):
            try:
                with open(_SERVICE_STATUS_FILE) as f:
                    svc_status = json.load(f)
                payload['service_message']   = svc_status.get('message', '')
                payload['service_timestamp'] = svc_status.get('timestamp')
            except Exception:
                pass

        return jsonify(payload)
    else:
        # In-process fallback
        running = _fallback_scanner is not None and _fallback_scanner.is_running()
        return jsonify({
            'running': running,
            'mode': 'in_process',
            'warning': 'FileScannerService not installed — scanner runs in-process only.'
        })


def get_security_status():
    status = {
        'realTimeProtection': {'enabled': None, 'message': 'Unknown', 'raw': None},
        'firewall':           {'enabled': None, 'message': 'Unknown', 'raw': None},
        'virusProtection':    {'enabled': None, 'message': 'Unknown', 'raw': None}
    }
    try:
        p = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True, text=True, shell=False, timeout=10
        )
        out_raw = (p.stdout or "") + (p.stderr or "")
        out = out_raw.lower()
        status['firewall']['raw'] = out_raw.strip()

        if p.returncode == 0 and out:
            domain_state = private_state = public_state = None
            profile_blocks = re.split(r'\r?\n\r?\n', out)
            for block in profile_blocks:
                if 'domain profile' in block:
                    m = re.search(r'state\s*[:\-\s]*\s*(on|off)', block)
                    if m: domain_state = m.group(1)
                if 'private profile' in block:
                    m = re.search(r'state\s*[:\-\s]*\s*(on|off)', block)
                    if m: private_state = m.group(1)
                if 'public profile' in block:
                    m = re.search(r'state\s*[:\-\s]*\s*(on|off)', block)
                    if m: public_state = m.group(1)

            if None in (domain_state, private_state, public_state):
                all_states = re.findall(r'state\s*[:\-\s]*\s*(on|off)', out)
                if len(all_states) >= 3:
                    domain_state  = domain_state  or all_states[0]
                    private_state = private_state or all_states[1]
                    public_state  = public_state  or all_states[2]

            def norm(s):
                return None if s is None else (s.strip().lower() == 'on')

            domain_on  = norm(domain_state)
            private_on = norm(private_state)
            public_on  = norm(public_state)

            if domain_on and private_on and public_on:
                status['firewall']['enabled'] = True
                status['firewall']['message'] = "Firewall enabled (Domain, Private, Public)"
            elif any((domain_on, private_on, public_on)):
                enabled = [n for n, v in [('Domain', domain_on), ('Private', private_on), ('Public', public_on)] if v]
                status['firewall']['enabled'] = True
                status['firewall']['message'] = "Firewall enabled for: " + ", ".join(enabled)
            elif domain_on is False and private_on is False and public_on is False:
                status['firewall']['enabled'] = False
                status['firewall']['message'] = "Firewall disabled for all profiles"
            else:
                status['firewall']['enabled'] = None
                status['firewall']['message'] = "Firewall status unknown"
        else:
            status['firewall']['message'] = f"netsh failed (rc={p.returncode})"
    except Exception as e:
        status['firewall']['message'] = f"Error checking firewall: {e}"
        status['firewall']['raw'] = str(e)

    return status


def check_open_ports():
    # 55000 added for detection; 5000 excluded (that's Flask itself)
    common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8000, 8080, 55000]
    open_ports = []
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex(('127.0.0.1', port)) == 0:
            open_ports.append(port)
        sock.close()
    return open_ports


def get_last_windows_update():
    try:
        import win32com.client
        update_session  = win32com.client.Dispatch("Microsoft.Update.Session")
        update_searcher = update_session.CreateUpdateSearcher()
        history = update_searcher.QueryHistory(0, update_searcher.GetTotalHistoryCount())
        for update in history:
            if update.Operation == 1 and update.ResultCode == 2:
                return update.Date.strftime('%Y-%m-%d %H:%M:%S')
        return 'Unknown'
    except Exception:
        return 'Unknown'


def generate_recommendations(security_status):
    recommendations = []
    if not security_status['realTimeProtection']['enabled']:
        recommendations.append({
            'message': 'Real-time protection is disabled. Enable it for better security.',
            'severity': 'high', 'actionText': 'Enable', 'actionClass': 'danger',
            'action': 'enableRealtimeProtection()'
        })
    if not security_status['firewall']['enabled']:
        recommendations.append({
            'message': 'Windows Firewall is disabled. Enable it to protect your network.',
            'severity': 'high', 'actionText': 'Enable', 'actionClass': 'danger',
            'action': 'enableFirewall()'
        })
    return recommendations


@app.route('/api/quarantine', methods=['GET'])
def list_quarantine():
    try:
        files = []
        for filename in os.listdir(QUARANTINE_DIR):
            path = os.path.join(QUARANTINE_DIR, filename)
            if os.path.isfile(path):
                files.append({
                    'filename': filename, 'path': path,
                    'size': os.path.getsize(path),
                    'quarantined_at': os.path.getmtime(path)
                })
        return jsonify(files)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/quarantine/restore', methods=['POST'])
def restore_from_quarantine():
    try:
        data = request.get_json()
        file_path = data.get('path')
        if not file_path or not os.path.exists(file_path):
            return jsonify({'error': 'File not found in quarantine'}), 404
        quarantined_filename = os.path.basename(file_path)
        parts = quarantined_filename.split('_', 1)
        original_filename = parts[1] if len(parts) > 1 else quarantined_filename
        watch_dir    = r"D:\Copy"
        restored_dir = os.path.join(watch_dir, "restored_files")
        os.makedirs(restored_dir, exist_ok=True)
        original_path = os.path.join(restored_dir, original_filename)
        counter = 1
        while os.path.exists(original_path):
            name, ext = os.path.splitext(original_filename)
            original_path = os.path.join(restored_dir, f"{name}_{counter}{ext}")
            counter += 1
        shutil.move(file_path, original_path)
        event = {
            'timestamp': time.time(), 'file': original_filename, 'status': 'restored',
            'detail': f'File restored from quarantine to {restored_dir}',
            'action': 'Restored from quarantine'
        }
        try:
            with open(EVENTS_FILE, 'r') as f: events = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            events = []
        events.append(event)
        with open(EVENTS_FILE, 'w') as f: json.dump(events, f, indent=2)
        return jsonify({'status': 'success', 'message': f'File restored to {restored_dir}', 'restored_path': original_path})
    except Exception as e:
        print(f"Error restoring file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/quarantine/delete', methods=['POST'])
def delete_from_quarantine():
    try:
        data = request.get_json()
        file_path = data.get('path')
        if not file_path or not os.path.exists(file_path):
            return jsonify({'error': 'File not found in quarantine'}), 404
        filename = os.path.basename(file_path)
        os.remove(file_path)
        event = {
            'timestamp': time.time(), 'file': filename, 'status': 'deleted',
            'detail': 'File permanently deleted from quarantine',
            'action': 'Deleted from quarantine'
        }
        try:
            with open(EVENTS_FILE, 'r') as f: events = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            events = []
        events.append(event)
        with open(EVENTS_FILE, 'w') as f: json.dump(events, f, indent=2)
        return jsonify({'status': 'success', 'message': 'File deleted permanently'})
    except Exception as e:
        print(f"Error deleting file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route("/system_info")
def system_info():
    info = {}
    recommendations = []

    info['hostname'] = socket.gethostname()
    try:    info['ip'] = socket.gethostbyname(info['hostname'])
    except: info['ip'] = "Unavailable"

    info['mac'] = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                            for ele in range(0, 8*6, 8)][::-1])
    info['os']             = platform.system() + " " + platform.release()
    info['architecture']   = platform.machine()
    info['processor']      = platform.processor()
    info['python_version'] = platform.python_version()

    security_status = get_security_status()
    firewall_status = security_status['firewall']
    info['firewall_details'] = {'domain': 'Unknown', 'private': 'Unknown', 'public': 'Unknown'}

    if firewall_status.get('raw'):
        raw_output = firewall_status['raw'].lower()
        for profile in ['domain', 'private', 'public']:
            m = re.search(rf'{profile} profile.*?state\s*[:\-\s]*\s*(on|off)', raw_output, re.DOTALL)
            if m:
                info['firewall_details'][profile] = m.group(1).upper()

    info['firewall']  = [f"{p.capitalize()} Profile: {s}" for p, s in info['firewall_details'].items()]
    disabled_profiles = [p.capitalize() for p, s in info['firewall_details'].items() if s != 'ON']

    if disabled_profiles:
        if len(disabled_profiles) == 3:
            recommendations.append("⚠️ CRITICAL: Windows Firewall is completely disabled for all profiles. Enable it immediately!")
        elif len(disabled_profiles) == 2:
            recommendations.append(f"⚠️ WARNING: Windows Firewall is disabled for {' and '.join(disabled_profiles)} profiles.")
        else:
            recommendations.append(f"⚠️ NOTICE: Windows Firewall is disabled for {disabled_profiles[0]} profile.")

    try:
        update_info = get_last_windows_update()
        if isinstance(update_info, dict):
            info['last_update']       = update_info.get('last_update', 'Unknown')
            info['updates_available'] = update_info.get('updates_available', 0)
            if info['last_update'] and info['last_update'] != 'Unknown':
                try:
                    days = (datetime.now() - datetime.strptime(info['last_update'], '%Y-%m-%d %H:%M:%S')).days
                    if days > 14:
                        recommendations.append(f"🔄 Last Windows update was {days} days ago. Check for updates.")
                except: pass
            if info.get('updates_available', 0) > 0:
                recommendations.append(f"📥 {info['updates_available']} Windows updates available.")
        else:
            info['last_update']       = update_info if isinstance(update_info, str) else "Unknown"
            info['updates_available'] = 0
    except Exception as e:
        info['last_update']       = "Error checking updates"
        info['updates_available'] = 0
        print(f"Error checking Windows updates: {e}")

    active_av = get_active_antivirus()
    info['antivirus'] = active_av
    if active_av == ["No antivirus detected"]:
        recommendations.append(
            "🛡️ CRITICAL: No active third-party antivirus detected! "
            "Windows Defender provides basic built-in protection, but a "
            "dedicated antivirus is strongly recommended."
        )

    open_ports = check_open_ports()
    info['open_ports'] = open_ports
    if open_ports:
        risky  = [p for p in open_ports if p in [21, 22, 23, 3389, 55000]]
        medium = [p for p in open_ports if p in [25, 3306, 8080, 55000]]
        if risky:
            recommendations.append(f"🚨 HIGH RISK: Ports {', '.join(map(str, risky))} are open! These are commonly exploited.")
        if medium:
            recommendations.append(f"⚠️ MEDIUM RISK: Ports {', '.join(map(str, medium))} are open. Ensure they are secured.")
        if len(open_ports) > 5:
            recommendations.append(f"⚠️ {len(open_ports)} open ports detected. Review and close unnecessary ports!")

    return render_template("system_info.html", info=info, recommendations=recommendations)


@app.route('/api/system_info/status')
def get_system_status():
    try:
        security_status = get_security_status()
        info = {'firewall_details': {}, 'antivirus': [], 'open_ports': []}

        if security_status['firewall'].get('raw'):
            raw = security_status['firewall']['raw'].lower()
            for profile in ['domain', 'private', 'public']:
                m = re.search(rf'{profile} profile.*?state\s*[:\-\s]*\s*(on|off)', raw, re.DOTALL)
                info['firewall_details'][profile] = m.group(1).upper() if m else 'OFF'

        info['antivirus']  = get_active_antivirus()
        info['open_ports'] = check_open_ports()
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/system_info/recommendations')
def get_recommendations():
    try:
        security_status = get_security_status()
        recommendations = []

        if security_status['firewall'].get('raw'):
            raw = security_status['firewall']['raw'].lower()
            disabled = [p.capitalize() for p in ['domain', 'private', 'public']
                        if re.search(rf'{p} profile.*?state\s*[:\-\s]*\s*off', raw, re.DOTALL)]
            if disabled:
                if len(disabled) == 3:
                    recommendations.append("⚠️ CRITICAL: Windows Firewall is completely disabled for all profiles.")
                elif len(disabled) == 2:
                    recommendations.append(f"⚠️ WARNING: Windows Firewall is disabled for {' and '.join(disabled)} profiles.")
                else:
                    recommendations.append(f"⚠️ NOTICE: Windows Firewall is disabled for {disabled[0]} profile.")

        if get_active_antivirus() == ["No antivirus detected"]:
            recommendations.append(
                "🛡️ CRITICAL: No active third-party antivirus detected! "
                "Windows Defender provides basic built-in protection, but a dedicated antivirus is strongly recommended."
            )

        open_ports = check_open_ports()
        if open_ports:
            risky  = [p for p in open_ports if p in [21, 22, 23, 3389, 55000]]
            medium = [p for p in open_ports if p in [25, 3306, 8080, 55000]]
            if risky:  recommendations.append(f"🚨 HIGH RISK: Ports {', '.join(map(str, risky))} are open!")
            if medium: recommendations.append(f"⚠️ MEDIUM RISK: Ports {', '.join(map(str, medium))} are open.")

        return jsonify(recommendations)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/login_activity')
def get_login_activity():
    from datetime import datetime, timedelta
    date_param = request.args.get('date')
    login_activities = []
    try:
        if date_param:
            filter_date = datetime.strptime(date_param, '%Y-%m-%d').date()
            start_date  = datetime.combine(filter_date, datetime.min.time())
            end_date    = start_date + timedelta(days=1)
            start_str   = start_date.strftime('%m/%d/%Y %H:%M:%S')
            end_str     = end_date.strftime('%m/%d/%Y %H:%M:%S')
            cmd = (
                f"powershell -Command \"$s=[DateTime]::ParseExact('{start_str}','MM/dd/yyyy HH:mm:ss',$null);"
                f"$e=[DateTime]::ParseExact('{end_str}','MM/dd/yyyy HH:mm:ss',$null);"
                "Get-EventLog -LogName Security -InstanceId 4624|"
                "Where-Object{$_.TimeGenerated-ge $s-and $_.TimeGenerated-lt $e-and $_.ReplacementStrings[8]-eq'2'}|"
                "Select-Object @{Name='Time';Expression={$_.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss')}},"
                "@{Name='Username';Expression={$_.ReplacementStrings[5]}},"
                "@{Name='Domain';Expression={$_.ReplacementStrings[6]}}|ConvertTo-Json\""
            )
        else:
            cmd = (
                "powershell -Command \"Get-EventLog -LogName Security -InstanceId 4624 -Newest 10|"
                "Where-Object{$_.ReplacementStrings[8]-eq'2'}|"
                "Select-Object @{Name='Time';Expression={$_.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss')}},"
                "@{Name='Username';Expression={$_.ReplacementStrings[5]}},"
                "@{Name='Domain';Expression={$_.ReplacementStrings[6]}}|ConvertTo-Json\""
            )
        result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.PIPE, timeout=30)
        if result.strip():
            login_activities = json.loads(result)
            if not isinstance(login_activities, list): login_activities = [login_activities]
            login_activities = [
                a for a in login_activities if a.get('Username') and
                a['Username'].lower() not in ['system','local service','network service','$','dwm-','umfd-']
            ]
    except subprocess.CalledProcessError as e:
        error_msg = str(e.stderr) if e.stderr else str(e)
        if 'Access is denied' in error_msg: return jsonify({"error": "Administrator rights required"}), 403
        return jsonify({"error": f"Failed to retrieve login data: {error_msg}"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Request timed out."}), 408
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify(login_activities)


@app.route('/api/recent_logins')
def get_recent_logins():
    try:
        cmd = (
            "powershell -Command \"Get-EventLog -LogName Security -InstanceId 4624 -Newest 20|"
            "Where-Object{$_.ReplacementStrings[8]-eq'2'}|"
            "Select-Object @{Name='Time';Expression={$_.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss')}},"
            "@{Name='Username';Expression={$_.ReplacementStrings[5]}},"
            "@{Name='LogonType';Expression={$_.ReplacementStrings[8]}}|"
            "Select-Object -First 5|ConvertTo-Json\""
        )
        result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.PIPE, timeout=15)
        if result.strip():
            logins = json.loads(result)
            if not isinstance(logins, list): logins = [logins]
            logins = [l for l in logins if l.get('Username') and
                      l['Username'].lower() not in ['system','local service','network service','$']]
            return jsonify(logins[:5])
        return jsonify([])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/login_details')
def login_details():
    from datetime import datetime
    login_data = {
        'current_user': getpass.getuser(), 'pc_name': socket.gethostname(),
        'password_set': None, 'last_login': None,
        'failed_attempts': [], 'recent_logins': [], 'error': None
    }
    try:
        subprocess.check_output(
            'powershell -Command "try{$u=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name;if($u){\'HasPassword\'}}catch{\'NoPassword\'}"',
            shell=True, text=True, timeout=5, stderr=subprocess.DEVNULL)
        login_data['password_set'] = True
        try:
            r = subprocess.check_output(
                f'powershell -Command "Get-LocalUser -Name \'{login_data["current_user"]}\' -ErrorAction SilentlyContinue|Select-Object -ExpandProperty PasswordRequired"',
                shell=True, text=True, timeout=5, stderr=subprocess.DEVNULL)
            if 'True' in r: login_data['password_set'] = True
            elif 'False' in r: login_data['password_set'] = False
        except:
            if '@' in login_data['current_user'] or '\\' not in login_data['current_user']:
                login_data['password_set'] = True
    except Exception as e:
        login_data['password_set'] = True

    try:
        r = subprocess.check_output(
            "powershell -Command \"$ErrorActionPreference='SilentlyContinue';"
            "$e=Get-EventLog -LogName Security -InstanceId 4624 -Newest 20 2>$null|"
            "Where-Object{$_.ReplacementStrings[8]-eq'2'-and $_.ReplacementStrings[5]-notmatch'SYSTEM|LOCAL SERVICE|NETWORK SERVICE'};"
            "if($e){$e[0].TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss')}\"",
            shell=True, text=True, timeout=15, stderr=subprocess.DEVNULL)
        if r.strip():
            login_data['last_login'] = datetime.strptime(r.strip(), '%Y-%m-%d %H:%M:%S').strftime('%B %d, %Y at %I:%M %p')
        else:
            bt = subprocess.check_output(
                "powershell -Command \"(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss')\"",
                shell=True, text=True, timeout=10)
            login_data['last_login'] = "System boot: " + datetime.strptime(bt.strip(), '%Y-%m-%d %H:%M:%S').strftime('%B %d, %Y at %I:%M %p')
    except Exception as e:
        login_data['last_login'] = "Run as administrator to view login history"

    try:
        r = subprocess.check_output(
            "powershell -Command \"$ErrorActionPreference='SilentlyContinue';"
            "Get-EventLog -LogName Security -InstanceId 4624 -Newest 50 2>$null|"
            "Where-Object{$_.ReplacementStrings[8]-eq'2'-and $_.ReplacementStrings[5]-notmatch'SYSTEM|LOCAL SERVICE|NETWORK SERVICE|\\$'}|"
            "Select-Object @{Name='Time';Expression={$_.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss')}},"
            "@{Name='Username';Expression={$_.ReplacementStrings[5]}}|"
            "Select-Object -First 10|ConvertTo-Json\"",
            shell=True, text=True, timeout=15, stderr=subprocess.DEVNULL)
        if r.strip():
            recent = json.loads(r)
            if not isinstance(recent, list): recent = [recent]
            seen = set()
            for l in recent:
                tk = l['Time'][:16]
                if tk not in seen:
                    seen.add(tk)
                    login_data['recent_logins'].append({
                        'time': datetime.strptime(l['Time'], '%Y-%m-%d %H:%M:%S').strftime('%B %d, %Y at %I:%M %p'),
                        'username': l.get('Username', 'N/A')
                    })
                    if len(login_data['recent_logins']) >= 5: break
    except Exception as e:
        print(f"Error getting recent logins: {e}")

    login_data['failed_attempts'] = []
    login_data['failed_attempts_error'] = None
    try:
        audit_enabled = False
        try:
            ac = subprocess.check_output('auditpol /get /subcategory:"Logon"',
                                         shell=True, text=True, timeout=5, stderr=subprocess.DEVNULL)
            if 'Success and Failure' in ac or 'Failure' in ac: audit_enabled = True
        except: pass
        if not audit_enabled:
            login_data['failed_attempts_error'] = "audit_not_enabled"
        else:
            r = subprocess.check_output(
                "powershell -Command \"$ErrorActionPreference='SilentlyContinue';"
                "Get-EventLog -LogName Security -InstanceId 4625 -Newest 10 2>$null|"
                "ForEach-Object{$t=$_.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss');"
                "$a=$_.ReplacementStrings[5];$d=$_.ReplacementStrings[6];"
                "if($a -and $a-ne'-' -and $a-notmatch'SYSTEM|LOCAL SERVICE|NETWORK SERVICE')"
                "{Write-Output \"$t|$a|$d\"}}\"",
                shell=True, text=True, timeout=15, stderr=subprocess.DEVNULL)
            for line in (r.strip().split('\n') if r.strip() else []):
                if '|' in line:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        try: ft = datetime.strptime(parts[0].strip(), '%Y-%m-%d %H:%M:%S').strftime('%B %d, %Y at %I:%M %p')
                        except: ft = parts[0].strip()
                        acc = parts[1].strip()
                        if acc and acc != '-':
                            login_data['failed_attempts'].append({
                                'time': ft, 'account': acc,
                                'domain': parts[2] if len(parts) > 2 else 'Local',
                                'type': 'Wrong Password'
                            })
    except subprocess.CalledProcessError as e:
        login_data['failed_attempts_error'] = "admin_required" if 'Access is denied' in str(e) else "cannot_read"
    except Exception as e:
        login_data['failed_attempts_error'] = "admin_required" if 'Access is denied' in str(e) else "cannot_read"

    return render_template('login_details.html', login_data=login_data,
                           current_date=datetime.now().strftime('%Y-%m-%d'))


def _load_manual_scan_reports():
    try:
        if os.path.exists(MANUAL_SCAN_REPORTS_FILE):
            with open(MANUAL_SCAN_REPORTS_FILE, 'r') as f: return json.load(f)
        return []
    except Exception as e:
        print(f"Error loading manual scan reports: {e}")
        return []

def _save_manual_scan_report(report):
    try:
        reports = _load_manual_scan_reports()
        reports.insert(0, report)
        reports = reports[:50]
        with open(MANUAL_SCAN_REPORTS_FILE, 'w') as f: json.dump(reports, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving manual scan report: {e}")
        return False


@app.route('/manual_scan')
def manual_scan_page():
    return render_template('manual_scan.html')


@app.route('/api/manual_scan/scan_folder', methods=['POST'])
def scan_folder_manually():
    try:
        data        = request.get_json()
        folder_path = data.get('folder_path', '')
        if not folder_path:                 return jsonify({'error': 'Folder path is required'}), 400
        if not os.path.exists(folder_path): return jsonify({'error': 'Folder does not exist'}), 404
        if not os.path.isdir(folder_path):  return jsonify({'error': 'Path is not a directory'}), 400
        clamscan_path = r"C:\ClamAV\clamav-1.5.1.win.x64\clamscan.exe"
        if not os.path.exists(clamscan_path): return jsonify({'error': 'ClamAV not found. Please install ClamAV first.'}), 500

        infected_files = []; total_files = 0; scanned_files = 0

        for root, dirs, files in os.walk(folder_path):
            for file in files:
                total_files += 1
                file_path = os.path.join(root, file)
                try:
                    result = subprocess.run([clamscan_path, file_path],
                                            capture_output=True, text=True, timeout=30)
                    scanned_files += 1
                    if 'FOUND' in result.stdout or 'Infected files: 1' in result.stdout:
                        threat_name = 'Unknown threat'
                        for line in result.stdout.split('\n'):
                            if 'FOUND' in line:
                                parts = line.split(':')
                                if len(parts) > 1:
                                    threat_name = parts[1].strip().replace('FOUND', '').strip()
                                break
                        infected_files.append({
                            'path': file_path, 'filename': file,
                            'relative_path': os.path.relpath(file_path, folder_path),
                            'threat': threat_name, 'size': os.path.getsize(file_path)
                        })
                except subprocess.TimeoutExpired: continue
                except Exception as e: print(f"Error scanning {file_path}: {e}"); continue

        return jsonify({
            'status': 'success', 'folder_path': folder_path,
            'total_files': total_files, 'scanned_files': scanned_files,
            'infected_count': len(infected_files), 'infected_files': infected_files
        })
    except Exception as e:
        print(f"Error in scan_folder_manually: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/manual_scan/delete_files', methods=['POST'])
def delete_infected_files():
    try:
        data               = request.get_json()
        files_to_delete    = data.get('files', [])
        folder_path        = data.get('folder_path', '')
        all_infected_files = data.get('all_infected_files', [])

        if not files_to_delete:
            return jsonify({'error': 'No files specified for deletion'}), 400

        deleted_files = []; failed_files = []
        for file_info in files_to_delete:
            file_path = file_info.get('path')
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    deleted_files.append({'filename': file_info.get('filename'), 'path': file_path, 'action': 'deleted'})
                else:
                    failed_files.append({'filename': file_info.get('filename'), 'path': file_path, 'reason': 'File not found'})
            except Exception as e:
                failed_files.append({'filename': file_info.get('filename'), 'path': file_path, 'reason': str(e)})

        deleted_paths = [f['path'] for f in deleted_files]
        not_deleted   = [f for f in all_infected_files if f.get('path') not in deleted_paths]

        _save_manual_scan_report({
            'timestamp': time.time(), 'folder_path': folder_path,
            'total_infected': len(all_infected_files),
            'files': (
                [{'filename': f['filename'], 'action': 'deleted',  'status': 'success'} for f in deleted_files] +
                [{'filename': f.get('filename'), 'action': 'kept', 'status': 'warning'} for f in not_deleted]
            )
        })

        return jsonify({
            'status': 'success', 'deleted_count': len(deleted_files),
            'deleted_files': deleted_files, 'failed_files': failed_files,
            'not_deleted': not_deleted, 'not_deleted_count': len(not_deleted)
        })
    except Exception as e:
        print(f"Error deleting files: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/manual_scan/reports', methods=['GET'])
def get_manual_scan_reports():
    try:    return jsonify(_load_manual_scan_reports())
    except Exception as e: return jsonify({'error': str(e)}), 500


@app.route('/api/manual_scan/clear_reports', methods=['POST'])
def clear_manual_scan_reports():
    try:
        with open(MANUAL_SCAN_REPORTS_FILE, 'w') as f: json.dump([], f)
        return jsonify({'status': 'success', 'message': 'Reports cleared'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/manual_scan/save_no_action', methods=['POST'])
def save_no_action():
    try:
        data               = request.get_json()
        folder_path        = data.get('folder_path', '')
        all_infected_files = data.get('all_infected_files', [])

        report = {
            'timestamp':      time.time(),
            'folder_path':    folder_path,
            'total_infected': len(all_infected_files),
            'files': [
                {'filename': f.get('filename', '-'), 'action': 'no action taken', 'status': 'kept'}
                for f in all_infected_files
            ]
        }

        _save_manual_scan_report(report)
        return jsonify({'status': 'success'})

    except Exception as e:
        print(f"Error saving no-action report: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)