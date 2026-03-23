# scanner_service.py
# ─────────────────────────────────────────────────────────────────────────────
# Windows Service wrapper for the file-scanner background worker.
#
# USAGE (run as Administrator in your project folder):
#   Install & set auto-start:  python scanner_service.py --startup auto install
#   Start now:                 python scanner_service.py start
#   Stop:                      python scanner_service.py stop
#   Restart:                   python scanner_service.py restart
#   Uninstall:                 python scanner_service.py remove
#   Check status:              python scanner_service.py status   (custom helper below)
#
# You can also open services.msc and manage it from there as
# "File Scanner Background Service".
# ─────────────────────────────────────────────────────────────────────────────

import sys
import os
import time
import logging
import subprocess

import win32serviceutil
import win32service
import win32event
import servicemanager

# ── Paths ─────────────────────────────────────────────────────────────────────
# Use the directory of THIS file as the project root.
# This works correctly even when running as SYSTEM (Windows Service),
# where os.getcwd() would point to System32 instead of the project folder.
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

# Force the working directory to the project folder immediately.
# Must happen before any relative-path imports (scanner.py, etc.)
os.chdir(PROJECT_DIR)

# Put the project folder first on sys.path so 'from scanner import ...' works
# under the SYSTEM account exactly as it does for your user account.
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

# Also add the Python Scripts/site-packages of the interpreter that is
# running THIS file, so all pip-installed packages are available to the service.
import sysconfig
_site = sysconfig.get_path('purelib')   # e.g. ...\Lib\site-packages
if _site and _site not in sys.path:
    sys.path.insert(1, _site)

LOG_FILE    = os.path.join(PROJECT_DIR, 'scanner_service.log')
STATUS_FILE = os.path.join(PROJECT_DIR, 'scanner_service_status.json')  # read by Flask /api/status

# ── Logging ───────────────────────────────────────────────────────────────────
# Use 'w' mode on first run so stale logs don't hide new errors, then 'a'.
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,          # DEBUG so we catch every import/startup detail
    format='%(asctime)s  %(levelname)-8s  %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)

# Write a startup breadcrumb immediately — if this appears in the log but
# nothing else does, the crash is happening inside SvcDoRun before our
# try/except catches it.
logging.info(f"scanner_service.py loaded  |  PROJECT_DIR={PROJECT_DIR}")
logging.info(f"Python executable: {sys.executable}")
logging.info(f"sys.path: {sys.path}")

# ── Status helpers ────────────────────────────────────────────────────────────
import json

def _write_status(running: bool, message: str = ''):
    try:
        with open(STATUS_FILE, 'w') as f:
            json.dump({
                'running': running,
                'message': message,
                'timestamp': time.time(),
            }, f)
    except Exception as e:
        logging.warning(f"Could not write status file: {e}")


# ═════════════════════════════════════════════════════════════════════════════
class FileScannerService(win32serviceutil.ServiceFramework):
    """Windows Service that keeps ScannerController alive in the background."""

    _svc_name_         = "FileScannerService"
    _svc_display_name_ = "File Scanner Background Service"
    _svc_description_  = (
        "Monitors watched folders for malware threats in the background. "
        "Managed by the Flask security dashboard."
    )

    # ── Init ──────────────────────────────────────────────────────────────────
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        # Event used to signal the main loop to exit
        self._stop_event = win32event.CreateEvent(None, 0, 0, None)
        self._scanner    = None
        self._running    = False

    # ── SCM callbacks ─────────────────────────────────────────────────────────
    def SvcStop(self):
        logging.info("Stop signal received from SCM.")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._running = False
        win32event.SetEvent(self._stop_event)
        self._shutdown_scanner()

    def SvcDoRun(self):
        try:
            logging.info("SvcDoRun entered.")
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ''),
            )
            self._running = True
            _write_status(True, "Service started")
            self._run()
        except Exception as _outer_exc:
            logging.exception(f"FATAL unhandled exception in SvcDoRun: {_outer_exc}")
            _write_status(False, f"FATAL: {_outer_exc}")
            raise

    # ── Core loop ─────────────────────────────────────────────────────────────
    def _run(self):
        try:
            from scanner import ScannerController
            self._scanner = ScannerController()
            self._scanner.start()
            logging.info("ScannerController started — watching for threats.")
            _write_status(True, "Scanner running")

            # Stay alive; poll every second for the stop signal
            while self._running:
                rc = win32event.WaitForSingleObject(self._stop_event, 1000)
                if rc == win32event.WAIT_OBJECT_0:
                    break

        except ImportError as e:
            msg = f"Cannot import scanner module: {e}"
            logging.error(msg)
            _write_status(False, msg)

        except Exception as e:
            msg = f"Unexpected error in service main loop: {e}"
            logging.exception(msg)
            _write_status(False, msg)

        finally:
            self._shutdown_scanner()
            _write_status(False, "Service stopped")
            logging.info("Service has stopped.")

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _shutdown_scanner(self):
        if self._scanner:
            try:
                self._scanner.stop()
                logging.info("ScannerController stopped cleanly.")
            except Exception as e:
                logging.error(f"Error stopping ScannerController: {e}")
            finally:
                self._scanner = None


# ═════════════════════════════════════════════════════════════════════════════
# CLI helpers
# ═════════════════════════════════════════════════════════════════════════════

def _check_admin():
    """Abort with a clear message if not running as Administrator."""
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[ERROR] This script must be run as Administrator.")
            print("        Right-click your terminal → 'Run as administrator', then retry.")
            sys.exit(1)
    except Exception:
        pass  # Non-Windows or ctypes unavailable — let pywin32 raise its own error


def _print_service_status():
    """Query SCM and print a human-readable status line."""
    try:
        status = win32serviceutil.QueryServiceStatus("FileScannerService")
        state_map = {
            win32service.SERVICE_STOPPED:          "STOPPED",
            win32service.SERVICE_START_PENDING:    "STARTING",
            win32service.SERVICE_STOP_PENDING:     "STOPPING",
            win32service.SERVICE_RUNNING:          "RUNNING",
            win32service.SERVICE_CONTINUE_PENDING: "CONTINUING",
            win32service.SERVICE_PAUSE_PENDING:    "PAUSING",
            win32service.SERVICE_PAUSED:           "PAUSED",
        }
        state = state_map.get(status[1], f"UNKNOWN ({status[1]})")
        print(f"[FileScannerService]  {state}")

        # Also show last Flask-visible status
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE) as f:
                s = json.load(f)
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(s.get('timestamp', 0)))
            print(f"  Internal status : {s.get('message', '?')}  (as of {ts})")

    except Exception as e:
        print(f"[ERROR] Could not query service: {e}")
        print("        Is the service installed?  Run:  python scanner_service.py install")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    # Custom 'status' verb — not built into pywin32
    if len(sys.argv) == 2 and sys.argv[1].lower() == 'status':
        _print_service_status()
        sys.exit(0)

    # install / remove / start / stop / restart need admin
    if len(sys.argv) > 1 and sys.argv[1].lower() not in ('debug',):
        _check_admin()

    if len(sys.argv) == 1:
        # Called directly by the Windows Service Control Manager
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(FileScannerService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(FileScannerService)