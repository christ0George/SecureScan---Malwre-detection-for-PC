import os
import time
import json
import shutil
import threading
import subprocess
import shlex
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Full path to clamscan.exe
CLAMSCAN_PATH = r"C:\ClamAV\clamav-1.5.1.win.x64\clamscan.exe"

# Configuration
WATCH_DIR = r"D:\\Copy"   # Default watch directory
QUARANTINE_DIR = str(Path(__file__).parent / "quarantine")
EVENTS_FILE = str(Path(__file__).parent / "events.json")
POLL_INTERVAL = 1.0

# Ensure directories exist
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(EVENTS_FILE), exist_ok=True)

def _load_events():
    """Load events from the events file."""
    try:
        if os.path.exists(EVENTS_FILE):
            with open(EVENTS_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return []

def _save_events(events):
    """Save events to the events file."""
    with open(EVENTS_FILE, 'w') as f:
        json.dump(events, f, indent=2)

def append_event(event_data):
    """Append a new event to the events log."""
    events = _load_events()
    events.insert(0, event_data)  # Add newest first
    events = events[:1000]  # Keep only the most recent 1000 events
    _save_events(events)

def quarantine_file(file_path):
    """Move a file to quarantine."""
    try:
        filename = os.path.basename(file_path)
        timestamp = int(time.time())
        dest = os.path.join(QUARANTINE_DIR, f"{filename}.{timestamp}")
        shutil.move(file_path, dest)
        return dest
    except Exception as e:
        print(f"Error quarantining file: {e}")
        return None

def scan_file(file_path):
    """Scan a file using ClamAV."""
    try:
        if not os.path.exists(file_path):
            return {
                'returncode': 1,
                'stdout': '',
                'stderr': f'{file_path}: No such file or directory'
            }
            
        try:
            # Try to open the file to check if it's accessible
            with open(file_path, 'rb') as f:
                pass
        except (IOError, PermissionError) as e:
            return {
                'returncode': 1,
                'stdout': '',
                'stderr': f'Cannot access {file_path}: {str(e)}'
            }

        # Run the actual scan
        result = subprocess.run(
            [CLAMSCAN_PATH, file_path],
            capture_output=True,
            text=True
        )
        
        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
        
    except Exception as e:
        return {
            'returncode': -1,
            'stdout': '',
            'stderr': f'Error scanning {file_path}: {str(e)}'
        }

class NewFileHandler(FileSystemEventHandler):
    """Handler for file system events."""
    
    def on_created(self, event):
        try:
            if event.is_directory:
                return
                
            file_path = event.src_path
            max_attempts = 3
            attempt = 0
            scan_result = None

            # Skip temporary files
            if file_path.endswith('.tmp') or file_path.endswith('~') or '~$' in file_path:
                return

            # Wait for file to be fully written with retries
            while attempt < max_attempts:
                try:
                    if os.path.exists(file_path):
                        # Try to open the file to ensure it's not locked
                        with open(file_path, 'rb') as f:
                            pass
                        break
                except (IOError, PermissionError):
                    pass
                    
                attempt += 1
                time.sleep(0.5)  # Wait before retry

            if attempt == max_attempts:
                print(f"Could not access file after {max_attempts} attempts: {file_path}")
                return

            # Scan the file
            scan_result = scan_file(file_path)
            
            # If file is not found in scan, it might have been moved/deleted
            if scan_result['returncode'] == 1 and 'No such file or directory' in scan_result['stderr']:
                print(f"File not found during scan, possibly moved/deleted: {file_path}")
                return
                
            # Create event
            event_data = {
                'timestamp': int(time.time()),
                'file': os.path.basename(file_path),
                'path': file_path,
                'status': 'clean',
                'detail': 'No threats found',
                'action': 'kept'
            }
            
            # Check scan results
            if scan_result and ('FOUND' in scan_result['stdout'] or 'Infected files: 1' in scan_result['stdout']):
                event_data['status'] = 'infected'
                event_data['detail'] = scan_result['stdout'].split('\n')[0]
                quarantine_path = quarantine_file(file_path)
                if quarantine_path and os.path.exists(quarantine_path):
                    event_data['action'] = 'quarantined'
                    event_data['quarantine_path'] = quarantine_path
                    # Remove the original file after successful quarantine
                    try:
                        os.remove(file_path)
                    except OSError as e:
                        print(f"Error removing original file {file_path}: {e}")
                else:
                    event_data['action'] = 'quarantine_failed'
                    event_data['detail'] = 'Quarantine failed'
            elif scan_result and scan_result['returncode'] != 0:
                event_data['status'] = 'error'
                event_data['detail'] = scan_result['stderr'] or 'Scan failed'
            
            # Only log if we have a valid scan result
            if scan_result:
                append_event(event_data)
                
        except Exception as e:
            print(f"Error processing file {file_path if 'file_path' in locals() else 'unknown'}: {e}")

class ScannerController:
    """Controller for the file system scanner."""
    
    def __init__(self, watch_dir=None):
        self.watch_dir = watch_dir or WATCH_DIR
        self.observer = None
        self.thread = None
        self._stop_event = threading.Event()
    
    def start(self):
        """Start the file system watcher."""
        if self.observer:
            return
        
        event_handler = NewFileHandler()
        self.observer = Observer()
        self.observer.schedule(event_handler, self.watch_dir, recursive=False)
        self.observer.start()
        
        # Log scanner start
        append_event({
            'timestamp': int(time.time()),
            'file': None,
            'path': self.watch_dir,
            'status': 'info',
            'detail': f'Scanner started on {self.watch_dir}',
            'action': 'start'
        })
        
        # Start a thread to keep the observer alive
        self._stop_event.clear()
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self):
        """Stop the file system watcher."""
        if not self.observer:
            return
        
        self._stop_event.set()
        self.observer.stop()
        self.observer.join()
        self.observer = None
        
        # Log scanner stop
        append_event({
            'timestamp': int(time.time()),
            'file': None,
            'path': self.watch_dir,
            'status': 'info',
            'detail': 'Scanner stopped',
            'action': 'stop'
        })
    
    def _run(self):
        """Run the observer in a separate thread."""
        try:
            while not self._stop_event.is_set():
                time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            pass
        finally:
            if self.observer:
                self.observer.stop()
                self.observer.join()
    
    def is_running(self):
        """Check if the scanner is running."""
        return self.observer is not None and self.observer.is_alive()