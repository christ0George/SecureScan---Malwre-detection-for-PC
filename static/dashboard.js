// Configuration
const CONFIG = {
  pollInterval: 2000, // ms - Scanner status check
  eventsRefreshInterval: 5000, // ms - Events refresh
  quarantineRefreshInterval: 10000, // ms - Quarantine refresh
  apiTimeout: 5000, // ms - API request timeout
  apiBaseUrl: '/api',
  defaultWatchDir: 'D:\\Copy' // Default directory to watch
};

// DOM Elements
const elements = {
  // Scanner Controls
  startScannerBtn: document.getElementById('start-scanner'),
  stopScannerBtn: document.getElementById('stop-scanner'),
  scannerStatus: document.getElementById('scanner-status'),
  watchDir: document.getElementById('watch-dir'),
  lastScan: document.getElementById('last-scan'),

  // File Scan
  fileInput: document.getElementById('file-input'),
  fileName: document.getElementById('file-name'),
  scanButton: document.getElementById('scan-button'),
  scanResult: document.getElementById('scan-result'),

  // Events Table
  eventsTable: null,  // Will be initialized in init()
  refreshEventsBtn: document.getElementById('refresh-events'),
  clearEventsBtn: document.getElementById('clear-events')
};

// State
let state = {
  scannerRunning: false,
  events: [],
  quarantineFiles: [],
  selectedFile: null,
  isPageVisible: true,
  intervals: {
    scanner: null,
    events: null,
    quarantine: null
  }
};

// Fetch with timeout and abort controller
const fetchWithTimeout = (url, options = {}, timeout = CONFIG.apiTimeout) => {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);

  return fetch(url, {
    ...options,
    signal: controller.signal
  }).finally(() => clearTimeout(id));
};

// Initialize the application
function init() {
  // Initialize elements that depend on the DOM being loaded
  elements.eventsTable = document.querySelector('#events-table tbody');

  if (!elements.eventsTable) {
    console.error('Could not find events table tbody');
  }

  setupEventListeners();
  loadScannerStatus();
  loadEvents();
  loadQuarantine();
  updateWatchDir();

  // Start auto-refresh intervals
  startAutoRefresh();

  // Add visibility change handler
  setupVisibilityHandler();
}

// Setup visibility handler to pause updates when page is hidden
function setupVisibilityHandler() {
  document.addEventListener('visibilitychange', () => {
    state.isPageVisible = !document.hidden;

    if (state.isPageVisible) {
      // Page is visible again, restart auto-refresh
      startAutoRefresh();
      // Immediately refresh data
      loadScannerStatus();
      loadEvents();
      loadQuarantine();
    } else {
      // Page is hidden, stop auto-refresh to save resources
      stopAutoRefresh();
    }
  });
}

// Start all auto-refresh intervals
function startAutoRefresh() {
  // Clear any existing intervals first
  stopAutoRefresh();

  // Scanner status - every 2 seconds
  state.intervals.scanner = setInterval(() => {
    if (state.isPageVisible) {
      loadScannerStatus();
    }
  }, CONFIG.pollInterval);

  // Events - every 5 seconds
  state.intervals.events = setInterval(() => {
    if (state.isPageVisible) {
      loadEvents();
    }
  }, CONFIG.eventsRefreshInterval);

  // Quarantine - every 10 seconds
  state.intervals.quarantine = setInterval(() => {
    if (state.isPageVisible) {
      loadQuarantine();
    }
  }, CONFIG.quarantineRefreshInterval);
}

// Stop all auto-refresh intervals
function stopAutoRefresh() {
  Object.values(state.intervals).forEach(interval => {
    if (interval) clearInterval(interval);
  });
  state.intervals = { scanner: null, events: null, quarantine: null };
}

// Set up event listeners
function setupEventListeners() {
  // Scanner controls
  elements.startScannerBtn.addEventListener('click', startScanner);
  elements.stopScannerBtn.addEventListener('click', stopScanner);

  // File scanning
  elements.fileInput.addEventListener('change', handleFileSelect);
  elements.scanButton.addEventListener('click', handleFileScan);

  // Events table
  elements.refreshEventsBtn.addEventListener('click', () => {
    loadEvents();
    showNotification('Events refreshed', 'info');
  });
  elements.clearEventsBtn.addEventListener('click', clearEvents);

  const refreshQuarantineBtn = document.getElementById('refresh-quarantine');
  const deleteSelectedBtn = document.getElementById('delete-selected');
  const restoreSelectedBtn = document.getElementById('restore-selected');

  if (refreshQuarantineBtn) {
    refreshQuarantineBtn.addEventListener('click', () => {
      loadQuarantine();
      showNotification('Quarantine refreshed', 'info');
    });
  }

  if (deleteSelectedBtn) {
    deleteSelectedBtn.addEventListener('click', handleDeleteSelected);
  }

  if (restoreSelectedBtn) {
    restoreSelectedBtn.addEventListener('click', handleRestoreSelected);
  }

  // Search functionality
  const searchInput = document.getElementById('quarantine-search');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      const searchTerm = e.target.value.toLowerCase();
      const rows = document.querySelectorAll('#quarantine-table tbody tr:not(.no-files)');

      rows.forEach(row => {
        const filename = row.querySelector('td:nth-child(2)')?.textContent?.toLowerCase() || '';
        row.style.display = filename.includes(searchTerm) ? '' : 'none';
      });
    });
  }

  // Select all checkbox in quarantine
  const selectAllCheckbox = document.getElementById('select-all');
  if (selectAllCheckbox) {
    selectAllCheckbox.addEventListener('change', (e) => {
      const checkboxes = document.querySelectorAll('.quarantine-checkbox');
      checkboxes.forEach(cb => cb.checked = e.target.checked);
      updateSelectionButtons();
    });
  }
}

// Scanner control functions
async function startScanner() {
  try {
    const response = await fetchWithTimeout(`${CONFIG.apiBaseUrl}/start`, {
      method: 'POST'
    });
    const data = await response.json();

    if (data.status === 'started') {
      updateScannerStatus(true);
      showNotification('Scanner started successfully', 'success');
      // Immediately check status
      loadScannerStatus();
    }
  } catch (error) {
    if (error.name !== 'AbortError') {
      console.error('Error starting scanner:', error);
      showNotification('Failed to start scanner', 'error');
    }
  }
}

async function stopScanner() {
  try {
    const response = await fetchWithTimeout(`${CONFIG.apiBaseUrl}/stop`, {
      method: 'POST'
    });
    const data = await response.json();

    if (data.status === 'stopped') {
      updateScannerStatus(false);
      showNotification('Scanner stopped', 'info');
      // Immediately check status
      loadScannerStatus();
    }
  } catch (error) {
    if (error.name !== 'AbortError') {
      console.error('Error stopping scanner:', error);
      showNotification('Failed to stop scanner', 'error');
    }
  }
}

async function loadScannerStatus() {
  try {
    const response = await fetchWithTimeout(`${CONFIG.apiBaseUrl}/status`, {}, 3000);
    const data = await response.json();
    updateScannerStatus(data.running);
  } catch (error) {
    if (error.name !== 'AbortError') {
      console.error('Error loading scanner status:', error);
    }
  }
}

function updateScannerStatus(isRunning) {
  if (state.scannerRunning === isRunning) return; // No change, skip update

  state.scannerRunning = isRunning;
  elements.scannerStatus.textContent = isRunning ? 'Running' : 'Stopped';
  elements.scannerStatus.className = `status-badge ${isRunning ? 'running' : 'stopped'}`;

  elements.startScannerBtn.disabled = isRunning;
  elements.stopScannerBtn.disabled = !isRunning;
}

// File scanning functions
function handleFileSelect(event) {
  const file = event.target.files[0];
  if (file) {
    state.selectedFile = file;
    elements.fileName.textContent = file.name;
    elements.scanButton.disabled = false;
    resetScanResult();
  }
}

async function handleFileScan() {
  if (!state.selectedFile) return;

  const formData = new FormData();
  formData.append('file', state.selectedFile);

  // Show loading state
  setScanResult('Scanning file...', 'info', 'hourglass_empty');
  elements.scanButton.disabled = true;

  try {
    const response = await fetchWithTimeout(`${CONFIG.apiBaseUrl}/scan`, {
      method: 'POST',
      body: formData
    }, 30000); // Longer timeout for file scanning

    const result = await response.json();

    if (result.status === 'infected') {
      setScanResult('Threat detected!', 'infected', 'warning');
      console.log('Threat details:', result.detail);
    } else if (result.status === 'clean') {
      setScanResult('No threats found', 'clean', 'check_circle');
    } else {
      setScanResult('Scan failed', 'error', 'error');
      console.error('Scan error:', result.detail);
    }

    // Update last scan time
    updateLastScanTime();

    // Reload events and quarantine immediately
    loadEvents();
    loadQuarantine();
  } catch (error) {
    console.error('Error scanning file:', error);
    setScanResult('Error scanning file', 'error', 'error');
  } finally {
    elements.scanButton.disabled = false;
  }
}

function resetScanResult() {
  elements.scanResult.className = 'scan-result';
  elements.scanResult.innerHTML = `
    <div class="result-icon">
      <i class="material-icons">info</i>
    </div>
    <div class="result-message">Ready to scan</div>
  `;
}

function setScanResult(message, type = 'info', icon = 'info') {
  elements.scanResult.className = `scan-result ${type}`;
  elements.scanResult.innerHTML = `
    <div class="result-icon">
      <i class="material-icons">${icon}</i>
    </div>
    <div class="result-message">${message}</div>
  `;
}

// Events table functions
async function loadEvents() {
  try {
    const response = await fetchWithTimeout(`${CONFIG.apiBaseUrl}/events`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const events = await response.json();

    // Only update if events have changed
    if (JSON.stringify(events) !== JSON.stringify(state.events)) {
      state.events = events;
      renderEvents(events);
    }
  } catch (error) {
    if (error.name !== 'AbortError') {
      console.error('Error loading events:', error);
    }
  }
}

function renderEvents(events) {
  const tbody = elements.eventsTable;
  if (!tbody) {
    console.error('Events table body not found');
    return;
  }

  if (!events || events.length === 0) {
    tbody.innerHTML = '<tr class="no-events"><td colspan="5">No events found</td></tr>';
    return;
  }

  // Filter out duplicate events
  const uniqueEvents = events.filter((event, index, self) => {
    if (!event || !event.file) return true;
    const firstIndex = self.findIndex(e =>
      e && e.file === event.file &&
      Math.abs((e.timestamp || 0) - (event.timestamp || 0)) < 2
    );
    return index === firstIndex;
  });

  // Sort events by timestamp (newest first)
  uniqueEvents.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

  // Use DocumentFragment for better performance
  const fragment = document.createDocumentFragment();

  // Render events
  uniqueEvents.forEach(event => {
    const row = document.createElement('tr');
    const timestamp = new Date((event.timestamp || 0) * 1000).toLocaleString();
    const statusClass = `status-${event.status || 'info'}`;

    row.innerHTML = `
      <td>${timestamp}</td>
      <td>${event.file || 'N/A'}</td>
      <td><span class="status-badge ${statusClass}">${event.status || 'info'}</span></td>
      <td>${event.detail || ''}</td>
      <td>${event.action || ''}</td>
    `;

    fragment.appendChild(row);
  });

  tbody.innerHTML = '';
  tbody.appendChild(fragment);
}

async function clearEvents() {
  if (!confirm('Are you sure you want to clear all events? This cannot be undone.')) {
    return;
  }

  try {
    const response = await fetchWithTimeout(`${CONFIG.apiBaseUrl}/events/clear`, {
      method: 'POST'
    });

    const result = await response.json();

    if (result.status === 'success') {
      state.events = [];
      renderEvents([]);
      showNotification('Events cleared successfully', 'success');
    } else {
      throw new Error(result.message || 'Failed to clear events');
    }
  } catch (error) {
    if (error.name !== 'AbortError') {
      console.error('Error clearing events:', error);
      showNotification(`Error: ${error.message}`, 'error');
    }
  }
}

// Quarantine functions
async function loadQuarantine() {
  try {
    const response = await fetchWithTimeout(`${CONFIG.apiBaseUrl}/quarantine`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const files = await response.json();

    // Only update if quarantine has changed
    if (JSON.stringify(files) !== JSON.stringify(state.quarantineFiles)) {
      state.quarantineFiles = files;
      renderQuarantine(files);
    }
  } catch (error) {
    if (error.name !== 'AbortError') {
      console.error('Error loading quarantine:', error);
    }
  }
}

function renderQuarantine(files) {
  const tbody = document.querySelector('#quarantine-table tbody');
  if (!tbody) {
    console.error('Quarantine table body not found');
    return;
  }

  if (!files || files.length === 0) {
    tbody.innerHTML = '<tr class="no-files"><td colspan="5">No files in quarantine</td></tr>';
    updateSelectionButtons();
    return;
  }

  // Use DocumentFragment for better performance
  const fragment = document.createDocumentFragment();

  files.forEach(file => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td><input type="checkbox" class="quarantine-checkbox" data-path="${file.path}"></td>
      <td>${file.filename}</td>
      <td>${formatFileSize(file.size || 0)}</td>
      <td>${new Date(file.quarantined_at * 1000).toLocaleString()}</td>
      <td class="actions">
        <button class="btn btn-sm btn-restore" data-path="${file.path}" data-filename="${file.filename}">
          <i class="material-icons">restore</i> Restore
        </button>
        <button class="btn btn-sm btn-delete" data-path="${file.path}" data-filename="${file.filename}">
          <i class="material-icons">delete_forever</i>
        </button>
      </td>
    `;
    fragment.appendChild(row);
  });

  tbody.innerHTML = '';
  tbody.appendChild(fragment);

  // Add event listeners for the new buttons
  document.querySelectorAll('.btn-restore').forEach(btn => {
    btn.addEventListener('click', handleRestoreFile);
  });

  document.querySelectorAll('.btn-delete').forEach(btn => {
    btn.addEventListener('click', handleDeleteFile);
  });

  document.querySelectorAll('.quarantine-checkbox').forEach(checkbox => {
    checkbox.addEventListener('change', updateSelectionButtons);
  });

  updateSelectionButtons();
}

// Improved restore file with danger confirmation
async function handleRestoreFile(event) {
  const filePath = event.currentTarget.dataset.path;
  const fileName = event.currentTarget.dataset.filename;

  // Show custom danger confirmation dialog
  const confirmed = await showDangerConfirmation(
    'Restore File from Quarantine?',
    `Are you sure you want to restore "${fileName}"? This file was quarantined because it may be dangerous. Restoring it could harm your system.`,
    'Restore Anyway',
    'Cancel'
  );

  if (!confirmed) {
    return;
  }

  try {
    showNotification('Restoring file...', 'info');

    const response = await fetchWithTimeout(`${CONFIG.apiBaseUrl}/quarantine/restore`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: filePath })
    });

    const result = await response.json();

    if (response.ok) {
      showNotification(`File restored successfully to: ${result.restored_path || 'restored_files folder'}`, 'success');
      loadQuarantine(); // Refresh the quarantine list
      loadEvents(); // Refresh events to show the restore action
    } else {
      throw new Error(result.error || 'Failed to restore file');
    }
  } catch (error) {
    if (error.name !== 'AbortError') {
      console.error('Error restoring file:', error);
      showNotification(`Failed to restore file: ${error.message}`, 'error');
    }
  }
}

async function handleDeleteFile(event) {
  const filePath = event.currentTarget.dataset.path;
  const fileName = event.currentTarget.dataset.filename;

  // Show custom danger confirmation dialog
  const confirmed = await showDangerConfirmation(
    'Permanently Delete File?',
    `Are you sure you want to permanently delete "${fileName}"? This action cannot be undone.`,
    'Delete Permanently',
    'Cancel'
  );

  if (!confirmed) {
    return;
  }

  try {
    const response = await fetchWithTimeout(`${CONFIG.apiBaseUrl}/quarantine/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: filePath })
    });

    if (response.ok) {
      showNotification('File deleted permanently', 'success');
      loadQuarantine(); // Refresh the quarantine list
      loadEvents(); // Refresh events to show the delete action
    } else {
      throw new Error('Failed to delete file');
    }
  } catch (error) {
    if (error.name !== 'AbortError') {
      console.error('Error deleting file:', error);
      showNotification(`Failed to delete file: ${error.message}`, 'error');
    }
  }
}

function updateSelectionButtons() {
  const checkboxes = document.querySelectorAll('.quarantine-checkbox:checked');
  const deleteSelectedBtn = document.getElementById('delete-selected');
  const restoreSelectedBtn = document.getElementById('restore-selected');

  if (deleteSelectedBtn && restoreSelectedBtn) {
    const hasSelection = checkboxes.length > 0;
    deleteSelectedBtn.disabled = !hasSelection;
    restoreSelectedBtn.disabled = !hasSelection;
  }
}

// Bulk action handlers with danger confirmation
async function handleDeleteSelected() {
  const checkboxes = document.querySelectorAll('.quarantine-checkbox:checked');
  if (checkboxes.length === 0) return;

  const confirmed = await showDangerConfirmation(
    'Delete Multiple Files?',
    `Are you sure you want to permanently delete ${checkboxes.length} selected file(s)? This action cannot be undone.`,
    'Delete All',
    'Cancel'
  );

  if (!confirmed) return;

  try {
    showNotification(`Deleting ${checkboxes.length} file(s)...`, 'info');

    const deletePromises = Array.from(checkboxes).map(checkbox =>
      fetchWithTimeout(`${CONFIG.apiBaseUrl}/quarantine/delete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: checkbox.dataset.path })
      })
    );

    await Promise.all(deletePromises);
    showNotification(`Successfully deleted ${checkboxes.length} file(s)`, 'success');
    loadQuarantine();
    loadEvents();
  } catch (error) {
    if (error.name !== 'AbortError') {
      console.error('Error deleting files:', error);
      showNotification('Failed to delete some files', 'error');
    }
  }
}

async function handleRestoreSelected() {
  const checkboxes = document.querySelectorAll('.quarantine-checkbox:checked');
  if (checkboxes.length === 0) return;

  const confirmed = await showDangerConfirmation(
    'Restore Multiple Files?',
    `Are you sure you want to restore ${checkboxes.length} selected file(s)? These files were quarantined because they may be dangerous.`,
    'Restore All',
    'Cancel'
  );

  if (!confirmed) return;

  try {
    showNotification(`Restoring ${checkboxes.length} file(s)...`, 'info');

    const restorePromises = Array.from(checkboxes).map(checkbox =>
      fetchWithTimeout(`${CONFIG.apiBaseUrl}/quarantine/restore`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: checkbox.dataset.path })
      })
    );

    await Promise.all(restorePromises);
    showNotification(`Successfully restored ${checkboxes.length} file(s)`, 'success');
    loadQuarantine();
    loadEvents();
  } catch (error) {
    if (error.name !== 'AbortError') {
      console.error('Error restoring files:', error);
      showNotification('Failed to restore some files', 'error');
    }
  }
}

// Custom danger confirmation dialog
function showDangerConfirmation(title, message, confirmText, cancelText) {
  return new Promise((resolve) => {
    // Remove any existing modal
    const existingModal = document.querySelector('.danger-modal');
    if (existingModal) {
      existingModal.remove();
    }

    // Create modal overlay
    const modal = document.createElement('div');
    modal.className = 'danger-modal';
    modal.innerHTML = `
      <div class="danger-modal-content">
        <div class="danger-modal-header">
          <i class="material-icons danger-icon">warning</i>
          <h3>${title}</h3>
        </div>
        <div class="danger-modal-body">
          <p>${message}</p>
        </div>
        <div class="danger-modal-footer">
          <button class="btn btn-cancel">${cancelText}</button>
          <button class="btn btn-danger">${confirmText}</button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    // Handle button clicks
    const cancelBtn = modal.querySelector('.btn-cancel');
    const confirmBtn = modal.querySelector('.btn-danger');

    cancelBtn.onclick = () => {
      modal.remove();
      resolve(false);
    };

    confirmBtn.onclick = () => {
      modal.remove();
      resolve(true);
    };

    // Close on backdrop click
    modal.onclick = (e) => {
      if (e.target === modal) {
        modal.remove();
        resolve(false);
      }
    };

    // Close on ESC key
    const escHandler = (e) => {
      if (e.key === 'Escape') {
        modal.remove();
        resolve(false);
        document.removeEventListener('keydown', escHandler);
      }
    };
    document.addEventListener('keydown', escHandler);
  });
}

// Helper functions
function updateLastScanTime() {
  if (elements.lastScan) {
    elements.lastScan.textContent = new Date().toLocaleString();
  }
}

function updateWatchDir() {
  if (elements.watchDir) {
    elements.watchDir.textContent = CONFIG.defaultWatchDir;
  }
}

function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function showNotification(message, type = 'info') {
  // Remove any existing toast
  const existingToast = document.querySelector('.toast');
  if (existingToast) {
    existingToast.remove();
  }

  // Create new toast
  const toast = document.createElement('div');
  toast.className = `toast ${type} show`;

  // Add icon based on type
  const icons = {
    'success': 'check_circle',
    'error': 'error',
    'warning': 'warning',
    'info': 'info'
  };

  toast.innerHTML = `
    <i class="material-icons">${icons[type] || 'info'}</i>
    <span>${message}</span>
  `;

  document.body.appendChild(toast);

  // Auto-remove after 4 seconds
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Clean up on page unload
window.addEventListener('beforeunload', () => {
  stopAutoRefresh();
});

// Initialize the app when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  init();
});