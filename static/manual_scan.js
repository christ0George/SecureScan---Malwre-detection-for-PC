// manual_scan.js — UI matches dashboard.js (same toast + danger modal system)

let currentScanResults = null;

// ── Notification toast (mirrors dashboard.js showNotification) ────────────────
function showNotification(message, type = 'info') {
    const existingToast = document.querySelector('.toast');
    if (existingToast) existingToast.remove();

    const icons = {
        success: 'check_circle',
        error: 'error',
        warning: 'warning',
        info: 'info'
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type} show`;
    toast.innerHTML = `
    <i class="material-icons">${icons[type] || 'info'}</i>
    <span>${message}</span>
  `;

    document.body.appendChild(toast);

    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ── Danger confirmation modal (mirrors dashboard.js showDangerConfirmation) ───
function showDangerConfirmation(title, message, confirmText, cancelText) {
    return new Promise((resolve) => {
        const existing = document.querySelector('.danger-modal');
        if (existing) existing.remove();

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

        modal.querySelector('.btn-cancel').onclick = () => { modal.remove(); resolve(false); };
        modal.querySelector('.btn-danger').onclick = () => { modal.remove(); resolve(true); };

        modal.onclick = (e) => { if (e.target === modal) { modal.remove(); resolve(false); } };

        const escHandler = (e) => {
            if (e.key === 'Escape') { modal.remove(); resolve(false); document.removeEventListener('keydown', escHandler); }
        };
        document.addEventListener('keydown', escHandler);
    });
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('btn-start-scan').addEventListener('click', startFolderScan);
    document.getElementById('btn-close-results').addEventListener('click', closeResults);
    document.getElementById('btn-select-all').addEventListener('click', selectAllFiles);
    document.getElementById('btn-delete-selected').addEventListener('click', deleteSelectedFiles);
    document.getElementById('btn-refresh-reports').addEventListener('click', loadReports);
    document.getElementById('btn-clear-reports').addEventListener('click', clearReports);

    // "Continue with No Action" button — added in the HTML action-buttons row
    const noActionBtn = document.getElementById('btn-no-action');
    if (noActionBtn) noActionBtn.addEventListener('click', continueWithNoAction);

    loadReports();
});

// ── Folder scan ───────────────────────────────────────────────────────────────
async function startFolderScan() {
    const folderPath = document.getElementById('folder-path').value.trim();

    if (!folderPath) {
        showNotification('Please enter a folder path', 'error');
        return;
    }

    const scanBtn = document.getElementById('btn-start-scan');
    const progress = document.getElementById('scan-progress');
    const results = document.getElementById('scan-results');

    progress.classList.add('active');
    results.classList.remove('active');
    scanBtn.disabled = true;

    try {
        const response = await fetch('/api/manual_scan/scan_folder', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ folder_path: folderPath })
        });

        const data = await response.json();

        if (response.ok && data.status === 'success') {
            currentScanResults = data;
            displayScanResults(data);
        } else {
            throw new Error(data.error || 'Scan failed');
        }
    } catch (error) {
        console.error('Scan error:', error);
        showNotification(`Scan failed: ${error.message}`, 'error');
    } finally {
        progress.classList.remove('active');
        scanBtn.disabled = false;
    }
}

// ── Display results ───────────────────────────────────────────────────────────
function displayScanResults(data) {
    const results = document.getElementById('scan-results');
    const infectedContainer = document.getElementById('infected-files-container');
    const cleanResult = document.getElementById('clean-result');

    document.getElementById('stat-folder').textContent = data.folder_path;
    document.getElementById('stat-total').textContent = data.total_files;
    document.getElementById('stat-scanned').textContent = data.scanned_files;
    document.getElementById('stat-infected').textContent = data.infected_count;

    results.classList.add('active');

    if (data.infected_count > 0) {
        infectedContainer.style.display = 'block';
        cleanResult.style.display = 'none';
        // renderInfectedFiles is defined in the inline <script> in manual_scan.html
        renderInfectedFiles(data.infected_files);
    } else {
        infectedContainer.style.display = 'none';
        cleanResult.style.display = 'block';
    }
}

// ── Select All ────────────────────────────────────────────────────────────────
function selectAllFiles() {
    document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = true);
    if (typeof syncDeleteBtn === 'function') syncDeleteBtn();
}

// ── Delete selected files ─────────────────────────────────────────────────────
async function deleteSelectedFiles() {
    if (!currentScanResults || !currentScanResults.infected_files) {
        showNotification('No scan results available', 'error');
        return;
    }

    const selectedFiles = typeof getSelectedFiles === 'function'
        ? getSelectedFiles()
        : Array.from(document.querySelectorAll('.file-checkbox:checked')).map(cb => ({
            path: cb.dataset.path,
            filename: cb.dataset.filename
        }));

    if (selectedFiles.length === 0) {
        showNotification('No files selected. Use "Continue with No Action" to keep all files.', 'warning');
        return;
    }

    const confirmed = await showDangerConfirmation(
        'Delete Infected Files?',
        `You are about to permanently delete <strong>${selectedFiles.length}</strong> file(s). This action cannot be undone.`,
        'Delete Permanently',
        'Cancel'
    );

    if (!confirmed) return;

    const deleteBtn = document.getElementById('btn-delete-selected');
    deleteBtn.disabled = true;
    deleteBtn.innerHTML = '<i class="material-icons">hourglass_empty</i> Deleting...';

    try {
        showNotification(`Deleting ${selectedFiles.length} file(s)…`, 'info');

        const response = await fetch('/api/manual_scan/delete_files', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                files: selectedFiles,
                folder_path: currentScanResults.folder_path,
                all_infected_files: currentScanResults.infected_files
            })
        });

        const result = await response.json();

        if (response.ok && result.status === 'success') {
            const total = result.deleted_count + result.not_deleted_count;
            showNotification(
                `Deleted ${result.deleted_count} of ${total} file(s). ${result.not_deleted_count} file(s) kept.`,
                'success'
            );
            setTimeout(() => { loadReports(); closeResults(); }, 2000);
        } else {
            throw new Error(result.error || 'Delete failed');
        }
    } catch (error) {
        console.error('Delete error:', error);
        showNotification(`Delete failed: ${error.message}`, 'error');
    } finally {
        deleteBtn.disabled = false;
        deleteBtn.innerHTML = '<i class="material-icons">delete_forever</i> Delete Selected Files';
    }
}

// ── Continue with No Action ───────────────────────────────────────────────────
async function continueWithNoAction() {
    if (!currentScanResults) return;

    try {
        const response = await fetch('/api/manual_scan/save_no_action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                folder_path: currentScanResults.folder_path,
                all_infected_files: currentScanResults.infected_files
            })
        });

        if (response.ok) {
            showNotification('Report saved — no files were deleted.', 'info');
            setTimeout(() => { loadReports(); closeResults(); }, 2000);
        } else {
            throw new Error('Failed to save report');
        }
    } catch (error) {
        console.error('No-action save error:', error);
        showNotification(`Failed to save report: ${error.message}`, 'error');
    }
}

// ── Close results ─────────────────────────────────────────────────────────────
function closeResults() {
    document.getElementById('scan-results').classList.remove('active');
    currentScanResults = null;
}

// ── Load reports ──────────────────────────────────────────────────────────────
async function loadReports() {
    try {
        const response = await fetch('/api/manual_scan/reports');
        const reports = await response.json();
        displayReports(reports);
    } catch (error) {
        console.error('Error loading reports:', error);
        showNotification('Failed to load reports', 'error');
    }
}

// ── Display reports ───────────────────────────────────────────────────────────
function displayReports(reports) {
    const tbody = document.getElementById('reports-table-body');
    tbody.innerHTML = '';

    if (!reports || reports.length === 0) {
        tbody.innerHTML = '<tr class="empty-state"><td colspan="4">No scan reports yet. Start scanning folders to see reports here.</td></tr>';
        return;
    }

    reports.forEach(report => {
        const row = document.createElement('tr');
        const date = new Date(report.timestamp * 1000).toLocaleString();

        row.innerHTML = `
      <td>${date}</td>
      <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
          title="${report.folder_path}">${report.folder_path}</td>
      <td><span style="color:var(--danger);font-weight:600;">${report.total_infected}</span></td>
      <td>
        <button class="expand-btn" onclick="toggleDetails(this, ${JSON.stringify(report).replace(/"/g, '&quot;')})">
          <i class="material-icons">expand_more</i> View Details
        </button>
      </td>
    `;
        tbody.appendChild(row);
    });
}

// ── Toggle report details ─────────────────────────────────────────────────────
function toggleDetails(button, report) {
    const tr = button.closest('tr');
    let detailsRow = tr.nextElementSibling;

    if (detailsRow && detailsRow.classList.contains('file-details-row')) {
        detailsRow.remove();
        button.innerHTML = '<i class="material-icons">expand_more</i> View Details';
    } else {
        detailsRow = document.createElement('tr');
        detailsRow.className = 'file-details-row expanded';

        let fileListHTML = '<ul class="file-list">';
        report.files.forEach(file => {
            const cls = file.action === 'deleted' ? 'action-deleted' : 'action-no-action';
            fileListHTML += `<li><span>${file.filename}</span><span class="${cls}">${file.action}</span></li>`;
        });
        fileListHTML += '</ul>';

        detailsRow.innerHTML = `
      <td colspan="4" class="file-details-cell">
        <strong>Files in this scan:</strong>
        ${fileListHTML}
      </td>
    `;
        tr.after(detailsRow);
        button.innerHTML = '<i class="material-icons">expand_less</i> Hide Details';
    }
}

// ── Clear reports ─────────────────────────────────────────────────────────────
async function clearReports() {
    const confirmed = await showDangerConfirmation(
        'Clear All Reports?',
        'Are you sure you want to clear all scan reports? This cannot be undone.',
        'Clear All',
        'Cancel'
    );

    if (!confirmed) return;

    try {
        const response = await fetch('/api/manual_scan/clear_reports', { method: 'POST' });

        if (response.ok) {
            showNotification('Reports cleared successfully', 'success');
            loadReports();
        } else {
            throw new Error('Failed to clear reports');
        }
    } catch (error) {
        console.error('Error clearing reports:', error);
        showNotification('Failed to clear reports', 'error');
    }
}

// ── Format file size ──────────────────────────────────────────────────────────
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}