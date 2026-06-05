let ragReady = false;
let hasExistingData = false;
let autoConvertEnabled = false;
let reportsPage = 1;
let reportsPageSize = 5;
let reportsTotalPages = 0;
let reportsTotalItems = 0;
let currentReportsCount = 0;

function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[char]));
}

function encodePathSegment(value) {
    return encodeURIComponent(String(value ?? '')).replace(/'/g, '%27');
}

function toggleReportContent(reportId) {
    const contentDiv = document.getElementById(reportId);
    const button = event.target;
    const isVisible = contentDiv.style.display === 'block';
    
    contentDiv.style.display = isVisible ? 'none' : 'block';
    button.textContent = isVisible ? '👁️ View' : '🙈 Hide';
}

function toggleOptions() {
    document.getElementById('archiveOptions').style.display =
        document.getElementById('useArchivesCheck').checked ? 'block' : 'none';
    document.getElementById('uploadOptions').style.display =
        document.getElementById('useUploadsCheck').checked ? 'block' : 'none';
    updateBuildButtonState();
}

function showDuplicateWarning(duplicates) {
    const warningDiv = document.getElementById('duplicateWarning');
    if (!warningDiv) return; // If warning div doesn't exist in HTML, skip
    
    if (duplicates && duplicates.length > 0) {
        warningDiv.style.display = 'block';
        warningDiv.innerHTML = `
            <strong>${duplicates.length} duplicate file(s) found in database:</strong><br>
            ${duplicates.map(d => `${escapeHtml(d.filename)} (hash: ${escapeHtml(d.hash.substring(0, 16))}...)`).join('<br>')}
            <br><small>These files will be skipped during upload.</small>
        `;
    } else {
        warningDiv.style.display = 'none';
    }
}

function updateBuildButtonState() {
    const useArchives = document.getElementById('useArchivesCheck').checked;
    const useUploads = document.getElementById('useUploadsCheck').checked;
    const btn = document.getElementById('buildRagBtn');
    
    btn.disabled = !(useArchives || useUploads || hasExistingData);
    
    if (hasExistingData && !useArchives && !useUploads) {
        btn.textContent = '🔄 Refresh RAG Context from Database';
    } else {
        btn.textContent = '🔄 Build/Update RAG Context';
    }
}
async function validateFiles() {
    const fileInput = document.getElementById('customDocs');
    const validationDiv = document.getElementById('fileValidation');
    const files = Array.from(fileInput.files);
    
    if (files.length === 0) {
        validationDiv.innerHTML = '';
        showDuplicateWarning([]);
        return;
    }
    
    const currentSelection = new Set();
    let duplicateCount = 0;
    const fileList = [];
    
    files.forEach(file => {
        const isDuplicateInSelection = currentSelection.has(file.name);
        
        if (isDuplicateInSelection) {
            duplicateCount++;
            fileList.push(`<span style="color: #dc3545;"> ${escapeHtml(file.name)} (duplicate in selection - will be removed)</span>`);
        } else {
            currentSelection.add(file.name);
            fileList.push(`<span style="color: #28a745;">✅ ${file.name}</span>`);
        }
    });
    
    try {
        const formData = new FormData();
        for (let file of files) {
            formData.append('files', file);
        }
        
        const response = await fetch('/check-duplicates', {
            method: 'POST',
            body: formData
        });
        
        if (response.ok) {
            const result = await response.json();
            
            if (result.duplicates && result.duplicates.length > 0) {
                const updatedFileList = [];
                for (let i = 0; i < fileList.length; i++) {
                    const fileName = files[i].name;
                    const dupInfo = result.duplicates.find(d => d.filename === fileName);
                    
                    if (dupInfo) {
                        updatedFileList.push(`<span style="color: #ffc107;">⚠️ ${fileName} (already in database - hash: ${dupInfo.hash.substring(0, 16)}...)</span>`);
                    } else {
                        updatedFileList.push(fileList[i]);
                    }
                }
                fileList.length = 0;
                fileList.push(...updatedFileList);
                
                showDuplicateWarning(result.duplicates);
            }
        }
    } catch (error) {
        console.warn('Could not check for server-side duplicates:', error);
    }
    
    validationDiv.innerHTML = `
        <div style="background-color: #1a1a1a; padding: 10px; border-radius: 5px;">
            <strong>📋 Files selected: ${files.length}</strong><br>
            ${fileList.join('<br>')}
            ${duplicateCount > 0 ? `<br><small style="color: #ffc107;">Note: ${duplicateCount} duplicate(s) in your selection will be ignored</small>` : ''}
        </div>
    `;
    
    updateBuildButtonState();
}

function updateRAGStatus(ready, message) {
    const statusDiv = document.getElementById('ragStatus');
    const statusText = document.getElementById('ragStatusText');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    ragReady = ready;
    statusText.textContent = message;
    statusDiv.className = ready ? 'status-indicator ready' : 'status-indicator not-ready';
    analyzeBtn.disabled = !ready;
}

function showProgress(sessionId, operation, onComplete = null) {
    const progressDiv = document.createElement('div');
    progressDiv.className = 'progress-container';
    progressDiv.innerHTML = `
        <div class="progress-bar">
            <div id="progress-fill" class="progress-fill" style="width: 0%;"></div>
        </div>
        <div id="progress-text" style="margin-bottom: 10px; font-weight: bold;">Starting ${operation}...</div>
        <div id="progress-log" class="progress-log"></div>
    `;
    document.getElementById('status').innerHTML = '';
    document.getElementById('status').appendChild(progressDiv);
    
    const ws = new WebSocket(`ws://${window.location.host}/ws/progress/${sessionId}`);
    let completionHandled = false;
    
    ws.onmessage = function(event) {
        const data = JSON.parse(event.data);
        document.getElementById('progress-fill').style.width = data.progress + '%';
        document.getElementById('progress-text').textContent = `${data.progress}% - ${data.message}`;
        
        const log = document.getElementById('progress-log');
        log.textContent += `[${data.timestamp}] ${data.message}\n`;
        log.scrollTop = log.scrollHeight;
        
        if (data.progress === 100 || data.status === 'error') {
            completionHandled = true;
            ws.close();
            
            // 🆕 For analysis operations, DON'T trigger redirect here
            // Let the polling interval handle it
            if (operation === 'RAG build') {
                if (data.status === 'success') {
                    updateRAGStatus(true, '✅ RAG context ready!');
                }
                if (onComplete) {
                    onComplete(data.status === 'success', data);
                }
            } else if (operation === 'analysis') {
                // Just call onComplete to restore button, but don't check redirect
                if (onComplete) {
                    onComplete(data.status === 'success', data);
                }
                // Polling interval will handle redirect
            } else {
                if (onComplete) {
                    onComplete(data.status === 'success', data);
                }
            }
        }
    };
    
    ws.onclose = function() {
        if (!completionHandled) {
            console.warn('⚠️ WebSocket closed without completion');
            if (onComplete) {
                onComplete(false);
            }
        }
    };
    
    ws.onerror = function(error) {
        console.error('❌ WebSocket error:', error);
        if (!completionHandled) {
            completionHandled = true;
            if (onComplete) {
                onComplete(false);
            }
        }
    };
}

async function buildRAG() {
    const useArchives = document.getElementById('useArchivesCheck').checked;
    const useUploads = document.getElementById('useUploadsCheck').checked;

    if (!useArchives && !useUploads && !hasExistingData) {
        alert("No existing data found. Please select at least one source for initial build.");
        return;
    }

    const btn = document.getElementById('buildRagBtn');
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = '⏳ Building RAG...';
    updateRAGStatus(false, '🔄 Building RAG context...');
    
    const formData = new FormData();
    formData.append('use_archives', useArchives);
    formData.append('use_uploads', useUploads);

    if (useArchives) {
        formData.append('ragDays', document.getElementById('ragDays').value);
    }
    
    if (useUploads) {
        const customFiles = document.getElementById('customDocs').files;
        for (let i = 0; i < customFiles.length; i++) {
            formData.append('customFiles', customFiles[i]);
        }
    }
    
    const restoreButton = (success = false) => {
        btn.disabled = false;
        btn.textContent = originalText;
        if (success) {
            document.getElementById('customDocs').value = '';
            document.getElementById('fileValidation').innerHTML = '';
        }
        updateBuildButtonState();
    };
    
    try {
        const response = await fetch('/build-rag', { method: 'POST', body: formData });
        if (response.ok) {
            const result = await response.json();
            showProgress(result.session_id, 'RAG build', restoreButton);
        } else {
            const error = await response.json();
            alert(`Error: ${error.detail}`);
            updateRAGStatus(false, `❌ Error: ${error.detail}`);
            restoreButton(false);
        }
    } catch (error) {
        updateRAGStatus(false, `❌ Network error: ${error.message}`);
        restoreButton(false);
    }
}

async function analyzeAlerts() {
    if (!ragReady) {
        alert('Please build RAG context first!');
        return;
    }
    
    const btn = document.getElementById('analyzeBtn');
    const alertTemplateInput = document.getElementById('alertTemplate');
    const alertTemplate = alertTemplateInput && alertTemplateInput.files.length > 0
        ? alertTemplateInput.files[0]
        : null;

    if (alertTemplate && !alertTemplate.name.toLowerCase().endsWith('.json')) {
        alert('Alert template must be a .json file.');
        return;
    }

    btn.disabled = true;
    btn.textContent = '⏳ Analyzing...';
    
    try {
        const formData = new FormData();
        formData.append('include_charts', 'true');
        if (alertTemplate) {
            formData.append('alertTemplate', alertTemplate);
        }

        const response = await fetch('/analyze-alerts', { method: 'POST', body: formData });
        if (response.ok) {
            const result = await response.json();
            const sessionId = result.session_id;
            
            let redirectCheckInterval = null;
            let redirectFound = false;
            
            // Start polling immediately so the browser can move to the review page once ready.
            redirectCheckInterval = setInterval(async () => {
                if (redirectFound) return; // Skip if already redirecting
                
                try {
                    const checkResponse = await fetch(`/api/check-analysis-result/${sessionId}`);
                    const checkResult = await checkResponse.json();
                    
                    
                    if (checkResult.redirect && checkResult.report_id) {
                        redirectFound = true;
                        clearInterval(redirectCheckInterval);
                        window.location.href = `/review-report/${checkResult.report_id}`;
                    }
                } catch (err) {
                    console.error('❌ Error checking redirect:', err);
                }
            }, 2000); // Check every 2 seconds
            
            // Stop polling after 10 minutes if the background task never returns a report.
            setTimeout(() => {
                if (redirectCheckInterval && !redirectFound) {
                    clearInterval(redirectCheckInterval);
                    console.warn('⚠️ Redirect polling stopped (timeout)');
                    btn.disabled = false;
                    btn.textContent = '🎯 Auto-Analyze Current Alerts with RAG';
                }
            }, 600000);
            
            showProgress(sessionId, 'analysis');
            
        } else {
            const error = await response.json();
            alert(`Error: ${error.detail}`);
            btn.disabled = false;
            btn.textContent = '🎯 Auto-Analyze Current Alerts with RAG';
        }
    } catch (error) {
        alert(`Network error: ${error.message}`);
        btn.disabled = false;
        btn.textContent = '🎯 Auto-Analyze Current Alerts with RAG';
    }
}
async function convertSingleReport() {
    const reportSelect = document.getElementById('reportSelect');
    const selectedReport = reportSelect.value;
    
    if (!selectedReport) {
        alert('Please select a report to convert');
        return;
    }
    
    try {
        const formData = new FormData();
        formData.append('filename', selectedReport);
        
        const response = await fetch('/convert-to-pdf', {
            method: 'POST',
            body: formData
        });
        
        if (response.ok) {
            const result = await response.json();
            alert(`✅ PDF created: ${result.pdf_filename}`);
            loadReports();
        } else {
            const error = await response.json();
            alert(`Error: ${error.detail}`);
        }
    } catch (error) {
        alert(`Network error: ${error.message}`);
    }
}

async function batchConvertReports() {
    try {
        const response = await fetch('/batch-convert-pdf', { method: 'POST' });
        if (response.ok) {
            const result = await response.json();
            const summary = result.results || result;
            
            if (summary.converted && summary.failed && summary.skipped) {
                alert(`✅ Batch conversion complete:\n${summary.converted.length} converted\n${summary.failed.length} failed\n${summary.skipped.length} skipped`);
            } else {
                alert(`✅ Batch conversion complete: ${JSON.stringify(summary)}`);
            }
            
            loadReports();
        } else {
            const error = await response.json();
            alert(`Error: ${error.detail}`);
        }
    } catch (error) {
        alert(`Network error: ${error.message}`);
    }
}

async function loadReports(page = reportsPage) {
    reportsPage = page;
    try {
        const params = new URLSearchParams({
            page: reportsPage,
            page_size: reportsPageSize,
            include_all_markdown: 'true'
        });
        const response = await fetch(`/reports?${params.toString()}`);
        const data = await response.json();
        const reports = data.items || [];
        reportsTotalPages = data.total_pages || 0;
        reportsTotalItems = data.total_items || reports.length;
        currentReportsCount = reports.length;
        const reportsList = document.getElementById('reportsList');
        const reportSelect = document.getElementById('reportSelect');
        
        if (reports.length === 0) {
            reportsList.innerHTML = '<p>No reports generated yet.</p>';
        } else {
            reportsList.innerHTML = reports.map(report => {
                const filename = report.filename || '';
                const encodedFilename = encodePathSegment(filename);
                const safeFilename = escapeHtml(filename);
                const safeCreated = escapeHtml(report.created);
                const safeSize = escapeHtml(report.size);
                return `
                    <div class="report-item">
                        <div>
                            <a href="/reports/${encodedFilename}" target="_blank">${safeFilename}</a><br>
                            <small>Generated: ${safeCreated} | Size: ${safeSize}</small>
                        </div>
                        <div class="report-actions">
                            ${filename.endsWith('.md') ? `<button onclick="convertReport(decodeURIComponent('${encodedFilename}'))"> To PDF</button>` : ''}
                            <button onclick="downloadReport(decodeURIComponent('${encodedFilename}'))"> Download</button>
                        </div>
                    </div>
                `;
            }).join('');
        }
        
        const markdownReports = data.markdown_reports
            ? data.markdown_reports
            : reports
                .filter(r => r.filename && r.filename.endsWith('.md'))
                .map(r => r.filename);
        reportSelect.innerHTML = '<option value="">Select a report to convert...</option>' +
            markdownReports.map(filename => `<option value="${escapeHtml(filename)}">${escapeHtml(filename)}</option>`).join('');
        renderReportsPagination();
        
    } catch (error) {
        console.error('Error loading reports:', error);
        const reportsList = document.getElementById('reportsList');
        reportsList.innerHTML = '<p style="color:#ffc107;">Unable to load reports.</p>';
    }
}

function renderReportsPagination() {
    const paginationContainer = document.getElementById('reportsPagination');
    if (!paginationContainer) return;
    if (!reportsTotalItems) {
        paginationContainer.innerHTML = '';
        return;
    }
    const totalPagesDisplay = reportsTotalPages || 1;
    const prevDisabled = reportsPage <= 1;
    const nextDisabled = reportsTotalPages && reportsPage >= reportsTotalPages;
    const showingStart = reportsTotalItems ? ((reportsPage - 1) * reportsPageSize) + 1 : 0;
    const showingEnd = reportsTotalItems ? Math.min(showingStart + currentReportsCount - 1, reportsTotalItems) : 0;
    paginationContainer.innerHTML = `
        <div class="pagination-summary">
            Showing ${currentReportsCount ? showingStart : 0}-${currentReportsCount ? showingEnd : 0} of ${reportsTotalItems}
        </div>
        <div class="pagination-controls">
            <button class="pagination-button${prevDisabled ? ' disabled' : ''}" ${prevDisabled ? 'disabled' : ''}
                onclick="changeReportsPage(${reportsPage - 1})">⬅️ Previous</button>
            <span>Page ${reportsPage} of ${totalPagesDisplay || 1}</span>
            <button class="pagination-button${nextDisabled ? ' disabled' : ''}" ${nextDisabled ? 'disabled' : ''}
                onclick="changeReportsPage(${reportsPage + 1})">Next ➡️</button>
        </div>
        <div class="page-size-form">
            <label>
                Per page:
                <select onchange="changeReportsPageSize(this.value)">
                    ${[5, 10, 15, 20].map(size => `
                        <option value="${size}" ${Number(size) === Number(reportsPageSize) ? 'selected' : ''}>${size}</option>
                    `).join('')}
                </select>
            </label>
        </div>
    `;
}

function changeReportsPage(page) {
    if (page < 1) return;
    if (reportsTotalPages && page > reportsTotalPages) return;
    loadReports(page);
}

function changeReportsPageSize(newSize) {
    reportsPageSize = Number(newSize) || reportsPageSize;
    reportsPage = 1;
    loadReports(reportsPage);
}

async function convertReport(filename) {
    try {
        const formData = new FormData();
        formData.append('filename', filename);
        
        const response = await fetch('/convert-to-pdf', {
            method: 'POST',
            body: formData
        });
        
        if (response.ok) {
            const result = await response.json();
            alert(`✅ PDF created: ${result.pdf_filename}`);
            loadReports();
        } else {
            const error = await response.json();
            alert(`Error: ${error.detail}`);
        }
    } catch (error) {
        alert(`Network error: ${error.message}`);
    }
}

function downloadReport(filename) {
    window.open(`/reports/${encodePathSegment(filename)}`, '_blank');
}

async function checkRAGStatus() {
    try {
        const response = await fetch('/rag-status');
        const status = await response.json();
        
        hasExistingData = status.alerts_with_embeddings > 0 || status.docs_with_embeddings > 0;
        
        if (status.ready) {
            ragReady = true;
            updateRAGStatus(true, `✅ RAG Ready: ${status.alerts_with_embeddings} archive alerts + ${status.docs_with_embeddings} custom docs (Persistent DB)`);
        } else {
            ragReady = false;
            updateRAGStatus(false, '⏳ RAG not initialized - Configure and build the context first');
        }
        
        updateBuildButtonState();
    } catch (error) {
        updateRAGStatus(false, '❌ Unable to check RAG status');
    }
}

async function checkPDFStatus() {
    try {
        const response = await fetch('/pdf-status');
        const status = await response.json();
        const statusDiv = document.getElementById('pdfStatus');
        const statusText = document.getElementById('pdfStatusText');
        
        if (status.available) {
            statusDiv.className = 'status-indicator ready';
            statusText.textContent = `✅ PDF conversion ready (${status.method})`;
        } else {
            statusDiv.className = 'status-indicator warning';
            statusText.textContent = '⚠️ PDF conversion not available - check dependencies';
        }
    } catch (error) {
        const statusDiv = document.getElementById('pdfStatus');
        const statusText = document.getElementById('pdfStatusText');
        statusDiv.className = 'status-indicator not-ready';
        statusText.textContent = '❌ Unable to check PDF status';
    }
}

async function checkAutoConvertStatus() {
    try {
        const response = await fetch('/auto-convert-status');
        const status = await response.json();
        document.getElementById('autoConvertCheck').checked = status.enabled;
        autoConvertEnabled = status.enabled;
    } catch (error) {
        console.error('Error checking auto-convert status:', error);
    }
}

document.addEventListener('DOMContentLoaded', function() {
    // Auto-convert checkbox
    document.getElementById('autoConvertCheck').addEventListener('change', async function() {
        autoConvertEnabled = this.checked;
        
        try {
            const response = await fetch('/set-auto-convert', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: autoConvertEnabled })
            });
            
            if (response.ok) {
            } else {
                console.error('Failed to set auto-convert setting');
                this.checked = !this.checked;
            }
        } catch (error) {
            console.error('Error setting auto-convert:', error);
            this.checked = !this.checked;
        }
    });

    // Upload checkbox
    document.getElementById('useUploadsCheck').addEventListener('change', function() {
        if (!this.checked) {
            document.getElementById('fileValidation').innerHTML = '';
            document.getElementById('customDocs').value = '';
        }
        toggleOptions();
    });

    // Initialize on page load
    loadReports();
    checkRAGStatus();
    checkPDFStatus();
    toggleOptions();
    checkAutoConvertStatus();
});
