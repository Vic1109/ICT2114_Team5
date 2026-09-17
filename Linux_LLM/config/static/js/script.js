let ragReady = false;
let hasExistingData = false;
let ragStatusAvailable = false;

const ANALYSIS_CRAWL_MS = 10000;
const ANALYSIS_CRAWL_STEP = 1;
const ANALYSIS_CRAWL_CAP = 99;

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
    if (!contentDiv) return;
    const button = (typeof event !== 'undefined' && event && event.target) ? event.target : null;
    const isVisible = !contentDiv.hidden && contentDiv.style.display !== 'none';
    contentDiv.hidden = isVisible;
    contentDiv.style.display = isVisible ? 'none' : 'block';
    if (button && button.tagName === 'BUTTON') {
        button.textContent = isVisible ? 'Preview' : 'Hide preview';
    }
}

function toggleOptions() {
    const archives = $('useArchivesCheck');
    const uploads = $('useUploadsCheck');
    const archiveOptions = $('archiveOptions');
    const uploadOptions = $('uploadOptions');
    if (archiveOptions && archives) {
        archiveOptions.style.display = archives.checked ? 'block' : 'none';
    }
    if (uploadOptions && uploads) {
        uploadOptions.style.display = uploads.checked ? 'block' : 'none';
    }
    updateBuildButtonState();
}

function selectedRagBuildMode() {
    const selected = document.querySelector('input[name="ragBuildMode"]:checked');
    return selected ? selected.value : 'extend';
}

function toggleBuildModeOptions() {
    const mode = selectedRagBuildMode();
    const confirmation = document.getElementById('replaceConfirmation');
    const confirmationCheck = document.getElementById('confirmReplaceCheck');
    const hint = document.getElementById('buildModeHint');

    if (confirmation) {
        confirmation.style.display = hasExistingData && mode === 'replace' ? 'block' : 'none';
    }
    if ((!hasExistingData || mode !== 'replace') && confirmationCheck) {
        confirmationCheck.checked = false;
    }
    if (hint) {
        if (!hasExistingData) {
            hint.textContent = 'No ready active corpus exists. The first successful build will create the initial context.';
        } else if (!ragReady && mode === 'extend') {
            hint.textContent = 'The active corpus failed readiness checks, so lossless extension is blocked. Use an explicitly confirmed replacement to recover.';
        } else if (mode === 'replace') {
            hint.textContent = 'Replacement activates only the selected sources and requires explicit confirmation.';
        } else {
            hint.textContent = 'Extension creates a lossless active union of the existing corpus and every selected new source.';
        }
    }
    updateBuildButtonState();
}

function showDuplicateWarning(duplicates) {
    const warningDiv = document.getElementById('duplicateWarning');
    if (!warningDiv) return;

    if (duplicates && duplicates.length > 0) {
        warningDiv.style.display = 'block';
        warningDiv.innerHTML = `
            <strong>${duplicates.length} duplicate file(s) found in database:</strong><br>
            ${duplicates.map(d => `${escapeHtml(d.filename)} (hash: <span class="mono">${escapeHtml(d.hash.substring(0, 16))}...</span>)`).join('<br>')}
            <br><small>These files will be skipped during upload.</small>
        `;
    } else {
        warningDiv.style.display = 'none';
    }
}

function updateBuildButtonState() {
    const btn = $('buildRagBtn');
    if (!btn) return;
    const archives = $('useArchivesCheck');
    const uploads = $('useUploadsCheck');
    if (!archives || !uploads) return;
    const useArchives = archives.checked;
    const useUploads = uploads.checked;
    const hasSelectedSources = useArchives || useUploads;
    const buildMode = selectedRagBuildMode();
    const confirmReplace = document.getElementById('confirmReplaceCheck');
    if (btn.dataset.busy === '1') {
        btn.disabled = true;
        return;
    }

    if (!ragStatusAvailable) {
        btn.disabled = true;
        btn.classList.remove('danger-button');
        btn.textContent = 'RAG Status Unavailable';
        return;
    }

    const replacingActive = hasExistingData && buildMode === 'replace';
    const replacementConfirmed = Boolean(confirmReplace && confirmReplace.checked);
    btn.disabled = replacingActive
        ? !(hasSelectedSources && replacementConfirmed)
        : hasSelectedSources
            ? (hasExistingData && !ragReady)
            : !hasExistingData;
    btn.classList.toggle('danger-button', replacingActive);

    if (hasExistingData && !hasSelectedSources && buildMode !== 'replace') {
        btn.textContent = 'Refresh Active RAG Status';
    } else if (!hasExistingData && hasSelectedSources) {
        btn.textContent = 'Build Initial RAG Context';
    } else if (replacingActive) {
        btn.textContent = 'Replace Active RAG Context';
    } else if (hasExistingData && !ragReady) {
        btn.textContent = 'Select Confirmed Replacement';
    } else {
        btn.textContent = 'Extend Active RAG Context';
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
            fileList.push(`<span>${escapeHtml(file.name)} (duplicate in selection - will be removed)</span>`);
        } else {
            currentSelection.add(file.name);
            fileList.push(`<span>${escapeHtml(file.name)}</span>`);
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
                        updatedFileList.push(
                            `<span>${escapeHtml(fileName)} ` +
                            `(already in database - hash: <span class="mono">${escapeHtml(dupInfo.hash.substring(0, 16))}...</span>)</span>`
                        );
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
        <div class="notice">
            <strong>Files selected: ${files.length}</strong><br>
            ${fileList.join('<br>')}
            ${duplicateCount > 0 ? `<br><small>Note: ${duplicateCount} duplicate(s) in your selection will be ignored</small>` : ''}
        </div>
    `;

    updateBuildButtonState();
}

function $(id) {
    return document.getElementById(id);
}

function setDisabled(id, disabled) {
    const el = $(id);
    if (el) el.disabled = !!disabled;
}

function updateRAGStatus(ready, message, state = null) {
    const statusDiv = $('ragStatus');
    const statusText = $('ragStatusText');
    const analyzeBtn = $('analyzeBtn');

    ragReady = ready;
    if (statusText) statusText.textContent = message;
    if (statusDiv) statusDiv.className = `status-indicator ${state || (ready ? 'ready' : 'not-ready')}`;
    if (analyzeBtn && $('alertTemplate')) analyzeBtn.disabled = !ready;
}

function setKnowledgeBusy(busy) {
    const btn = $('buildRagBtn');
    if (btn) {
        btn.dataset.busy = busy ? '1' : '';
        btn.setAttribute('aria-busy', busy ? 'true' : 'false');
    }
    [
        'buildRagBtn', 'useArchivesCheck', 'useUploadsCheck', 'customDocs',
        'ragDays', 'extendRagMode', 'replaceRagMode', 'confirmReplaceCheck'
    ].forEach(id => setDisabled(id, busy));
    if (!busy) updateBuildButtonState();
}

function setAnalysisBusy(busy, buttonLabel) {
    const btn = $('analyzeBtn');
    const file = $('alertTemplate');
    if (btn) {
        btn.disabled = true;
        btn.setAttribute('aria-busy', busy ? 'true' : 'false');
        if (buttonLabel) btn.innerHTML = buttonLabel;
        else if (!busy) btn.textContent = 'Auto-Analyze Current Alerts with RAG';
        if (!busy) btn.disabled = !ragReady;
    }
    if (file) file.disabled = busy;
}

function setMetric(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function isProgressHandshake(message) {
    return /connected to progress tracker/i.test(String(message || ''));
}

function showNotice(kind, title, body, technical) {
    const status = document.getElementById('status');
    if (!status) return;
    const details = technical
        ? `<details><summary>Technical details</summary><pre>${escapeHtml(technical)}</pre></details>`
        : '';
    status.innerHTML = `
        <div class="notice ${escapeHtml(kind)}" role="${kind === 'error' ? 'alert' : 'status'}">
            <h3>${escapeHtml(title)}</h3>
            <p>${escapeHtml(body)}</p>
            ${details}
        </div>
    `;
}

function errorHelp(detail) {
    const text = String(detail || '');
    if (/timeout/i.test(text)) {
        return 'The local inference service did not respond within the configured timeout. Try again or verify that the inference service is running.';
    }
    if (/unauthor/i.test(text) || /401/.test(text)) {
        return 'Authentication is required. Sign in again and retry.';
    }
    if (/rag/i.test(text) && /status/i.test(text)) {
        return 'The knowledge-base status endpoint is unavailable. Confirm PostgreSQL is running, then refresh this page.';
    }
    return 'Review the technical details, correct the input if needed, and retry.';
}

function showProgress(sessionId, operation, onComplete = null) {
    const mount = $('jobProgress') || $('status') || $('analysisProgress');
    if (!mount) {
        if (onComplete) onComplete(false);
        return;
    }
    mount.hidden = false;
    mount.classList.add('job-progress', 'is-active');
    mount.classList.remove('is-idle');
    const hasStructure = mount.querySelector('#progress-text') && mount.querySelector('#progress-fill');
    if (!hasStructure) {
        mount.innerHTML = `
            <div class="job-progress-message">
                <span class="spinner" aria-hidden="true"></span>
                <span id="progress-text">Starting ${escapeHtml(operation)}...</span>
            </div>
            <div class="progress-bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" id="progress-bar">
                <div id="progress-fill" class="progress-fill" style="width: 0%;"></div>
            </div>
            <div id="progress-log" class="progress-log" aria-live="polite"></div>
        `;
    }
    const spinner = mount.querySelector('.spinner');
    if (spinner) spinner.hidden = false;
    const textEl = mount.querySelector('#progress-text') || $('progress-text');
    if (textEl) textEl.textContent = `Starting ${operation}...`;
    const fill = mount.querySelector('#progress-fill') || $('progress-fill');
    const bar = mount.querySelector('#progress-bar') || $('progress-bar');
    const log = mount.querySelector('#progress-log') || $('progress-log');
    if (log) {
        log.hidden = false;
        log.textContent = '';
    }
    if ($('status') && $('status') !== mount) $('status').innerHTML = '';

    const isAnalysis = operation === 'analysis';
    let displayPercent = 0;
    let lastMessage = `Starting ${operation}...`;
    let crawlTimer = null;

    function renderPercent() {
        if (fill) fill.style.width = displayPercent + '%';
        if (bar) bar.setAttribute('aria-valuenow', String(displayPercent));
        if (textEl) {
            textEl.textContent = `${displayPercent}% — ${lastMessage}`;
        }
    }

    function applyPercent(value, { force = false } = {}) {
        const next = Math.max(0, Math.min(100, Number(value)));
        if (!Number.isFinite(next)) return;
        if (force || next > displayPercent) {
            displayPercent = next;
            renderPercent();
        }
    }

    function stopCrawl() {
        if (crawlTimer) {
            clearInterval(crawlTimer);
            crawlTimer = null;
        }
    }

    function finish(success, data) {
        stopCrawl();
        if (onComplete) onComplete(success, data);
    }

    applyPercent(0, { force: true });
    if (isAnalysis) {
        crawlTimer = setInterval(() => {
            if (displayPercent < ANALYSIS_CRAWL_CAP) {
                applyPercent(displayPercent + ANALYSIS_CRAWL_STEP);
            }
        }, ANALYSIS_CRAWL_MS);
    }

    const websocketProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${websocketProtocol}//${window.location.host}/ws/progress/${sessionId}`);
    let completionHandled = false;

    ws.onmessage = function(event) {
        const data = JSON.parse(event.data);
        const progressValue = Number(data.progress);
        const hasNumericProgress = Number.isFinite(progressValue);
        const handshake = isProgressHandshake(data.message);
        if (data.message && !handshake) lastMessage = String(data.message);

        if (data.status === 'error') {
            applyPercent(hasNumericProgress ? progressValue : 0, { force: true });
        } else if (!handshake && hasNumericProgress) {
            if (progressValue >= 100) {
                applyPercent(100, { force: true });
            } else if (isAnalysis) {
                applyPercent(Math.min(progressValue, ANALYSIS_CRAWL_CAP));
            } else {
                applyPercent(progressValue);
            }
        } else if (textEl) {
            textEl.textContent = `${displayPercent}% — ${lastMessage}`;
        }

        if (log && data.message && !handshake) {
            log.textContent += `[${data.timestamp}] ${data.message}\n`;
            log.scrollTop = log.scrollHeight;
        }

        if (handshake) {
            return;
        }

        if (data.progress === 100 || data.status === 'error') {
            completionHandled = true;
            stopCrawl();
            ws.close();

            if (operation.startsWith('RAG ')) {
                if (data.status === 'success') {
                    updateRAGStatus(true, 'RAG operation completed; loading active union counts...');
                } else if (data.status === 'error') {
                    showNotice(
                        'error',
                        'Knowledge-base update did not complete',
                        errorHelp(data.message),
                        data.message
                    );
                }
            }
            finish(data.status === 'success', data);
        }
    };

    ws.onclose = function() {
        stopCrawl();
        if (!completionHandled) {
            console.warn('WebSocket closed without completion');
            finish(false);
        }
    };

    ws.onerror = function(error) {
        console.error('WebSocket error:', error);
        if (!completionHandled) {
            completionHandled = true;
            stopCrawl();
            showNotice(
                'error',
                'Progress channel closed',
                'The operation may still be running on the server. Refresh status or retry if no result appears.',
                String(error && error.message ? error.message : 'websocket error')
            );
            finish(false);
        }
    };
}

async function buildRAG() {
    const useArchives = document.getElementById('useArchivesCheck').checked;
    const useUploads = document.getElementById('useUploadsCheck').checked;
    const hasSelectedSources = useArchives || useUploads;
    const buildMode = selectedRagBuildMode();
    const confirmReplace = Boolean(document.getElementById('confirmReplaceCheck').checked);

    if (!ragStatusAvailable) {
        showNotice('error', 'RAG status is unavailable', 'No corpus operation can start safely.');
        return;
    }

    if (!useArchives && !useUploads && !hasExistingData) {
        showNotice('error', 'No sources selected', 'Select at least one source for the initial build.');
        return;
    }

    if (hasExistingData && buildMode === 'replace') {
        if (!hasSelectedSources) {
            showNotice('error', 'Replacement requires sources', 'Select at least one source for a replacement RAG build.');
            return;
        }
        if (!confirmReplace) {
            showNotice('error', 'Confirmation required', 'Confirm that unselected sources will leave the active retrieval context.');
            return;
        }
        const accepted = window.confirm(
            'Replace the active RAG context? Only the sources selected for this build will remain active.'
        );
        if (!accepted) {
            return;
        }
    }

    if (hasExistingData && !ragReady && hasSelectedSources && buildMode === 'extend') {
        showNotice(
            'error',
            'Lossless extension blocked',
            'The active RAG corpus failed readiness checks and cannot be extended losslessly. Select replacement mode and confirm it.'
        );
        return;
    }

    const btn = document.getElementById('buildRagBtn');
    const originalText = btn.textContent;
    setKnowledgeBusy(true);
    const busyLabel = buildMode === 'replace' && hasExistingData
        ? 'Replacing RAG context...'
        : hasExistingData && hasSelectedSources
            ? 'Extending RAG context...'
            : 'Building RAG context...';
    btn.innerHTML = `<span class="spinner" aria-hidden="true"></span>${escapeHtml(busyLabel)}`;
    updateRAGStatus(
        false,
        buildMode === 'replace' && hasExistingData
            ? 'Building confirmed replacement context...'
            : hasExistingData && hasSelectedSources
                ? 'Building lossless active union...'
                : 'Building initial RAG context...'
    );

    const formData = new FormData();
    formData.append('use_archives', useArchives);
    formData.append('use_uploads', useUploads);
    formData.append('build_mode', buildMode);
    formData.append('confirm_replace', confirmReplace);

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
        setKnowledgeBusy(false);
        if (success) {
            const docs = document.getElementById('customDocs');
            const validation = document.getElementById('fileValidation');
            if (docs) docs.value = '';
            if (validation) validation.innerHTML = '';
            const extend = document.getElementById('extendRagMode');
            const confirm = document.getElementById('confirmReplaceCheck');
            if (extend) extend.checked = true;
            if (confirm) confirm.checked = false;
        } else {
            btn.textContent = originalText;
        }
        updateBuildButtonState();
        checkRAGStatus();
    };

    try {
        const response = await fetch('/build-rag', { method: 'POST', body: formData });
        if (response.ok) {
            const result = await response.json();
            const operation = result.build_mode === 'extend'
                ? 'RAG extension'
                : result.build_mode === 'replace'
                    ? 'RAG replacement'
                    : 'RAG status refresh';
            showProgress(result.session_id, operation, restoreButton);
        } else {
            const error = await response.json();
            showNotice('error', 'Knowledge-base update failed', errorHelp(error.detail), JSON.stringify(error.detail));
            updateRAGStatus(false, `Error: ${error.detail}`);
            restoreButton(false);
        }
    } catch (error) {
        updateRAGStatus(false, `Network error: ${error.message}`);
        showNotice('error', 'Network error', errorHelp(error.message), error.message);
        restoreButton(false);
    }
}

async function analyzeAlerts() {
    if (!ragReady) {
        showNotice('error', 'Knowledge base not ready', 'Build or restore RAG context before analysing alerts.');
        return;
    }

    const btn = document.getElementById('analyzeBtn');
    const alertTemplateInput = document.getElementById('alertTemplate');
    const alertTemplate = alertTemplateInput && alertTemplateInput.files.length > 0
        ? alertTemplateInput.files[0]
        : null;

    const acceptedAlertExtensions = ['.json', '.jsonl', '.ndjson'];
    if (alertTemplate && !acceptedAlertExtensions.some(ext => alertTemplate.name.toLowerCase().endsWith(ext))) {
        showNotice('error', 'Unsupported alert file', 'Alert template must be a .json, .jsonl, or .ndjson file.');
        return;
    }

    setAnalysisBusy(true, '<span class="spinner" aria-hidden="true"></span>Analysing alerts...');

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
            const pollingTimeoutMs = Math.min(
                86400000,
                Math.max(60000, Number(result.poll_timeout_ms) || 660000)
            );

            let redirectCheckInterval = null;
            let redirectFound = false;

            redirectCheckInterval = setInterval(async () => {
                if (redirectFound) return;

                try {
                    const checkResponse = await fetch(`/api/check-analysis-result/${sessionId}`);
                    const checkResult = await checkResponse.json();

                    if (checkResult.redirect && checkResult.report_id) {
                        redirectFound = true;
                        clearInterval(redirectCheckInterval);
                        window.location.href = `/review-report/${checkResult.report_id}`;
                    }
                } catch (err) {
                    console.error('Error checking redirect:', err);
                }
            }, 2000);

            setTimeout(() => {
                if (redirectCheckInterval && !redirectFound) {
                    clearInterval(redirectCheckInterval);
                    console.warn('Redirect polling stopped (timeout)');
                    setAnalysisBusy(false);
                    showNotice(
                        'error',
                        'Analysis did not finish in time',
                        'The local analysis job exceeded the configured wait window. Check reports or retry.',
                        `poll_timeout_ms=${pollingTimeoutMs}`
                    );
                }
            }, pollingTimeoutMs);

            showProgress(sessionId, 'analysis', function(success) {
                if (!success) setAnalysisBusy(false);
            });

        } else {
            const error = await response.json();
            showNotice('error', 'Analysis could not start', errorHelp(error.detail), JSON.stringify(error.detail));
            setAnalysisBusy(false);
        }
    } catch (error) {
        showNotice('error', 'Network error', errorHelp(error.message), error.message);
        setAnalysisBusy(false);
    }
}

function downloadReport(filename) {
    const link = document.createElement('a');
    link.href = `/reports/${encodePathSegment(filename)}`;
    link.download = String(filename || 'report.md');
    link.rel = 'noopener';
    document.body.appendChild(link);
    link.click();
    link.remove();
}

async function downloadReportPdf(filename, button) {
    const btn = button || (typeof event !== 'undefined' ? event.currentTarget : null);
    const previous = btn ? btn.innerHTML : '';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner" aria-hidden="true"></span>Converting...';
    }
    try {
        const formData = new FormData();
        formData.append('filename', filename);
        const response = await fetch('/convert-to-pdf', { method: 'POST', body: formData });
        if (!response.ok) {
            const error = await response.json().catch(() => ({ detail: 'PDF conversion failed' }));
            showNotice('error', 'PDF conversion failed', errorHelp(error.detail), JSON.stringify(error.detail));
            return;
        }
        const result = await response.json();
        const pdfName = result.pdf_filename;
        if (!pdfName) {
            showNotice('error', 'PDF conversion failed', 'The converter did not return a filename.');
            return;
        }
        const pdfLink = document.createElement('a');
        pdfLink.href = `/reports/${encodePathSegment(pdfName)}`;
        pdfLink.download = pdfName;
        pdfLink.rel = 'noopener';
        document.body.appendChild(pdfLink);
        pdfLink.click();
        pdfLink.remove();
    } catch (error) {
        showNotice('error', 'Network error', errorHelp(error.message), error.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = previous || 'Download PDF';
        }
    }
}

async function checkRAGStatus() {
    try {
        const response = await fetch('/rag-status');
        const status = await response.json();
        if (!response.ok || status.error) {
            throw new Error('RAG status unavailable');
        }
        ragStatusAvailable = true;

        const archiveRecords = status.active_archive_records ?? status.alerts_with_embeddings ?? 0;
        const embeddedChunks = status.active_document_chunks ?? status.custom_doc_chunks_with_embeddings ?? status.docs_with_embeddings ?? 0;
        const embeddedDocuments = status.active_source_documents ?? status.uploaded_documents_with_embeddings ?? 0;
        const totalChunks = status.active_total_chunks ?? (archiveRecords + embeddedChunks);
        ragReady = Boolean(status.ready);
        hasExistingData = Boolean(
            status.active_corpus_id || archiveRecords > 0 || embeddedChunks > 0
        );

        setMetric('metricDocs', String(embeddedDocuments));
        setMetric('metricChunks', String(embeddedChunks));
        setMetric('metricArchives', String(archiveRecords));
        setMetric('metricReady', status.ready ? 'Ready' : (hasExistingData ? 'Not retrieval-ready' : 'Not initialized'));

        if (status.ready) {
            const staleWarning = status.rag_rebuild_recommended
                ? ` Rebuild recommended: ${status.stale_uploaded_documents || 0} stale uploaded doc(s), ${status.stale_custom_doc_chunks || 0} stale chunk(s).`
                : '';
            updateRAGStatus(
                true,
                `Active RAG union: ${embeddedDocuments} CTI source document(s), ${embeddedChunks} CTI chunk(s), and ${archiveRecords} archive record(s) (${totalChunks} total retrievable chunk(s)).${staleWarning}`,
                status.rag_rebuild_recommended ? 'warning' : 'ready'
            );
        } else {
            const integrityMessage = hasExistingData
                ? 'Active RAG corpus is not retrieval-ready. Use a confirmed replacement to recover.'
                : 'RAG not initialized - Configure and build the context first';
            updateRAGStatus(false, integrityMessage, hasExistingData ? 'warning' : 'not-ready');
        }

        toggleBuildModeOptions();
    } catch (error) {
        ragStatusAvailable = false;
        hasExistingData = false;
        ragReady = false;
        setMetric('metricReady', 'Unavailable');
        updateRAGStatus(false, 'Unable to check RAG status');
        toggleBuildModeOptions();
    }
}

document.addEventListener('DOMContentLoaded', function() {
    const uploads = $('useUploadsCheck');
    if (uploads) {
        uploads.addEventListener('change', function() {
            if (!this.checked) {
                const validation = $('fileValidation');
                const docs = $('customDocs');
                if (validation) validation.innerHTML = '';
                if (docs) docs.value = '';
            }
            toggleOptions();
        });
    }

    if ($('overviewMetrics') || $('buildRagBtn') || $('alertTemplate')) {
        checkRAGStatus();
    }
    toggleOptions();
});
