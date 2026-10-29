(() => {
    const rows = document.getElementById('auditRows');
    const count = document.getElementById('auditCount');
    const filters = document.getElementById('auditFilters');
    const actionSelect = document.getElementById('auditAction');
    const loadMore = document.getElementById('auditLoadMore');
    if (!rows || !count || !filters || !actionSelect || !loadMore) return;

    const PAGE_SIZE = 100;
    let events = [];

    function escapeHtml(value) {
        return String(value ?? '').replace(/[&<>"']/g, (character) => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        })[character]);
    }

    async function apiRequest(url) {
        const response = await fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
        let payload = {};
        try { payload = await response.json(); } catch (_) { /* use status text below */ }
        if (!response.ok) throw new Error(payload.detail || `Request failed (${response.status})`);
        return payload;
    }

    function readableAction(action) {
        return String(action || '').replace(/_/g, ' ');
    }

    function outcomeBadge(outcome) {
        const value = String(outcome || '');
        const kind = value === 'success' ? 'account-status-enabled' : 'account-status-disabled';
        return `<span class="account-status ${kind}">${escapeHtml(readableAction(value))}</span>`;
    }

    function render() {
        count.textContent = `${events.length} event${events.length === 1 ? '' : 's'} shown`;
        if (!events.length) {
            rows.innerHTML = '<tr><td colspan="7"><div class="empty-state">No events match these filters.</div></td></tr>';
            return;
        }
        rows.innerHTML = events.map((event) => {
            const time = Number(event.created_at) ? new Date(Number(event.created_at) * 1000).toLocaleString() : '';
            return `<tr>
                <td class="audit-time">${escapeHtml(time)}</td>
                <td><strong>${escapeHtml(event.actor)}</strong></td>
                <td>${escapeHtml(readableAction(event.action))}</td>
                <td class="mono">${escapeHtml(event.target || '')}</td>
                <td>${outcomeBadge(event.outcome)}</td>
                <td class="mono audit-ip">${escapeHtml(event.client_ip || '')}</td>
                <td class="audit-detail">${escapeHtml(event.detail || '')}</td>
            </tr>`;
        }).join('');
    }

    function query(beforeId) {
        const params = new URLSearchParams({ limit: String(PAGE_SIZE) });
        for (const [key, value] of new FormData(filters)) {
            if (String(value).trim()) params.set(key, String(value).trim());
        }
        if (beforeId) params.set('before_id', String(beforeId));
        return `/admin/audit?${params}`;
    }

    async function loadEvents(append = false) {
        loadMore.disabled = true;
        if (!append) rows.innerHTML = '<tr><td colspan="7">Loading events…</td></tr>';
        try {
            const beforeId = append && events.length ? events[events.length - 1].id : null;
            const page = await apiRequest(query(beforeId));
            const batch = Array.isArray(page) ? page : [];
            events = append ? events.concat(batch) : batch;
            render();
            loadMore.hidden = batch.length < PAGE_SIZE;
        } catch (error) {
            count.textContent = 'Unable to load events';
            rows.innerHTML = `<tr><td colspan="7"><div class="notice error">${escapeHtml(error.message)}</div></td></tr>`;
        } finally {
            loadMore.disabled = false;
        }
    }

    async function loadActions() {
        try {
            const actions = await apiRequest('/admin/audit/actions');
            const selected = actionSelect.value;
            actionSelect.innerHTML = '<option value="">All actions</option>' + (Array.isArray(actions) ? actions : [])
                .map((action) => `<option value="${escapeHtml(action)}">${escapeHtml(readableAction(action))}</option>`)
                .join('');
            actionSelect.value = selected;
        } catch (_) { /* the filter keeps "All actions" */ }
    }

    filters.addEventListener('submit', (event) => {
        event.preventDefault();
        loadEvents();
    });
    actionSelect.addEventListener('change', () => loadEvents());
    document.getElementById('auditOutcome')?.addEventListener('change', () => loadEvents());
    loadMore.addEventListener('click', () => loadEvents(true));
    document.getElementById('refreshAudit')?.addEventListener('click', () => {
        loadActions();
        loadEvents();
    });

    loadActions();
    loadEvents();
})();
