(() => {
    const manager = document.getElementById('accountManager');
    const rows = document.getElementById('accountRows');
    const notice = document.getElementById('accountNotice');
    const count = document.getElementById('accountCount');
    if (!manager || !rows || !notice || !count) return;

    const currentUser = (manager.dataset.currentUser || '').toLocaleLowerCase();

    function escapeHtml(value) {
        return String(value ?? '').replace(/[&<>"']/g, (character) => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        })[character]);
    }

    function showNotice(message, kind = 'success') {
        notice.textContent = message;
        notice.className = `notice ${kind}`;
        notice.hidden = false;
    }

    async function apiRequest(url, options = {}) {
        const response = await fetch(url, {
            ...options,
            credentials: 'same-origin',
            headers: { Accept: 'application/json', ...(options.headers || {}) },
        });
        let payload = {};
        try { payload = await response.json(); } catch (_) { /* use status text below */ }
        if (!response.ok) {
            throw new Error(payload.detail || `Request failed (${response.status})`);
        }
        return payload;
    }

    function renderUsers(users) {
        count.textContent = `${users.length} account${users.length === 1 ? '' : 's'}`;
        if (!users.length) {
            rows.innerHTML = '<tr><td colspan="6"><div class="empty-state">No accounts found.</div></td></tr>';
            return;
        }

        rows.innerHTML = users.map((user) => {
            const username = String(user.username || '');
            const ownAccount = username.toLocaleLowerCase() === currentUser;
            const enabled = Boolean(user.enabled);
            const role = user.role === 'admin' ? 'admin' : 'analyst';
            const created = Number(user.created_at)
                ? new Date(Number(user.created_at) * 1000).toLocaleString()
                : 'Unknown';
            const safeUsername = escapeHtml(username);
            const disabledOwnActions = ownAccount ? 'disabled title="You cannot disable, delete, or reset MFA for your own account"' : '';
            const disableLabel = enabled ? 'Disable' : 'Enable';
            const statusClass = enabled ? 'account-status-enabled' : 'account-status-disabled';

            return `<tr data-username="${safeUsername}">
                <td><strong>${safeUsername}</strong>${ownAccount ? ' <span class="account-you">You</span>' : ''}</td>
                <td>
                    <div class="account-role-control">
                        <select class="account-role-select" aria-label="Role for ${safeUsername}" ${ownAccount ? 'disabled title="You cannot change your own role"' : ''}>
                            <option value="analyst" ${role === 'analyst' ? 'selected' : ''}>Analyst</option>
                            <option value="admin" ${role === 'admin' ? 'selected' : ''}>Admin</option>
                        </select>
                        <button type="button" class="btn-sm" data-action="save-role" ${ownAccount ? 'disabled' : ''}>Save</button>
                    </div>
                </td>
                <td><span class="account-status ${statusClass}">${enabled ? 'Enabled' : 'Disabled'}</span></td>
                <td>${user.mfa_enabled ? 'Set up' : 'Not set up'}</td>
                <td>${escapeHtml(created)}</td>
                <td>
                    <div class="account-row-actions">
                        <button type="button" class="btn-sm" data-action="toggle" ${disabledOwnActions}>${disableLabel}</button>
                        <button type="button" class="btn-sm" data-action="reset-password">Reset password</button>
                        <button type="button" class="btn-sm" data-action="reset-mfa" ${disabledOwnActions}>Reset MFA</button>
                        <button type="button" class="btn-sm danger" data-action="delete" ${disabledOwnActions}>Delete</button>
                    </div>
                </td>
            </tr>`;
        }).join('');
    }

    async function loadUsers() {
        rows.innerHTML = '<tr><td colspan="6">Loading accounts…</td></tr>';
        try {
            const users = await apiRequest('/admin/users');
            renderUsers(Array.isArray(users) ? users : []);
        } catch (error) {
            count.textContent = 'Unable to load accounts';
            rows.innerHTML = `<tr><td colspan="6"><div class="notice error">${escapeHtml(error.message)}</div></td></tr>`;
        }
    }

    async function performAction(button) {
        const row = button.closest('tr[data-username]');
        if (!row) return;
        const username = row.dataset.username;
        const encodedUsername = encodeURIComponent(username);
        const action = button.dataset.action;
        if (action === 'reset-password') {
            openPasswordDialog(username);
            return;
        }
        button.disabled = true;

        try {
            if (action === 'save-role') {
                const role = row.querySelector('.account-role-select').value;
                await apiRequest(`/admin/users/${encodedUsername}/role`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ role }),
                });
                showNotice(`Updated ${username} to ${role}.`);
            } else if (action === 'toggle') {
                const isEnabled = row.querySelector('.account-status').classList.contains('account-status-enabled');
                await apiRequest(isEnabled ? `/admin/users/${encodedUsername}` : `/admin/users/${encodedUsername}/enable`, {
                    method: isEnabled ? 'DELETE' : 'POST',
                });
                showNotice(isEnabled ? `Disabled ${username}.` : `Enabled ${username}.`);
            } else if (action === 'reset-mfa') {
                if (!window.confirm(`Reset MFA for ${username}? They will need to enroll again at their next sign-in.`)) {
                    button.disabled = false;
                    return;
                }
                await apiRequest(`/admin/users/${encodedUsername}/reset-mfa`, { method: 'POST' });
                showNotice(`MFA reset for ${username}. They must set it up again at their next sign-in.`);
            } else if (action === 'delete') {
                if (!window.confirm(`Permanently delete ${username}? This cannot be undone.`)) {
                    button.disabled = false;
                    return;
                }
                await apiRequest(`/admin/users/${encodedUsername}/permanently`, { method: 'DELETE' });
                showNotice(`Permanently deleted ${username}.`);
            }
            await loadUsers();
        } catch (error) {
            showNotice(error.message, 'error');
            button.disabled = false;
        }
    }

    function passwordMismatch(form) {
        if (form.elements.password.value !== form.elements.confirm_password.value) {
            return 'The passwords do not match.';
        }
        return '';
    }

    const createForm = document.getElementById('createAccountForm');
    createForm?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const mismatch = passwordMismatch(createForm);
        if (mismatch) {
            showNotice(mismatch, 'error');
            return;
        }
        const submit = createForm.querySelector('button[type="submit"]');
        submit.disabled = true;
        const username = createForm.elements.username.value.trim();
        try {
            await apiRequest('/admin/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username,
                    password: createForm.elements.password.value,
                    role: createForm.elements.role.value,
                }),
            });
            createForm.reset();
            showNotice(`Created ${username}. They will set up MFA at their first sign-in.`);
            await loadUsers();
        } catch (error) {
            showNotice(error.message, 'error');
        } finally {
            submit.disabled = false;
        }
    });

    const passwordDialog = document.getElementById('passwordDialog');
    const passwordForm = document.getElementById('passwordForm');
    const passwordError = document.getElementById('passwordDialogError');
    let passwordTarget = '';

    function openPasswordDialog(username) {
        if (!passwordDialog || !passwordForm) return;
        passwordTarget = username;
        passwordForm.reset();
        passwordError.hidden = true;
        document.getElementById('passwordDialogUser').textContent = username;
        passwordDialog.showModal();
        passwordForm.elements.password.focus();
    }

    document.getElementById('passwordCancel')?.addEventListener('click', () => passwordDialog.close());

    passwordForm?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const mismatch = passwordMismatch(passwordForm);
        if (mismatch) {
            passwordError.textContent = mismatch;
            passwordError.hidden = false;
            return;
        }
        const submit = passwordForm.querySelector('button[type="submit"]');
        submit.disabled = true;
        try {
            await apiRequest(`/admin/users/${encodeURIComponent(passwordTarget)}/password`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: passwordForm.elements.password.value }),
            });
            passwordDialog.close();
            showNotice(`Password reset for ${passwordTarget}.`);
        } catch (error) {
            passwordError.textContent = error.message;
            passwordError.hidden = false;
        } finally {
            submit.disabled = false;
        }
    });

    rows.addEventListener('click', (event) => {
        const button = event.target.closest('button[data-action]');
        if (button) performAction(button);
    });

    document.getElementById('refreshAccounts')?.addEventListener('click', loadUsers);
    loadUsers();
})();
