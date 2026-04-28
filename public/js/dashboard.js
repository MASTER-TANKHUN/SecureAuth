/* 
  Dashboard logic 
  Developed by MasterT
*/
document.addEventListener('DOMContentLoaded', async () => {
  const user = await requireAuth();
  if (!user) return;

  // Header info
  document.getElementById('welcomeText').textContent = `Welcome, ${user.username}!`;
  document.getElementById('userEmail').textContent = user.email;

  // Stats
  const mfaStatus = document.getElementById('mfaStatus');
  mfaStatus.textContent = user.mfaEnabled ? 'Enabled' : 'Disabled';
  mfaStatus.className = 'stat-value ' + (user.mfaEnabled ? 'status-success' : 'status-warning');
  
  document.getElementById('emailStatus').textContent = user.isVerified ? 'Yes' : 'No';
  const setupMfaLink = document.getElementById('setupMfaLink');
  if (user.mfaEnabled) {
    setupMfaLink.textContent = 'MFA Active';
    setupMfaLink.removeAttribute('href');
    setupMfaLink.setAttribute('aria-disabled', 'true');
    setupMfaLink.classList.add('btn-disabled-link');
    setupMfaLink.addEventListener('click', (event) => event.preventDefault());
  }

  // Login history
  const logsResult = await apiRequest('/user/login-history');
  const tbody = document.getElementById('logTableBody');

  if (logsResult.ok && Array.isArray(logsResult.data.logs)) {
    const logs = logsResult.data.logs;
    document.getElementById('loginCount').textContent = logs.length;

    if (logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="table-empty-cell">No history</td></tr>';
    } else {
      tbody.innerHTML = logs.map(log => {
        const badge = log.success ? 'success' : 'error';
        const ua = log.userAgent || '-';
        const displayUa = ua.length > 40 ? ua.substring(0, 40) + '...' : ua;
        return `<tr>
          <td><span class="badge badge-${badge}">${log.success ? 'Success' : 'Failed'}</span></td>
          <td>${escapeHtml(log.ipAddress || '-')}</td>
          <td title="${escapeHtml(ua)}">${escapeHtml(displayUa)}</td>
          <td>${new Date(log.timestamp).toLocaleString()}</td>
        </tr>`;
      }).join('');
    }
  } else {
    tbody.innerHTML = '<tr><td colspan="4" class="table-empty-cell">Failed to load history</td></tr>';
    showAlert('alert', logsResult.data?.message || 'Failed to load login history.');
  }

  // Logout
  document.getElementById('logoutBtn').addEventListener('click', async () => {
    await apiRequest('/auth/logout', { method: 'POST' });
    window.location.href = '/index.html';
  });
});
