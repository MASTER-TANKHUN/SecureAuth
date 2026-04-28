/* MFA disable confirmation page logic */
document.addEventListener('DOMContentLoaded', async () => {
  const icon = document.getElementById('statusIcon');
  const title = document.getElementById('statusTitle');
  const msg = document.getElementById('statusMessage');
  const actionBtn = document.getElementById('actionBtn');

  let token = new URLSearchParams(window.location.search).get('token');
  if (!token && window.location.hash) {
    const hashParams = new URLSearchParams(window.location.hash.substring(1));
    token = hashParams.get('token');
  }

  if (!token) {
    icon.textContent = '';
    title.textContent = 'Invalid Link';
    msg.textContent = 'No confirmation token was found.';
    actionBtn.href = '/dashboard.html';
    return;
  }

  const user = await checkAuth();
  if (!user) {
    icon.textContent = '';
    title.textContent = 'Login Required';
    msg.textContent = 'Please sign in in this browser, then reopen this link to finish disabling MFA.';
    actionBtn.href = '/index.html';
    actionBtn.querySelector('.btn-text').textContent = 'Go to Login';
    return;
  }

  const result = await apiRequest('/auth/mfa/confirm-disable', {
    method: 'POST',
    body: JSON.stringify({ token }),
  });

  if (result.ok && result.data.success) {
    icon.textContent = '';
    title.textContent = 'MFA Disabled';
    msg.textContent = result.data.message;
    actionBtn.href = '/dashboard.html';
    actionBtn.querySelector('.btn-text').textContent = 'Back to Dashboard';
  } else {
    icon.textContent = '';
    title.textContent = result.status === 403 ? 'Wrong Account' : 'Request Failed';
    msg.textContent = result.data.message || 'The confirmation link may be expired or invalid.';
    actionBtn.href = '/dashboard.html';
    actionBtn.querySelector('.btn-text').textContent = 'Back to Dashboard';
  }
});
