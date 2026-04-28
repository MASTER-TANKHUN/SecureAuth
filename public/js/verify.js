/* Email verification page logic */
document.addEventListener('DOMContentLoaded', async () => {
  let token = new URLSearchParams(window.location.search).get('token');
  if (!token && window.location.hash) {
    const hashParams = new URLSearchParams(window.location.hash.substring(1));
    token = hashParams.get('token');
  }

  const icon = document.getElementById('statusIcon');
  const title = document.getElementById('statusTitle');
  const msg = document.getElementById('statusMessage');

  if (!token) {
    icon.textContent = '';
    title.textContent = 'Invalid Link';
    msg.textContent = 'No verification token found.';
    return;
  }

  const result = await apiRequest('/auth/verify-email', {
    method: 'POST',
    body: JSON.stringify({ token }),
  });

  if (result.ok && result.data.success) {
    icon.textContent = '';
    title.textContent = 'Verification Complete';
    msg.textContent = result.data.message || 'Your account is now active. You can log in.';
  } else {
    icon.textContent = '';
    title.textContent = 'Verification Failed';
    msg.textContent = result.data.message || 'The link may be expired or invalid.';
  }
});
