/* 
  Login page logic 
  Developed by MasterT
*/
document.addEventListener('DOMContentLoaded', () => {
  requireGuest();

  const form = document.getElementById('loginForm');
  const btn = document.getElementById('loginBtn');
  const mfaSection = document.getElementById('mfaSection');
  const mfaInputs = document.querySelectorAll('#mfaInputs input');
  const verifyMfaBtn = document.getElementById('verifyMfaBtn');

  let pendingEmail = '';
  let pendingPassword = '';

  // Main login
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert('alert');

    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;

    if (!email || !password) return showAlert('alert', 'Fill in all fields.');

    setLoading(btn, true);
    const result = await apiRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    setLoading(btn, false);

    // Switch to MFA if needed
    if (result.data.requiresMfa) {
      pendingEmail = email;
      pendingPassword = password;
      form.classList.add('hidden');
      mfaSection.classList.remove('hidden');
      mfaInputs[0].focus();
      return;
    }

    if (result.ok && result.data.success) {
      showAlert('alert', 'Success! Redirecting...', 'success');
      setTimeout(() => window.location.href = '/dashboard.html', 800);
    } else {
      showAlert('alert', result.data.message || 'Login failed.');
    }
  });

  // MFA input handling
  mfaInputs.forEach((input, idx) => {
    input.addEventListener('input', (e) => {
      const val = e.target.value.replace(/\D/g, '');
      e.target.value = val;
      if (val && idx < mfaInputs.length - 1) mfaInputs[idx + 1].focus();
      if (idx === mfaInputs.length - 1 && val) verifyMfaBtn.focus();
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !e.target.value && idx > 0) mfaInputs[idx - 1].focus();
    });
    input.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasted = (e.clipboardData.getData('text') || '').replace(/\D/g, '').slice(0, 6);
      pasted.split('').forEach((ch, i) => { if (mfaInputs[i]) mfaInputs[i].value = ch; });
      if (pasted.length === 6) verifyMfaBtn.focus();
    });
  });

  // MFA verification
  verifyMfaBtn.addEventListener('click', async () => {
    const code = Array.from(mfaInputs).map(i => i.value).join('');
    if (code.length !== 6) return showAlert('alert', 'Enter 6-digit code.');

    setLoading(verifyMfaBtn, true);
    const result = await apiRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: pendingEmail, password: pendingPassword, mfaCode: code }),
    });
    setLoading(verifyMfaBtn, false);

    if (result.ok && result.data.success) {
      showAlert('alert', 'Success!', 'success');
      setTimeout(() => window.location.href = '/dashboard.html', 800);
    } else {
      showAlert('alert', result.data.message || 'Invalid MFA code.');
      mfaInputs.forEach(i => i.value = '');
      mfaInputs[0].focus();
    }
  });

  // Use backup code
  document.getElementById('useBackupLink')?.addEventListener('click', (e) => {
    e.preventDefault();
    const code = prompt('Enter backup code:');
    if (!code) return;

    (async () => {
      setLoading(verifyMfaBtn, true);
      const result = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: pendingEmail, password: pendingPassword, mfaCode: code.trim() }),
      });
      setLoading(verifyMfaBtn, false);
      if (result.ok && result.data.success) {
        window.location.href = '/dashboard.html';
      } else {
        showAlert('alert', result.data.message || 'Invalid backup code.');
      }
    })();
  });
});
