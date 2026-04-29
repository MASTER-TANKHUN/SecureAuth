/* MFA setup page logic */
document.addEventListener('DOMContentLoaded', async () => {
  const user = await requireAuth();
  if (!user) return;

  const beginBtn = document.getElementById('beginSetupBtn');
  const enableBtn = document.getElementById('enableMfaBtn');
  const mfaInputs = document.querySelectorAll('#mfaInputs input');
  const passwordInput = document.getElementById('setupPassword');
  let pendingBackupCodes = [];

  // Step 1: Password confirmation → fetch MFA setup data
  beginBtn.addEventListener('click', async () => {
    const password = passwordInput.value;
    if (!password) {
      showAlert('alert', 'Please enter your password.');
      return;
    }

    setLoading(beginBtn, true);
    const setup = await apiRequest('/auth/mfa/setup', {
      method: 'POST',
      body: JSON.stringify({ password }),
    });
    setLoading(beginBtn, false);

    if (setup.ok && setup.data.success) {
      document.getElementById('qrCode').src = setup.data.qrCode;
      pendingBackupCodes = setup.data.backupCodes || [];

      // Hide password section, show QR + verification section
      document.getElementById('passwordSection').classList.add('hidden');
      document.getElementById('mfaSetupSection').classList.remove('hidden');
      mfaInputs[0].focus();
    } else {
      showAlert('alert', setup.data.message || 'Failed to setup MFA.');
    }
  });

  // Allow Enter key on password field
  passwordInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') beginBtn.click();
  });

  // MFA input auto-advance
  mfaInputs.forEach((input, idx) => {
    input.addEventListener('input', (e) => {
      e.target.value = e.target.value.replace(/\D/g, '');
      if (e.target.value && idx < mfaInputs.length - 1) mfaInputs[idx + 1].focus();
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !e.target.value && idx > 0) mfaInputs[idx - 1].focus();
    });
    input.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasted = (e.clipboardData.getData('text') || '').replace(/\D/g, '').slice(0, 6);
      pasted.split('').forEach((ch, i) => { if (mfaInputs[i]) mfaInputs[i].value = ch; });
    });
  });

  // Step 2: Enable MFA with TOTP code
  enableBtn.addEventListener('click', async () => {
    const code = Array.from(mfaInputs).map(i => i.value).join('');
    if (code.length !== 6) {
      showAlert('alert', 'Please enter the complete 6-digit code.');
      return;
    }

    setLoading(enableBtn, true);
    const result = await apiRequest('/auth/mfa/verify', {
      method: 'POST',
      body: JSON.stringify({ code }),
    });
    setLoading(enableBtn, false);

    if (result.ok && result.data.success) {
      showAlert('alert', 'MFA enabled successfully!', 'success');
      enableBtn.disabled = true;
      enableBtn.querySelector('.btn-text').textContent = 'MFA Enabled';

      // Show backup codes saved from setup response
      const backupCodes = pendingBackupCodes;
      const section = document.getElementById('backupSection');
      const container = document.getElementById('backupCodes');
      section.classList.remove('hidden');
      backupCodes.forEach(c => {
        const el = document.createElement('code');
        el.textContent = c;
        container.appendChild(el);
      });
    } else {
      showAlert('alert', result.data.message || 'Invalid code. Try again.');
      mfaInputs.forEach(i => { i.value = ''; });
      mfaInputs[0].focus();
    }
  });
});
