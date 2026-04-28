/* Reset password page logic */
document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('resetForm');
  const passwordInput = document.getElementById('password');
  const confirmPasswordInput = document.getElementById('confirmPassword');
  const submitBtn = document.getElementById('submitBtn');
  let completed = false;

  let token = new URLSearchParams(window.location.search).get('token');
  if (!token && window.location.hash) {
    const hashParams = new URLSearchParams(window.location.hash.substring(1));
    token = hashParams.get('token');
  }

  if (!token) {
    showAlert('alert', 'Invalid or missing reset link. Please request a new password reset.', 'error');
    submitBtn.disabled = true;
  }

  passwordInput.addEventListener('input', () => {
    updateStrengthMeter(passwordInput.value);
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert('alert');

    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    if (!password || !confirmPassword) {
      showAlert('alert', 'Please fill in all fields.');
      return;
    }

    if (password !== confirmPassword) {
      showAlert('alert', 'Passwords do not match.');
      return;
    }

    if (getPasswordStrength(password) < 2) {
      showAlert('alert', 'Password is too weak. Please use a stronger password.');
      return;
    }

    setLoading(submitBtn, true);

    try {
      const result = await apiRequest('/auth/reset-password', {
        method: 'POST',
        body: JSON.stringify({ token, password }),
      });

      if (result.ok && result.data.success) {
        showAlert('alert', result.data.message, 'success');
        form.reset();
        completed = true;
        submitBtn.disabled = true;
        submitBtn.querySelector('.btn-text').textContent = 'Password Reset';
        setTimeout(() => {
          window.location.href = '/index.html';
        }, 2000);
      } else {
        showAlert('alert', result.data.message || 'Failed to reset password. Please try again.');
      }
    } catch (error) {
      showAlert('alert', 'An error occurred. Please try again.');
    } finally {
      if (!completed) {
        setLoading(submitBtn, false);
      } else {
        submitBtn.classList.remove('loading');
      }
    }
  });
});
