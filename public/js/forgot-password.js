/* Forgot password page logic */
document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('forgotForm');
  const emailInput = document.getElementById('email');
  const submitBtn = document.getElementById('submitBtn');
  let completed = false;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert('alert');

    const email = emailInput.value.trim();
    if (!email) {
      showAlert('alert', 'Please enter your email address.');
      return;
    }

    setLoading(submitBtn, true);

    try {
      const result = await apiRequest('/auth/forgot-password', {
        method: 'POST',
        body: JSON.stringify({ email }),
      });

      if (result.ok && result.data.success) {
        showAlert('alert', result.data.message, 'success');
        form.reset();
        completed = true;
        submitBtn.disabled = true;
        submitBtn.querySelector('.btn-text').textContent = 'Link Sent';

        // Dev mode helper
        if (result.data.devToken) {
          setTimeout(() => {
            showLinkAlert(
              'alert',
              'Developer reset link:',
              `/reset-password.html#token=${result.data.devToken}`,
              `/reset-password.html#token=${result.data.devToken}`,
              'info'
            );
          }, 2000);
        }
      } else {
        showAlert('alert', result.data.message || 'Failed to send reset link. Please try again.');
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
