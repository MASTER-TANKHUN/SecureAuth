/* 
  Register page logic 
  Developed by MasterT
*/
document.addEventListener('DOMContentLoaded', () => {
  requireGuest();

  const form = document.getElementById('registerForm');
  const btn = document.getElementById('registerBtn');
  const passwordInput = document.getElementById('password');

  // Strength meter
  passwordInput.addEventListener('input', (e) => updateStrengthMeter(e.target.value));

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert('alert');

    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = passwordInput.value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (!username || !email || !password) return showAlert('alert', 'Fill in all fields.');
    if (password !== confirmPassword) return showAlert('alert', 'Passwords do not match.');
    if (getPasswordStrength(password) < 2) return showAlert('alert', 'Password is too weak.');

    setLoading(btn, true);
    const result = await apiRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, email, password }),
    });
    setLoading(btn, false);

    if (result.ok && result.data.success) {
      showAlert('alert', result.data.message, 'success');
      form.reset();
      updateStrengthMeter('');
      
      // Dev mode verification helper
      if (result.data.devToken) {
        setTimeout(() => {
          showLinkAlert(
            'alert',
            'Developer verification link:',
            `/verify.html#token=${result.data.devToken}`,
            `/verify.html#token=${result.data.devToken}`,
            'info'
          );
        }, 2000);
      }
    } else {
      const msg = result.data.errors ? result.data.errors.join('. ') : result.data.message;
      showAlert('alert', msg || 'Registration failed.');
    }
  });
});
