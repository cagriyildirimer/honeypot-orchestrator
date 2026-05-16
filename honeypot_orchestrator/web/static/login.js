function showLoginError(message) {
  const node = document.querySelector("#loginError");
  if (!node) {
    return;
  }
  node.hidden = !message;
  node.textContent = message || "";
}

async function submitLogin(event) {
  event.preventDefault();
  const button = document.querySelector("#loginButton");
  const usernameInput = document.querySelector("#usernameInput");
  const passwordInput = document.querySelector("#passwordInput");
  if (!button || !usernameInput || !passwordInput) {
    return;
  }
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  button.disabled = true;
  showLoginError("");

  try {
    const session = await requestJson("/api/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    window.location.assign("/dashboard");
  } catch (error) {
    showLoginError(error.message);
  } finally {
    button.disabled = false;
  }
}

async function bootstrapLogin() {
  const loginForm = document.querySelector("#loginForm");
  if (!loginForm) {
    return;
  }
  loginForm.addEventListener("submit", submitLogin);

  try {
    const session = await requestJson("/api/session");
    if (session.authenticated) {
      window.location.replace("/dashboard");
    }
  } catch (error) {
    showLoginError("");
  }
}

bootstrapLogin();
