function showLoginError(message) {
  const node = document.querySelector("#loginError");
  node.hidden = !message;
  node.textContent = message || "";
}

async function submitLogin(event) {
  event.preventDefault();
  const username = document.querySelector("#usernameInput").value.trim();
  const password = document.querySelector("#passwordInput").value;
  const button = document.querySelector("#loginButton");
  button.disabled = true;
  showLoginError("");

  try {
    await requestJson("/api/login", {
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
  document.querySelector("#loginForm").addEventListener("submit", submitLogin);

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
