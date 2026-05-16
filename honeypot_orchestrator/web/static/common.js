async function requestJson(url, options = {}) {
  const headers = {
    ...(options.headers || {}),
  };
  if (options.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  let payload = {};
  try {
    payload = await response.json();
  } catch (error) {
    payload = {};
  }

  if (!response.ok) {
    const message = payload.error || `Request failed: ${response.status}`;
    throw new Error(message);
  }
  return payload;
}

const THEME_STORAGE_KEY = "honeypot-director-theme";

function storedTheme() {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY);
  } catch (error) {
    return "";
  }
}

function saveTheme(theme) {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch (error) {
    return false;
  }
  return true;
}

function currentTheme() {
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}

function applyTheme(theme) {
  const normalized = theme === "dark" ? "dark" : "light";
  document.documentElement.dataset.theme = normalized;
  saveTheme(normalized);
  document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
    button.textContent = normalized === "dark" ? "Light Mode" : "Dark Mode";
    button.setAttribute(
      "aria-label",
      normalized === "dark" ? "Switch to light mode" : "Switch to dark mode"
    );
  });
}

function initializeThemeControls() {
  const savedTheme = storedTheme();
  applyTheme(savedTheme === "dark" ? "dark" : "light");
  document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      applyTheme(currentTheme() === "dark" ? "light" : "dark");
    });
  });
}

initializeThemeControls();

function text(value) {
  if (value === undefined || value === null || value === "") {
    return "-";
  }
  return String(value);
}

function setText(selector, value) {
  const element = document.querySelector(selector);
  if (!element) {
    return false;
  }
  element.textContent = value;
  return true;
}

function showToast(message, tone = "neutral") {
  const toast = document.querySelector("#toast");
  if (!toast) {
    return;
  }
  toast.hidden = false;
  toast.className = `toast ${tone}`;
  toast.textContent = message;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => {
    toast.hidden = true;
  }, 2600);
}

function formatTimestamp(value) {
  if (!value || value === "-") {
    return "-";
  }
  const normalized = String(value).replace(" UTC", "Z").replace(" ", "T");
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatEventSource(event) {
  if (!event || !event.src_ip) {
    return "-";
  }
  return `${event.src_ip}:${event.src_port || ""}`;
}

function summarizeEvent(event) {
  if (!event) {
    return "-";
  }
  return text(event.summary || event.path || event.command || event.error || event.detail);
}

async function ensureAuthenticated() {
  const session = await requestJson("/api/session");
  if (!session.authenticated) {
    window.location.replace("/login");
    throw new Error("Authentication required.");
  }
  return session;
}

async function logoutAndRedirect() {
  try {
    await requestJson("/api/logout", { method: "POST" });
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    window.location.assign("/login");
  }
}
