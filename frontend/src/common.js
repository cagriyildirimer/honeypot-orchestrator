let csrfToken = null;

async function requestJson(url, options = {}) {
  const headers = {
    ...(options.headers || {}),
  };

  if (options.method && options.method.toUpperCase() === "POST" && url !== "/api/login") {
    try {
      const res = await fetch("/api/csrf");
      const data = await res.json();
      if (data.csrf_token) {
        csrfToken = data.csrf_token;
      }
    } catch (e) {
      console.error("Failed to fetch CSRF token");
    }
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }
  }

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
    if (response.status === 401 && window.location.pathname !== "/login") {
      window.location.replace("/login");
      throw new Error("Session expired. Please log in again.");
    }
    const message = payload.error || `Request failed: ${response.status}`;
    throw new Error(message);
  }
  return payload;
}

const THEME_STORAGE_KEY = "honeypot-director-theme";
const SCHEME_STORAGE_KEY = "honeypot-director-scheme";

const THEME_OPTIONS = [
  { key: "vision", label: "Vision Blue" },
  { key: "nebula", label: "Nebula Violet" },
  { key: "aurora", label: "Aurora Cyan" },
  { key: "emerald", label: "Emerald Ops" },
  { key: "sunset", label: "Sunset Alert" },
  { key: "slate", label: "Slate Mono" },
];

const SCHEME_OPTIONS = [
  { key: "dark", label: "Dark Mode" },
  { key: "light", label: "Light Mode" },
];

function normalizeTheme(theme) {
  return THEME_OPTIONS.some((option) => option.key === theme) ? theme : "vision";
}

function normalizeScheme(scheme) {
  return SCHEME_OPTIONS.some((option) => option.key === scheme) ? scheme : "dark";
}

function storedTheme() {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY);
  } catch (error) {
    return "";
  }
}

function storedScheme() {
  try {
    return localStorage.getItem(SCHEME_STORAGE_KEY);
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

function saveScheme(scheme) {
  try {
    localStorage.setItem(SCHEME_STORAGE_KEY, scheme);
  } catch (error) {
    return false;
  }
  return true;
}

function currentTheme() {
  return normalizeTheme(document.documentElement.dataset.theme || "vision");
}

function currentScheme() {
  return normalizeScheme(document.documentElement.dataset.scheme || "dark");
}

function applyTheme(theme) {
  const normalized = normalizeTheme(theme);
  document.documentElement.dataset.theme = normalized;
  saveTheme(normalized);
}

function applyScheme(scheme) {
  const normalized = normalizeScheme(scheme);
  document.documentElement.dataset.scheme = normalized;
  saveScheme(normalized);
}

function initializeTheme() {
  const savedTheme = storedTheme();
  applyTheme(savedTheme);
  const savedScheme = storedScheme();
  applyScheme(savedScheme);
}

initializeTheme();

function text(value) {
  if (value === undefined || value === null || value === "") {
    return "-";
  }
  return String(value);
}


function showToast(message, tone = "neutral") {
  const toast = document.querySelector("#toast");
  if (!toast) {
    return;
  }
  
  clearTimeout(showToast.timer);
  clearTimeout(showToast.hideTimer);

  toast.textContent = message;
  toast.className = `toast ${tone}`;
  toast.hidden = false;

  showToast.timer = setTimeout(() => {
    toast.classList.add("hiding");
    showToast.hideTimer = setTimeout(() => {
      toast.hidden = true;
      toast.classList.remove("hiding");
    }, 400);
  }, 3000);
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


async function logoutAndRedirect() {
  try {
    await requestJson("/api/logout", { method: "POST" });
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    window.location.assign("/login");
  }
}

window.requestJson = requestJson;
window.THEME_OPTIONS = THEME_OPTIONS;
window.currentTheme = currentTheme;
window.applyTheme = applyTheme;
window.SCHEME_OPTIONS = SCHEME_OPTIONS;
window.currentScheme = currentScheme;
window.applyScheme = applyScheme;
window.text = text;
window.showToast = showToast;
window.formatTimestamp = formatTimestamp;
window.formatEventSource = formatEventSource;
window.summarizeEvent = summarizeEvent;
window.logoutAndRedirect = logoutAndRedirect;
