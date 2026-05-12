async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
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
