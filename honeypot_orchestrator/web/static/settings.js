const settingsState = {
  username: "",
  refreshTimer: null,
};

function formatBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) {
    return `${value} B`;
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function renderSettings(payload) {
  settingsState.username = payload.session ? payload.session.username : settingsState.username;

  setText("#sessionUser", settingsState.username || "-");
  setText("#settingsUsername", settingsState.username || "-");
  setText("#panelUrl", payload.panel ? payload.panel.url : "-");
  setText("#appVersion", payload.runtime ? payload.runtime.version : "-");
  setText("#uptime", payload.runtime ? payload.runtime.uptime : "-");
  setText("#healthStatus", payload.runtime ? payload.runtime.health : "-");
  const healthStatus = document.querySelector("#healthStatus");
  if (healthStatus) {
    healthStatus.className = `status-pill ${payload.runtime && payload.runtime.health === "ok" ? "running" : "stopped"}`;
  }
  setText("#logPath", payload.logging ? payload.logging.path : "-");
  setText("#logSize", payload.logging ? formatBytes(payload.logging.size_bytes) : "-");
}

async function refreshSettings() {
  const payload = await requestJson("/api/settings");
  renderSettings(payload);
}

async function copyLogs() {
  try {
    const response = await fetch("/api/logs/export");
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }
    const content = await response.text();
    await copyText(content);
    showToast("Logs copied as JSONL.", "success");
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function copyText(content) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    await navigator.clipboard.writeText(content);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = content;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) {
    throw new Error("Could not copy logs.");
  }
}

async function clearLogs() {
  const button = document.querySelector("#clearLogsButton");
  if (!button) {
    return;
  }
  button.disabled = true;
  try {
    await requestJson("/api/logs/clear", { method: "POST" });
    await refreshSettings();
    showToast("Logs cleared.", "success");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

function startSettingsRefresh() {
  stopSettingsRefresh();
  settingsState.refreshTimer = setInterval(refreshSettings, 5000);
}

function stopSettingsRefresh() {
  if (settingsState.refreshTimer) {
    clearInterval(settingsState.refreshTimer);
    settingsState.refreshTimer = null;
  }
}

async function bootstrapSettings() {
  document.querySelector("#logoutButton")?.addEventListener("click", () => {
    stopSettingsRefresh();
    logoutAndRedirect();
  });
  document.querySelector("#copyLogsButton")?.addEventListener("click", copyLogs);
  document.querySelector("#clearLogsButton")?.addEventListener("click", clearLogs);

  try {
    const session = await ensureAuthenticated();
    settingsState.username = session.username || "";
    await refreshSettings();
    startSettingsRefresh();
  } catch (error) {
    window.location.replace("/login");
  }
}

bootstrapSettings();
