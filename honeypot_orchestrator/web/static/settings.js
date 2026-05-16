const settingsState = {
  username: "",
  role: "",
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
  settingsState.role = payload.session ? payload.session.role : settingsState.role;
  const isAdmin = settingsState.role === "admin";

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
  setAdminOnlyLogControls(isAdmin);
}

function setAdminOnlyLogControls(isAdmin) {
  const copyButton = document.querySelector("#copyLogsButton");
  const clearButton = document.querySelector("#clearLogsButton");
  const exportLink = document.querySelector("#exportLogsLink");
  if (copyButton) {
    copyButton.disabled = !isAdmin;
    copyButton.title = isAdmin ? "" : "Admin access required.";
  }
  if (clearButton) {
    clearButton.disabled = !isAdmin;
    clearButton.title = isAdmin ? "" : "Admin access required.";
  }
  if (exportLink) {
    exportLink.classList.toggle("disabled", !isAdmin);
    exportLink.setAttribute("aria-disabled", isAdmin ? "false" : "true");
    if (isAdmin) {
      exportLink.removeAttribute("tabindex");
    } else {
      exportLink.setAttribute("tabindex", "-1");
    }
    exportLink.title = isAdmin ? "" : "Admin access required.";
  }
}

async function refreshSettings() {
  const payload = await requestJson("/api/settings");
  renderSettings(payload);
}

async function copyLogs() {
  if (settingsState.role !== "admin") {
    showToast("Admin access required.", "error");
    return;
  }
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
  if (settingsState.role !== "admin") {
    showToast("Admin access required.", "error");
    return;
  }
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
  document.querySelector("#exportLogsLink")?.addEventListener("click", (event) => {
    if (settingsState.role !== "admin") {
      event.preventDefault();
      showToast("Admin access required.", "error");
    }
  });

  try {
    const session = await ensureAuthenticated();
    settingsState.username = session.username || "";
    settingsState.role = session.role || "";
    await refreshSettings();
    startSettingsRefresh();
  } catch (error) {
    window.location.replace("/login");
  }
}

bootstrapSettings();
