const state = {
  username: "",
  role: "",
  refreshTimer: null,
  refreshInFlight: false,
};

const STANDARD_PORTS = {
  dns: 53,
  ftp: 21,
  http: 80,
  ldap: 389,
  ldaps: 636,
  mssql: 1433,
  netbios: 139,
  rdp: 3389,
  smb: 445,
  ssh: 22,
  telnet: 23,
};

function standardPortNote(service) {
  const standardPort = STANDARD_PORTS[service.name];
  if (!standardPort) {
    return "Custom listener";
  }
  if (standardPort === service.port) {
    return `Standard ${standardPort}`;
  }
  return `Lab ${service.port} / Standard ${standardPort}`;
}

function servicePortTone(service) {
  const standardPort = STANDARD_PORTS[service.name];
  return standardPort && standardPort === service.port ? "standard" : "lab";
}

function renderProfileSelector(profileStatus) {
  const profileSelect = document.querySelector("#profileSelect");
  if (!profileSelect) {
    return;
  }
  const activeProfile = profileStatus && profileStatus.current ? profileStatus.current.name : "";
  profileSelect.innerHTML = "";

  for (const profile of (profileStatus && profileStatus.available) || []) {
    const option = document.createElement("option");
    option.value = profile.name;
    option.textContent = profile.display_name;
    option.selected = profile.name === activeProfile;
    profileSelect.appendChild(option);
  }

  const isAdmin = state.role === "admin";
  profileSelect.disabled = !isAdmin;
  const applyButton = document.querySelector("#applyProfileButton");
  if (applyButton) {
    applyButton.disabled = !isAdmin;
    applyButton.title = isAdmin ? "" : "Admin access required.";
  }

  const displayName = text(profileStatus && profileStatus.current ? profileStatus.current.display_name : "-");
  setText("#activeProfile", displayName);
}

function renderServices(services) {
  const container = document.querySelector("#services");
  if (!container) {
    return;
  }
  container.innerHTML = "";

  if (!services.length) {
    const empty = document.createElement("article");
    empty.className = "service-card muted-card";
    empty.innerHTML = `
      <div class="service-card-header">
        <strong>No Services</strong>
      </div>
      <p>No listeners are assigned to the current profile.</p>
    `;
    container.appendChild(empty);
    setText("#serviceSummary", "0 active");
    setText("#serviceFootnote", "No listeners enabled for this profile.");
    return;
  }

  for (const service of services) {
    const card = document.createElement("article");
    card.className = `service-card ${service.running ? "live" : "idle"}`;
    const host = service.display_host || service.host;
    card.innerHTML = `
      <div class="service-card-header">
        <div>
          <strong>${text(service.name)}</strong>
          <span>${text(host)}:${text(service.port)}</span>
        </div>
        <span class="status-pill ${service.running ? "running" : "stopped"}">
          ${service.running ? "Live" : "Idle"}
        </span>
      </div>
      <div class="service-card-tags">
        <span class="tag ${servicePortTone(service)}">${text(standardPortNote(service))}</span>
        <span class="tag template">${text(service.template)}</span>
      </div>
      <p>${service.running ? "This listener is exposed right now." : "This listener exists in the profile but is not active."}</p>
    `;
    container.appendChild(card);
  }

  const activeCount = services.filter((service) => service.running).length;
  setText("#serviceSummary", `${activeCount} active`);
  setText("#serviceFootnote", `${activeCount} of ${services.length} profile listeners are currently online.`);
}

function renderActivitySummary(stats) {
  const list = document.querySelector("#activitySummary");
  if (!list) {
    return;
  }
  list.innerHTML = "";
  const entries = Object.entries((stats && stats.by_service) || {})
    .sort((left, right) => right[1] - left[1])
    .slice(0, 5);

  if (!entries.length) {
    const item = document.createElement("li");
    item.textContent = "No events yet. Apply a profile to begin collecting traffic.";
    list.appendChild(item);
    return;
  }

  for (const [service, count] of entries) {
    const item = document.createElement("li");
    item.innerHTML = `<span>${text(service)}</span><strong>${count}</strong>`;
    list.appendChild(item);
  }
}

function renderEvents(events, fallbackProfile) {
  const body = document.querySelector("#events");
  if (!body) {
    return;
  }
  body.innerHTML = "";

  if (!events.length) {
    const row = document.createElement("tr");
    row.innerHTML = '<td colspan="6" class="empty-row">No events captured yet.</td>';
    body.appendChild(row);
    return;
  }

  for (const event of events) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${text(formatTimestamp(event.timestamp))}</td>
      <td>${text(event.service)}</td>
      <td><span class="table-chip">${text(event.event_type)}</span></td>
      <td>${text(formatEventSource(event))}</td>
      <td>${text(event.profile || fallbackProfile)}</td>
      <td>${summarizeEvent(event)}</td>
    `;
    body.appendChild(row);
  }
}

function renderDashboard(payload) {
  const services = payload.services || [];
  const stats = payload.stats || {};
  const profile = payload.profile || null;
  renderProfileSelector(profile);
  renderServices(services);
  renderActivitySummary(stats);
  renderEvents((payload.events || []).slice(0, 10), profile && profile.current ? profile.current.name : "-");

  const running = services.filter((service) => service.running).length;
  setText("#sessionUser", state.username || "-");
  setText("#runningServices", String(running));
  setText("#loginAttempts", String((stats.by_type && stats.by_type.login_attempt) || 0));
  setText("#lastUpdated", formatTimestamp(payload.generated_at));
  setText("#heroTotalEvents", String(stats.total_recent_events || 0));
}

async function refreshDashboard() {
  if (state.refreshInFlight) {
    return;
  }
  state.refreshInFlight = true;
  try {
    const payload = await requestJson("/api/overview?limit=10");
    renderDashboard(payload);
  } catch (error) {
    showToast(error.message, "error");
    if (error.message === "Authentication required.") {
      window.location.replace("/login");
    }
  } finally {
    state.refreshInFlight = false;
  }
}

async function applyProfile() {
  const button = document.querySelector("#applyProfileButton");
  const profileSelect = document.querySelector("#profileSelect");
  if (!button || !profileSelect || !profileSelect.value || state.role !== "admin") {
    return;
  }

  button.disabled = true;
  try {
    const payload = await requestJson("/api/profile", {
      method: "POST",
      body: JSON.stringify({ profile: profileSelect.value }),
    });
    await refreshDashboard();
    const serviceCount = ((payload.current && payload.current.services) || []).length;
    showToast(`${text(payload.current.display_name)} applied with ${serviceCount} service${serviceCount === 1 ? "" : "s"}.`, "success");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

function startAutoRefresh() {
  stopAutoRefresh();
  state.refreshTimer = setInterval(refreshDashboard, 5000);
}

function stopAutoRefresh() {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
    state.refreshTimer = null;
  }
}

async function bootstrapDashboard() {
  document.querySelector("#logoutButton")?.addEventListener("click", () => {
    stopAutoRefresh();
    logoutAndRedirect();
  });
  document.querySelector("#refreshButton")?.addEventListener("click", refreshDashboard);
  document.querySelector("#applyProfileButton")?.addEventListener("click", applyProfile);

  try {
    const session = await ensureAuthenticated();
    state.username = session.username || "";
    state.role = session.role || "";
    await refreshDashboard();
    startAutoRefresh();
  } catch (error) {
    window.location.replace("/login");
  }
}

bootstrapDashboard();
