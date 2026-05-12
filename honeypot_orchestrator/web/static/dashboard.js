const state = {
  username: "",
  services: [],
  profile: null,
  stats: null,
  filters: {
    service: "",
    eventType: "",
    limit: 50,
  },
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

function setText(selector, value) {
  const element = document.querySelector(selector);
  if (!element) {
    return false;
  }
  element.textContent = value;
  return true;
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

function standardPortNote(service) {
  const standardPort = STANDARD_PORTS[service.name];
  if (!standardPort) {
    return "Custom listener";
  }
  if (standardPort === service.port) {
    return `Standard port ${standardPort}`;
  }
  return `Lab port ${service.port}, typical ${standardPort}`;
}

function servicePortTone(service) {
  const standardPort = STANDARD_PORTS[service.name];
  return standardPort && standardPort === service.port ? "standard" : "lab";
}

function renderProfileSelector(profileStatus) {
  state.profile = profileStatus;
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

  setText(
    "#activeProfile",
    text(profileStatus && profileStatus.current ? profileStatus.current.display_name : "-"),
  );
}

function populateFilterOptions(services, stats) {
  const serviceFilter = document.querySelector("#serviceFilter");
  const eventTypeFilter = document.querySelector("#eventTypeFilter");
  if (!serviceFilter || !eventTypeFilter) {
    return;
  }
  const currentService = state.filters.service;
  const currentEventType = state.filters.eventType;

  serviceFilter.innerHTML = '<option value="">All services</option>';
  for (const service of services) {
    const option = document.createElement("option");
    option.value = service.name;
    option.textContent = `${service.name.toUpperCase()} · ${service.port}`;
    option.selected = option.value === currentService;
    serviceFilter.appendChild(option);
  }

  eventTypeFilter.innerHTML = '<option value="">All event types</option>';
  const eventTypes = Object.keys((stats && stats.by_type) || {}).sort();
  for (const eventType of eventTypes) {
    const option = document.createElement("option");
    option.value = eventType;
    option.textContent = eventType;
    option.selected = option.value === currentEventType;
    eventTypeFilter.appendChild(option);
  }
}

function renderServices(services) {
  const container = document.querySelector("#services");
  if (!container) {
    return;
  }
  container.innerHTML = "";

  if (!services.length) {
    const empty = document.createElement("article");
    empty.className = "service-card is-stopped";
    empty.innerHTML = `
      <div class="service-head">
        <div>
          <strong>No Services</strong>
          <span>Apply a profile to expose matching ports.</span>
        </div>
      </div>
      <p>This profile does not currently expose any listeners.</p>
    `;
    container.appendChild(empty);
    setText("#serviceSummary", "0 active");
    setText("#serviceFootnote", "No listeners enabled for this profile.");
    return;
  }

  for (const service of services) {
    const host = service.display_host || service.host;
    const card = document.createElement("article");
    card.className = `service-card ${service.running ? "is-running" : "is-stopped"}`;
    card.innerHTML = `
      <div class="service-head">
        <div>
          <strong>${text(service.name)}</strong>
          <span>${text(host)}:${text(service.port)}</span>
        </div>
        <span class="status ${service.running ? "running" : "stopped"}">
          ${service.running ? "Live" : "Idle"}
        </span>
      </div>
      <div class="service-meta">
        <span class="port-chip ${servicePortTone(service)}">${text(standardPortNote(service))}</span>
        <span class="port-chip template">${text(service.template)}</span>
      </div>
      <p>
        ${service.running
          ? "This listener is active under the selected profile."
          : "This listener belongs to the selected profile but is not active."}
      </p>
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
  const byService = Object.entries((stats && stats.by_service) || {})
    .sort((left, right) => right[1] - left[1])
    .slice(0, 5);

  if (!byService.length) {
    const item = document.createElement("li");
    item.textContent = "No events yet. Apply a profile to begin collecting traffic.";
    list.appendChild(item);
    return;
  }

  for (const [service, count] of byService) {
    const item = document.createElement("li");
    item.innerHTML = `<span>${text(service)}</span><strong>${count}</strong>`;
    list.appendChild(item);
  }
}

function renderEvents(events) {
  const body = document.querySelector("#events");
  if (!body) {
    return;
  }
  body.innerHTML = "";

  if (!events.length) {
    const row = document.createElement("tr");
    row.innerHTML = '<td colspan="6" class="empty-row">No matching events found.</td>';
    body.appendChild(row);
    return;
  }

  for (const event of events) {
    const row = document.createElement("tr");
    const source = event.src_ip ? `${event.src_ip}:${event.src_port || ""}` : "-";
    row.innerHTML = `
      <td>${text(formatTimestamp(event.timestamp))}</td>
      <td>${text(event.service)}</td>
      <td><span class="event-chip">${text(event.event_type)}</span></td>
      <td>${text(source)}</td>
      <td>${text(event.profile || (state.profile && state.profile.current ? state.profile.current.name : "-"))}</td>
      <td>${text(event.summary || event.path || event.command || event.error || event.detail)}</td>
    `;
    body.appendChild(row);
  }
}

function renderDashboard(payload) {
  state.services = payload.services || [];
  state.stats = payload.stats || {};
  renderProfileSelector(payload.profile);
  renderServices(state.services);
  renderEvents(payload.events || []);
  renderActivitySummary(state.stats);
  populateFilterOptions(state.services, state.stats);

  const running = state.services.filter((service) => service.running).length;
  setText("#runningServices", String(running));
  setText("#totalEvents", String(state.stats.total_recent_events || 0));
  setText("#loginAttempts", String((state.stats.by_type && state.stats.by_type.login_attempt) || 0));
  setText("#dashboardAddress", `${text(payload.web.display_host || payload.web.host)}:${text(payload.web.port)}`);
  setText("#logPath", text(payload.log_path));
  setText("#lastUpdated", formatTimestamp(payload.generated_at));
  setText("#sessionUser", state.username || "-");
}

async function refreshDashboard() {
  if (state.refreshInFlight) {
    return;
  }

  state.refreshInFlight = true;
  try {
    const query = new URLSearchParams();
    query.set("limit", String(state.filters.limit));
    if (state.filters.service) {
      query.set("service", state.filters.service);
    }
    if (state.filters.eventType) {
      query.set("event_type", state.filters.eventType);
    }

    const payload = await requestJson(`/api/overview?${query.toString()}`);
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

async function logout() {
  try {
    await requestJson("/api/logout", { method: "POST" });
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    stopAutoRefresh();
    window.location.assign("/login");
  }
}

async function applyProfile() {
  const button = document.querySelector("#applyProfileButton");
  const profileSelect = document.querySelector("#profileSelect");
  if (!button || !profileSelect) {
    return;
  }
  const profile = profileSelect.value;
  if (!profile) {
    return;
  }

  button.disabled = true;
  try {
    const payload = await requestJson("/api/profile", {
      method: "POST",
      body: JSON.stringify({ profile }),
    });
    state.profile = payload;
    await refreshDashboard();
    const serviceCount = ((payload.current && payload.current.services) || []).length;
    showToast(`${text(payload.current.display_name)} applied with ${serviceCount} service${serviceCount === 1 ? "" : "s"}.`, "success");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

function applyFilters(event) {
  event.preventDefault();
  const serviceFilter = document.querySelector("#serviceFilter");
  const eventTypeFilter = document.querySelector("#eventTypeFilter");
  const limitInput = document.querySelector("#limitInput");
  state.filters.service = serviceFilter ? serviceFilter.value : "";
  state.filters.eventType = eventTypeFilter ? eventTypeFilter.value : "";
  state.filters.limit = Number(limitInput ? limitInput.value : 50) || 50;
  refreshDashboard();
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
  document.querySelector("#logoutButton")?.addEventListener("click", logout);
  document.querySelector("#refreshButton")?.addEventListener("click", refreshDashboard);
  document.querySelector("#applyProfileButton")?.addEventListener("click", applyProfile);
  document.querySelector("#filtersForm")?.addEventListener("submit", applyFilters);

  try {
    const session = await requestJson("/api/session");
    if (!session.authenticated) {
      window.location.replace("/login");
      return;
    }
    state.username = session.username || "";
    await refreshDashboard();
    startAutoRefresh();
  } catch (error) {
    window.location.replace("/login");
  }
}

bootstrapDashboard();
