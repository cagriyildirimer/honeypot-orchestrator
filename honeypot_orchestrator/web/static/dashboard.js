const state = {
  username: "",
  services: [],
  stats: null,
  filters: {
    service: "",
    eventType: "",
    limit: 50,
  },
  refreshTimer: null,
  refreshInFlight: false,
};

function showToast(message, tone = "neutral") {
  const toast = document.querySelector("#toast");
  toast.hidden = false;
  toast.className = `toast ${tone}`;
  toast.textContent = message;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => {
    toast.hidden = true;
  }, 2600);
}

function populateFilterOptions(services, stats) {
  const serviceFilter = document.querySelector("#serviceFilter");
  const eventTypeFilter = document.querySelector("#eventTypeFilter");
  const currentService = state.filters.service;
  const currentEventType = state.filters.eventType;

  serviceFilter.innerHTML = '<option value="">All services</option>';
  for (const service of services) {
    const option = document.createElement("option");
    option.value = service.name;
    option.textContent = service.name.toUpperCase();
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
  container.innerHTML = "";

  for (const service of services) {
    const card = document.createElement("article");
    card.className = `service-card ${service.running ? "is-running" : "is-stopped"}`;
    const actionLabel = service.running ? "Stop Service" : "Start Service";
    const actionName = service.running ? "stop" : "start";
    card.innerHTML = `
      <div class="service-head">
        <div>
          <strong>${text(service.name)}</strong>
          <span>${text(service.host)}:${text(service.port)}</span>
        </div>
        <span class="status ${service.running ? "running" : "stopped"}">
          ${service.running ? "Live" : "Idle"}
        </span>
      </div>
      <p>
        ${service.running
          ? "This listener is active and accepting traffic."
          : "Currently offline. Bring it online only when needed."}
      </p>
      <button type="button" data-service="${service.name}" data-action="${actionName}">
        ${actionLabel}
      </button>
    `;
    container.appendChild(card);
  }

  document.querySelector("#serviceSummary").textContent =
    `${services.filter((service) => service.running).length} active`;
}

function renderActivitySummary(stats) {
  const list = document.querySelector("#activitySummary");
  list.innerHTML = "";
  const byService = Object.entries((stats && stats.by_service) || {})
    .sort((left, right) => right[1] - left[1])
    .slice(0, 5);

  if (!byService.length) {
    const item = document.createElement("li");
    item.textContent = "No events yet. Start a service to begin collecting traffic.";
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
  body.innerHTML = "";

  if (!events.length) {
    const row = document.createElement("tr");
    row.innerHTML = '<td colspan="5" class="empty-row">No matching events found.</td>';
    body.appendChild(row);
    return;
  }

  for (const event of events) {
    const row = document.createElement("tr");
    const source = event.src_ip ? `${event.src_ip}:${event.src_port || ""}` : "-";
    row.innerHTML = `
      <td>${text(event.timestamp)}</td>
      <td>${text(event.service)}</td>
      <td>${text(event.event_type)}</td>
      <td>${text(source)}</td>
      <td>${text(event.summary || event.path || event.command || event.error || event.detail)}</td>
    `;
    body.appendChild(row);
  }
}

function renderDashboard(status, stats, events) {
  state.services = status.services;
  state.stats = stats;
  renderServices(status.services);
  renderEvents(events.events);
  renderActivitySummary(stats);
  populateFilterOptions(status.services, stats);

  const running = status.services.filter((service) => service.running).length;
  document.querySelector("#runningServices").textContent = running;
  document.querySelector("#totalEvents").textContent = stats.total_recent_events || 0;
  document.querySelector("#loginAttempts").textContent = stats.by_type.login_attempt || 0;
  document.querySelector("#dashboardAddress").textContent = `${status.web.host}:${status.web.port}`;
  document.querySelector("#sessionUser").textContent = state.username || "-";
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

    const [status, events, stats] = await Promise.all([
      requestJson("/api/status"),
      requestJson(`/api/events?${query.toString()}`),
      requestJson("/api/stats"),
    ]);
    renderDashboard(status, stats, events);
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

async function handleServiceAction(event) {
  const button = event.target.closest("button[data-service]");
  if (!button) {
    return;
  }
  const service = button.dataset.service;
  const action = button.dataset.action;
  button.disabled = true;

  try {
    const payload = await requestJson(`/api/services/${service}/${action}`, {
      method: "POST",
    });
    await refreshDashboard();
    const label =
      payload.action === "started"
        ? "started"
        : payload.action === "stopped"
          ? "stopped"
          : payload.action.replaceAll("_", " ");
    showToast(`${service.toUpperCase()} ${label}.`, "success");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

function applyFilters(event) {
  event.preventDefault();
  state.filters.service = document.querySelector("#serviceFilter").value;
  state.filters.eventType = document.querySelector("#eventTypeFilter").value;
  state.filters.limit = Number(document.querySelector("#limitInput").value) || 50;
  refreshDashboard();
}

function startAutoRefresh() {
  stopAutoRefresh();
  state.refreshTimer = setInterval(refreshDashboard, 4000);
}

function stopAutoRefresh() {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
    state.refreshTimer = null;
  }
}

async function bootstrapDashboard() {
  document.querySelector("#logoutButton").addEventListener("click", logout);
  document.querySelector("#refreshButton").addEventListener("click", refreshDashboard);
  document.querySelector("#filtersForm").addEventListener("submit", applyFilters);
  document.querySelector("#services").addEventListener("click", handleServiceAction);

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
