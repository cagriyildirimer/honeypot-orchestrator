const state = {
  username: "",
  refreshTimer: null,
  refreshInFlight: false,
  activeProfileName: "-",
  filters: {
    service: "",
    eventType: "",
    limit: 100,
    search: "",
  },
  rawEvents: [],
};

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
    option.textContent = `${service.name.toUpperCase()} - ${service.port}`;
    option.selected = option.value === currentService;
    serviceFilter.appendChild(option);
  }

  eventTypeFilter.innerHTML = '<option value="">All event types</option>';
  for (const eventType of Object.keys((stats && stats.by_type) || {}).sort()) {
    const option = document.createElement("option");
    option.value = eventType;
    option.textContent = eventType;
    option.selected = option.value === currentEventType;
    eventTypeFilter.appendChild(option);
  }
}

function summarizeEventTypes(stats) {
  const list = document.querySelector("#eventTypeSummary");
  if (!list) {
    return;
  }
  list.innerHTML = "";
  const entries = Object.entries((stats && stats.by_type) || {})
    .sort((left, right) => right[1] - left[1])
    .slice(0, 6);

  if (!entries.length) {
    const item = document.createElement("li");
    item.textContent = "No event types visible yet.";
    list.appendChild(item);
    return;
  }

  for (const [eventType, count] of entries) {
    const item = document.createElement("li");
    item.innerHTML = `<span>${text(eventType)}</span><strong>${count}</strong>`;
    list.appendChild(item);
  }
}

function summarizeServices(stats) {
  const list = document.querySelector("#serviceSummary");
  if (!list) {
    return;
  }
  list.innerHTML = "";
  const entries = Object.entries((stats && stats.by_service) || {})
    .sort((left, right) => right[1] - left[1])
    .slice(0, 6);

  if (!entries.length) {
    const item = document.createElement("li");
    item.textContent = "No services visible yet.";
    list.appendChild(item);
    return;
  }

  for (const [service, count] of entries) {
    const item = document.createElement("li");
    item.innerHTML = `<span>${text(service)}</span><strong>${count}</strong>`;
    list.appendChild(item);
  }
}

function filterEvents(events) {
  const search = state.filters.search.trim().toLowerCase();
  if (!search) {
    return events;
  }
  return events.filter((event) => {
    const haystack = JSON.stringify(event).toLowerCase();
    return haystack.includes(search);
  });
}

function renderEventTable(events, fallbackProfile) {
  const body = document.querySelector("#events");
  if (!body) {
    return;
  }
  body.innerHTML = "";

  if (!events.length) {
    const row = document.createElement("tr");
    row.innerHTML = '<td colspan="6" class="empty-row">No matching events found.</td>';
    body.appendChild(row);
    setText("#eventJson", "No event selected.");
    return;
  }

  events.forEach((event, index) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${text(formatTimestamp(event.timestamp))}</td>
      <td>${text(event.service)}</td>
      <td><span class="table-chip">${text(event.event_type)}</span></td>
      <td>${text(formatEventSource(event))}</td>
      <td>${text(event.profile || fallbackProfile)}</td>
      <td>${summarizeEvent(event)}</td>
    `;
    row.addEventListener("click", () => {
      body.querySelectorAll("tr").forEach((node) => node.classList.remove("selected"));
      row.classList.add("selected");
      setText("#eventJson", JSON.stringify(event, null, 2));
    });
    if (index === 0) {
      row.classList.add("selected");
      setText("#eventJson", JSON.stringify(event, null, 2));
    }
    body.appendChild(row);
  });
}

function renderLogs(payload) {
  state.activeProfileName = payload.profile && payload.profile.current ? payload.profile.current.name : "-";
  const events = filterEvents(payload.events || []);
  state.rawEvents = payload.events || [];
  setText("#sessionUser", state.username || "-");
  setText("#lastUpdated", formatTimestamp(payload.generated_at));
  setText("#totalEvents", String((payload.stats && payload.stats.total_recent_events) || 0));
  setText("#showingSummary", `${events.length} events`);
  populateFilterOptions(payload.services || [], payload.stats || {});
  summarizeEventTypes(payload.stats || {});
  summarizeServices(payload.stats || {});
  renderEventTable(events, payload.profile && payload.profile.current ? payload.profile.current.name : "-");
}

async function refreshLogs() {
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
    renderLogs(payload);
  } catch (error) {
    showToast(error.message, "error");
    if (error.message === "Authentication required.") {
      window.location.replace("/login");
    }
  } finally {
    state.refreshInFlight = false;
  }
}

function applyFilters(event) {
  event.preventDefault();
  state.filters.service = document.querySelector("#serviceFilter")?.value || "";
  state.filters.eventType = document.querySelector("#eventTypeFilter")?.value || "";
  state.filters.limit = Number(document.querySelector("#limitInput")?.value || 100) || 100;
  state.filters.search = document.querySelector("#searchInput")?.value || "";
  refreshLogs();
}

function clearFilters() {
  state.filters = {
    service: "",
    eventType: "",
    limit: 100,
    search: "",
  };
  const serviceFilter = document.querySelector("#serviceFilter");
  const eventTypeFilter = document.querySelector("#eventTypeFilter");
  const limitInput = document.querySelector("#limitInput");
  const searchInput = document.querySelector("#searchInput");
  if (serviceFilter) {
    serviceFilter.value = "";
  }
  if (eventTypeFilter) {
    eventTypeFilter.value = "";
  }
  if (limitInput) {
    limitInput.value = "100";
  }
  if (searchInput) {
    searchInput.value = "";
  }
  refreshLogs();
}

function startAutoRefresh() {
  stopAutoRefresh();
  state.refreshTimer = setInterval(refreshLogs, 6000);
}

function stopAutoRefresh() {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
    state.refreshTimer = null;
  }
}

async function bootstrapLogs() {
  document.querySelector("#logoutButton")?.addEventListener("click", () => {
    stopAutoRefresh();
    logoutAndRedirect();
  });
  document.querySelector("#refreshButton")?.addEventListener("click", refreshLogs);
  document.querySelector("#filtersForm")?.addEventListener("submit", applyFilters);
  document.querySelector("#clearFiltersButton")?.addEventListener("click", clearFilters);
  document.querySelector("#searchInput")?.addEventListener("input", (event) => {
    state.filters.search = event.target.value || "";
    const filteredEvents = filterEvents(state.rawEvents);
    renderEventTable(filteredEvents, state.activeProfileName);
    setText("#showingSummary", `${filteredEvents.length} events`);
  });

  try {
    const session = await ensureAuthenticated();
    state.username = session.username || "";
    await refreshLogs();
    startAutoRefresh();
  } catch (error) {
    window.location.replace("/login");
  }
}

bootstrapLogs();
