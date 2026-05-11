async function getJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json();
}

function text(value) {
  if (value === undefined || value === null || value === "") {
    return "-";
  }
  return String(value);
}

function renderServices(services) {
  const container = document.querySelector("#services");
  container.innerHTML = "";
  for (const service of services) {
    const card = document.createElement("article");
    card.className = "service-card";
    card.innerHTML = `
      <strong>${text(service.name)}</strong>
      <span>${text(service.host)}:${text(service.port)}</span>
      <span class="status ${service.running ? "running" : "stopped"}">
        ${service.running ? "Running" : "Stopped"}
      </span>
    `;
    container.appendChild(card);
  }
}

function renderEvents(events) {
  const body = document.querySelector("#events");
  body.innerHTML = "";
  for (const event of events) {
    const row = document.createElement("tr");
    const source = event.src_ip ? `${event.src_ip}:${event.src_port || ""}` : "-";
    row.innerHTML = `
      <td>${text(event.timestamp)}</td>
      <td>${text(event.service)}</td>
      <td>${text(event.event_type)}</td>
      <td>${text(source)}</td>
      <td>${text(event.summary || event.path || event.command || event.error)}</td>
    `;
    body.appendChild(row);
  }
}

async function refresh() {
  const [status, events, stats] = await Promise.all([
    getJson("/api/status"),
    getJson("/api/events?limit=50"),
    getJson("/api/stats"),
  ]);

  renderServices(status.services);
  renderEvents(events.events);

  const running = status.services.filter((service) => service.running).length;
  document.querySelector("#runningServices").textContent = running;
  document.querySelector("#totalEvents").textContent = stats.total_recent_events;
  document.querySelector("#loginAttempts").textContent = stats.by_type.login_attempt || 0;
}

document.querySelector("#refreshButton").addEventListener("click", refresh);
refresh();
setInterval(refresh, 5000);
