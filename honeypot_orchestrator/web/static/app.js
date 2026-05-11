async function getJson(url) {
  // Web panelinin JSON API uçlarından veri çeker.
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json();
}

function text(value) {
  // Boş değerleri tabloda daha okunabilir bir tire ile gösterir.
  if (value === undefined || value === null || value === "") {
    return "-";
  }
  return String(value);
}

function renderServices(services) {
  // /api/status cevabındaki servis listesini kartlara dönüştürür.
  const container = document.querySelector("#services");
  container.innerHTML = "";
  for (const service of services) {
    const card = document.createElement("article");
    card.className = "service-card";
    // running değerine göre karttaki durum etiketi yeşil veya kırmızı görünür.
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
  // Son olay kayıtlarını Recent Events tablosuna satır satır yazar.
  const body = document.querySelector("#events");
  body.innerHTML = "";
  for (const event of events) {
    const row = document.createElement("tr");
    // Kaynak IP yoksa tabloda "-" gösterilir.
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
  // Panel verileri aynı anda çekilir; böylece yenileme daha hızlı biter.
  const [status, events, stats] = await Promise.all([
    getJson("/api/status"),
    getJson("/api/events?limit=50"),
    getJson("/api/stats"),
  ]);

  renderServices(status.services);
  renderEvents(events.events);

  // Üstteki sayaçlar API'den gelen son değerlere göre güncellenir.
  const running = status.services.filter((service) => service.running).length;
  document.querySelector("#runningServices").textContent = running;
  document.querySelector("#totalEvents").textContent = stats.total_recent_events;
  document.querySelector("#loginAttempts").textContent = stats.by_type.login_attempt || 0;
}

// Kullanıcı butona basınca yeniler; ayrıca sayfa açılır açılmaz ve 5 saniyede bir yenilenir.
document.querySelector("#refreshButton").addEventListener("click", refresh);
refresh();
setInterval(refresh, 5000);
