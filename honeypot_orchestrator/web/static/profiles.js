const profilesState = {
  username: "",
  role: "",
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

  const isAdmin = profilesState.role === "admin";
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
  setText("#runningServices", String(activeCount));
  setText("#serviceSummary", `${activeCount} active`);
  setText("#serviceFootnote", `${activeCount} of ${services.length} profile listeners are currently online.`);
}

function renderProfiles(payload) {
  const services = payload.services || [];
  renderProfileSelector(payload.profile || null);
  renderServices(services);
  setText("#sessionUser", profilesState.username || "-");
  setText("#lastUpdated", formatTimestamp(payload.generated_at));
}

async function refreshProfiles() {
  if (profilesState.refreshInFlight) {
    return;
  }
  profilesState.refreshInFlight = true;
  try {
    const payload = await requestJson("/api/overview?limit=1");
    renderProfiles(payload);
  } catch (error) {
    showToast(error.message, "error");
    if (error.message === "Authentication required.") {
      window.location.replace("/login");
    }
  } finally {
    profilesState.refreshInFlight = false;
  }
}

async function applyProfile() {
  const button = document.querySelector("#applyProfileButton");
  const profileSelect = document.querySelector("#profileSelect");
  if (!button || !profileSelect || !profileSelect.value || profilesState.role !== "admin") {
    return;
  }

  button.disabled = true;
  try {
    const payload = await requestJson("/api/profile", {
      method: "POST",
      body: JSON.stringify({ profile: profileSelect.value }),
    });
    await refreshProfiles();
    const serviceCount = ((payload.current && payload.current.services) || []).length;
    showToast(`${text(payload.current.display_name)} applied with ${serviceCount} service${serviceCount === 1 ? "" : "s"}.`, "success");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    button.disabled = profilesState.role !== "admin";
  }
}

async function bootstrapProfiles() {
  document.querySelector("#logoutButton")?.addEventListener("click", logoutAndRedirect);
  document.querySelector("#refreshButton")?.addEventListener("click", refreshProfiles);
  document.querySelector("#applyProfileButton")?.addEventListener("click", applyProfile);

  try {
    const session = await ensureAuthenticated();
    profilesState.username = session.username || "";
    profilesState.role = session.role || "";
    await refreshProfiles();
  } catch (error) {
    window.location.replace("/login");
  }
}

bootstrapProfiles();
