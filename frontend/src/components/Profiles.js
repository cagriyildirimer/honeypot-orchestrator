const h = React.createElement;
const { useEffect, useState } = React;
import { STANDARD_PORTS } from '../utils.js';
import { PageSkeleton, MetricCard } from './Core.js';

function getServiceDetails(serviceName) {
  const baseName = serviceName.split("_")[0].toLowerCase();
  const displayName = baseName.toUpperCase();
  return {
    baseName,
    displayName
  };
}

export function ProfilesPage(props) {
  const [payload, setPayload] = useState(null);
  const [selectedProfile, setSelectedProfile] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [togglingMap, setTogglingMap] = useState({});

  async function loadProfiles() {
    const next = await window.requestJson("/api/overview?limit=1");
    setPayload(next);
    const currentProfile = next && next.profile && next.profile.current ? next.profile.current.name : "";
    setSelectedProfile(currentProfile);
  }

  function setServiceRunning(serviceName, running) {
    setPayload((currentPayload) => {
      if (!currentPayload || !Array.isArray(currentPayload.services)) {
        return currentPayload;
      }
      return {
        ...currentPayload,
        services: currentPayload.services.map((service) =>
          service.name === serviceName ? { ...service, running } : service
        ),
      };
    });
  }

  useEffect(() => {
    loadProfiles().catch((error) => window.showToast(error.message, "error"));
  }, []);

  if (!payload) {
    return h(PageSkeleton, null);
  }

  const services = payload.services || [];
  const profileStatus = payload.profile || {};
  const current = profileStatus.current || {};
  const available = profileStatus.available || [];
  const running = services.filter((service) => service.running).length;

  async function applyProfile(event) {
    event.preventDefault();
    if (props.session.role !== "admin") {
      window.showToast("Admin access required.", "error");
      return;
    }
    if (!selectedProfile) {
      return;
    }
    setSubmitting(true);
    try {
      await window.requestJson("/api/profile", {
        method: "POST",
        body: JSON.stringify({ profile: selectedProfile }),
      });
      await loadProfiles();
      window.showToast(`${selectedProfile} applied.`, "success");
    } catch (error) {
      window.showToast(error.message, "error");
    } finally {
      setSubmitting(false);
    }
  }

  return h(
    React.Fragment,
    null,
    h(
      "header",
      { className: "topbar" },
      h(
        "div",
        null,
        h("h1", null, "Profiles"),
        h("p", { className: "page-subtitle" }, "Select and apply host personas to the honeypot stack.")
      ),
      h(
        "div",
        { className: "topbar-actions" },
        h("button", { type: "button", className: "button secondary", onClick: () => loadProfiles().catch((error) => window.showToast(error.message, "error")) }, "Refresh"),
        h("span", { className: "topbar-icons-slot" }),
        h("div", { className: "user-pill" }, h("span", null, "Signed in as"), h("strong", null, props.session.username || "-")),
        h("button", { type: "button", className: "button", onClick: props.onLogout }, "Log out")
      )
    ),
    h(
      "section",
      { className: "toolbar-panel static-panel" },
      h(
        "form",
        { className: "profile-control", onSubmit: applyProfile },
        h(
          "label",
          { className: "field-block" },
          h("span", null, "Active Profile"),
          h(
            "select",
            {
              id: "reactProfileSelect",
              value: selectedProfile,
              disabled: props.session.role !== "admin" || submitting,
              onChange: (event) => setSelectedProfile(event.target.value),
            },
            available.map((profile) =>
              h("option", { key: profile.name, value: profile.name }, profile.display_name)
            )
          )
        ),
        h("button", { type: "submit", id: "applyProfileButton", className: "button", disabled: props.session.role !== "admin" || submitting }, submitting ? "Applying..." : "Apply Profile")
      ),
      h("div", { className: "refresh-note" }, h("span", null, "Current profile"), h("strong", null, window.text(current.display_name)))
    ),
    h(
      "section",
      { className: "metric-grid profile-metrics", "aria-label": "Profile metrics" },
      h(MetricCard, { label: "Running Services", value: String(running), note: `${running} of ${services.length} active.` }),
      h(MetricCard, { label: "Profile Description", value: window.text(current.display_name || "-"), note: window.text(current.description || "No description available.") })
    ),
    h(
      "section",
      { className: "panel services-panel static-panel" },
      h("div", { className: "section-heading" }, h("div", null, h("h2", null, "Services"), h("p", null, "Listeners assigned to the selected profile."))),
      h(
        "div",
        { className: "service-grid-fixed" },
        services.length
          ? services.map((service) => {
              const { baseName, displayName } = getServiceDetails(service.name);
              const standardPort = STANDARD_PORTS[baseName] || STANDARD_PORTS[service.name];
              const isPortMismatch = Boolean(standardPort && standardPort !== service.port);

              return h(
                "article",
                { key: `${service.name}-${service.port}`, className: `service-card-modern ${service.running ? "live" : "stopped"}` },
                h(
                  "div",
                  { className: "service-card-header" },
                  h(
                    "div",
                    { className: "service-header-title-row" },
                    h("strong", { className: "service-name-title" }, displayName),
                    h("span", { className: "service-port-title" }, `:${service.port}`)
                  ),
                  h(
                    "label",
                    { className: "toggle-switch", title: service.running ? "Turn Off" : "Turn On" },
                    h("input", {
                      type: "checkbox",
                      checked: service.running,
                      disabled: props.session.role !== "admin" || submitting || Boolean(togglingMap[service.name]),
                      onChange: async (e) => {
                        const enabled = e.target.checked;
                        const serviceName = service.name;
                        const label = displayName;

                        setTogglingMap((prev) => ({ ...prev, [serviceName]: true }));
                        setServiceRunning(serviceName, enabled);

                        try {
                          await window.requestJson("/api/services/toggle", {
                            method: "POST",
                            body: JSON.stringify({ service: serviceName, enabled: enabled })
                          });
                          window.showToast(enabled ? `${label} started` : `${label} stopped`, enabled ? "success" : "neutral");
                          await loadProfiles();
                        } catch (err) {
                          window.showToast(err.message || "Toggle failed", "error");
                          await loadProfiles();
                        } finally {
                          setTogglingMap((prev) => ({ ...prev, [serviceName]: false }));
                        }
                      }
                    }),
                    h("span", { className: "toggle-slider" })
                  )
                ),
                h(
                  "div",
                  { className: "service-card-body" },
                  isPortMismatch
                    ? h(
                        "div",
                        { className: "port-warning-box" },
                        h("span", { className: "warning-icon" }, "⚠️"),
                        h(
                          "div",
                          { className: "warning-text" },
                          h("strong", null, `Port Conflict (Standard: ${standardPort})`),
                          h("span", null, `Bound to custom port ${service.port}`)
                        )
                      )
                    : h(
                        "div",
                        { className: "port-standard-box" },
                        h("span", { className: "check-icon" }, "✓"),
                        h("span", null, `Standard Listener Port`)
                      )
                ),
                h(
                  "div",
                  { className: "service-card-footer" },
                  h(
                    "span",
                    { className: `status-indicator ${service.running ? "active" : "inactive"}` },
                    h("span", { className: "status-dot" }),
                    service.running ? "EXPOSED / LISTENING" : "STOPPED"
                  )
                )
              );
            })
          : h("article", { className: "service-card-modern" }, h("p", null, "No listeners are assigned to the current profile."))
      )
    )
  );
}
