const h = React.createElement;
const { useEffect, useState, useRef, useMemo } = React;
import { ROLE_LABELS, APPEARANCE_THEMES, formatBytes, copyText, usePolling } from '../utils.js';
import { PageSkeleton } from './Core.js';
export function WhitelistPage(props) {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [ip, setIp] = useState("");
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function loadWhitelist() {
    const next = await window.requestJson("/api/whitelist");
    if (next && next.whitelist) {
      setEntries(next.whitelist);
    }
    setLoading(false);
  }

  useEffect(() => {
    loadWhitelist().catch((error) => window.showToast(error.message, "error"));
  }, []);

  async function handleAdd(event) {
    event.preventDefault();
    if (props.session.role !== "admin") {
      window.showToast("Admin access required.", "error");
      return;
    }
    if (!ip.trim() || !description.trim()) {
      window.showToast("IP and Description are required.", "error");
      return;
    }
    setSubmitting(true);
    try {
      await window.requestJson("/api/whitelist", {
        method: "POST",
        body: JSON.stringify({ ip: ip.trim(), description: description.trim() }),
      });
      window.showToast(`IP ${ip.trim()} added to whitelist.`, "success");
      setIp("");
      setDescription("");
      await loadWhitelist();
    } catch (error) {
      window.showToast(error.message, "error");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(targetIp) {
    if (props.session.role !== "admin") {
      window.showToast("Admin access required.", "error");
      return;
    }
    try {
      await window.requestJson("/api/whitelist/delete", {
        method: "POST",
        body: JSON.stringify({ ip: targetIp }),
      });
      window.showToast(`IP ${targetIp} removed from whitelist.`, "success");
      await loadWhitelist();
    } catch (error) {
      window.showToast(error.message, "error");
    }
  }

  if (loading) {
    return h(PageSkeleton, null);
  }

  const isAdmin = props.session.role === "admin";

  return h(
    React.Fragment,
    null,
    h(
      "header",
      { className: "topbar" },
      h(
        "div",
        null,
        h("h1", null, "Whitelist"),
        h("p", { className: "page-subtitle" }, "Manage whitelisted IPs that are allowed to probe the decoy services without being banned.")
      ),
      h(
        "div",
        { className: "topbar-actions" },
        h("div", { className: "user-pill" }, h("span", null, "Signed in as"), h("strong", null, props.session.username || "-")),
        h("button", { type: "button", className: "button secondary", onClick: loadWhitelist }, "Refresh"),
        h("button", { type: "button", className: "button", onClick: props.onLogout }, "Log out")
      )
    ),
    isAdmin
      ? h(
          "section",
          { className: "panel" },
          h("div", { className: "section-heading compact" }, h("div", null, h("h2", null, "Add to Whitelist"), h("p", null, "Enter details to whitelist an IP. Description is mandatory."))),
          h(
            "form",
            { className: "settings-form", onSubmit: handleAdd },
            h(
              "div",
              { style: { display: "grid", gridTemplateColumns: "1fr 2fr auto", gap: "16px", alignItems: "end" } },
              h("label", { className: "field-block", style: { marginBottom: 0 } }, h("span", null, "IP Address"), h("input", { type: "text", value: ip, onChange: (e) => setIp(e.target.value), placeholder: "e.g. 192.168.1.50", required: true })),
              h("label", { className: "field-block", style: { marginBottom: 0 } }, h("span", null, "Reason / Description"), h("input", { type: "text", value: description, onChange: (e) => setDescription(e.target.value), placeholder: "e.g. Admin workstation for testing", required: true })),
              h("button", { type: "submit", className: "button", disabled: submitting }, submitting ? "Adding..." : "Add IP")
            )
          )
        )
      : null,
    h(
      "section",
      { className: "panel" },
      h("div", { className: "section-heading" }, h("div", null, h("h2", null, "Whitelisted IPs"), h("p", null, "Currently whitelisted IP addresses."))),
      h(
        "div",
        { className: "table-shell" },
        h(
          "table",
          null,
          h(
            "thead",
            null,
            h("tr", null, h("th", null, "IP Address"), h("th", null, "Description"), h("th", null, "Added Time"), h("th", { className: "table-actions-head" }, "Actions"))
          ),
          h(
            "tbody",
            null,
            entries.length
              ? entries.map((entry) =>
                  h(
                    "tr",
                    { key: entry.ip },
                    h("td", null, h("span", { className: "table-strong" }, window.text(entry.ip))),
                    h("td", null, window.text(entry.description)),
                    h("td", null, window.text(entry.timestamp)),
                    h(
                      "td",
                      { className: "table-actions-cell" },
                      h("button", { type: "button", className: "button danger secondary", disabled: !isAdmin, onClick: () => handleDelete(entry.ip) }, "Remove")
                    )
                  )
                )
              : h("tr", null, h("td", { colSpan: 4, className: "empty-row" }, "No whitelisted IPs found."))
          )
        )
      )
    )
  );
}

export function BlacklistPage(props) {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [ip, setIp] = useState("");
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [autoBlacklist, setAutoBlacklist] = useState(true);

  async function loadBlacklist() {
    const next = await window.requestJson("/api/blacklist");
    if (next && next.blacklist) {
      setEntries(next.blacklist);
    }
    setLoading(false);
  }

  async function loadSettings() {
    try {
      const res = await window.requestJson("/api/settings/auto-blacklist");
      if (res && typeof res.auto_blacklist_enabled === "boolean") {
        setAutoBlacklist(res.auto_blacklist_enabled);
      }
    } catch (err) {
      console.error("Failed to load settings", err);
    }
  }

  useEffect(() => {
    loadBlacklist().catch((error) => window.showToast(error.message, "error"));
    loadSettings();
  }, []);

  async function handleToggleAutoBlacklist(e) {
    if (props.session.role !== "admin") {
      window.showToast("Admin access required.", "error");
      return;
    }
    const nextVal = e.target.checked;
    try {
      await window.requestJson("/api/settings/auto-blacklist", {
        method: "POST",
        body: JSON.stringify({ enabled: nextVal })
      });
      setAutoBlacklist(nextVal);
      window.showToast(nextVal ? "Automated blocklist enabled" : "Automated blocklist disabled", "success");
    } catch (err) {
      window.showToast(err.message || "Failed to update setting", "error");
    }
  }

  async function handleAdd(event) {
    event.preventDefault();
    if (props.session.role !== "admin") {
      window.showToast("Admin access required.", "error");
      return;
    }
    if (!ip.trim() || !description.trim()) {
      window.showToast("IP/MAC and Description are required.", "error");
      return;
    }
    setSubmitting(true);
    try {
      await window.requestJson("/api/blacklist", {
        method: "POST",
        body: JSON.stringify({ ip: ip.trim(), description: description.trim() }),
      });
      window.showToast(`Target ${ip.trim()} added to blacklist.`, "success");
      setIp("");
      setDescription("");
      await loadBlacklist();
    } catch (error) {
      window.showToast(error.message, "error");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(targetIp) {
    if (props.session.role !== "admin") {
      window.showToast("Admin access required.", "error");
      return;
    }
    try {
      await window.requestJson("/api/blacklist/delete", {
        method: "POST",
        body: JSON.stringify({ ip: targetIp }),
      });
      window.showToast(`Target ${targetIp} removed from blacklist.`, "success");
      await loadBlacklist();
    } catch (error) {
      window.showToast(error.message, "error");
    }
  }

  if (loading) {
    return h(PageSkeleton, null);
  }

  const isAdmin = props.session.role === "admin";

  return h(
    React.Fragment,
    null,
    h(
      "header",
      { className: "topbar" },
      h(
        "div",
        null,
        h("h1", null, "Blacklist"),
        h("p", { className: "page-subtitle" }, "Manage blacklisted IPs and MAC addresses that are blocked from connecting to honeypot services.")
      ),
      h(
        "div",
        { className: "topbar-actions" },
        h("div", { className: "user-pill" }, h("span", null, "Signed in as"), h("strong", null, props.session.username || "-")),
        h("button", { type: "button", className: "button secondary", onClick: loadBlacklist }, "Refresh"),
        h("button", { type: "button", className: "button", onClick: props.onLogout }, "Log out")
      )
    ),
    h(
      "section",
      { className: "panel", style: { marginBottom: "20px" } },
      h(
        "div",
        { style: { display: "flex", alignItems: "center", justifyContent: "space-between" } },
        h(
          "div",
          null,
          h("h2", { style: { margin: 0, fontSize: "16px" } }, "Automated Ban Settings"),
          h("p", { style: { margin: "4px 0 0 0", fontSize: "13px", color: "var(--muted)" } }, "Enable or disable automatic banning of IP addresses that exceed activity limits.")
        ),
        h(
          "label",
          { className: "toggle-switch", title: autoBlacklist ? "Disable Automated Bans" : "Enable Automated Bans" },
          h("input", {
            type: "checkbox",
            checked: autoBlacklist,
            disabled: !isAdmin,
            onChange: handleToggleAutoBlacklist
          }),
          h("span", { className: "toggle-slider" })
        )
      )
    ),
    isAdmin
      ? h(
          "section",
          { className: "panel" },
          h("div", { className: "section-heading compact" }, h("div", null, h("h2", null, "Add to Blacklist"), h("p", null, "Enter details to blacklist an IP or MAC address. Description is mandatory."))),
          h(
            "form",
            { className: "settings-form", onSubmit: handleAdd },
            h(
              "div",
              { style: { display: "grid", gridTemplateColumns: "1fr 2fr auto", gap: "16px", alignItems: "end" } },
              h("label", { className: "field-block", style: { marginBottom: 0 } }, h("span", null, "IP or MAC Address"), h("input", { type: "text", value: ip, onChange: (e) => setIp(e.target.value), placeholder: "e.g. 192.168.1.100 or 00:11:22:aa:bb:cc", required: true })),
              h("label", { className: "field-block", style: { marginBottom: 0 } }, h("span", null, "Reason / Description"), h("input", { type: "text", value: description, onChange: (e) => setDescription(e.target.value), placeholder: "e.g. Automated port scanner detected", required: true })),
              h("button", { type: "submit", className: "button", disabled: submitting }, submitting ? "Adding..." : "Block Target")
            )
          )
        )
      : null,
    h(
      "section",
      { className: "panel" },
      h("div", { className: "section-heading" }, h("div", null, h("h2", null, "Blacklisted Targets"), h("p", null, "Currently blocked IP or MAC addresses."))),
      h(
        "div",
        { className: "table-shell" },
        h(
          "table",
          null,
          h(
            "thead",
            null,
            h("tr", null, h("th", null, "IP / MAC Address"), h("th", null, "Description"), h("th", null, "Blocked Time"), h("th", { className: "table-actions-head" }, "Actions"))
          ),
          h(
            "tbody",
            null,
            entries.length
              ? entries.map((entry) =>
                  h(
                    "tr",
                    { key: entry.ip },
                    h("td", null, h("span", { className: "table-strong" }, window.text(entry.ip))),
                    h("td", null, window.text(entry.description)),
                    h("td", null, window.text(entry.timestamp)),
                    h(
                      "td",
                      { className: "table-actions-cell" },
                      h("button", { type: "button", className: "button danger secondary", disabled: !isAdmin, onClick: () => handleDelete(entry.ip) }, "Unblock")
                    )
                  )
                )
              : h("tr", null, h("td", { colSpan: 4, className: "empty-row" }, "No blacklisted targets found."))
          )
        )
      )
    )
  );
}

export function AppearancePage(props) {
  const [theme, setTheme] = useState(window.currentTheme());
  const [scheme, setScheme] = useState(window.currentScheme());

  function selectTheme(nextTheme) {
    window.applyTheme(nextTheme);
    setTheme(nextTheme);
  }

  function selectScheme(nextScheme) {
    window.applyScheme(nextScheme);
    setScheme(nextScheme);
  }

  const schemeLabel = scheme === "light" ? "Light Mode" : "Dark Mode";
  const accentLabel = (APPEARANCE_THEMES.find((item) => item.key === theme) || APPEARANCE_THEMES[0]).label;

  return h(
    React.Fragment,
    null,
    h(
      "header",
      { className: "topbar" },
      h("div", null, h("h1", null, "Appearance"), h("p", { className: "page-subtitle" }, "Theme controls for the web panel.")),
      h(
        "div",
        { className: "topbar-actions" },
        h("div", { className: "user-pill" }, h("span", null, "Signed in as"), h("strong", null, props.session.username || "-")),
        h("button", { type: "button", className: "button", onClick: props.onLogout }, "Log out")
      )
    ),
    h(
      "section",
      { className: "panel" },
      h(
        "div",
        { className: "section-heading" },
        h("div", null, h("h2", null, "Base Mode"), h("p", null, "Choose a light or dark foundation for the interface.")),
        h("span", { className: "status-counter" }, schemeLabel)
      ),
      h(
        "div",
        { className: "scheme-selector" },
        h(
          "button",
          {
            type: "button",
            className: `scheme-btn${scheme === "dark" ? " active" : ""}`,
            onClick: () => selectScheme("dark"),
          },
          h("span", { className: "scheme-icon" }, "\u{1F319}"),
          "Dark Mode"
        ),
        h(
          "button",
          {
            type: "button",
            className: `scheme-btn${scheme === "light" ? " active" : ""}`,
            onClick: () => selectScheme("light"),
          },
          h("span", { className: "scheme-icon" }, "\u2600\uFE0F"),
          "Light Mode"
        )
      ),
      h("hr", { className: "appearance-divider" }),
      h(
        "div",
        { className: "section-heading" },
        h("div", null, h("h2", null, "Color Accent"), h("p", null, "Pick a color palette that pairs with your base mode.")),
        h("span", { className: "status-counter" }, accentLabel)
      ),
      h(
        "div",
        { className: "theme-grid" },
        APPEARANCE_THEMES.map((item) =>
          h(
            "button",
            {
              key: item.key,
              type: "button",
              className: `theme-card${item.key === theme ? " active" : ""}`,
              onClick: () => selectTheme(item.key),
            },
            h(
              "span",
              { className: "theme-swatch-row", "aria-hidden": "true" },
              item.colors.map((color) => h("i", { key: color, style: { background: color } }))
            ),
            h("strong", null, item.label),
            h("small", null, item.note)
          )
        )
      )
    )
  );
}

export function SystemPage(props) {
  const [payload, setPayload] = useState(null);

  async function loadSettings() {
    const next = await window.requestJson("/api/settings");
    setPayload(next);
  }

  usePolling(loadSettings, 5000, []);

  if (!payload) {
    return h(PageSkeleton, null);
  }

  const isAdmin = props.session.role === "admin";

  return h(
    React.Fragment,
    null,
    h(
      "header",
      { className: "topbar" },
      h("div", null, h("h1", null, "System"), h("p", { className: "page-subtitle" }, "Panel runtime, health, and log export tools.")),
      h(
        "div",
        { className: "topbar-actions" },
        h("div", { className: "user-pill" }, h("span", null, "Signed in as"), h("strong", null, props.session.username || "-")),
        h("button", { type: "button", className: "button secondary", onClick: () => loadSettings().catch((error) => window.showToast(error.message, "error")) }, "Refresh"),
        h("button", { type: "button", className: "button", onClick: props.onLogout }, "Log out")
      )
    ),
    h(
      "section",
      { className: "panel resources-panel", style: { marginBottom: "24px" } },
      h("div", { className: "section-heading compact" }, h("div", null, h("h2", null, "System Resources"), h("p", null, "Real-time CPU, Memory, and Disk usage status."))),
      h(
        "div",
        { className: "resources-grid" },
        h(ResourceGauge, { label: "CPU Usage", percent: payload.resources?.cpu?.percent || 0, note: "Processor utilization", colorClass: "--accent" }),
        h(ResourceGauge, { 
          label: "RAM Usage", 
          percent: payload.resources?.ram?.percent || 0, 
          note: `${payload.resources?.ram?.used_mb || 0} MB / ${payload.resources?.ram?.total_mb || 0} MB`, 
          colorClass: "--accent-focus" 
        }),
        h(ResourceGauge, { 
          label: "Disk Usage", 
          percent: payload.resources?.disk?.percent || 0, 
          note: `${payload.resources?.disk?.used_gb || 0} GB / ${payload.resources?.disk?.total_gb || 0} GB`, 
          colorClass: "--success" 
        })
      )
    ),
    h(
      "div",
      { className: "settings-grid" },
      h(DetailPanel, {
        title: "Panel",
        copy: "Address and runtime details.",
        items: [
          ["URL", payload.panel ? payload.panel.url : "-"],
          ["Bind Host", payload.panel ? payload.panel.host : "-"],
          ["Display Host", payload.panel ? payload.panel.display_host : "-"],
          ["Port", payload.panel ? payload.panel.port : "-"],
        ],
      }),
      h(DetailPanel, {
        title: "Runtime",
        copy: "Current server status and version.",
        items: [
          ["Health", h("span", { className: `status-pill ${payload.runtime && payload.runtime.health === "ok" ? "running" : "stopped"}` }, payload.runtime ? payload.runtime.health : "-")],
          ["Uptime", payload.runtime ? payload.runtime.uptime : "-"],
          ["Version", payload.runtime ? payload.runtime.version : "-"],
        ],
      })
    )
  );
}

export function ResourceGauge({ label, percent, note, colorClass }) {
  const size = 120;
  const strokeWidth = 10;
  const r = (size - strokeWidth) / 2; // 55
  const circumference = 2 * Math.PI * r; // ~345.6
  const offset = circumference - (percent / 100) * circumference;

  // Color palette per gauge type
  const colorMap = {
    "--accent":       { start: "#0075ff", end: "#21d4fd", glow: "rgba(0, 117, 255, 0.35)" },
    "--accent-focus": { start: "#7b2ff7", end: "#c471f5", glow: "rgba(123, 47, 247, 0.35)" },
    "--success":      { start: "#01b574", end: "#38ef7d", glow: "rgba(1, 181, 116, 0.35)" },
  };

  // Override with danger/warning colors at thresholds
  const colors = percent >= 90
    ? { start: "#e31a1a", end: "#ff6b6b", glow: "rgba(227, 26, 26, 0.45)" }
    : percent >= 75
      ? { start: "#ff8c00", end: "#ffb547", glow: "rgba(255, 181, 71, 0.4)" }
      : (colorMap[colorClass] || colorMap["--accent"]);

  const gradientId = `gauge-grad-${label.replace(/\s/g, "")}`;

  return h(
    "div",
    { className: "resource-gauge-card" },

    // SVG Gauge
    h(
      "div",
      { className: "gauge-ring-wrap" },
      h(
        "svg",
        { width: size, height: size, viewBox: `0 0 ${size} ${size}`, className: "gauge-ring-svg" },

        // Gradient definition
        h("defs", null,
          h("linearGradient", { id: gradientId, x1: "0%", y1: "0%", x2: "100%", y2: "100%" },
            h("stop", { offset: "0%", stopColor: colors.start }),
            h("stop", { offset: "100%", stopColor: colors.end })
          )
        ),

        // Background track
        h("circle", {
          cx: size / 2,
          cy: size / 2,
          r: r,
          fill: "none",
          stroke: "var(--gauge-track)",
          strokeWidth: strokeWidth
        }),

        // Progress arc
        h("circle", {
          cx: size / 2,
          cy: size / 2,
          r: r,
          fill: "none",
          stroke: `url(#${gradientId})`,
          strokeWidth: strokeWidth,
          strokeDasharray: circumference,
          strokeDashoffset: offset,
          strokeLinecap: "round",
          className: "gauge-ring-progress",
          style: {
            filter: `drop-shadow(0 0 6px ${colors.glow})`
          }
        })
      ),

      // Center content (percentage)
      h("div", { className: "gauge-ring-center" },
        h("span", { className: "gauge-ring-value", style: { color: colors.start } }, `${percent}%`)
      )
    ),

    // Label + Note
    h("div", { className: "gauge-ring-info" },
      h("strong", { className: "gauge-ring-label" }, label),
      h("span", { className: "gauge-ring-note" }, note)
    )
  );
}


export function DetailPanel(props) {
  return h(
    "section",
    { className: "panel" },
    h("div", { className: "section-heading compact" }, h("div", null, h("h2", null, props.title), h("p", null, props.copy))),
    h(
      "dl",
      { className: "detail-list" },
      props.items.map((item) => h("div", { key: item[0] }, h("dt", null, item[0]), h("dd", null, item[1])))
    )
  );
}

export function UsersPage(props) {
  const [users, setUsers] = useState([]);
  const [mode, setMode] = useState("idle");
  const [activeUser, setActiveUser] = useState("");
  const [form, setForm] = useState({ username: "", password: "", role: "viewer" });

  async function loadUsers() {
    if (props.session.role === "admin") {
      const payload = await window.requestJson("/api/users");
      setUsers(payload.users || []);
      return;
    }
    const payload = await window.requestJson("/api/settings");
    setUsers(payload.users || []);
  }

  useEffect(() => {
    loadUsers().catch((error) => window.showToast(error.message, "error"));
  }, [props.session.role]);

  function beginCreate() {
    setMode("create");
    setActiveUser("");
    setForm({ username: "", password: "", role: "viewer" });
  }

  function beginEdit(user) {
    setMode("edit");
    setActiveUser(user.username);
    setForm({ username: user.username, password: "", role: user.role || "viewer" });
  }

  async function createUser(event) {
    event.preventDefault();
    try {
      await window.requestJson("/api/users", {
        method: "POST",
        body: JSON.stringify({ username: form.username.trim(), password: form.password, role: form.role }),
      });
      window.showToast(`User ${form.username.trim()} created.`, "success");
      setMode("idle");
      setActiveUser("");
      await loadUsers();
    } catch (error) {
      window.showToast(error.message, "error");
    }
  }

  async function saveRole(event) {
    event.preventDefault();
    try {
      await window.requestJson("/api/users/role", {
        method: "POST",
        body: JSON.stringify({ username: activeUser, role: form.role }),
      });
      window.showToast(`Role updated for ${activeUser}.`, "success");
      await loadUsers();
    } catch (error) {
      window.showToast(error.message, "error");
    }
  }

  async function changePassword(event) {
    event.preventDefault();
    try {
      await window.requestJson("/api/users/password", {
        method: "POST",
        body: JSON.stringify({ username: activeUser, password: form.password }),
      });
      setForm({ ...form, password: "" });
      window.showToast(`Password updated for ${activeUser}.`, "success");
    } catch (error) {
      window.showToast(error.message, "error");
    }
  }

  async function removeUser(username) {
    try {
      await window.requestJson("/api/users/delete", {
        method: "POST",
        body: JSON.stringify({ username }),
      });
      if (username === activeUser) {
        setMode("idle");
        setActiveUser("");
      }
      await loadUsers();
      window.showToast(`User ${username} deleted.`, "success");
    } catch (error) {
      window.showToast(error.message, "error");
    }
  }

  const isAdmin = props.session.role === "admin";

  return h(
    React.Fragment,
    null,
    h(
      "header",
      { className: "topbar" },
      h("div", null, h("h1", null, "Users"), h("p", { className: "page-subtitle" }, "Manage dashboard accounts and permissions.")),
      h(
        "div",
        { className: "topbar-actions" },
        h("div", { className: "user-pill" }, h("span", null, "Signed in as"), h("strong", null, props.session.username || "-")),
        h("button", { type: "button", className: "button secondary", onClick: () => loadUsers().catch((error) => window.showToast(error.message, "error")) }, "Refresh"),
        h("button", { type: "button", className: "button", onClick: props.onLogout }, "Log out")
      )
    ),
    h(
      "section",
      { className: "panel" },
      h(
        "div",
        { className: "section-heading" },
        h("div", null, h("h2", null, "Accounts"), h("p", null, "Create, remove, and update dashboard users."))
      ),
      h(
        "div",
        { className: "table-shell" },
        h(
          "table",
          null,
          h(
            "thead",
            null,
            h("tr", null, h("th", null, "User"), h("th", null, "Role"), h("th", { className: "table-actions-head" }, "Actions"))
          ),
          h(
            "tbody",
            null,
            users.map((user) =>
              h(
                "tr",
                { key: user.username },
                h(
                  "td",
                  null,
                  h(
                    "div",
                    { className: "user-name-cell" },
                    h("span", null, window.text(user.username)),
                    user.username === props.session.username ? h("span", { className: "current-user-marker", "aria-label": "Current user" }) : null
                  )
                ),
                h("td", null, h("span", { className: "table-strong" }, ROLE_LABELS[user.role] || ROLE_LABELS.viewer)),
                h(
                  "td",
                  { className: "table-actions-cell" },
                  h("button", { type: "button", className: "button secondary", disabled: !isAdmin, onClick: () => beginEdit(user) }, "Edit")
                )
              )
            ),
          )
        )
      ),
      isAdmin
        ? h(
            "div",
            { className: "button-row users-add-row" },
            h("button", { type: "button", className: "button secondary icon-button", "aria-label": "Create user", onClick: beginCreate }, "+")
          )
        : null
    ),
    isAdmin && mode !== "idle"
      ? h(
          "section",
          { className: "panel" },
          h(
            "div",
            { className: "section-heading" },
            h(
              "div",
              null,
              h("h2", null, mode === "create" ? "Create User" : `Edit ${activeUser}`),
              h("p", null, mode === "create" ? "Create a new dashboard user." : "Change role, reset password, or delete this account.")
            )
          ),
          mode === "create"
            ? h(
                "form",
                { className: "settings-form", onSubmit: createUser },
                h("label", { className: "field-block" }, h("span", null, "Username"), h("input", { value: form.username, onChange: (event) => setForm({ ...form, username: event.target.value }), required: true })),
                h("label", { className: "field-block" }, h("span", null, "Password"), h("input", { type: "password", value: form.password, onChange: (event) => setForm({ ...form, password: event.target.value }), required: true })),
                h(
                  "label",
                  { className: "field-block" },
                  h("span", null, "Role"),
                  h(
                    "select",
                    { value: form.role, onChange: (event) => setForm({ ...form, role: event.target.value }) },
                    h("option", { value: "admin" }, ROLE_LABELS.admin),
                    h("option", { value: "viewer" }, ROLE_LABELS.viewer)
                  )
                ),
                h("div", { className: "button-row" }, h("button", { type: "submit", className: "button" }, "Create User"), h("button", { type: "button", className: "button secondary", onClick: () => setMode("idle") }, "Cancel"))
              )
            : h(
                "div",
                { className: "settings-grid" },
                h(
                  "section",
                  { className: "panel settings-card" },
                  h("h3", null, "Role"),
                  h(
                    "form",
                    { className: "settings-form", onSubmit: saveRole },
                    h(
                      "label",
                      { className: "field-block" },
                      h("span", null, "Access Level"),
                      h(
                        "select",
                        { value: form.role, onChange: (event) => setForm({ ...form, role: event.target.value }) },
                        h("option", { value: "admin" }, ROLE_LABELS.admin),
                        h("option", { value: "viewer" }, ROLE_LABELS.viewer)
                      )
                    ),
                    h("div", { className: "button-row" }, h("button", { type: "submit", className: "button" }, "Save Role"))
                  )
                ),
                h(
                  "section",
                  { className: "panel settings-card" },
                  h("h3", null, "Password"),
                  h(
                    "form",
                    { className: "settings-form", onSubmit: changePassword },
                    h("label", { className: "field-block" }, h("span", null, "New Password"), h("input", { type: "password", value: form.password, onChange: (event) => setForm({ ...form, password: event.target.value }), required: true })),
                    h("div", { className: "button-row" }, h("button", { type: "submit", className: "button" }, "Change Password"))
                  )
                ),
                h(
                  "section",
                  { className: "panel settings-card" },
                  h("h3", null, "Danger Zone"),
                  h("p", { className: "support-text" }, activeUser === props.session.username ? "The signed-in user cannot be deleted." : "Delete this account permanently."),
                  h(
                    "div",
                    { className: "button-row" },
                    h("button", { type: "button", className: "button danger", disabled: activeUser === props.session.username, onClick: () => removeUser(activeUser) }, "Delete User")
                  )
                ),
                h(
                  "div",
                  { className: "button-row users-panel-close" },
                  h("button", { type: "button", className: "button secondary", onClick: () => setMode("idle") }, "Close")
                )
              )
        )
      : null
  );
}

export function SiemSettingsPage(props) {
  const emptyForm = { id: "", name: "", enabled: true, host: "", port: 514, protocol: "udp", scope: "all" };
  const [configs, setConfigs] = useState([]);
  const [mode, setMode] = useState("idle");
  const [activeId, setActiveId] = useState("");
  const [form, setForm] = useState(emptyForm);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testingId, setTestingId] = useState("");

  async function loadConfig() {
    try {
      const next = await window.requestJson("/api/settings/siem");
      if (next) {
        setConfigs(Array.isArray(next.configs) ? next.configs : []);
      }
    } catch (e) {
      window.showToast("Failed to load SIEM settings: " + e.message, "error");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadConfig();
  }, []);

  function beginCreate() {
    setMode("create");
    setActiveId("");
    setForm({ ...emptyForm, id: `siem-${Date.now().toString(36)}` });
  }

  function beginEdit(config) {
    setMode("edit");
    setActiveId(config.id);
    setForm({ ...emptyForm, ...config });
  }

  async function saveConfigs(nextConfigs, message) {
    if (props.session.role !== "admin") {
      window.showToast("Admin access required.", "error");
      return;
    }
    setSaving(true);
    try {
      const payload = await window.requestJson("/api/settings/siem", {
        method: "POST",
        body: JSON.stringify({ configs: nextConfigs })
      });
      setConfigs(payload.configs || nextConfigs);
      window.showToast(message || "SIEM settings saved.", "success");
      return true;
    } catch (e) {
      window.showToast("Save failed: " + e.message, "error");
      return false;
    } finally {
      setSaving(false);
    }
  }

  async function handleSave(e) {
    e.preventDefault();
    const clean = {
      ...form,
      name: String(form.name || "").trim(),
      host: String(form.host || "").trim(),
      port: parseInt(form.port, 10) || 514,
    };
    if (!clean.name) {
      window.showToast("SIEM name is required.", "error");
      return;
    }
    if (clean.enabled && !clean.host) {
      window.showToast("Host address is required when enabled.", "error");
      return;
    }

    const nextConfigs = mode === "edit"
      ? configs.map((item) => item.id === activeId ? clean : item)
      : [...configs, clean];
    const saved = await saveConfigs(nextConfigs, mode === "edit" ? `${clean.name} updated.` : `${clean.name} added.`);
    if (!saved) {
      return;
    }
    setMode("idle");
    setActiveId("");
    setForm(emptyForm);
  }

  async function removeConfig(config) {
    await saveConfigs(configs.filter((item) => item.id !== config.id), `${config.name || config.host} deleted.`);
    if (activeId === config.id) {
      setMode("idle");
      setActiveId("");
    }
  }

  async function handleTest(config) {
    if (!config.enabled || !config.host) {
      window.showToast("Enable this SIEM target and set a host before testing.", "error");
      return;
    }
    setTestingId(config.id);
    try {
      const res = await window.requestJson("/api/settings/siem/test", {
        method: "POST",
        body: JSON.stringify({ id: config.id })
      });
      if (res.ok) {
        window.showToast(`Test event sent to ${config.name || config.host}.`, "success");
      }
    } catch (e) {
      window.showToast("Test failed: " + e.message, "error");
    } finally {
      setTestingId("");
    }
  }

  if (loading) {
    return h(PageSkeleton, null);
  }

  const isAdmin = props.session.role === "admin";
  const activeConfig = configs.find((item) => item.id === activeId);
  const tableRows = configs.length
    ? configs.map((config) =>
        h(
          "tr",
          { key: config.id },
          h("td", null, h("span", { className: "table-strong" }, window.text(config.name))),
          h("td", null, `${window.text(config.host)}:${window.text(config.port)}`),
          h("td", null, String(config.protocol || "udp").toUpperCase()),
          h("td", null, config.scope === "alerts" ? "Critical Alerts" : "All Events"),
          h("td", null, h("span", { className: `status-pill ${config.enabled ? "running" : "stopped"}` }, config.enabled ? "Enabled" : "Disabled")),
          h(
            "td",
            { className: "table-actions-cell" },
            h("button", { type: "button", className: "button secondary", disabled: !isAdmin || testingId === config.id, onClick: () => handleTest(config) }, testingId === config.id ? "Testing..." : "Test"),
            h("button", { type: "button", className: "button secondary", disabled: !isAdmin, onClick: () => beginEdit(config) }, "Edit"),
            h("button", { type: "button", className: "button danger secondary", disabled: !isAdmin || saving, onClick: () => removeConfig(config) }, "Delete")
          )
        )
      )
    : [h("tr", { key: "empty" }, h("td", { colSpan: 6, className: "empty-row" }, "No SIEM targets configured."))];

  const targetsPanel = h(
    "section",
    { className: "panel" },
    h("div", { className: "section-heading" }, h("div", null, h("h2", null, "SIEM Targets"), h("p", null, "Create, test, edit, and remove external log destinations."))),
    h(
      "div",
      { className: "table-shell" },
      h(
        "table",
        null,
        h("thead", null, h("tr", null, h("th", null, "Name"), h("th", null, "Destination"), h("th", null, "Protocol"), h("th", null, "Scope"), h("th", null, "Status"), h("th", { className: "table-actions-head" }, "Actions"))),
        h("tbody", null, tableRows)
      )
    ),
    isAdmin
      ? h(
          "div",
          { className: "button-row users-add-row" },
          h("button", { type: "button", className: "button secondary icon-button", "aria-label": "Create SIEM target", onClick: beginCreate }, "+")
        )
      : null
  );

  const editorPanel = isAdmin && mode !== "idle"
    ? h(
        "section",
        { className: "panel" },
        h("div", { className: "section-heading" }, h("div", null, h("h2", null, mode === "create" ? "Create SIEM Target" : `Edit ${activeConfig ? activeConfig.name : "SIEM Target"}`), h("p", null, "Define where and how honeypot events are forwarded."))),
        h(
          "form",
          { className: "settings-form siem-editor-form", onSubmit: handleSave },
          h("label", { className: "field-block" }, h("span", null, "SIEM Name"), h("input", { value: form.name, onChange: (event) => setForm({ ...form, name: event.target.value }), placeholder: "SOC Collector", required: true })),
          h("label", { className: "field-block" }, h("span", null, "Host / URL"), h("input", { value: form.host, onChange: (event) => setForm({ ...form, host: event.target.value }), placeholder: "192.168.1.50 or http://siem.local", required: form.enabled })),
          h("label", { className: "field-block" }, h("span", null, "Port"), h("input", { type: "number", min: "1", max: "65535", value: String(form.port), onChange: (event) => setForm({ ...form, port: event.target.value }) })),
          h(
            "label",
            { className: "field-block" },
            h("span", null, "Protocol"),
            h(
              "select",
              { value: form.protocol, onChange: (event) => setForm({ ...form, protocol: event.target.value }) },
              h("option", { value: "udp" }, "UDP Syslog"),
              h("option", { value: "tcp" }, "TCP Syslog"),
              h("option", { value: "http" }, "HTTP POST")
            )
          ),
          h(
            "label",
            { className: "field-block" },
            h("span", null, "Forwarding Scope"),
            h(
              "select",
              { value: form.scope, onChange: (event) => setForm({ ...form, scope: event.target.value }) },
              h("option", { value: "all" }, "All Events"),
              h("option", { value: "alerts" }, "Critical Alerts Only")
            )
          ),
          h(
            "label",
            { className: "siem-enabled-row" },
            h("span", null, "Enabled"),
            h(
              "span",
              { className: "toggle-switch" },
              h("input", { type: "checkbox", checked: form.enabled, onChange: (event) => setForm({ ...form, enabled: event.target.checked }) }),
              h("span", { className: "toggle-slider" })
            )
          ),
          h(
            "div",
            { className: "button-row" },
            h("button", { type: "submit", className: "button", disabled: saving }, saving ? "Saving..." : mode === "create" ? "Create Target" : "Save Target"),
            h("button", { type: "button", className: "button secondary", onClick: () => setMode("idle") }, "Cancel")
          )
        )
      )
    : null;

  return h(
    React.Fragment,
    null,
    h(
      "header",
      { className: "topbar" },
      h(
        "div",
        null,
        h("h1", null, "SIEM Integration"),
        h("p", { className: "page-subtitle" }, "Forward honeypot events to an external SIEM (Splunk, QRadar, Wazuh, etc).")
      ),
      h(
        "div",
        { className: "topbar-actions" },
        h("div", { className: "user-pill" }, h("span", null, "Signed in as"), h("strong", null, props.session.username || "-")),
        h("button", { type: "button", className: "button", onClick: props.onLogout }, "Log out")
      )
    ),
    targetsPanel,
    editorPanel
  );
}
