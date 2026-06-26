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

  function selectTheme(nextTheme) {
    window.applyTheme(nextTheme);
    setTheme(nextTheme);
  }

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
        h("div", null, h("h2", null, "Theme"), h("p", null, "Choose a coordinated color system for the web panel.")),
        h("span", { className: "status-counter" }, (APPEARANCE_THEMES.find((item) => item.key === theme) || APPEARANCE_THEMES[0]).label)
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
      }),
      h(
        "section",
        { className: "panel" },
        h("div", { className: "section-heading compact" }, h("div", null, h("h2", null, "Logging"), h("p", null, "Inspect and export current event storage."))),
        h(
          "dl",
          { className: "detail-list" },
          h("div", null, h("dt", null, "Path"), h("dd", null, payload.logging ? payload.logging.path : "-")),
          h("div", null, h("dt", null, "Size"), h("dd", null, payload.logging ? formatBytes(payload.logging.size_bytes) : "-"))
        ),
        h(
          "div",
          { className: "button-row" },
          h(
            "a",
            {
              className: `button secondary${isAdmin ? "" : " disabled"}`,
              href: "/api/ioc/csv",
              download: "ioc_export.csv",
              onClick: (event) => {
                if (!isAdmin) {
                  event.preventDefault();
                  window.showToast("Admin access required.", "error");
                }
              },
            },
            "Export IOC (CSV)"
          ),
          h(
            "a",
            {
              className: `button secondary${isAdmin ? "" : " disabled"}`,
              href: "/api/ioc/stix",
              download: "ioc_export.stix.json",
              onClick: (event) => {
                if (!isAdmin) {
                  event.preventDefault();
                  window.showToast("Admin access required.", "error");
                }
              },
            },
            "Export IOC (STIX)"
          )
        )
      )
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
  const [config, setConfig] = useState({
    enabled: false,
    host: "",
    port: 514,
    protocol: "udp",
    scope: "all"
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  async function loadConfig() {
    try {
      const next = await window.requestJson("/api/settings/siem");
      if (next) {
        setConfig(next);
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

  async function handleSave(e) {
    e.preventDefault();
    if (props.session.role !== "admin") {
      window.showToast("Admin access required.", "error");
      return;
    }
    if (config.enabled && !config.host) {
      window.showToast("Host address is required when enabled.", "error");
      return;
    }

    setSaving(true);
    try {
      await window.requestJson("/api/settings/siem", {
        method: "POST",
        body: JSON.stringify(config)
      });
      window.showToast("SIEM settings saved.", "success");
    } catch (e) {
      window.showToast("Save failed: " + e.message, "error");
    } finally {
      setSaving(false);
    }
  }

  async function handleTest() {
    if (!config.enabled) {
      window.showToast("Please enable and save SIEM settings before testing.", "error");
      return;
    }
    setTesting(true);
    try {
      const res = await window.requestJson("/api/settings/siem/test", { method: "POST" });
      if (res.ok) {
        window.showToast("Test event sent to SIEM successfully.", "success");
      }
    } catch (e) {
      window.showToast("Test failed: " + e.message, "error");
    } finally {
      setTesting(false);
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
    h(
      "section",
      { className: "panel" },
      h("div", { className: "section-heading" }, h("div", null, h("h2", null, "SIEM Configuration"), h("p", null, "Define how logs should be exported."))),
      h(
        "form",
        { className: "settings-form", onSubmit: handleSave, style: { maxWidth: "600px" } },
        h(
          "div",
          { style: { display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" } },
          h("span", null, h("strong", null, "Enable SIEM Forwarding")),
          h(
            "label",
            { className: "toggle-switch" },
            h("input", {
              type: "checkbox",
              checked: config.enabled,
              disabled: !isAdmin,
              onChange: (e) => setConfig({ ...config, enabled: e.target.checked })
            }),
            h("span", { className: "toggle-slider" })
          )
        ),
        h(
          "div",
          { style: { opacity: config.enabled ? 1 : 0.5, pointerEvents: config.enabled ? "auto" : "none" } },
          h(
            "label",
            { className: "field-block" },
            h("span", null, "SIEM Host (IP or Domain)"),
            h("input", { type: "text", value: config.host, onChange: (e) => setConfig({ ...config, host: e.target.value }), placeholder: "e.g. 192.168.1.50 or http://siem:8080" })
          ),
          h(
            "div",
            { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" } },
            h(
              "label",
              { className: "field-block" },
              h("span", null, "Port"),
              h("input", { type: "number", value: config.port, onChange: (e) => setConfig({ ...config, port: parseInt(e.target.value) || 514 }) })
            ),
            h(
              "label",
              { className: "field-block" },
              h("span", null, "Protocol"),
              h(
                "select",
                { value: config.protocol, onChange: (e) => setConfig({ ...config, protocol: e.target.value }) },
                h("option", { value: "udp" }, "UDP"),
                h("option", { value: "tcp" }, "TCP"),
                h("option", { value: "http" }, "HTTP POST")
              )
            )
          ),
          h(
            "label",
            { className: "field-block" },
            h("span", null, "Forwarding Scope"),
            h(
              "select",
              { value: config.scope, onChange: (e) => setConfig({ ...config, scope: e.target.value }) },
              h("option", { value: "all" }, "All Events"),
              h("option", { value: "alerts" }, "Critical Alerts Only")
            ),
            h("small", { style: { display: "block", marginTop: "4px", color: "#888" } }, "Select whether to send every log or only high-risk events.")
          )
        ),
        isAdmin
          ? h(
              "div",
              { className: "button-row", style: { marginTop: "24px" } },
              h("button", { type: "submit", className: "button", disabled: saving }, saving ? "Saving..." : "Save Settings"),
              h("button", { type: "button", className: "button secondary", disabled: testing || !config.enabled, onClick: handleTest }, testing ? "Testing..." : "Test Connection")
            )
          : null
      )
    )
  );
}
