const h = React.createElement;
const { useEffect, useState, useRef, useMemo } = React;
import { parseEventTime, buildSuspiciousOverview, filterLogEvents, usePolling } from '../utils.js';
import { PageSkeleton, MetricCard, EventDrawer } from './Core.js';
import { EventsTable } from './Dashboard.js';

export function LogsPage(props) {
  const [payload, setPayload] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [filters, setFilters] = useState({ service: "", eventType: "", search: "", searchField: "", excludeSystem: false });
  
  // Pagination States
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  async function loadLogs() {
    const query = new URLSearchParams();
    query.set("limit", String(pageSize));
    query.set("page", String(currentPage));
    if (filters.service) {
      query.set("service", filters.service);
    }
    if (filters.eventType) {
      query.set("event_type", filters.eventType);
    }
    if (filters.search) {
      query.set("search", filters.search);
    }
    if (filters.searchField) {
      query.set("search_field", filters.searchField);
    }
    if (filters.excludeSystem) {
      query.set("exclude_system", "true");
    }
    const next = await window.requestJson(`/api/overview?${query.toString()}`);
    setPayload(next);
  }

  usePolling(loadLogs, 6000, [currentPage, pageSize, filters.service, filters.eventType, filters.search, filters.searchField, filters.excludeSystem]);

  // Reset page to 1 when filters are changed
  useEffect(() => {
    setCurrentPage(1);
  }, [filters.service, filters.eventType, filters.search, filters.searchField, filters.excludeSystem]);

  if (!payload) {
    return h(PageSkeleton, null);
  }

  const profile = payload.profile && payload.profile.current ? payload.profile.current.name : "-";
  const events = payload.events || [];
  const services = payload.services || [];
  const stats = payload.stats || {};
  const eventTypes = Object.keys(stats.by_type || {}).sort();

  const totalFiltered = stats.total_filtered !== undefined ? stats.total_filtered : stats.total_recent_events || events.length;
  const totalPages = Math.max(1, Math.ceil(totalFiltered / pageSize));

  const suspiciousEvents = Number(stats.suspicious_events_count || 0);
  const totalEvents = Number(stats.total_recent_events || 0);
  const suspiciousOverview = stats.top_ip ? { topIp: { ip: stats.top_ip, count: stats.top_ip_count } } : { topIp: null };

  // Render pagination bar
  const paginationControls = h(
    "div",
    {
      className: "pagination-controls-row",
      style: {
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        marginTop: "20px",
        paddingTop: "16px",
        borderTop: "1px solid var(--border)",
        flexWrap: "wrap",
        gap: "12px"
      }
    },
    h(
      "div",
      { style: { display: "flex", alignItems: "center", gap: "16px" } },
      h(
        "label",
        { style: { display: "flex", alignItems: "center", gap: "8px", fontSize: "13px", color: "var(--muted)" } },
        h("span", null, "Show:"),
        h(
          "select",
          {
            value: String(pageSize),
            onChange: (e) => {
              setPageSize(Number(e.target.value));
              setCurrentPage(1);
            },
            className: "select-input",
            style: { padding: "4px 8px", minWidth: "80px", height: "30px", fontSize: "13px" }
          },
          [10, 25, 50, 100].map(sz => h("option", { key: sz, value: String(sz) }, `${sz} per page`))
        )
      ),
      h("span", { style: { fontSize: "13px", color: "var(--muted-strong)" } }, 
        `Showing ${totalFiltered > 0 ? (currentPage - 1) * pageSize + 1 : 0} - ${Math.min(currentPage * pageSize, totalFiltered)} of ${totalFiltered} logs`
      )
    ),
    h(
      "div",
      { style: { display: "flex", alignItems: "center", gap: "8px" } },
      h(
        "button",
        {
          type: "button",
          className: "button secondary",
          disabled: currentPage <= 1,
          onClick: () => setCurrentPage(prev => Math.max(1, prev - 1)),
          style: { height: "32px", padding: "0 12px", minHeight: "32px", fontSize: "13px" }
        },
        "Previous"
      ),
      h("span", { style: { fontSize: "13.5px", fontWeight: "600", padding: "0 8px", color: "var(--text)" } }, 
        `Page ${currentPage} of ${totalPages}`
      ),
      h(
        "button",
        {
          type: "button",
          className: "button secondary",
          disabled: currentPage >= totalPages,
          onClick: () => setCurrentPage(prev => Math.min(totalPages, prev + 1)),
          style: { height: "32px", padding: "0 12px", minHeight: "32px", fontSize: "13px" }
        },
        "Next"
      )
    )
  );

  return h(
    React.Fragment,
    null,
    h(
      "header",
      { className: "topbar" },
      h("div", null, h("h1", null, "Logs"), h("p", { className: "page-subtitle" }, "Filter, search, and inspect captured events.")),
      h(
        "div",
        { className: "topbar-actions" },
        h("div", { className: "user-pill" }, h("span", null, "Signed in as"), h("strong", null, props.session.username || "-")),
        h("button", { type: "button", className: "button secondary", onClick: () => loadLogs().catch((error) => window.showToast(error.message, "error")) }, "Refresh"),
        h("button", { type: "button", className: "button", onClick: props.onLogout }, "Log out")
      )
    ),
    h(
      "section",
      { className: "metric-grid compact-metrics", "aria-label": "Log metrics" },
      h(MetricCard, { label: "Suspicious Events", value: String(suspiciousEvents), note: "Events with a source IP address." }),
      h(MetricCard, { label: "Total Events", value: String(totalEvents), note: "All recent events in the log overview." }),
      h(MetricCard, { label: "Most Suspicious IP", value: suspiciousOverview.topIp ? suspiciousOverview.topIp.ip : "-", note: suspiciousOverview.topIp ? `${suspiciousOverview.topIp.count} requests in the last 24 hours` : "No source IP activity in the last 24 hours" })
    ),
    h(
      "section",
      { className: "toolbar-panel" },
      h(
        "form",
        {
          className: "filter-grid",
          onSubmit: (event) => {
            event.preventDefault();
            loadLogs().catch((error) => window.showToast(error.message, "error"));
          },
        },
        h("label", { className: "field-block" }, h("span", null, "Service"),
          h(
            "select",
            {
              value: filters.service,
              onChange: (event) => setFilters({ ...filters, service: event.target.value }),
            },
            h("option", { value: "" }, "All services"),
            services.map((service) => h("option", { key: service.name, value: service.name }, `${service.name.toUpperCase()} - ${service.port}`))
          )
        ),
        h("label", { className: "field-block" }, h("span", null, "Type"),
          h(
            "select",
            {
              value: filters.eventType,
              onChange: (event) => setFilters({ ...filters, eventType: event.target.value }),
            },
            h("option", { value: "" }, "All event types"),
            eventTypes.map((eventType) => h("option", { key: eventType, value: eventType }, eventType))
          )
        ),
        h("label", { className: "field-block" }, h("span", null, "Search Field"),
          h(
            "select",
            {
              value: filters.searchField,
              onChange: (event) => setFilters({ ...filters, searchField: event.target.value }),
            },
            h("option", { value: "" }, "All Fields"),
            h("option", { value: "src_ip" }, "Source IP"),
            h("option", { value: "summary" }, "Summary"),
            h("option", { value: "profile" }, "Profile"),
            h("option", { value: "service" }, "Service"),
            h("option", { value: "event_type" }, "Event Type")
          )
        ),
        h("label", { className: "field-block search-block" }, h("span", null, "Search"),
          h("input", {
            type: "search",
            value: filters.search,
            placeholder: "Search summary, source, or profile (regex supported)",
            onChange: (event) => setFilters({ ...filters, search: event.target.value || "" }),
          })
        ),
        h("label", { className: "field-block", style: { display: "flex", flexDirection: "row", alignItems: "center", gap: "8px", cursor: "pointer", height: "38px", marginTop: "24px" } },
          h("input", {
            type: "checkbox",
            checked: filters.excludeSystem,
            onChange: (event) => setFilters({ ...filters, excludeSystem: event.target.checked }),
            style: { width: "16px", height: "16px", cursor: "pointer" }
          }),
          h("span", { style: { fontSize: "13px", fontWeight: "600", whiteSpace: "nowrap", color: "var(--text)" } }, "Exclude System Logs")
        ),
        h(
          "div",
          { className: "filter-actions" },
          h("button", { type: "submit", className: "button secondary" }, "Apply Filters"),
          h(
            "button",
            {
              type: "button",
              className: "button secondary",
              onClick: () => setFilters({ service: "", eventType: "", search: "", searchField: "", excludeSystem: false }),
            },
            "Reset"
          )
        )
      )
    ),
    h(
      "section",
      { className: "panel" },
      h("div", { className: "section-heading" }, h("div", null, h("h2", null, "Events"), h("p", null, "Latest matching records from the event log."))),
      h(EventsTable, { events: events, fallbackProfile: profile, onSelect: setSelectedEvent }),
      paginationControls
    ),
    h(EventDrawer, { event: selectedEvent, onClose: () => setSelectedEvent(null) })
  );
}
