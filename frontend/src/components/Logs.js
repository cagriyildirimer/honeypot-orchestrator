const h = React.createElement;
const { useEffect, useState, useRef, useMemo } = React;
import { parseEventTime, buildSuspiciousOverview, filterLogEvents, usePolling } from '../utils.js';
import { PageSkeleton, MetricCard, EventDrawer } from './Core.js';
import { EventsTable } from './Dashboard.js';
export function LogsPage(props) {
  const [payload, setPayload] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [filters, setFilters] = useState({ service: "", eventType: "", limit: 100, search: "" });

  async function loadLogs() {
    const query = new URLSearchParams();
    query.set("limit", String(filters.limit));
    if (filters.service) {
      query.set("service", filters.service);
    }
    if (filters.eventType) {
      query.set("event_type", filters.eventType);
    }
    const next = await window.requestJson(`/api/overview?${query.toString()}`);
    setPayload(next);
  }

  usePolling(loadLogs, 6000, [filters.service, filters.eventType, filters.limit]);

  if (!payload) {
    return h(PageSkeleton, null);
  }

  const profile = payload.profile && payload.profile.current ? payload.profile.current.name : "-";
  const events = payload.events || [];
  const visibleEvents = filterLogEvents(events, filters);
  const services = payload.services || [];
  const stats = payload.stats || {};
  const eventTypes = Object.keys(stats.by_type || {}).sort();
  const suspiciousEvents = events.filter((event) => event && event.src_ip).length;
  const totalEvents = Number(stats.total_recent_events || events.length || 0);
  const suspiciousOverview = buildSuspiciousOverview(events, parseEventTime(payload.generated_at));

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
        h("label", { className: "field-block" }, h("span", null, "Limit"),
          h(
            "select",
            {
              value: String(filters.limit),
              onChange: (event) => setFilters({ ...filters, limit: Number(event.target.value) || 100 }),
            },
            [100, 250, 500, 1000].map((limit) => h("option", { key: limit, value: String(limit) }, String(limit)))
          )
        ),
        h("label", { className: "field-block search-block" }, h("span", null, "Search"),
          h("input", {
            type: "search",
            value: filters.search,
            placeholder: "Search summary, source, or profile",
            onChange: (event) => setFilters({ ...filters, search: event.target.value || "" }),
          })
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
              onClick: () => setFilters({ service: "", eventType: "", limit: 100, search: "" }),
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
      h(EventsTable, { events: visibleEvents, fallbackProfile: profile, onSelect: setSelectedEvent })
    ),
    h(EventDrawer, { event: selectedEvent, onClose: () => setSelectedEvent(null) })
  );
}
