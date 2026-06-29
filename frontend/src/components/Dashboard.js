const h = React.createElement;
const { useEffect, useState, useRef, useMemo } = React;
import { DONUT_COLORS, TIMELINE_RANGES, parseEventTime, summarizeRangeLabel, buildSuspiciousOverview, buildRiskModel, timelineRangeConfig, formatTimelineBucketLabel, buildTimelineBuckets, smoothLinePath, buildTimelinePoints, buildTimelineAreaPath, timelineHitBox, usePolling } from '../utils.js';
import { PageSkeleton, MetricCard, EventDrawer, GeoWorldMap, ThreatIntelPanel } from './Core.js';
export function DashboardPage(props) {
  const [payload, setPayload] = useState(null);
  const [loading, setLoading] = useState(true);
  const [timelineRangeKey, setTimelineRangeKey] = useState("day");
  const [selectedEvent, setSelectedEvent] = useState(null);
  async function loadOverview() {
    const next = await window.requestJson("/api/overview?limit=2000");
    setPayload(next);
    setLoading(false);
  }

  usePolling(loadOverview, 5000, []);

  if (loading && !payload) {
    return h(PageSkeleton, null);
  }

  const stats = payload && payload.stats ? payload.stats : {};
  const services = payload && payload.services ? payload.services : [];
  const events = payload && payload.events ? payload.events : [];
  const profile = payload && payload.profile && payload.profile.current ? payload.profile.current : null;
  const runningServices = services.filter((service) => service.running).length;
  const suspiciousEvents = events.filter((event) => event && event.src_ip).length;
  const totalEvents = Number(stats.total_recent_events || events.length || 0);
  const timelineReference = parseEventTime(payload && payload.generated_at);
  
  // B2: Real-time event counter for the last 60 seconds
  const eventsLastMinute = events.filter((event) => {
    if (!event.timestamp) return false;
    const ts = parseEventTime(event.timestamp).getTime();
    return timelineReference.getTime() - ts <= 60000;
  }).length;

  const risk = buildRiskModel(events);
  const suspiciousOverview = buildSuspiciousOverview(events, timelineReference);
  const timelineRange = timelineRangeConfig(timelineRangeKey);
  const timeline = buildTimelineBuckets(events, timelineReference, timelineRangeKey);
  const timelineTotal = timeline.reduce((total, bucket) => total + bucket.suspiciousCount, 0);
  const timelineAnyEvents = timeline.some((bucket) => bucket.totalCount > 0);
  const timelinePeak = Math.max(
    0,
    ...timeline.map((bucket) => Math.max(bucket.suspiciousCount, bucket.totalCount))
  );
  const serviceEntries = Object.entries(stats.by_service || {})
    .filter((entry) => Number(entry[1]) > 0)
    .sort((left, right) => Number(right[1]) - Number(left[1]))
    .slice(0, 5);

  return h(
    React.Fragment,
    null,
    h(
      "header",
      { className: "topbar" },
      h(
        "div",
        null,
        h("h1", { style: { display: "flex", alignItems: "center", gap: "12px" } }, "Dashboard", 
          h("span", { className: "status-pill running animate-pulse" }, "Live"),
          h("span", { className: "status-counter", style: { fontSize: "14px", background: "rgba(255,255,255,0.05)", padding: "4px 8px", borderRadius: "12px", border: "1px solid rgba(255,255,255,0.1)" } }, `${eventsLastMinute} events/min`)
        ),
        h("p", { className: "page-subtitle" }, "Recent activity and event volume overview.")
      ),
      h(
        "div",
        { className: "topbar-actions" },
        h(
          "div",
          { className: "user-pill" },
          h("span", null, "Signed in as"),
          h("strong", null, props.session.username || "-")
        ),
        h(
          "button",
          {
            type: "button",
            className: "button secondary",
            onClick: () => loadOverview().catch((error) => window.showToast(error.message, "error")),
          },
          "Refresh"
        ),
        h(
          "button",
          { type: "button", className: "button", onClick: props.onLogout },
          "Log out"
        )
      )
    ),
    h(
      "section",
      { className: "metric-grid", "aria-label": "Dashboard metrics" },
      h(MetricCard, { label: "Suspicious Events", value: String(suspiciousEvents), note: "Events with a source IP address." }),
      h(MetricCard, { label: "Total Events", value: String(totalEvents), note: "All recent events in the overview." }),
      h(MetricCard, { label: "Running Services", value: String(runningServices), note: `${runningServices} of ${services.length} listeners online.` }),
      h(MetricCard, { label: "Active Profile", value: profile ? window.text(profile.display_name) : "-", note: "Currently applied persona." })
    ),
    h(
      "section",
      { className: "panel geo-map-panel" },
      h(
        "div",
        { className: "section-heading" },
        h("div", null, h("h2", null, "Attacker Origins"), h("p", null, "Geographic distribution of suspicious IPs (last 24h).")),
        h("span", { className: "status-counter" }, `${(payload.geo_markers || []).length} locations`)
      ),
      h(GeoWorldMap, { markers: payload.geo_markers || [] })
    ),

    h(
      "section",
      { className: "overview-section", "data-risk-tone": risk.band.tone },
      h(
        "div",
        { className: "section-heading" },
        h(
          "div",
          null,
          h("h2", null, "Activity Overview"),
          h("p", null, "Recent hot spots and event timeline.")
        )
      ),
      h(
        "div",
        { className: "risk-layout" },
        h(
          "div",
          { className: "risk-main" },
          h(
            "div",
            { className: "risk-summary-row", "aria-label": "Risk highlights" },
            h(
              "div",
              { className: "risk-summary-item tilt-effect" },
              h("span", null, "Peak Hour"),
              h(
                "strong",
                null,
                suspiciousOverview.topHour
                  ? summarizeRangeLabel(
                      suspiciousOverview.topHour.start,
                      new Date(suspiciousOverview.topHour.start.getTime() + (60 * 60 * 1000))
                    )
                  : "None"
              ),
              h("small", null, suspiciousOverview.topHour ? `${suspiciousOverview.topHour.count} suspicious events` : "No suspicious traffic in the last 24 hours")
            ),
            h(
              "div",
              { className: "risk-summary-item tilt-effect" },
              h("span", null, "Suspicious Events"),
              h("strong", null, String(suspiciousOverview.totalCount || 0)),
              h("small", null, "Total suspicious events in the last 24 hours")
            ),
            h(
              "div",
              { className: "risk-summary-item tilt-effect" },
              h("span", null, "Top Service"),
              h("strong", null, suspiciousOverview.topService ? window.text(suspiciousOverview.topService.name) : "-"),
              h("small", null, suspiciousOverview.topService ? `${suspiciousOverview.topService.count} suspicious events` : "No source-IP activity yet")
            ),
            h(
              "div",
              { className: "risk-summary-item tilt-effect" },
              h("span", null, "Most Suspicious IP"),
              h("strong", null,
                suspiciousOverview.topIp
                  ? [
                      suspiciousOverview.topIp.ip,
                      stats.top_ip_blocked
                        ? h("span", { key: "blocked-badge", style: { color: "#e31a1a", marginLeft: "6px" }, title: "Blocked" }, "⊘")
                        : null
                    ]
                  : "-"
              ),
              h("small", null, suspiciousOverview.topIp
                ? (stats.top_ip_mac && stats.top_ip_mac !== "unknown" && stats.top_ip_mac !== "N/A"
                  ? `MAC: ${stats.top_ip_mac} (${suspiciousOverview.topIp.count} requests)`
                  : `${suspiciousOverview.topIp.count} requests in the last 24 hours`)
                : "No source IP activity in the last 24 hours")
            )
          ),
          h(
            "div",
            { className: "overview-split" },
            h(
              "div",
              { className: "timeline-card" },
              h(
                "div",
                { className: "timeline-card-heading" },
                h(
                  "div",
                  null,
                  h("span", { className: "timeline-kicker" }, "Overview"),
                  h("h3", null, "Event Timeline")
                ),
                h(
                  "div",
                  { className: "timeline-pills", "aria-label": "Timeline range" },
                  TIMELINE_RANGES.map((range) =>
                    h(
                      "button",
                      {
                        key: range.key,
                        type: "button",
                        className: `timeline-pill${range.key === timelineRangeKey ? " active" : ""}`,
                        onClick: () => setTimelineRangeKey(range.key),
                      },
                      range.label
                  )
                ),
                  h("span", { className: "timeline-pill metric" }, `${timelineTotal} suspicious`)
                )
              ),
              timelineAnyEvents
                ? h(TimelineLineChart, { timeline, peak: timelinePeak, range: timelineRange })
                : h("div", { className: "timeline-empty" }, `No events in the selected ${timelineRange.label.toLowerCase()} range.`)
            ),
            h(
              "div",
              { className: "service-activity-card" },
              h(
                "div",
                { className: "section-heading compact" },
                h(
                  "div",
                  null,
                  h("h2", null, "Service Activity"),
                  h("p", null, "Event distribution by service.")
                ),
                h("span", { className: "status-counter" }, `${events.length} events`)
              ),
              h(
                "div",
                { className: "donut-layout compact" },
                h(ServiceActivityDonut, { entries: serviceEntries }),
                h(
                  "ul",
                  { className: "donut-legend compact" },
                  serviceEntries.length
                    ? serviceEntries.map(([service, count], index) =>
                        h(
                          "li",
                          { key: service },
                          h("span", { className: "donut-legend-label" },
                            h("i", {
                              style: { background: DONUT_COLORS[index % DONUT_COLORS.length] },
                            }),
                            h("span", { className: "donut-legend-text" }, service)
                          ),
                          h("strong", null, String(count))
                        )
                      )
                    : h("li", null, h("span", null, "No service activity yet."), h("strong", null, "0"))
                )
              )
            )
          )
        )
      )
    ),
    h(
      "section",
      { className: "panel timeline-panel" },
      h(
        "div",
        { className: "section-heading" },
        h(
          "div",
          null,
          h("h2", null, "Activity Heat"),
          h("p", null, "Last 24 hours in four-hour slices.")
        ),
        h("span", { className: "status-counter" }, `${Math.round(risk.weightedTotal)} signals`)
      ),
      h(ActivityHeatGrid, { model: risk })
    ),
    h(
      "section",
      { className: "panel" },
      h(
        "div",
        { className: "section-heading" },
        h(
          "div",
          null,
          h("h2", null, "Recent Suspicious Events"),
          h("p", null, "Latest 10 captured events containing attacker IPs.")
        ),
        h(
          "a",
          { className: "text-link", href: "/logs", onClick: props.navigateClick("/logs") },
          "Open logs"
        )
      ),
      h(EventsTable, { events: events.filter(e => e && e.src_ip).slice(0, 10), fallbackProfile: profile ? profile.name : "-", onSelect: (e) => setSelectedEvent(e) })
    ),
    h(EventDrawer, { event: selectedEvent, onClose: () => setSelectedEvent(null) })
  );
}

export function ActivityHeatGrid(props) {
  const model = props.model;
  const services = model.topServices.length ? model.topServices : ["web", "orchestrator"];
  const peak = Math.max(
    1,
    ...model.buckets.flatMap((bucket) => services.map((service) => Number(bucket.counts[service] || 0)))
  );
  const children = [
    h("div", { key: "corner", className: "heat-corner" }, "Service"),
  ];
  model.buckets.forEach((bucket, index) => {
    children.push(
      h(
        "div",
        { key: `time-${index}`, className: "heat-time-label" },
        bucket.start.toLocaleTimeString([], { hour: "2-digit" })
      )
    );
  });
  services.forEach((service) => {
    children.push(h("div", { key: `label-${service}`, className: "heat-service-label" }, service));
    model.buckets.forEach((bucket, index) => {
      const value = Number(bucket.counts[service] || 0);
      const intensity = Math.min(1, value / peak);
      const level = value <= 0.05 ? "quiet" : intensity >= 0.78 ? "hot" : intensity >= 0.4 ? "warm" : "cool";
      children.push(
        h("div", {
          key: `${service}-${index}`,
          className: "heat-cell",
          "data-level": level,
          title: `${service} | ${summarizeRangeLabel(bucket.start, bucket.end)} | ${value.toFixed(1)} weighted`,
          style: { "--heat-intensity": intensity.toFixed(3) },
        })
      );
    });
  });
  return h("div", { className: "activity-heat-grid", style: { "--heat-columns": String(model.buckets.length) } }, children);
}

export function ServiceActivityDonut(props) {
  const entries = Array.isArray(props.entries) ? props.entries : [];
  const [activeIndex, setActiveIndex] = useState(null);
  const total = entries.reduce((sum, [, count]) => sum + (Number(count) || 0), 0);
  const radius = 74;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  const activeEntry = activeIndex === null ? null : entries[activeIndex] || null;
  const activeCount = activeEntry ? Number(activeEntry[1]) || 0 : 0;
  const activePercent = total > 0 && activeEntry ? Math.round((activeCount / total) * 100) : 0;

  const truncatedService = activeEntry && activeEntry[0].length > 10
    ? activeEntry[0].substring(0, 8) + "..."
    : (activeEntry ? activeEntry[0] : "");

  // 4px gap between segments if multiple segments exist
  const gap = total > 0 && entries.length > 1 ? 4 : 0;

  return h(
    "div",
    { className: "donut-chart", onMouseLeave: () => setActiveIndex(null) },
    h(
      "svg",
      { className: "donut-svg", viewBox: "0 0 220 220", role: "img", "aria-label": "Service activity donut chart" },
      h("circle", { className: "donut-track", cx: "110", cy: "110", r: String(radius) }),
      total
        ? entries.map(([service, count], index) => {
            const value = Number(count) || 0;
            const segmentLength = (value / total) * circumference;
            const dashOffset = -offset;
            offset += segmentLength;

            // Subtract the gap to separate segments visually
            const drawLength = Math.max(0.1, segmentLength - gap);

            return h("circle", {
              key: service,
              className: `donut-segment${index === activeIndex ? " active" : ""}`,
              cx: "110",
              cy: "110",
              r: String(radius),
              stroke: DONUT_COLORS[index % DONUT_COLORS.length],
              strokeDasharray: `${drawLength} ${Math.max(0, circumference - drawLength)}`,
              strokeDashoffset: String(dashOffset),
              transform: "rotate(-90 110 110)",
              onMouseEnter: () => setActiveIndex(index),
              onFocus: () => setActiveIndex(index),
              onBlur: () => setActiveIndex(null),
              tabIndex: "0",
            });
          })
        : h("circle", { className: "donut-empty", cx: "110", cy: "110", r: String(radius) }),
      h("text", { className: "donut-center-label", x: "110", y: "104", textAnchor: "middle" }, String(activeEntry ? activeCount : total)),
      h("text", { className: "donut-center-sub", x: "110", y: "128", textAnchor: "middle" }, activeEntry ? `${activePercent}% ${truncatedService}` : "events")
    ),
    activeEntry
      ? h(
          "div",
          { className: "donut-tooltip" },
          h("strong", null, activeEntry[0]),
          h("span", null, `${activeCount} events • ${activePercent}%`)
        )
      : null
  );
}

export function TimelineLineChart(props) {
  const timeline = props.timeline || [];
  const range = props.range || TIMELINE_RANGES[0];
  const [hoverIndex, setHoverIndex] = useState(null);
  const peak = Math.max(1, props.peak || 0);
  const suspiciousPoints = buildTimelinePoints(timeline, peak, "suspiciousCount");
  const totalPoints = buildTimelinePoints(timeline, peak, "totalCount");
  const suspiciousPath = smoothLinePath(suspiciousPoints);
  const totalPath = smoothLinePath(totalPoints);
  const areaPath = buildTimelineAreaPath(suspiciousPoints);
  const activeIndex = hoverIndex === null ? null : Math.max(0, Math.min(suspiciousPoints.length - 1, hoverIndex));
  const activePoint = activeIndex === null ? null : suspiciousPoints[activeIndex];
  const activeTotalPoint = activeIndex === null ? null : totalPoints[activeIndex];
  const tooltipBelow = Boolean(activePoint && Math.min(activePoint.y, activeTotalPoint ? activeTotalPoint.y : activePoint.y) < 52);
  const gridLines = [0, 0.25, 0.5, 0.75, 1].map((ratio, index) => {
    const y = Math.round(20 + ratio * 136);
    const label = Math.round(peak * (1 - ratio));
    return [
      h("line", {
        key: `grid-${index}`,
        className: "timeline-grid-line",
        x1: "42",
        y1: String(y),
        x2: "618",
        y2: String(y),
      }),
      h(
        "text",
        {
          key: `y-label-${index}`,
          className: "timeline-y-label",
          x: "28",
          y: String(y + 4),
          textAnchor: "end",
        },
        String(label)
      ),
    ];
  });
  return h(
    "div",
    { className: "timeline-chart", onMouseLeave: () => setHoverIndex(null) },
    h(
      "svg",
      { className: "timeline-svg", viewBox: "0 0 640 190", role: "img", "aria-label": "Event timeline line chart" },
      h(
        "defs",
        null,
        h(
          "linearGradient",
          { id: "timelineAreaGradient", x1: "0", y1: "0", x2: "0", y2: "1" },
          h("stop", { offset: "0%", stopColor: "var(--timeline-area-start)" }),
          h("stop", { offset: "100%", stopColor: "var(--timeline-area-end)" })
        )
      ),
      gridLines,
      h("path", { className: "timeline-area", d: areaPath }),
      h("path", { className: "timeline-total-line", d: totalPath }),
      h("path", { className: "timeline-line", d: suspiciousPath }),
      activePoint
        ? h("line", {
            className: "timeline-hover-line",
            x1: String(activePoint.x),
            y1: "20",
            x2: String(activePoint.x),
            y2: "156",
          })
        : null,
      totalPoints.map((point, index) =>
        h("circle", {
          key: `total-point-${index}`,
          className: `timeline-point total${index === activeIndex ? " active" : ""}`,
          cx: String(point.x),
          cy: String(point.y),
          r: index === activeIndex ? "3.8" : point.bucket.totalCount ? "2.1" : "0",
        })
      ),
      suspiciousPoints.map((point, index) =>
        h("circle", {
          key: `point-${index}`,
          className: `timeline-point${index === activeIndex ? " active" : ""}`,
          cx: String(point.x),
          cy: String(point.y),
          r: index === activeIndex ? "4.2" : point.bucket.suspiciousCount ? "2.4" : "0",
        })
      ),
      suspiciousPoints.map((point, index) => {
        const labelStep = range.key === "month" ? 5 : range.key === "week" ? 1 : 2;
        return index % labelStep === 0
          ? h(
              "text",
              {
                key: `label-${index}`,
                className: "timeline-label",
                x: String(point.x),
                y: "180",
                textAnchor: "middle",
              },
              formatTimelineBucketLabel(point.bucket, range)
            )
          : null;
      }),
      suspiciousPoints.map((point, index) =>
        {
          const hitBox = timelineHitBox(suspiciousPoints, index);
          return h("rect", {
            key: `hit-${index}`,
            className: "timeline-hit-zone",
            x: String(hitBox.x),
            y: "20",
            width: String(hitBox.width),
            height: "136",
            onMouseEnter: () => setHoverIndex(index),
            onMouseMove: () => setHoverIndex(index),
            onFocus: () => setHoverIndex(index),
            onBlur: () => setHoverIndex(null),
            tabIndex: "0",
          });
        }
      )
    ),
    activePoint
      ? h(
          "div",
          {
            className: `timeline-tooltip${tooltipBelow ? " below" : ""}`,
            style: {
              left: `${Math.max(8, Math.min(82, (activePoint.x / 640) * 100))}%`,
              top: `${tooltipBelow ? Math.min(150, activePoint.y + 14) : Math.max(18, activePoint.y - 8)}px`,
            },
          },
          h("strong", null, formatTimelineBucketLabel(activePoint.bucket, range)),
          h("span", null, `Events: ${activePoint.bucket.totalCount} | Suspicious Events: ${activePoint.bucket.suspiciousCount}`)
        )
      : null
  );
}

export function EventsTable(props) {
  const events = props.events || [];
  return h(
    "div",
    { className: "table-shell" },
    h(
      "table",
      null,
      h(
        "thead",
        null,
        h(
          "tr",
          null,
          h("th", null, "Time"),
          h("th", null, "Service"),
          h("th", null, "Type"),
          h("th", null, "Source"),
          h("th", null, "Profile"),
          h("th", null, "Summary")
        )
      ),
      h(
        "tbody",
        null,
        events.length
          ? events.map((event, index) =>
              h(
                "tr",
                {
                  key: `${event.timestamp || "event"}-${index}`,
                  onClick: props.onSelect ? () => props.onSelect(event) : undefined,
                  className: "animate-slide-in",
                },
                h("td", null, window.text(window.formatTimestamp(event.timestamp))),
                h("td", null, window.text(event.service)),
                h("td", null, h("span", { className: "table-chip" }, window.text(event.event_type))),
                h("td", null, window.text(window.formatEventSource(event))),
                h("td", null, window.text(event.profile || props.fallbackProfile)),
                h("td", null, window.summarizeEvent(event))
              )
            )
          : h("tr", null, h("td", { colSpan: 6, className: "empty-row" }, "No events found."))
      )
    )
  );
}
