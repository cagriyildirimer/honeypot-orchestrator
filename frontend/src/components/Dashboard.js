const h = React.createElement;
const { useEffect, useState, useRef, useMemo } = React;
import { target, rect, x, y, midX, midY, rotateX, rotateY, target, NAV_ITEMS, SETTINGS_ITEMS, STANDARD_PORTS, DONUT_COLORS, RISK_EVENT_WEIGHTS, RISK_IGNORED_EVENT_TYPES, ROLE_LABELS, TIMELINE_RANGES, APPEARANCE_THEMES, pathToPage, isSettingsPage, parseEventTime, normalized, date, classifyRisk, getRiskWeight, eventType, isRiskRelevantEvent, eventType, service, summarizeRangeLabel, buildSuspiciousOverview, now, windowMs, start, hourTotals, serviceTotals, ipTotals, date, time, hourStart, hourKey, service, ip, topHour, topService, topIp, buildRiskModel, now, windowMs, start, bucketCount, bucketSizeMs, buckets, serviceTotals, typeTotals, date, time, service, eventType, weight, recencyBoost, weightedValue, bucketIndex, bucket, sortedServices, topServices, strongestBucket, burstScore, diversityScore, concentrationScore, baseScore, score, band, hottestService, timelineRangeConfig, formatTimelineBucketLabel, alignTimelineWindowStart, base, bucketMs, bucketHours, aligned, aligned, buildTimelineBuckets, range, bucketCount, windowMs, bucketMs, now, start, buckets, date, time, index, smoothLinePath, slopes, path, current, next, dx, minY, maxY, controlOneY, controlTwoY, controlOne, controlTwo, buildTimelinePoints, width, height, padding, plotWidth, plotHeight, divisor, maxValue, buildTimelineAreaPath, baseline, timelineHitBox, start, end, formatBytes, value, standardPortNote, baseName, standardPort, servicePortTone, baseName, standardPort, filterLogEvents, search, copyText, textarea, copied, usePolling, run, timer } from '../utils.js';
import { Skeleton, PageSkeleton, NavLink, AnimatedCounter, MetricCard, AppLayout, EventDrawer, GeoWorldMap } from './Core.js';
import { LiveActivityPage } from './Live.js';
import { SettingsAppearance, SettingsWhitelist, SettingsBlocklist, SettingsUsers, SettingsSystem, SettingsRouter } from './Settings.js';
import { ProfilesPage } from './Profiles.js';
import { LogsPage } from './Logs.js';
import { AppRouter } from './AppRouter.js';

export function DashboardPage(props) {
    const [payload, setPayload] = useState(null);
    const [loading, setLoading] = useState(true);
    const [timelineRangeKey, setTimelineRangeKey] = useState("day");
    const [selectedEvent, setSelectedEvent] = useState(null);
    const [tiData, setTiData] = useState(null);

    async function loadOverview() {
      const next = await window.requestJson("/api/overview?limit=2000");
      setPayload(next);
      setLoading(false);
    }

    async function loadThreatIntel() {
      try {
        const data = await window.requestJson("/api/threat-intel");
        setTiData(data);
      } catch (e) {
        // silently ignore TI errors
      }
    }

    usePolling(loadOverview, 5000, []);
    usePolling(loadThreatIntel, 30000, []);

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
      h(ThreatIntelPanel, { data: tiData }),
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
                h("span", null, "Suspicios Events"),
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
            h("h2", null, "Recent Events"),
            h("p", null, "Latest 10 captured records.")
          ),
          h(
            "a",
            { className: "text-link", href: "/logs", onClick: props.navigateClick("/logs") },
            "Open logs"
          )
        ),
        h(EventsTable, { events: events.slice(0, 10), fallbackProfile: profile ? profile.name : "-", onSelect: (e) => setSelectedEvent(e) })
      ),
      h(EventDrawer, { event: selectedEvent, onClose: () => setSelectedEvent(null) })
    );
  }


