(function () {
  const h = React.createElement;
  const { useEffect, useState } = React;

  const NAV_ITEMS = [
    { key: "dashboard", label: "Dashboard", path: "/dashboard" },
    { key: "profiles", label: "Profiles", path: "/profiles" },
    { key: "logs", label: "Logs", path: "/logs" },
  ];
  const SETTINGS_ITEMS = [
    { key: "appearance", label: "Appearance", path: "/settings/appearance" },
    { key: "system", label: "System", path: "/settings/system" },
    { key: "users", label: "Users", path: "/settings/users" },
  ];
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
  const DONUT_COLORS = ["#0075ff", "#21d4fd", "#4318ff", "#01b574", "#ffb547", "#e31a1a", "#a0aec0"];
  const RISK_EVENT_WEIGHTS = {
    login_failed: 8,
    login_attempt: 12,
    auth_failed: 12,
    credential_attempt: 14,
    connection: 5,
    connection_opened: 5,
    bind_attempt: 12,
    request: 4,
    request_error: 0,
    service_stopped: 0,
    service_started: 0,
    profile_changed: 0,
    started: 0,
    stopping: 0,
    login_success: 0,
  };
  const RISK_IGNORED_EVENT_TYPES = new Set([
    "service_started",
    "service_stopped",
    "started",
    "stopping",
    "profile_changed",
    "client_disconnected",
    "login_success",
    "request_error",
    "user_created",
    "user_deleted",
    "user_password_changed",
    "user_role_changed",
  ]);
  const ROLE_LABELS = {
    admin: "Full access",
    viewer: "Log viewer",
  };
  const TIMELINE_RANGES = [
    { key: "day", label: "Daily", shortLabel: "24h", bucketCount: 12, windowMs: 24 * 60 * 60 * 1000, labelMode: "hour" },
    { key: "week", label: "Weekly", shortLabel: "7d", bucketCount: 7, windowMs: 7 * 24 * 60 * 60 * 1000, labelMode: "weekday" },
    { key: "month", label: "Monthly", shortLabel: "30d", bucketCount: 30, windowMs: 30 * 24 * 60 * 60 * 1000, labelMode: "date" },
  ];

  function pathToPage(pathname) {
    if (pathname === "/dashboard" || pathname === "/") {
      return "dashboard";
    }
    if (pathname === "/profiles") {
      return "profiles";
    }
    if (pathname === "/logs") {
      return "logs";
    }
    if (pathname === "/settings/appearance") {
      return "appearance";
    }
    if (pathname === "/settings/system") {
      return "system";
    }
    if (pathname === "/settings/users") {
      return "users";
    }
    return "dashboard";
  }

  function isSettingsPage(page) {
    return SETTINGS_ITEMS.some((item) => item.key === page);
  }

  function parseEventTime(value) {
    if (!value) {
      return null;
    }
    const normalized = String(value).replace(" UTC", "Z").replace(" ", "T");
    const date = new Date(normalized);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function classifyRisk(score) {
    if (score >= 85) {
      return { label: "Critical", headline: "Live hostile pressure", tone: "critical" };
    }
    if (score >= 65) {
      return { label: "High", headline: "Aggressive probing wave", tone: "high" };
    }
    if (score >= 42) {
      return { label: "Elevated", headline: "Sustained suspicious activity", tone: "elevated" };
    }
    if (score >= 20) {
      return { label: "Guarded", headline: "Watchlist activity rising", tone: "guarded" };
    }
    return { label: "Low", headline: "Quiet perimeter", tone: "low" };
  }

  function getRiskWeight(event) {
    const eventType = String(event && event.event_type ? event.event_type : "").toLowerCase();
    if (Object.prototype.hasOwnProperty.call(RISK_EVENT_WEIGHTS, eventType)) {
      return RISK_EVENT_WEIGHTS[eventType];
    }
    return eventType.includes("login") || eventType.includes("bind") ? 12 : 4;
  }

  function isRiskRelevantEvent(event) {
    if (!event) {
      return false;
    }
    const eventType = String(event.event_type || "").toLowerCase();
    if (RISK_IGNORED_EVENT_TYPES.has(eventType)) {
      return false;
    }
    const service = String(event.service || "").toLowerCase();
    if (service === "web" || service === "orchestrator") {
      return false;
    }
    return Boolean(event.src_ip);
  }

  function summarizeRangeLabel(start, end) {
    return `${start.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} - ${end.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  }

  function buildRiskModel(events) {
    const now = Date.now();
    const windowMs = 24 * 60 * 60 * 1000;
    const start = now - windowMs;
    const bucketCount = 6;
    const bucketSizeMs = windowMs / bucketCount;
    const buckets = Array.from({ length: bucketCount }, (_, index) => ({
      start: new Date(start + index * bucketSizeMs),
      end: new Date(start + (index + 1) * bucketSizeMs),
      total: 0,
      counts: {},
    }));
    const serviceTotals = {};
    const typeTotals = {};
    let weightedTotal = 0;

    for (const event of events || []) {
      if (!isRiskRelevantEvent(event)) {
        continue;
      }
      const date = parseEventTime(event.timestamp);
      if (!date) {
        continue;
      }
      const time = date.getTime();
      if (time < start || time > now) {
        continue;
      }
      const service = String(event.service || "unknown").toLowerCase();
      const eventType = String(event.event_type || "unknown").toLowerCase();
      const weight = getRiskWeight(event);
      const recencyBoost = 1 + ((time - start) / windowMs) * 0.35;
      const weightedValue = weight * recencyBoost;
      const bucketIndex = Math.min(buckets.length - 1, Math.floor((time - start) / bucketSizeMs));
      const bucket = buckets[bucketIndex];
      bucket.total += weightedValue;
      bucket.counts[service] = (bucket.counts[service] || 0) + weightedValue;
      serviceTotals[service] = (serviceTotals[service] || 0) + weightedValue;
      typeTotals[eventType] = (typeTotals[eventType] || 0) + weight;
      weightedTotal += weightedValue;
    }

    const sortedServices = Object.entries(serviceTotals).sort((left, right) => right[1] - left[1]);
    const topServices = sortedServices.slice(0, 3).map(([service]) => service);
    const strongestBucket = buckets.reduce(
      (best, bucket) => (bucket.total > best.total ? bucket : best),
      buckets[0] || { total: 0, start: new Date(now), end: new Date(now), counts: {} }
    );
    const burstScore = strongestBucket.total;
    const diversityScore = Math.min(18, Object.keys(typeTotals).length * 3);
    const concentrationScore = Math.min(20, burstScore * 1.7);
    const baseScore = Math.min(100, weightedTotal * 1.12 + diversityScore + concentrationScore);
    const score = Math.round(baseScore);
    const band = classifyRisk(score);
    const hottestService = sortedServices[0] || ["-", 0];

    return {
      score,
      band,
      weightedTotal,
      burstScore,
      hottestService: { name: hottestService[0], value: hottestService[1] },
      activeTypeCount: Object.keys(typeTotals).length,
      strongestBucket,
      topServices,
      buckets,
      summary:
        score >= 65
          ? `Traffic clustered around ${window.text(hottestService[0])} during the busiest window.`
          : score >= 20
            ? `Recent pressure is centered on ${window.text(hottestService[0])}.`
            : "No meaningful burst pattern in the recent event window.",
    };
  }

  function timelineRangeConfig(rangeKey) {
    return TIMELINE_RANGES.find((range) => range.key === rangeKey) || TIMELINE_RANGES[0];
  }

  function formatTimelineBucketLabel(bucket, range) {
    if (range.labelMode === "weekday") {
      return bucket.start.toLocaleDateString([], { weekday: "short" });
    }
    if (range.labelMode === "date") {
      return bucket.start.toLocaleDateString([], { month: "short", day: "numeric" });
    }
    return bucket.start.toLocaleTimeString([], { hour: "2-digit" });
  }

  function buildTimelineBuckets(events, referenceDate, rangeKey) {
    const range = timelineRangeConfig(rangeKey);
    const bucketCount = range.bucketCount;
    const windowMs = range.windowMs;
    const bucketMs = windowMs / bucketCount;
    const now = referenceDate instanceof Date && !Number.isNaN(referenceDate.getTime())
      ? referenceDate.getTime()
      : Date.now();
    const start = now - windowMs;
    const buckets = Array.from({ length: bucketCount }, (_, index) => ({
      count: 0,
      start: new Date(start + index * bucketMs),
      end: new Date(start + (index + 1) * bucketMs),
    }));
    for (const event of events || []) {
      if (!event || !event.src_ip) {
        continue;
      }
      const date = parseEventTime(event.timestamp);
      if (!date) {
        continue;
      }
      const time = date.getTime();
      if (time < start || time > now) {
        continue;
      }
      const index = Math.min(bucketCount - 1, Math.floor((time - start) / bucketMs));
      buckets[index].count += 1;
    }
    return buckets;
  }

  function smoothLinePath(points) {
    if (!points.length) {
      return "";
    }
    if (points.length === 1) {
      return `M ${points[0].x} ${points[0].y}`;
    }
    const slopes = points.map((point, index) => {
      if (index === 0) {
        return (points[1].y - point.y) / Math.max(1, points[1].x - point.x);
      }
      if (index === points.length - 1) {
        return (point.y - points[index - 1].y) / Math.max(1, point.x - points[index - 1].x);
      }
      return (points[index + 1].y - points[index - 1].y) / Math.max(1, points[index + 1].x - points[index - 1].x);
    });
    const path = [`M ${points[0].x} ${points[0].y}`];
    for (let index = 0; index < points.length - 1; index += 1) {
      const current = points[index];
      const next = points[index + 1];
      const dx = next.x - current.x;
      const minY = Math.min(current.y, next.y);
      const maxY = Math.max(current.y, next.y);
      const controlOneY = current.y + (slopes[index] * dx) / 3;
      const controlTwoY = next.y - (slopes[index + 1] * dx) / 3;
      const controlOne = { x: current.x + dx / 3, y: Math.min(maxY, Math.max(minY, controlOneY)) };
      const controlTwo = { x: next.x - dx / 3, y: Math.min(maxY, Math.max(minY, controlTwoY)) };
      path.push(`C ${controlOne.x.toFixed(1)} ${controlOne.y.toFixed(1)}, ${controlTwo.x.toFixed(1)} ${controlTwo.y.toFixed(1)}, ${next.x} ${next.y}`);
    }
    return path.join(" ");
  }

  function buildTimelinePoints(timeline, peak) {
    const width = 640;
    const height = 230;
    const padding = { top: 24, right: 22, bottom: 42, left: 42 };
    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;
    const divisor = Math.max(1, timeline.length - 1);
    const maxValue = Math.max(1, peak);
    return timeline.map((bucket, index) => ({
      bucket,
      x: Math.round(padding.left + (index / divisor) * plotWidth),
      y: Math.round(padding.top + plotHeight - (bucket.count / maxValue) * plotHeight),
    }));
  }

  function buildTimelineAreaPath(points) {
    if (!points.length) {
      return "";
    }
    const baseline = 188;
    return `${smoothLinePath(points)} L ${points[points.length - 1].x} ${baseline} L ${points[0].x} ${baseline} Z`;
  }

  function timelineHitBox(points, index) {
    const start = index === 0 ? 42 : (points[index - 1].x + points[index].x) / 2;
    const end = index === points.length - 1 ? 618 : (points[index].x + points[index + 1].x) / 2;
    return { x: start, width: Math.max(1, end - start) };
  }

  function formatBytes(bytes) {
    const value = Number(bytes) || 0;
    if (value < 1024) {
      return `${value} B`;
    }
    if (value < 1024 * 1024) {
      return `${(value / 1024).toFixed(1)} KB`;
    }
    return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  }

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

  function filterLogEvents(events, filters) {
    const search = String(filters.search || "").trim().toLowerCase();
    return (events || []).filter((event) => {
      if (filters.service && event.service !== filters.service) {
        return false;
      }
      if (filters.eventType && event.event_type !== filters.eventType) {
        return false;
      }
      if (!search) {
        return true;
      }
      return JSON.stringify(event).toLowerCase().includes(search);
    });
  }

  function copyText(content) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(content);
    }
    return new Promise((resolve, reject) => {
      const textarea = document.createElement("textarea");
      textarea.value = content;
      textarea.setAttribute("readonly", "");
      textarea.style.position = "fixed";
      textarea.style.left = "-9999px";
      document.body.appendChild(textarea);
      textarea.select();
      const copied = document.execCommand("copy");
      textarea.remove();
      if (copied) {
        resolve();
      } else {
        reject(new Error("Could not copy text."));
      }
    });
  }

  function usePolling(callback, delay, deps) {
    useEffect(() => {
      let active = true;
      function run() {
        return Promise.resolve(callback()).catch(() => null);
      }
      run();
      const timer = setInterval(() => {
        if (active) {
          run();
        }
      }, delay);
      return () => {
        active = false;
        clearInterval(timer);
      };
    }, deps);
  }

  function NavLink(props) {
    return h(
      "a",
      {
        className: `nav-link${props.active ? " active" : ""}`,
        href: props.href,
        onClick: props.onClick,
      },
      props.label
    );
  }

  function MetricCard(props) {
    return h(
      "article",
      { className: "metric-card" },
      h("span", null, props.label),
      h("strong", null, props.value),
      h("small", null, props.note)
    );
  }

  function AppLayout(props) {
    const [settingsOpen, setSettingsOpen] = useState(isSettingsPage(props.page));

    useEffect(() => {
      if (isSettingsPage(props.page)) {
        setSettingsOpen(true);
      }
    }, [props.page]);

    return h(
      "div",
      { className: "app-frame" },
      h(
        "aside",
        { className: "sidebar" },
        h(
          "a",
          {
            className: "brand",
            href: "/dashboard",
            onClick: props.navigateClick("/dashboard"),
            "aria-label": "Honeypot Director dashboard",
          },
          h("span", { className: "brand-mark" }, "HD"),
          h("span", { className: "brand-text" }, "Honeypot Director")
        ),
        h(
          "nav",
          { className: "nav-stack", "aria-label": "Primary navigation" },
          NAV_ITEMS.map((item) =>
            h(NavLink, {
              key: item.key,
              href: item.path,
              label: item.label,
              active: props.page === item.key,
              onClick: props.navigateClick(item.path),
            })
          ),
          h(
            "div",
            { className: "nav-group" },
            h(
              "button",
              {
                type: "button",
                className: `nav-link nav-category-button${isSettingsPage(props.page) ? " active" : ""}`,
                onClick: () => setSettingsOpen(!settingsOpen),
                "aria-expanded": settingsOpen ? "true" : "false",
              },
              h("span", null, "Settings"),
              h("span", { className: "nav-caret", "aria-hidden": "true" })
            ),
            settingsOpen
              ? h(
                  "div",
                  { className: "nav-submenu" },
                  SETTINGS_ITEMS.map((item) =>
                    h(NavLink, {
                      key: item.key,
                      href: item.path,
                      label: item.label,
                      active: props.page === item.key,
                      onClick: props.navigateClick(item.path),
                    })
                  )
                )
              : null
          )
        )
      ),
      h(
        "main",
        { className: "main-content" },
        props.children,
        h("div", { id: "toast", className: "toast", hidden: true })
      )
    );
  }

  function DashboardPage(props) {
    const [payload, setPayload] = useState(null);
    const [loading, setLoading] = useState(true);
    const [timelineRangeKey, setTimelineRangeKey] = useState("day");

    async function loadOverview() {
      const next = await window.requestJson("/api/overview?limit=2000");
      setPayload(next);
      setLoading(false);
    }

    usePolling(loadOverview, 5000, []);

    if (loading && !payload) {
      return h("div", { className: "panel" }, "Loading dashboard...");
    }

    const stats = payload && payload.stats ? payload.stats : {};
    const services = payload && payload.services ? payload.services : [];
    const events = payload && payload.events ? payload.events : [];
    const profile = payload && payload.profile && payload.profile.current ? payload.profile.current : null;
    const runningServices = services.filter((service) => service.running).length;
    const loginAttempts = Number((stats.by_type && stats.by_type.login_attempt) || 0);
    const risk = buildRiskModel(events);
    const timelineReference = parseEventTime(payload && payload.generated_at);
    const timelineRange = timelineRangeConfig(timelineRangeKey);
    const timeline = buildTimelineBuckets(events, timelineReference, timelineRangeKey);
    const timelineTotal = timeline.reduce((total, bucket) => total + bucket.count, 0);
    const timelinePeak = Math.max(0, ...timeline.map((bucket) => bucket.count));
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
          h("h1", null, "Dashboard"),
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
        h(MetricCard, { label: "Running Services", value: String(runningServices), note: `${runningServices} of ${services.length} listeners online.` }),
        h(MetricCard, { label: "Recent Events", value: String(stats.total_recent_events || 0), note: "Loaded recent log records." }),
        h(MetricCard, { label: "Login Attempts", value: String(loginAttempts), note: "Credential-oriented events." }),
        h(MetricCard, { label: "Profile", value: profile ? window.text(profile.display_name) : "-", note: "Currently applied persona." })
      ),
      h(
        "section",
        { className: "panel risk-panel", "data-risk-tone": risk.band.tone },
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
                { className: "risk-summary-item" },
                h("span", null, "Peak Window"),
                h("strong", null, risk.burstScore > 0 ? summarizeRangeLabel(risk.strongestBucket.start, risk.strongestBucket.end) : "None"),
                h("small", null, `${Math.round(risk.burstScore)} weighted events`)
              ),
              h(
                "div",
                { className: "risk-summary-item" },
                h("span", null, "Top Service"),
                h("strong", null, window.text(risk.hottestService.name)),
                h("small", null, `${Math.round(risk.hottestService.value)} weighted events`)
              ),
              h(
                "div",
                { className: "risk-summary-item" },
                h("span", null, "Event Mix"),
                h("strong", null, String(risk.activeTypeCount)),
                h("small", null, risk.activeTypeCount ? "Distinct event types seen" : "No suspicious event mix")
              )
            ),
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
                  h("span", { className: "timeline-pill metric" }, `${timelineTotal} events`)
                )
              ),
              timelineTotal
                ? h(TimelineLineChart, { timeline, peak: timelinePeak, range: timelineRange })
                : h("div", { className: "timeline-empty" }, `No events in the selected ${timelineRange.label.toLowerCase()} range.`)
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
        { className: "panel donut-panel" },
        h(
          "div",
          { className: "section-heading" },
          h(
            "div",
            null,
            h("h2", null, "Service Activity"),
            h("p", null, "Event distribution by service.")
          ),
          h("span", { className: "status-counter" }, `${events.length} events`)
        ),
        h(
          "ul",
          { className: "summary-list" },
          serviceEntries.length
            ? serviceEntries.map(([service, count], index) =>
                h(
                  "li",
                  { key: service },
                  h("span", null,
                    h("i", {
                      className: "summary-dot",
                      style: { background: DONUT_COLORS[index % DONUT_COLORS.length] },
                    }),
                    service
                  ),
                  h("strong", null, String(count))
                )
              )
            : h("li", null, h("span", null, "No service activity yet."), h("strong", null, "0"))
        )
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
        h(EventsTable, { events: events.slice(0, 10), fallbackProfile: profile ? profile.name : "-", onSelect: null })
      )
    );
  }

  function ActivityHeatGrid(props) {
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

  function TimelineLineChart(props) {
    const timeline = props.timeline || [];
    const range = props.range || TIMELINE_RANGES[0];
    const [hoverIndex, setHoverIndex] = useState(null);
    const peak = Math.max(1, props.peak || 0);
    const points = buildTimelinePoints(timeline, peak);
    const path = smoothLinePath(points);
    const areaPath = buildTimelineAreaPath(points);
    const activeIndex = hoverIndex === null ? null : Math.max(0, Math.min(points.length - 1, hoverIndex));
    const activePoint = activeIndex === null ? null : points[activeIndex];
    const gridLines = [0, 0.25, 0.5, 0.75, 1].map((ratio, index) => {
      const y = Math.round(24 + ratio * 164);
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
        { className: "timeline-svg", viewBox: "0 0 640 230", role: "img", "aria-label": "Event timeline line chart" },
        h(
          "defs",
          null,
          h(
            "linearGradient",
            { id: "timelineAreaGradient", x1: "0", y1: "0", x2: "0", y2: "1" },
            h("stop", { offset: "0%", stopColor: "rgba(33, 212, 253, 0.34)" }),
            h("stop", { offset: "100%", stopColor: "rgba(0, 117, 255, 0)" })
          )
        ),
        gridLines,
        h("path", { className: "timeline-area", d: areaPath }),
        h("path", { className: "timeline-line", d: path }),
        activePoint
          ? h("line", {
              className: "timeline-hover-line",
              x1: String(activePoint.x),
              y1: "24",
              x2: String(activePoint.x),
              y2: "188",
            })
          : null,
        points.map((point, index) =>
          h("circle", {
            key: `point-${index}`,
            className: `timeline-point${index === activeIndex ? " active" : ""}`,
            cx: String(point.x),
            cy: String(point.y),
            r: index === activeIndex ? "4.2" : point.bucket.count ? "2.4" : "0",
          })
        ),
        points.map((point, index) => {
          const labelStep = range.key === "month" ? 5 : range.key === "week" ? 1 : 2;
          return index % labelStep === 0
            ? h(
                "text",
                {
                  key: `label-${index}`,
                  className: "timeline-label",
                  x: String(point.x),
                  y: "216",
                  textAnchor: "middle",
                },
                formatTimelineBucketLabel(point.bucket, range)
              )
            : null;
        }),
        points.map((point, index) =>
          {
            const hitBox = timelineHitBox(points, index);
            return h("rect", {
              key: `hit-${index}`,
              className: "timeline-hit-zone",
              x: String(hitBox.x),
              y: "24",
              width: String(hitBox.width),
              height: "164",
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
              className: "timeline-tooltip",
              style: {
                left: `${Math.max(8, Math.min(82, (activePoint.x / 640) * 100))}%`,
                top: `${Math.max(18, activePoint.y - 8)}px`,
              },
            },
            h("strong", null, `${activePoint.bucket.count} events`),
            h("span", null, `${formatTimelineBucketLabel(activePoint.bucket, range)} ${range.label.toLowerCase()}`)
          )
        : null
    );
  }

  function EventsTable(props) {
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

  function ProfilesPage(props) {
    const [payload, setPayload] = useState(null);
    const [selectedProfile, setSelectedProfile] = useState("");
    const [submitting, setSubmitting] = useState(false);

    async function loadProfiles() {
      const next = await window.requestJson("/api/overview?limit=1");
      setPayload(next);
      const currentProfile = next && next.profile && next.profile.current ? next.profile.current.name : "";
      setSelectedProfile(currentProfile);
    }

    useEffect(() => {
      loadProfiles().catch((error) => window.showToast(error.message, "error"));
    }, []);

    if (!payload) {
      return h("div", { className: "panel" }, "Loading profiles...");
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
          h("div", { className: "user-pill" }, h("span", null, "Signed in as"), h("strong", null, props.session.username || "-")),
          h("button", { type: "button", className: "button secondary", onClick: () => loadProfiles().catch((error) => window.showToast(error.message, "error")) }, "Refresh"),
          h("button", { type: "button", className: "button", onClick: props.onLogout }, "Log out")
        )
      ),
      h(
        "section",
        { className: "toolbar-panel" },
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
        { className: "panel services-panel" },
        h("div", { className: "section-heading" }, h("div", null, h("h2", null, "Services"), h("p", null, "Listeners assigned to the selected profile."))),
        h(
          "div",
          { className: "service-grid" },
          services.length
            ? services.map((service) =>
                h(
                  "article",
                  { key: `${service.name}-${service.port}`, className: `service-card ${service.running ? "live" : ""}` },
                  h(
                    "div",
                    { className: "service-card-header" },
                    h("div", null, h("strong", null, window.text(service.name)), h("span", null, `${window.text(service.display_host || service.host)}:${window.text(service.port)}`)),
                    h("span", { className: `status-pill ${service.running ? "running" : "stopped"}` }, service.running ? "Live" : "Idle")
                  ),
                  h(
                    "div",
                    { className: "service-card-tags" },
                    h("span", { className: `tag ${servicePortTone(service)}` }, window.text(standardPortNote(service))),
                    h("span", { className: "tag template" }, window.text(service.template))
                  ),
                  h("p", null, service.running ? "This listener is exposed right now." : "This listener exists in the profile but is not active.")
                )
              )
            : h("article", { className: "service-card" }, h("p", null, "No listeners are assigned to the current profile."))
        )
      )
    );
  }

  function LogsPage(props) {
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
      return h("div", { className: "panel" }, "Loading logs...");
    }

    const profile = payload.profile && payload.profile.current ? payload.profile.current.name : "-";
    const visibleEvents = filterLogEvents(payload.events || [], filters);
    const services = payload.services || [];
    const stats = payload.stats || {};
    const eventTypes = Object.keys(stats.by_type || {}).sort();

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
        h(MetricCard, { label: "Total Recent Events", value: String(stats.total_recent_events || 0), note: "Last 1000 log records." }),
        h(MetricCard, { label: "Showing", value: `${visibleEvents.length} events`, note: "After current filters." }),
        h(MetricCard, { label: "Generated", value: window.text(window.formatTimestamp(payload.generated_at)), note: "Dashboard server time." })
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
      selectedEvent
        ? h(
            "div",
            {
              className: "modal-backdrop",
              onClick: (event) => {
                if (event.target === event.currentTarget) {
                  setSelectedEvent(null);
                }
              },
            },
            h(
              "div",
              { className: "modal-panel" },
              h("div", { className: "section-heading" }, h("div", null, h("h2", null, "Event Detail"), h("p", null, "Full JSON record."))),
              h("pre", { className: "json-viewer" }, JSON.stringify(selectedEvent, null, 2)),
              h(
                "div",
                { className: "button-row" },
                h(
                  "button",
                  {
                    type: "button",
                    className: "button secondary",
                    onClick: () => copyText(JSON.stringify(selectedEvent, null, 2)).then(() => window.showToast("Raw JSON copied.", "success")).catch((error) => window.showToast(error.message, "error")),
                  },
                  "Copy JSON"
                ),
                h("button", { type: "button", className: "button", onClick: () => setSelectedEvent(null) }, "Close")
              )
            )
          )
        : null
    );
  }

  function AppearancePage(props) {
    const [theme, setTheme] = useState(window.currentTheme());

    function toggleTheme() {
      const nextTheme = theme === "dark" ? "light" : "dark";
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
          h("div", null, h("h2", null, "Theme"), h("p", null, "Switch between light and dark mode.")),
          h("button", { type: "button", className: "button secondary", onClick: toggleTheme }, theme === "dark" ? "Light Mode" : "Dark Mode")
        )
      )
    );
  }

  function SystemPage(props) {
    const [payload, setPayload] = useState(null);
    const [busy, setBusy] = useState(false);

    async function loadSettings() {
      const next = await window.requestJson("/api/settings");
      setPayload(next);
    }

    usePolling(loadSettings, 5000, []);

    if (!payload) {
      return h("div", { className: "panel" }, "Loading system settings...");
    }

    const isAdmin = props.session.role === "admin";

    async function clearLogs() {
      if (!isAdmin) {
        window.showToast("Admin access required.", "error");
        return;
      }
      setBusy(true);
      try {
        await window.requestJson("/api/logs/clear", { method: "POST" });
        await loadSettings();
        window.showToast("Logs cleared.", "success");
      } catch (error) {
        window.showToast(error.message, "error");
      } finally {
        setBusy(false);
      }
    }

    async function copyLogs() {
      if (!isAdmin) {
        window.showToast("Admin access required.", "error");
        return;
      }
      try {
        const response = await fetch("/api/logs/export");
        if (!response.ok) {
          throw new Error(`Request failed: ${response.status}`);
        }
        const content = await response.text();
        await copyText(content);
        window.showToast("Logs copied as JSONL.", "success");
      } catch (error) {
        window.showToast(error.message, "error");
      }
    }

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
                href: "/api/logs/export",
                download: "honeypot-events.jsonl",
                onClick: (event) => {
                  if (!isAdmin) {
                    event.preventDefault();
                    window.showToast("Admin access required.", "error");
                  }
                },
              },
              "Export JSONL"
            ),
            h("button", { type: "button", className: "button secondary", disabled: !isAdmin, onClick: copyLogs }, "Copy Logs"),
            h("button", { type: "button", className: "button danger", disabled: !isAdmin || busy, onClick: clearLogs }, busy ? "Clearing..." : "Clear Logs")
          )
        )
      )
    );
  }

  function DetailPanel(props) {
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

  function UsersPage(props) {
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

  function App() {
    const [page, setPage] = useState(pathToPage(window.location.pathname));
    const [session, setSession] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
      const titles = {
        dashboard: "Honeypot Director Dashboard",
        profiles: "Honeypot Director Profiles",
        logs: "Honeypot Director Logs",
        appearance: "Honeypot Director Appearance",
        system: "Honeypot Director System",
        users: "Honeypot Director Users",
      };
      document.title = titles[page] || "Honeypot Director";
    }, [page]);

    useEffect(() => {
      function handlePopState() {
        setPage(pathToPage(window.location.pathname));
      }
      window.addEventListener("popstate", handlePopState);
      return () => window.removeEventListener("popstate", handlePopState);
    }, []);

    useEffect(() => {
      window.requestJson("/api/session")
        .then((payload) => {
          if (!payload.authenticated) {
            window.location.replace("/login");
            return;
          }
          setSession(payload);
          setLoading(false);
        })
        .catch(() => {
          window.location.replace("/login");
        });
    }, []);

    function navigate(path) {
      if (window.location.pathname === path) {
        return;
      }
      window.history.pushState({}, "", path);
      setPage(pathToPage(path));
      window.scrollTo({ top: 0, behavior: "smooth" });
    }

    function navigateClick(path) {
      return function handleNavigate(event) {
        event.preventDefault();
        navigate(path);
      };
    }

    function handleLogout() {
      window.logoutAndRedirect();
    }

    if (loading || !session) {
      return h("div", { className: "app-frame" }, h("main", { className: "main-content" }, h("section", { className: "panel" }, "Loading application...")));
    }

    let pageNode = null;
    if (page === "dashboard") {
      pageNode = h(DashboardPage, { session, onLogout: handleLogout, navigateClick });
    } else if (page === "profiles") {
      pageNode = h(ProfilesPage, { session, onLogout: handleLogout });
    } else if (page === "logs") {
      pageNode = h(LogsPage, { session, onLogout: handleLogout });
    } else if (page === "appearance") {
      pageNode = h(AppearancePage, { session, onLogout: handleLogout });
    } else if (page === "system") {
      pageNode = h(SystemPage, { session, onLogout: handleLogout });
    } else if (page === "users") {
      pageNode = h(UsersPage, { session, onLogout: handleLogout });
    }

    return h(AppLayout, { page, navigateClick }, pageNode);
  }

  const rootElement = document.querySelector("#app-root");
  if (!rootElement) {
    return;
  }
  ReactDOM.createRoot(rootElement).render(h(App));
})();
