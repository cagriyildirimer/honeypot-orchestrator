(function () {
  const h = React.createElement;
  const { useEffect, useState } = React;

  // Global 3D Tilt Effect
  document.addEventListener('mousemove', (e) => {
    const target = e.target.closest('.tilt-effect');
    if (!target) return;
    const rect = target.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const midX = rect.width / 2;
    const midY = rect.height / 2;
    const rotateX = ((y - midY) / midY) * -1.5;
    const rotateY = ((x - midX) / midX) * 1.5;
    target.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
    target.style.transition = 'none';
  });
  document.addEventListener('mouseout', (e) => {
    const target = e.target.closest('.tilt-effect');
    if (!target) return;
    target.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg)';
    target.style.transition = 'transform 0.4s cubic-bezier(0.25, 0.8, 0.25, 1)';
  });


  const NAV_ITEMS = [
    { key: "dashboard", label: "Dashboard", path: "/dashboard" },
    { key: "profiles", label: "Profiles", path: "/profiles" },
    { key: "live", label: "Live Activity", path: "/live" },
    { key: "logs", label: "Logs", path: "/logs" },
  ];
  const SETTINGS_ITEMS = [
    { key: "appearance", label: "Appearance", path: "/settings/appearance" },
    { key: "whitelist", label: "Whitelist", path: "/settings/whitelist" },
    { key: "blocklist", label: "Blocklist", path: "/settings/blocklist" },
    { key: "users", label: "User", path: "/settings/users" },
    { key: "system", label: "System", path: "/settings/system" },
  ];
  const STANDARD_PORTS = {
    dns: 53,
    ftp: 21,
    http: 80,
    ldap: 389,
    ldaps: 636,
    llmnr: 5355,
    mssql: 1433,
    nbtnns: 137,
    netbios: 139,
    rdp: 3389,
    rpc: 135,
    smb: 445,
    ssh: 22,
    telnet: 23,
  };
  const DONUT_COLORS = [
    "#0075ff",
    "#21d4fd",
    "#4318ff",
    "#01b574",
    "#ffb547",
    "#e31a1a",
  ];
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
  const APPEARANCE_THEMES = [
    { key: "vision", label: "Vision Blue", note: "Deep blue glass with cyan highlights.", colors: ["#0075ff", "#21d4fd"] },
    { key: "nebula", label: "Nebula Violet", note: "Violet and magenta for high-contrast monitoring.", colors: ["#8b5cf6", "#ec4899"] },
    { key: "aurora", label: "Aurora Cyan", note: "Cold cyan and mint for clean operational views.", colors: ["#00d4ff", "#38f8c4"] },
    { key: "emerald", label: "Emerald Ops", note: "Green operational palette with soft lime accents.", colors: ["#01b574", "#9ae66e"] },
    { key: "sunset", label: "Sunset Alert", note: "Warm orange/yellow for alert-heavy dashboards.", colors: ["#f97316", "#fbcf33"] },
    { key: "slate", label: "Slate Mono", note: "Neutral steel palette for quiet long-running sessions.", colors: ["#64748b", "#e2e8f0"] },
  ];

  function pathToPage(pathname) {
    if (pathname === "/dashboard" || pathname === "/") {
      return "dashboard";
    }
    if (pathname === "/live") {
      return "live";
    }
    if (pathname === "/whitelist" || pathname === "/settings/whitelist") {
      return "whitelist";
    }
    if (pathname === "/blacklist" || pathname === "/settings/blacklist" || pathname === "/settings/blocklist") {
      return "blocklist";
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

  function buildSuspiciousOverview(events, referenceDate) {
    const now = referenceDate instanceof Date && !Number.isNaN(referenceDate.getTime())
      ? referenceDate.getTime()
      : Date.now();
    const windowMs = 24 * 60 * 60 * 1000;
    const start = now - windowMs;
    const hourTotals = {};
    const serviceTotals = {};
    const ipTotals = {};
    let totalCount = 0;

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
      totalCount += 1;

      const hourStart = new Date(time);
      hourStart.setMinutes(0, 0, 0);
      const hourKey = hourStart.toISOString();
      hourTotals[hourKey] = (hourTotals[hourKey] || 0) + 1;

      const service = String(event.service || "unknown").toLowerCase();
      serviceTotals[service] = (serviceTotals[service] || 0) + 1;

      const ip = String(event.src_ip || "-");
      ipTotals[ip] = (ipTotals[ip] || 0) + 1;
    }

    const topHour = Object.entries(hourTotals).sort((left, right) => right[1] - left[1])[0] || null;
    const topService = Object.entries(serviceTotals).sort((left, right) => right[1] - left[1])[0] || null;
    const topIp = Object.entries(ipTotals).sort((left, right) => right[1] - left[1])[0] || null;

    return {
      totalCount,
      topHour: topHour
        ? {
            start: new Date(topHour[0]),
            count: Number(topHour[1]) || 0,
          }
        : null,
      topService: topService
        ? {
            name: topService[0],
            count: Number(topService[1]) || 0,
          }
        : null,
      topIp: topIp
        ? {
            ip: topIp[0],
            count: Number(topIp[1]) || 0,
          }
        : null,
    };
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
    return bucket.start.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function alignTimelineWindowStart(referenceDate, range) {
    const base = referenceDate instanceof Date && !Number.isNaN(referenceDate.getTime())
      ? new Date(referenceDate.getTime())
      : new Date();
    const bucketMs = range.windowMs / range.bucketCount;

    if (range.key === "day") {
      const bucketHours = Math.max(1, Math.round(bucketMs / (60 * 60 * 1000)));
      const aligned = new Date(base.getTime());
      aligned.setMinutes(0, 0, 0);
      aligned.setHours(aligned.getHours() - (aligned.getHours() % bucketHours));
      aligned.setHours(aligned.getHours() - ((range.bucketCount - 1) * bucketHours));
      return aligned.getTime();
    }

    const aligned = new Date(base.getTime());
    aligned.setHours(0, 0, 0, 0);
    aligned.setDate(aligned.getDate() - (range.bucketCount - 1));
    return aligned.getTime();
  }

  function buildTimelineBuckets(events, referenceDate, rangeKey) {
    const range = timelineRangeConfig(rangeKey);
    const bucketCount = range.bucketCount;
    const windowMs = range.windowMs;
    const bucketMs = windowMs / bucketCount;
    const now = referenceDate instanceof Date && !Number.isNaN(referenceDate.getTime())
      ? referenceDate.getTime()
      : Date.now();
    const start = alignTimelineWindowStart(referenceDate, range);
    const buckets = Array.from({ length: bucketCount }, (_, index) => ({
      count: 0,
      suspiciousCount: 0,
      totalCount: 0,
      start: new Date(start + index * bucketMs),
      end: new Date(start + (index + 1) * bucketMs),
    }));
    for (const event of events || []) {
      if (!event) {
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
      buckets[index].totalCount += 1;
      if (event.src_ip) {
        buckets[index].suspiciousCount += 1;
      }
      buckets[index].count = buckets[index].suspiciousCount;
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

  function buildTimelinePoints(timeline, peak, valueKey = "count") {
    const width = 640;
    const height = 190;
    const padding = { top: 20, right: 22, bottom: 34, left: 42 };
    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;
    const divisor = Math.max(1, timeline.length - 1);
    const maxValue = Math.max(1, peak);
    return timeline.map((bucket, index) => ({
      bucket,
      x: Math.round(padding.left + (index / divisor) * plotWidth),
      y: Math.round(padding.top + plotHeight - ((Number(bucket[valueKey]) || 0) / maxValue) * plotHeight),
    }));
  }

  function buildTimelineAreaPath(points) {
    if (!points.length) {
      return "";
    }
    const baseline = 156;
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
    const baseName = service.name.split("_")[0];
    const standardPort = STANDARD_PORTS[baseName] || STANDARD_PORTS[service.name];
    if (!standardPort) {
      return "Custom listener";
    }
    if (standardPort === service.port) {
      return `Standard ${standardPort}`;
    }
    return `Lab ${service.port} / Standard ${standardPort}`;
  }

  function servicePortTone(service) {
    const baseName = service.name.split("_")[0];
    const standardPort = STANDARD_PORTS[baseName] || STANDARD_PORTS[service.name];
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

  function Skeleton(props) {
    return h("div", { 
      className: `skeleton ${props.className || ""}`, 
      style: { width: "100%", height: "20px", ...props.style } 
    });
  }

  function PageSkeleton() {
    return h(
      "div",
      null,
      h("header", { className: "topbar", style: { marginBottom: "18px" } }, 
        h(Skeleton, { style: { width: "250px", height: "38px", borderRadius: "12px" } })
      ),
      h("section", { className: "metric-grid" },
        Array.from({ length: 4 }).map((_, i) => 
          h("article", { key: i, className: "metric-card" }, 
            h(Skeleton, { style: { width: "40%", height: "14px", marginBottom: "12px" } }),
            h(Skeleton, { style: { width: "70%", height: "28px", marginBottom: "12px" } }),
            h(Skeleton, { style: { width: "100%", height: "12px" } })
          )
        )
      ),
      h("section", { className: "panel", style: { marginTop: "18px" } }, 
        h(Skeleton, { style: { width: "100%", height: "300px", borderRadius: "16px" } })
      )
    );
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

  function AnimatedCounter(props) {
    const value = typeof props.value === "string" ? parseInt(props.value, 10) : props.value;
    if (isNaN(value)) return h("strong", null, props.value);

    const [count, setCount] = useState(0);

    useEffect(() => {
      let start = count;
      const end = value;
      if (start === end) return;
      
      const duration = 1000;
      let startTimestamp = null;
      
      const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        const easeProgress = 1 - Math.pow(1 - progress, 4);
        setCount(Math.floor(start + easeProgress * (end - start)));
        
        if (progress < 1) {
          window.requestAnimationFrame(step);
        } else {
          setCount(end);
        }
      };
      
      window.requestAnimationFrame(step);
    }, [value]);

    return h("strong", null, count.toString());
  }

  function MetricCard(props) {
    return h(
      "article",
      { className: "metric-card" },
      h("span", null, props.label),
      h(AnimatedCounter, { value: props.value }),
      h("small", null, props.note)
    );
  }

  function AppLayout(props) {
    const [settingsOpen, setSettingsOpen] = useState(isSettingsPage(props.page));
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

    useEffect(() => {
      if (isSettingsPage(props.page)) {
        setSettingsOpen(true);
      }
    }, [props.page]);

    return h(
      "div",
      { className: "app-frame" },
      h(
        "header",
        { className: "mobile-header" },
        h(
          "button",
          {
            type: "button",
            className: "hamburger-btn",
            onClick: () => setMobileMenuOpen(!mobileMenuOpen),
            "aria-label": "Toggle Menu",
          },
          h("span", { className: `hamburger-icon${mobileMenuOpen ? " open" : ""}` })
        ),
        h(
          "a",
          {
            className: "mobile-brand",
            href: "/dashboard",
            onClick: (e) => {
              setMobileMenuOpen(false);
              props.navigateClick("/dashboard")(e);
            },
          },
          h("span", { className: "brand-mark" }, "HD"),
          h("span", { className: "brand-text" }, "Honeypot Director")
        )
      ),
      mobileMenuOpen
        ? h("div", {
            className: "sidebar-backdrop",
            onClick: () => setMobileMenuOpen(false),
          })
        : null,
      h(
        "aside",
        { className: `sidebar${mobileMenuOpen ? " mobile-open" : ""}` },
        h(
          "a",
          {
            className: "brand",
            href: "/dashboard",
            onClick: (e) => {
              setMobileMenuOpen(false);
              props.navigateClick("/dashboard")(e);
            },
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
              onClick: (e) => {
                setMobileMenuOpen(false);
                props.navigateClick(item.path)(e);
              },
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
                      onClick: (e) => {
                        setMobileMenuOpen(false);
                        props.navigateClick(item.path)(e);
                      },
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

  function EventDrawer(props) {
    if (!props.event) return null;
    return h(
      "div",
      { className: "drawer-overlay", onClick: props.onClose },
      h(
        "div",
        { className: "drawer", onClick: (e) => e.stopPropagation() },
        h(
          "div",
          { className: "drawer-header" },
          h("h3", null, "Event Details"),
          h("button", { className: "button secondary small", onClick: props.onClose }, "Close")
        ),
        h(
          "div",
          { className: "drawer-body" },
          h("pre", { className: "json-viewer" }, JSON.stringify(props.event, null, 2))
        )
      )
    );
  }

  function GeoWorldMap(props) {
    const containerRef = React.useRef(null);
    const globeRef = React.useRef(null);
    const markers = props.markers || [];

    React.useEffect(() => {
      if (!containerRef.current) return;
      if (!globeRef.current && window.Globe) {
        globeRef.current = window.Globe()(containerRef.current)
          .globeImageUrl('//unpkg.com/three-globe/example/img/earth-blue-marble.jpg')
          .bumpImageUrl('//unpkg.com/three-globe/example/img/earth-topology.png')
          .backgroundColor('rgba(0,0,0,0)')
          .width(800)
          .height(400)
          .pointOfView({ altitude: 2.0 });

        globeRef.current.controls().autoRotate = true;
        globeRef.current.controls().autoRotateSpeed = 1.0;
        globeRef.current.controls().enableZoom = false;
      }

      const globe = globeRef.current;
      if (globe) {
        const points = markers.map(m => ({
          lat: m.lat,
          lng: m.lon,
          size: Math.max(0.1, Math.min(1.0, m.count / 10)),
          color: '#e31a1a',
          name: `${m.city ? m.city + ', ' : ''}${m.country} (${m.count} events - IP: ${m.ip})`
        }));

        globe.pointsData(points)
          .pointAltitude(d => d.size * 0.1)
          .pointColor('color')
          .pointRadius(d => d.size * 2)
          .pointLabel('name');
      }
    }, [markers]);

    return h("div", { className: "geo-map-container", style: { display: 'flex', justifyContent: 'center', minHeight: '400px', position: 'relative' } },
      h("div", { ref: containerRef }),
      markers.length === 0 ? h("div", { className: "geo-empty", style: { position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', pointerEvents: 'none' } }, "No external attacker IPs detected yet.") : null
    );
  }

  function DashboardPage(props) {
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

  function ServiceActivityDonut(props) {
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

  function TimelineLineChart(props) {
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

  function LiveActivityPage(props) {
    const [events, setEvents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedEvent, setSelectedEvent] = useState(null);

    async function loadEvents() {
      const next = await window.requestJson("/api/events?limit=150");
      if (next && next.events) {
        // Filter down to interesting security/attacker actions
        const securityEvents = next.events.filter(e => {
          if (!e || !e.src_ip) return false;
          // Avoid noise, show login_attempt, command, queries, etc.
          return e.event_type !== "service_started" && e.event_type !== "service_stopped";
        });
        setEvents(securityEvents);
      }
      setLoading(false);
    }

    usePolling(loadEvents, 1500, []);

    if (loading && !events.length) {
      return h(PageSkeleton, null);
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
          h("h1", null, "Live Attacker Monitor"),
          h("p", { className: "page-subtitle" }, "Real-time command stream and hostile interaction logs.")
        ),
        h(
          "div",
          { className: "topbar-actions" },
          h(
            "button",
            {
              type: "button",
              className: "button",
              onClick: () => loadEvents(),
            },
            "Force Sync"
          ),
          h(
            "button",
            { type: "button", className: "button secondary", onClick: props.onLogout },
            "Log out"
          )
        )
      ),
      h(
        "section",
        { className: "panel raw-panel", style: { border: "1px solid var(--border)", background: "#060b28" } },
        h(
          "div",
          { className: "section-heading" },
          h("h2", null, "Attacker Activity Console"),
          h("p", null, "Simulated interaction outputs caught on decoy listeners.")
        ),
        h(
          "div",
          {
            className: "json-viewer",
            style: {
              background: "#020410",
              color: "#38f8c4",
              border: "1px solid rgba(56, 248, 196, 0.25)",
              boxShadow: "0 0 15px rgba(56, 248, 196, 0.08)",
              fontFamily: "'JetBrains Mono', monospace",
              padding: "18px",
              minHeight: "480px"
            }
          },
          events.length === 0
            ? h("div", { style: { color: "#a0aec0", textAlign: "center", paddingTop: "120px" } }, "📡 Listening for target activity... Expose decoy services to start receiving live logs.")
            : events.map((event, idx) => {
                const timestamp = event.timestamp || "";
                const src = `${event.src_ip}:${event.src_port || 0}`;
                const service = String(event.service || "unknown").toUpperCase();
                const type = event.event_type || "";
                
                // Construct a beautiful CLI line representing the attacker's action
                let detailText = "";
                if (type === "connection") {
                  detailText = "New raw TCP handshake completed. (Possible port scan / Nmap ping)";
                } else if (type === "client_disconnected") {
                  detailText = "Target disconnected from honeypot socket.";
                } else if (type === "connection_error") {
                  detailText = `Socket connection errored out. (Type: ${event.error || "unknown"})`;
                } else if (type === "smb_negotiate") {
                  detailText = "SMBv2 session negotiation initiated. (Likely smbclient, Nmap probe, or mounting attempt)";
                } else if (type === "smb_session_setup") {
                  detailText = "SMB session security challenge requested. (El sıkışması başlatıldı)";
                } else if (type === "login_attempt") {
                  if (service === "SMB") {
                    detailText = `SMB Authentication login attempted for domain='${event.domain || "WORKGROUP"}' username='${event.username || "anonymous"}' workstation='${event.workstation || "none"}' (Authentication rejected)`;
                  } else if (service === "MSSQL") {
                    detailText = `MSSQL Authentication failed for user='${event.username || "unknown"}' password='${event.password || "none"}' (Host: ${event.client_hostname || "unknown"}, App: ${event.app_name || "unknown"}, DB: ${event.database_name || "master"}).`;
                  } else if (service === "SSH") {
                    detailText = `SSH Login attempted for username='${event.username || "unknown"}' password='${event.password || "unknown"}' (Access Denied)`;
                  } else if (service === "FTP") {
                    detailText = `FTP Login attempted for user='${event.username || "unknown"}' password='${event.password || "unknown"}' (Access Denied)`;
                  } else if (service === "TELNET") {
                    detailText = `Telnet Login attempted for user='${event.username || "unknown"}' password='${event.password || "unknown"}' (Access Denied)`;
                  } else if (service === "LDAP") {
                    detailText = `LDAP Bind Authentication attempted for username='${event.username || "anonymous"}' password='${event.password ? "******" : "none"}' (Invalid Credentials)`;
                  } else {
                    detailText = `Authentication attempted for username='${event.username || "unknown"}' (Rejected)`;
                  }
                } else if (type === "ftp_command") {
                  detailText = `FTP Command executed: ${event.command} ${event.argument || ""}`;
                } else if (type === "dns_query") {
                  detailText = `DNS resolution queried for name='${event.query_name}' (Record Type: ${event.query_type}, Class: ${event.query_class})`;
                } else if (type === "ldap_search") {
                  detailText = `LDAP Query executed. scope='${event.scope}' base_dn='${event.base_dn || "rootDSE"}'`;
                } else if (type === "rdp_connection_request") {
                  detailText = `RDP X.224 Connection Request. (Cookie: ${event.cookie || "none"})`;
                } else if (type === "netbios_session_request") {
                  detailText = `NetBIOS Session Request captured for target name='${event.called_name}' from caller='${event.calling_name}'`;
                } else if (type === "netbios_followup") {
                  detailText = `NetBIOS Follow-up request payload: signature='${event.signature}'`;
                } else if (type === "ldaps_tls_client_hello") {
                  detailText = `LDAPS TLS handshake started. (TLS Client Hello, Version: ${event.tls_version}, Record Type: ${event.tls_record_type})`;
                } else if (type === "mssql_prelogin") {
                  detailText = `MSSQL Pre-login handshake negotiated. (TDS Packet Type: ${event.packet_type})`;
                } else if (type === "rpc_connection") {
                  detailText = `MSRPC Connection established. Waiting for bind request...`;
                } else if (type === "rpc_request") {
                  detailText = `MSRPC Request received (PTYPE: ${event.ptype || "unknown"}, Payload: ${event.data_hex || "none"})`;
                } else if (type === "rpc_response") {
                  detailText = event.summary || `MSRPC Response sent.`;
                } else if (type === "rpc_error") {
                  detailText = `MSRPC encountered an error: ${event.error || "unknown"}`;
                } else if (type === "login_success" && service === "MSSQL") {
                  detailText = `MSSQL Authentication SUCCEEDED for user='${event.username || "unknown"}' password='${event.password || "none"}' (Host: ${event.client_hostname || "unknown"}, App: ${event.app_name || "unknown"}, DB: ${event.database_name || "master"}). Unlocked deep interactive shell!`;
                } else if (type === "sql_query" && service === "MSSQL") {
                  detailText = `MSSQL T-SQL Batch query executed: "${event.query || ""}" (User: ${event.username || "sa"})`;
                } else if (event.summary) {
                  detailText = event.summary;
                } else {
                  detailText = JSON.stringify(event);
                }

                return h(
                  "div",
                  {
                    key: idx,
                    onClick: () => setSelectedEvent(event),
                    style: {
                      cursor: "pointer",
                      marginBottom: "12px",
                      borderBottom: "1px solid rgba(255, 255, 255, 0.04)",
                      paddingBottom: "8px"
                    }
                  },
                  h("span", { style: { color: "rgba(255,255,255,0.4)", marginRight: "10px" } }, `[${window.formatTimestamp(event.timestamp)}]`),
                  h("span", { style: { color: "#00d4ff", fontWeight: "bold", marginRight: "10px" } }, `[${src}]`),
                  h("span", { style: { color: "#ffb547", fontWeight: "bold", marginRight: "10px" } }, `[${service}]`),
                  h("span", { style: { color: "#ffffff" } }, detailText)
                );
              })
        )
      ),
      h(EventDrawer, { event: selectedEvent, onClose: () => setSelectedEvent(null) })
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
                    h(
                      "label",
                      { className: "toggle-switch", title: service.running ? "Turn Off" : "Turn On" },
                      h("input", {
                        type: "checkbox",
                        checked: service.running,
                        onChange: async (e) => {
                          const enabled = e.target.checked;
                          const label = service.name.replace(/_/g, " ");
                          try {
                            await window.requestJson("/api/services/toggle", {
                              method: "POST",
                              body: JSON.stringify({ service: service.name, enabled: enabled })
                            });
                            window.showToast(enabled ? `${label} started` : `${label} stopped`, enabled ? "success" : "neutral");
                            loadProfiles();
                          } catch (err) {
                            window.showToast(err.message || "Toggle failed", "error");
                            loadProfiles();
                          }
                        }
                      }),
                      h("span", { className: "toggle-slider" })
                    )
                  ),
                  h(
                    "div",
                    { className: "service-card-tags" },
                    h("span", { className: `tag ${servicePortTone(service)}` }, window.text(standardPortNote(service))),
                    h("span", { className: "tag template" }, window.text(service.template))
                  ),
                  h("p", null, service.running ? "This listener is exposed right now." : "This listener exists in the profile but is not active."),
                  (function() {
                    const baseName = service.name.split("_")[0];
                    const standardPort = STANDARD_PORTS[baseName] || STANDARD_PORTS[service.name];
                    return standardPort && standardPort !== service.port
                      ? h("p", { style: { fontSize: "11.5px", color: "#f59e0b", marginTop: "8px", display: "flex", alignItems: "center", gap: "5px", lineHeight: "1.4" } }, 
                          `⚠️ Exposed on custom port ${service.port} to prevent host port conflict (Standard: ${standardPort}).`
                        )
                      : null;
                  })()
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

  function WhitelistPage(props) {
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

  function BlacklistPage(props) {
    const [entries, setEntries] = useState([]);
    const [loading, setLoading] = useState(true);
    const [ip, setIp] = useState("");
    const [description, setDescription] = useState("");
    const [submitting, setSubmitting] = useState(false);

    async function loadBlacklist() {
      const next = await window.requestJson("/api/blacklist");
      if (next && next.blacklist) {
        setEntries(next.blacklist);
      }
      setLoading(false);
    }

    useEffect(() => {
      loadBlacklist().catch((error) => window.showToast(error.message, "error"));
    }, []);

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

  function AppearancePage(props) {
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

  function SystemPage(props) {
    const [payload, setPayload] = useState(null);
    const [busy, setBusy] = useState(false);

    async function loadSettings() {
      const next = await window.requestJson("/api/settings");
      setPayload(next);
    }

    usePolling(loadSettings, 5000, []);

    if (!payload) {
      return h(PageSkeleton, null);
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
        live: "Honeypot Director Live Monitor",
        whitelist: "Honeypot Director Whitelist",
        blacklist: "Honeypot Director Blacklist",
        blocklist: "Honeypot Director Blocklist",
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
      return h("div", { className: "app-frame" }, h("main", { className: "main-content" }, h(PageSkeleton, null)));
    }

    let pageNode = null;
    if (page === "dashboard") {
      pageNode = h(DashboardPage, { session, onLogout: handleLogout, navigateClick });
    } else if (page === "live") {
      pageNode = h(LiveActivityPage, { session, onLogout: handleLogout });
    } else if (page === "whitelist") {
      pageNode = h(WhitelistPage, { session, onLogout: handleLogout });
    } else if (page === "blacklist" || page === "blocklist") {
      pageNode = h(BlacklistPage, { session, onLogout: handleLogout });
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
