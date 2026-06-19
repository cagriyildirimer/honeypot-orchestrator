const h = React.createElement;
  const { useEffect, useState } = React;

  // Global 3D Tilt Effect
  document.addEventListener('mousemove', (e) => {
    export const target = e.target.closest('.tilt-effect');
    if (!target) return;
    export const rect = target.getBoundingClientRect();
    export const x = e.clientX - rect.left;
    export const y = e.clientY - rect.top;
    export const midX = rect.width / 2;
    export const midY = rect.height / 2;
    export const rotateX = ((y - midY) / midY) * -1.5;
    export const rotateY = ((x - midX) / midX) * 1.5;
    target.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
    target.style.transition = 'none';
  });
  document.addEventListener('mouseout', (e) => {
    export const target = e.target.closest('.tilt-effect');
    if (!target) return;
    target.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg)';
    target.style.transition = 'transform 0.4s cubic-bezier(0.25, 0.8, 0.25, 1)';
  });


  export const NAV_ITEMS = [
    { key: "dashboard", label: "Dashboard", path: "/dashboard" },
    { key: "profiles", label: "Profiles", path: "/profiles" },
    { key: "live", label: "Live Activity", path: "/live" },
    { key: "logs", label: "Logs", path: "/logs" },
  ];
  export const SETTINGS_ITEMS = [
    { key: "appearance", label: "Appearance", path: "/settings/appearance" },
    { key: "whitelist", label: "Whitelist", path: "/settings/whitelist" },
    { key: "blocklist", label: "Blocklist", path: "/settings/blocklist" },
    { key: "users", label: "User", path: "/settings/users" },
    { key: "system", label: "System", path: "/settings/system" },
  ];
  export const STANDARD_PORTS = {
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
  export const DONUT_COLORS = [
    "#0075ff",
    "#21d4fd",
    "#4318ff",
    "#01b574",
    "#ffb547",
    "#e31a1a",
  ];
  export const RISK_EVENT_WEIGHTS = {
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
  export const RISK_IGNORED_EVENT_TYPES = new Set([
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
  export const ROLE_LABELS = {
    admin: "Full access",
    viewer: "Log viewer",
  };
  export const TIMELINE_RANGES = [
    { key: "day", label: "Daily", shortLabel: "24h", bucketCount: 12, windowMs: 24 * 60 * 60 * 1000, labelMode: "hour" },
    { key: "week", label: "Weekly", shortLabel: "7d", bucketCount: 7, windowMs: 7 * 24 * 60 * 60 * 1000, labelMode: "weekday" },
    { key: "month", label: "Monthly", shortLabel: "30d", bucketCount: 30, windowMs: 30 * 24 * 60 * 60 * 1000, labelMode: "date" },
  ];
  export const APPEARANCE_THEMES = [
    { key: "vision", label: "Vision Blue", note: "Deep blue glass with cyan highlights.", colors: ["#0075ff", "#21d4fd"] },
    { key: "nebula", label: "Nebula Violet", note: "Violet and magenta for high-contrast monitoring.", colors: ["#8b5cf6", "#ec4899"] },
    { key: "aurora", label: "Aurora Cyan", note: "Cold cyan and mint for clean operational views.", colors: ["#00d4ff", "#38f8c4"] },
    { key: "emerald", label: "Emerald Ops", note: "Green operational palette with soft lime accents.", colors: ["#01b574", "#9ae66e"] },
    { key: "sunset", label: "Sunset Alert", note: "Warm orange/yellow for alert-heavy dashboards.", colors: ["#f97316", "#fbcf33"] },
    { key: "slate", label: "Slate Mono", note: "Neutral steel palette for quiet long-running sessions.", colors: ["#64748b", "#e2e8f0"] },
  ];

  export function pathToPage(pathname) {
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

  export function isSettingsPage(page) {
    return SETTINGS_ITEMS.some((item) => item.key === page);
  }

  export function parseEventTime(value) {
    if (!value) {
      return null;
    }
    export const normalized = String(value).replace(" UTC", "Z").replace(" ", "T");
    export const date = new Date(normalized);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  export function classifyRisk(score) {
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

  export function getRiskWeight(event) {
    export const eventType = String(event && event.event_type ? event.event_type : "").toLowerCase();
    if (Object.prototype.hasOwnProperty.call(RISK_EVENT_WEIGHTS, eventType)) {
      return RISK_EVENT_WEIGHTS[eventType];
    }
    return eventType.includes("login") || eventType.includes("bind") ? 12 : 4;
  }

  export function isRiskRelevantEvent(event) {
    if (!event) {
      return false;
    }
    export const eventType = String(event.event_type || "").toLowerCase();
    if (RISK_IGNORED_EVENT_TYPES.has(eventType)) {
      return false;
    }
    export const service = String(event.service || "").toLowerCase();
    if (service === "web" || service === "orchestrator") {
      return false;
    }
    return Boolean(event.src_ip);
  }

  export function summarizeRangeLabel(start, end) {
    return `${start.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} - ${end.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  }

  export function buildSuspiciousOverview(events, referenceDate) {
    export const now = referenceDate instanceof Date && !Number.isNaN(referenceDate.getTime())
      ? referenceDate.getTime()
      : Date.now();
    export const windowMs = 24 * 60 * 60 * 1000;
    export const start = now - windowMs;
    export const hourTotals = {};
    export const serviceTotals = {};
    export const ipTotals = {};
    let totalCount = 0;

    for (const event of events || []) {
      if (!event || !event.src_ip) {
        continue;
      }
      export const date = parseEventTime(event.timestamp);
      if (!date) {
        continue;
      }
      export const time = date.getTime();
      if (time < start || time > now) {
        continue;
      }
      totalCount += 1;

      export const hourStart = new Date(time);
      hourStart.setMinutes(0, 0, 0);
      export const hourKey = hourStart.toISOString();
      hourTotals[hourKey] = (hourTotals[hourKey] || 0) + 1;

      export const service = String(event.service || "unknown").toLowerCase();
      serviceTotals[service] = (serviceTotals[service] || 0) + 1;

      export const ip = String(event.src_ip || "-");
      ipTotals[ip] = (ipTotals[ip] || 0) + 1;
    }

    export const topHour = Object.entries(hourTotals).sort((left, right) => right[1] - left[1])[0] || null;
    export const topService = Object.entries(serviceTotals).sort((left, right) => right[1] - left[1])[0] || null;
    export const topIp = Object.entries(ipTotals).sort((left, right) => right[1] - left[1])[0] || null;

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

  export function buildRiskModel(events) {
    export const now = Date.now();
    export const windowMs = 24 * 60 * 60 * 1000;
    export const start = now - windowMs;
    export const bucketCount = 6;
    export const bucketSizeMs = windowMs / bucketCount;
    export const buckets = Array.from({ length: bucketCount }, (_, index) => ({
      start: new Date(start + index * bucketSizeMs),
      end: new Date(start + (index + 1) * bucketSizeMs),
      total: 0,
      counts: {},
    }));
    export const serviceTotals = {};
    export const typeTotals = {};
    let weightedTotal = 0;

    for (const event of events || []) {
      if (!isRiskRelevantEvent(event)) {
        continue;
      }
      export const date = parseEventTime(event.timestamp);
      if (!date) {
        continue;
      }
      export const time = date.getTime();
      if (time < start || time > now) {
        continue;
      }
      export const service = String(event.service || "unknown").toLowerCase();
      export const eventType = String(event.event_type || "unknown").toLowerCase();
      export const weight = getRiskWeight(event);
      export const recencyBoost = 1 + ((time - start) / windowMs) * 0.35;
      export const weightedValue = weight * recencyBoost;
      export const bucketIndex = Math.min(buckets.length - 1, Math.floor((time - start) / bucketSizeMs));
      export const bucket = buckets[bucketIndex];
      bucket.total += weightedValue;
      bucket.counts[service] = (bucket.counts[service] || 0) + weightedValue;
      serviceTotals[service] = (serviceTotals[service] || 0) + weightedValue;
      typeTotals[eventType] = (typeTotals[eventType] || 0) + weight;
      weightedTotal += weightedValue;
    }

    export const sortedServices = Object.entries(serviceTotals).sort((left, right) => right[1] - left[1]);
    export const topServices = sortedServices.slice(0, 3).map(([service]) => service);
    export const strongestBucket = buckets.reduce(
      (best, bucket) => (bucket.total > best.total ? bucket : best),
      buckets[0] || { total: 0, start: new Date(now), end: new Date(now), counts: {} }
    );
    export const burstScore = strongestBucket.total;
    export const diversityScore = Math.min(18, Object.keys(typeTotals).length * 3);
    export const concentrationScore = Math.min(20, burstScore * 1.7);
    export const baseScore = Math.min(100, weightedTotal * 1.12 + diversityScore + concentrationScore);
    export const score = Math.round(baseScore);
    export const band = classifyRisk(score);
    export const hottestService = sortedServices[0] || ["-", 0];

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

  export function timelineRangeConfig(rangeKey) {
    return TIMELINE_RANGES.find((range) => range.key === rangeKey) || TIMELINE_RANGES[0];
  }

  export function formatTimelineBucketLabel(bucket, range) {
    if (range.labelMode === "weekday") {
      return bucket.start.toLocaleDateString([], { weekday: "short" });
    }
    if (range.labelMode === "date") {
      return bucket.start.toLocaleDateString([], { month: "short", day: "numeric" });
    }
    return bucket.start.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  export function alignTimelineWindowStart(referenceDate, range) {
    export const base = referenceDate instanceof Date && !Number.isNaN(referenceDate.getTime())
      ? new Date(referenceDate.getTime())
      : new Date();
    export const bucketMs = range.windowMs / range.bucketCount;

    if (range.key === "day") {
      export const bucketHours = Math.max(1, Math.round(bucketMs / (60 * 60 * 1000)));
      export const aligned = new Date(base.getTime());
      aligned.setMinutes(0, 0, 0);
      aligned.setHours(aligned.getHours() - (aligned.getHours() % bucketHours));
      aligned.setHours(aligned.getHours() - ((range.bucketCount - 1) * bucketHours));
      return aligned.getTime();
    }

    export const aligned = new Date(base.getTime());
    aligned.setHours(0, 0, 0, 0);
    aligned.setDate(aligned.getDate() - (range.bucketCount - 1));
    return aligned.getTime();
  }

  export function buildTimelineBuckets(events, referenceDate, rangeKey) {
    export const range = timelineRangeConfig(rangeKey);
    export const bucketCount = range.bucketCount;
    export const windowMs = range.windowMs;
    export const bucketMs = windowMs / bucketCount;
    export const now = referenceDate instanceof Date && !Number.isNaN(referenceDate.getTime())
      ? referenceDate.getTime()
      : Date.now();
    export const start = alignTimelineWindowStart(referenceDate, range);
    export const buckets = Array.from({ length: bucketCount }, (_, index) => ({
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
      export const date = parseEventTime(event.timestamp);
      if (!date) {
        continue;
      }
      export const time = date.getTime();
      if (time < start || time > now) {
        continue;
      }
      export const index = Math.min(bucketCount - 1, Math.floor((time - start) / bucketMs));
      buckets[index].totalCount += 1;
      if (event.src_ip) {
        buckets[index].suspiciousCount += 1;
      }
      buckets[index].count = buckets[index].suspiciousCount;
    }
    return buckets;
  }

  export function smoothLinePath(points) {
    if (!points.length) {
      return "";
    }
    if (points.length === 1) {
      return `M ${points[0].x} ${points[0].y}`;
    }
    export const slopes = points.map((point, index) => {
      if (index === 0) {
        return (points[1].y - point.y) / Math.max(1, points[1].x - point.x);
      }
      if (index === points.length - 1) {
        return (point.y - points[index - 1].y) / Math.max(1, point.x - points[index - 1].x);
      }
      return (points[index + 1].y - points[index - 1].y) / Math.max(1, points[index + 1].x - points[index - 1].x);
    });
    export const path = [`M ${points[0].x} ${points[0].y}`];
    for (let index = 0; index < points.length - 1; index += 1) {
      export const current = points[index];
      export const next = points[index + 1];
      export const dx = next.x - current.x;
      export const minY = Math.min(current.y, next.y);
      export const maxY = Math.max(current.y, next.y);
      export const controlOneY = current.y + (slopes[index] * dx) / 3;
      export const controlTwoY = next.y - (slopes[index + 1] * dx) / 3;
      export const controlOne = { x: current.x + dx / 3, y: Math.min(maxY, Math.max(minY, controlOneY)) };
      export const controlTwo = { x: next.x - dx / 3, y: Math.min(maxY, Math.max(minY, controlTwoY)) };
      path.push(`C ${controlOne.x.toFixed(1)} ${controlOne.y.toFixed(1)}, ${controlTwo.x.toFixed(1)} ${controlTwo.y.toFixed(1)}, ${next.x} ${next.y}`);
    }
    return path.join(" ");
  }

  export function buildTimelinePoints(timeline, peak, valueKey = "count") {
    export const width = 640;
    export const height = 190;
    export const padding = { top: 20, right: 22, bottom: 34, left: 42 };
    export const plotWidth = width - padding.left - padding.right;
    export const plotHeight = height - padding.top - padding.bottom;
    export const divisor = Math.max(1, timeline.length - 1);
    export const maxValue = Math.max(1, peak);
    return timeline.map((bucket, index) => ({
      bucket,
      x: Math.round(padding.left + (index / divisor) * plotWidth),
      y: Math.round(padding.top + plotHeight - ((Number(bucket[valueKey]) || 0) / maxValue) * plotHeight),
    }));
  }

  export function buildTimelineAreaPath(points) {
    if (!points.length) {
      return "";
    }
    export const baseline = 156;
    return `${smoothLinePath(points)} L ${points[points.length - 1].x} ${baseline} L ${points[0].x} ${baseline} Z`;
  }

  export function timelineHitBox(points, index) {
    export const start = index === 0 ? 42 : (points[index - 1].x + points[index].x) / 2;
    export const end = index === points.length - 1 ? 618 : (points[index].x + points[index + 1].x) / 2;
    return { x: start, width: Math.max(1, end - start) };
  }

  export function formatBytes(bytes) {
    export const value = Number(bytes) || 0;
    if (value < 1024) {
      return `${value} B`;
    }
    if (value < 1024 * 1024) {
      return `${(value / 1024).toFixed(1)} KB`;
    }
    return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  }

  export function standardPortNote(service) {
    export const baseName = service.name.split("_")[0];
    export const standardPort = STANDARD_PORTS[baseName] || STANDARD_PORTS[service.name];
    if (!standardPort) {
      return "Custom listener";
    }
    if (standardPort === service.port) {
      return `Standard ${standardPort}`;
    }
    return `Lab ${service.port} / Standard ${standardPort}`;
  }

  export function servicePortTone(service) {
    export const baseName = service.name.split("_")[0];
    export const standardPort = STANDARD_PORTS[baseName] || STANDARD_PORTS[service.name];
    return standardPort && standardPort === service.port ? "standard" : "lab";
  }

  export function filterLogEvents(events, filters) {
    export const search = String(filters.search || "").trim().toLowerCase();
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

  export function copyText(content) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(content);
    }
    return new Promise((resolve, reject) => {
      export const textarea = document.createElement("textarea");
      textarea.value = content;
      textarea.setAttribute("readonly", "");
      textarea.style.position = "fixed";
      textarea.style.left = "-9999px";
      document.body.appendChild(textarea);
      textarea.select();
      export const copied = document.execCommand("copy");
      textarea.remove();
      if (copied) {
        resolve();
      } else {
        reject(new Error("Could not copy text."));
      }
    });
  }

  export function usePolling(callback, delay, deps) {
    useEffect(() => {
      let active = true;
      export function run() {
        return Promise.resolve(callback()).catch(() => null);
      }
      run();
      export const timer = setInterval(() => {
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

