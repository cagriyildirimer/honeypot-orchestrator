const state = {
  username: "",
  role: "",
  timelineRange: "day",
  lastEvents: [],
  refreshTimer: null,
  refreshInFlight: false,
};

const TIMELINE_RANGES = {
  day: {
    label: "Daily",
    subtitle: "Event volume across the last 24 hours.",
    windowMs: 24 * 60 * 60 * 1000,
    bucketCount: 12,
  },
  week: {
    label: "Weekly",
    subtitle: "Event volume across the last 7 days.",
    windowMs: 7 * 24 * 60 * 60 * 1000,
    bucketCount: 7,
  },
  month: {
    label: "Monthly",
    subtitle: "Event volume across the last 30 days.",
    windowMs: 30 * 24 * 60 * 60 * 1000,
    bucketCount: 10,
  },
};

const DONUT_COLORS = ["#14b8a6", "#2563eb", "#f59e0b", "#ef4444", "#8b5cf6", "#10b981", "#64748b"];

function renderEvents(events, fallbackProfile) {
  const body = document.querySelector("#events");
  if (!body) {
    return;
  }
  body.innerHTML = "";

  if (!events.length) {
    const row = document.createElement("tr");
    row.innerHTML = '<td colspan="6" class="empty-row">No events captured yet.</td>';
    body.appendChild(row);
    return;
  }

  for (const event of events) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${text(formatTimestamp(event.timestamp))}</td>
      <td>${text(event.service)}</td>
      <td><span class="table-chip">${text(event.event_type)}</span></td>
      <td>${text(formatEventSource(event))}</td>
      <td>${text(event.profile || fallbackProfile)}</td>
      <td>${summarizeEvent(event)}</td>
    `;
    body.appendChild(row);
  }
}

function parseEventTime(value) {
  if (!value) {
    return null;
  }
  const normalized = String(value).replace(" UTC", "Z").replace(" ", "T");
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
}

function buildTimelineBuckets(events, rangeKey) {
  const range = TIMELINE_RANGES[rangeKey] || TIMELINE_RANGES.day;
  const bucketCount = range.bucketCount;
  const windowMs = range.windowMs;
  const bucketMs = windowMs / bucketCount;
  const now = Date.now();
  const start = now - windowMs;
  const buckets = Array.from({ length: bucketCount }, (_, index) => ({
    count: 0,
    start: new Date(start + index * bucketMs),
  }));

  for (const event of events || []) {
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

function formatTimelineLabel(date, rangeKey) {
  if (rangeKey === "day") {
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  return date.toLocaleDateString([], { month: "short", day: "2-digit" });
}

function renderTimeline(events) {
  const container = document.querySelector("#eventTimeline");
  if (!container) {
    return;
  }
  const range = TIMELINE_RANGES[state.timelineRange] || TIMELINE_RANGES.day;
  const buckets = buildTimelineBuckets(events, state.timelineRange);
  const total = buckets.reduce((sum, bucket) => sum + bucket.count, 0);
  const max = Math.max(1, ...buckets.map((bucket) => bucket.count));
  const width = 720;
  const height = 190;
  const padding = { top: 16, right: 16, bottom: 34, left: 34 };
  const innerWidth = width - padding.left - padding.right;
  const innerHeight = height - padding.top - padding.bottom;
  const points = buckets.map((bucket, index) => {
    const x = padding.left + (index / Math.max(1, buckets.length - 1)) * innerWidth;
    const y = padding.top + innerHeight - (bucket.count / max) * innerHeight;
    return { x, y, bucket };
  });
  const linePath = smoothPath(points);
  const areaPath = `${linePath} L ${points[points.length - 1].x.toFixed(1)} ${padding.top + innerHeight} L ${points[0].x.toFixed(1)} ${padding.top + innerHeight} Z`;
  const yTicks = [0, Math.ceil(max / 2), max];
  const labelStep = state.timelineRange === "day" ? 3 : 2;
  const xLabels = points.filter((_, index) => index % labelStep === 0 || index === points.length - 1);

  container.innerHTML = `
    <svg class="timeline-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Event timeline for ${range.label.toLowerCase()} range">
      <line class="timeline-axis" x1="${padding.left}" y1="${padding.top + innerHeight}" x2="${width - padding.right}" y2="${padding.top + innerHeight}"></line>
      ${yTicks.map((tick) => {
        const y = padding.top + innerHeight - (tick / max) * innerHeight;
        return `
          <line class="timeline-grid-line" x1="${padding.left}" y1="${y.toFixed(1)}" x2="${width - padding.right}" y2="${y.toFixed(1)}"></line>
          <text class="timeline-label" x="8" y="${(y + 4).toFixed(1)}">${tick}</text>
        `;
      }).join("")}
      <path class="timeline-area" d="${areaPath}"></path>
      <path class="timeline-line" d="${linePath}"></path>
      ${points.map((point, index) => `
        <rect
          class="timeline-hit-zone"
          x="${(point.x - innerWidth / Math.max(1, points.length - 1) / 2).toFixed(1)}"
          y="${padding.top}"
          width="${(innerWidth / Math.max(1, points.length - 1)).toFixed(1)}"
          height="${innerHeight}"
          data-index="${index}"
        ></rect>
      `).join("")}
      ${xLabels.map((point) => `
        <text class="timeline-label" text-anchor="middle" x="${point.x.toFixed(1)}" y="${height - 8}">
          ${formatTimelineLabel(point.bucket.start, state.timelineRange)}
        </text>
      `).join("")}
    </svg>
    <div id="timelineTooltip" class="timeline-tooltip" hidden></div>
  `;
  setText("#timelineSummary", `${total} event${total === 1 ? "" : "s"}`);
  setText("#timelineSubtitle", range.subtitle);
  document.querySelectorAll("[data-timeline-range]").forEach((button) => {
    button.classList.toggle("active", button.dataset.timelineRange === state.timelineRange);
  });
  bindTimelineTooltip(container, points, width, height);
}

function smoothPath(points) {
  if (!points.length) {
    return "";
  }
  if (points.length === 1) {
    return `M ${points[0].x.toFixed(1)} ${points[0].y.toFixed(1)}`;
  }
  const commands = [`M ${points[0].x.toFixed(1)} ${points[0].y.toFixed(1)}`];
  for (let index = 0; index < points.length - 1; index += 1) {
    const current = points[index];
    const next = points[index + 1];
    const controlOffset = (next.x - current.x) * 0.42;
    const c1x = current.x + controlOffset;
    const c1y = current.y;
    const c2x = next.x - controlOffset;
    const c2y = next.y;
    commands.push(`C ${c1x.toFixed(1)} ${c1y.toFixed(1)}, ${c2x.toFixed(1)} ${c2y.toFixed(1)}, ${next.x.toFixed(1)} ${next.y.toFixed(1)}`);
  }
  return commands.join(" ");
}

function bindTimelineTooltip(container, points, width, height) {
  const tooltip = container.querySelector("#timelineTooltip");
  const svg = container.querySelector(".timeline-svg");
  if (!tooltip || !svg) {
    return;
  }
  container.querySelectorAll(".timeline-hit-zone").forEach((zone) => {
    zone.addEventListener("mousemove", (event) => {
      const point = points[Number(zone.dataset.index) || 0];
      const rect = svg.getBoundingClientRect();
      const scaleX = rect.width / width;
      const scaleY = rect.height / height;
      tooltip.hidden = false;
      tooltip.innerHTML = `
        <strong>${point.bucket.count} event${point.bucket.count === 1 ? "" : "s"}</strong>
        <span>${formatTimelineLabel(point.bucket.start, state.timelineRange)}</span>
      `;
      const left = point.x * scaleX;
      const top = point.y * scaleY;
      tooltip.style.left = `${Math.min(Math.max(12, left - 54), rect.width - 116)}px`;
      tooltip.style.top = `${Math.max(10, top - 46)}px`;
      event.stopPropagation();
    });
    zone.addEventListener("mouseleave", () => {
      tooltip.hidden = true;
    });
  });
  container.addEventListener("mouseleave", () => {
    tooltip.hidden = true;
  });
}

function polarToCartesian(center, radius, angleInDegrees) {
  const angleInRadians = ((angleInDegrees - 90) * Math.PI) / 180;
  return {
    x: center + radius * Math.cos(angleInRadians),
    y: center + radius * Math.sin(angleInRadians),
  };
}

function describeArc(center, radius, startAngle, endAngle) {
  const start = polarToCartesian(center, radius, endAngle);
  const end = polarToCartesian(center, radius, startAngle);
  const largeArcFlag = endAngle - startAngle <= 180 ? "0" : "1";
  return [
    "M", start.x.toFixed(2), start.y.toFixed(2),
    "A", radius, radius, 0, largeArcFlag, 0, end.x.toFixed(2), end.y.toFixed(2),
  ].join(" ");
}

function renderServiceDonut(stats) {
  const container = document.querySelector("#serviceDonut");
  const legend = document.querySelector("#serviceDonutLegend");
  if (!container || !legend) {
    return;
  }
  const entries = Object.entries((stats && stats.by_service) || {})
    .filter(([, count]) => Number(count) > 0)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 7);
  const total = entries.reduce((sum, [, count]) => sum + Number(count), 0);
  setText("#donutSummary", `${total} event${total === 1 ? "" : "s"}`);
  legend.innerHTML = "";

  if (!entries.length) {
    container.innerHTML = `
      <svg class="donut-svg" viewBox="0 0 180 180" role="img" aria-label="No service activity">
        <circle class="donut-empty" cx="90" cy="90" r="58"></circle>
        <text class="donut-center-label" x="90" y="86" text-anchor="middle">No</text>
        <text class="donut-center-sub" x="90" y="105" text-anchor="middle">events</text>
      </svg>
    `;
    return;
  }

  let currentAngle = 0;
  const arcs = entries.map(([service, count], index) => {
    const value = Number(count);
    const angle = (value / total) * 360;
    const startAngle = currentAngle;
    const endAngle = currentAngle + angle;
    currentAngle = endAngle;
    const color = DONUT_COLORS[index % DONUT_COLORS.length];
    const percent = Math.round((value / total) * 100);
    return {
      service,
      value,
      percent,
      color,
      fullCircle: angle >= 359.99,
      path: describeArc(90, 58, startAngle, endAngle),
    };
  });

  container.innerHTML = `
    <svg class="donut-svg" viewBox="0 0 180 180" role="img" aria-label="Service activity distribution">
      <circle class="donut-track" cx="90" cy="90" r="58"></circle>
      ${arcs.map((arc, index) => arc.fullCircle ? `
        <circle
          class="donut-segment"
          cx="90"
          cy="90"
          r="58"
          stroke="${arc.color}"
          data-index="${index}"
        ></circle>
      ` : `
        <path
          class="donut-segment"
          d="${arc.path}"
          stroke="${arc.color}"
          data-index="${index}"
        ></path>
      `).join("")}
      <text class="donut-center-label" x="90" y="86" text-anchor="middle">${total}</text>
      <text class="donut-center-sub" x="90" y="105" text-anchor="middle">events</text>
    </svg>
    <div id="donutTooltip" class="timeline-tooltip" hidden></div>
  `;

  for (const arc of arcs) {
    const item = document.createElement("li");
    item.innerHTML = `
      <span><i style="background:${arc.color}"></i>${text(arc.service)}</span>
      <strong>${arc.value}</strong>
    `;
    legend.appendChild(item);
  }

  bindDonutTooltip(container, arcs);
}

function bindDonutTooltip(container, arcs) {
  const tooltip = container.querySelector("#donutTooltip");
  if (!tooltip) {
    return;
  }
  container.querySelectorAll(".donut-segment").forEach((segment) => {
    segment.addEventListener("mousemove", (event) => {
      const arc = arcs[Number(segment.dataset.index) || 0];
      const rect = container.getBoundingClientRect();
      tooltip.hidden = false;
      tooltip.innerHTML = `
        <strong>${text(arc.service)}</strong>
        <span>${arc.value} event${arc.value === 1 ? "" : "s"} · ${arc.percent}%</span>
      `;
      tooltip.style.left = `${Math.min(Math.max(8, event.clientX - rect.left - 52), rect.width - 120)}px`;
      tooltip.style.top = `${Math.min(Math.max(8, event.clientY - rect.top - 48), rect.height - 58)}px`;
    });
    segment.addEventListener("mouseleave", () => {
      tooltip.hidden = true;
    });
  });
  container.addEventListener("mouseleave", () => {
    tooltip.hidden = true;
  });
}

function renderDashboard(payload) {
  const stats = payload.stats || {};
  const profile = payload.profile || null;
  const services = payload.services || [];
  state.lastEvents = payload.events || [];
  renderServiceDonut(stats);
  renderEvents((payload.events || []).slice(0, 10), profile && profile.current ? profile.current.name : "-");
  renderTimeline(state.lastEvents);

  const running = services.filter((service) => service.running).length;
  setText("#sessionUser", state.username || "-");
  setText("#runningServices", String(running));
  setText("#serviceFootnote", `${running} of ${services.length} profile listeners are currently online.`);
  setText("#activeProfile", text(profile && profile.current ? profile.current.display_name : "-"));
  setText("#loginAttempts", String((stats.by_type && stats.by_type.login_attempt) || 0));
  setText("#heroTotalEvents", String(stats.total_recent_events || 0));
}

async function refreshDashboard() {
  if (state.refreshInFlight) {
    return;
  }
  state.refreshInFlight = true;
  try {
    const payload = await requestJson("/api/overview?limit=1000");
    renderDashboard(payload);
  } catch (error) {
    showToast(error.message, "error");
    if (error.message === "Authentication required.") {
      window.location.replace("/login");
    }
  } finally {
    state.refreshInFlight = false;
  }
}

function startAutoRefresh() {
  stopAutoRefresh();
  state.refreshTimer = setInterval(refreshDashboard, 5000);
}

function stopAutoRefresh() {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
    state.refreshTimer = null;
  }
}

async function bootstrapDashboard() {
  document.querySelector("#logoutButton")?.addEventListener("click", () => {
    stopAutoRefresh();
    logoutAndRedirect();
  });
  document.querySelector("#refreshButton")?.addEventListener("click", refreshDashboard);
  document.querySelectorAll("[data-timeline-range]").forEach((button) => {
    button.addEventListener("click", () => {
      state.timelineRange = button.dataset.timelineRange || "day";
      renderTimeline(state.lastEvents);
    });
  });

  try {
    const session = await ensureAuthenticated();
    state.username = session.username || "";
    state.role = session.role || "";
    await refreshDashboard();
    startAutoRefresh();
  } catch (error) {
    window.location.replace("/login");
  }
}

bootstrapDashboard();
