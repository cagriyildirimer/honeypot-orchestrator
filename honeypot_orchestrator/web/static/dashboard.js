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
const RISK_EVENT_WEIGHTS = {
  login_failed: 8,
  login_attempt: 12,
  auth_failed: 12,
  credential_attempt: 14,
  connection_opened: 5,
  request_error: 6,
  service_stopped: 3,
  service_started: 2,
  profile_changed: 1,
  started: 1,
  stopping: 1,
  login_success: 0,
};

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

function summarizeRangeLabel(start, end) {
  return `${start.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} - ${end.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
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
  return eventType.includes("fail") || eventType.includes("error") ? 8 : 4;
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
    hottestService: {
      name: hottestService[0],
      value: hottestService[1],
    },
    activeTypeCount: Object.keys(typeTotals).length,
    strongestBucket,
    topServices,
    buckets,
    summary:
      score >= 65
        ? `Traffic clustered around ${text(hottestService[0])} during the busiest window.`
        : score >= 20
          ? `Recent pressure is centered on ${text(hottestService[0])}.`
          : "No meaningful burst pattern in the recent event window.",
  };
}

function renderRiskGauge(model) {
  const container = document.querySelector("#riskPulseGauge");
  if (!container) {
    return;
  }
  const score = Math.max(0, Math.min(100, Number(model && model.score) || 0));
  const radius = 76;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference * (1 - score / 100);
  container.innerHTML = `
    <defs>
      <linearGradient id="riskGaugeGradient" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="var(--risk-gauge-start)"></stop>
        <stop offset="100%" stop-color="var(--risk-gauge-end)"></stop>
      </linearGradient>
    </defs>
    <circle class="risk-gauge-track" cx="110" cy="110" r="${radius}"></circle>
    <circle
      class="risk-gauge-value"
      cx="110"
      cy="110"
      r="${radius}"
      stroke-dasharray="${circumference.toFixed(2)}"
      stroke-dashoffset="${dashOffset.toFixed(2)}"
    ></circle>
    <circle class="risk-gauge-core" cx="110" cy="110" r="58"></circle>
    <text class="risk-gauge-score" x="110" y="104" text-anchor="middle">${score}</text>
    <text class="risk-gauge-label" x="110" y="126" text-anchor="middle">${text(model.band.label)}</text>
  `;
}

function renderActivityHeat(model) {
  const container = document.querySelector("#activityHeat");
  if (!container) {
    return;
  }
  const services = model.topServices.length ? model.topServices : ["web", "orchestrator"];
  const peak = Math.max(
    1,
    ...model.buckets.flatMap((bucket) => services.map((service) => Number(bucket.counts[service] || 0)))
  );
  container.innerHTML = "";
  container.style.setProperty("--heat-columns", String(model.buckets.length));

  const corner = document.createElement("div");
  corner.className = "heat-corner";
  corner.textContent = "Service";
  container.appendChild(corner);

  model.buckets.forEach((bucket) => {
    const label = document.createElement("div");
    label.className = "heat-time-label";
    label.textContent = bucket.start.toLocaleTimeString([], { hour: "2-digit" });
    container.appendChild(label);
  });

  services.forEach((service) => {
    const rowLabel = document.createElement("div");
    rowLabel.className = "heat-service-label";
    rowLabel.textContent = text(service);
    container.appendChild(rowLabel);

    model.buckets.forEach((bucket) => {
      const value = Number(bucket.counts[service] || 0);
      const intensity = Math.min(1, value / peak);
      const cell = document.createElement("div");
      cell.className = "heat-cell";
      cell.style.setProperty("--heat-intensity", intensity.toFixed(3));
      cell.setAttribute(
        "aria-label",
        `${service} ${summarizeRangeLabel(bucket.start, bucket.end)} ${value.toFixed(1)} weighted events`
      );
      cell.title = `${text(service)} | ${summarizeRangeLabel(bucket.start, bucket.end)} | ${value.toFixed(1)} weighted`;
      if (value <= 0.05) {
        cell.dataset.level = "quiet";
      } else if (intensity >= 0.78) {
        cell.dataset.level = "hot";
      } else if (intensity >= 0.4) {
        cell.dataset.level = "warm";
      } else {
        cell.dataset.level = "cool";
      }
      container.appendChild(cell);
    });
  });

  setText("#activityHeatSummary", `${Math.round(model.weightedTotal)} signals`);
}

function renderRiskPanel(events) {
  const model = buildRiskModel(events);
  const panel = document.querySelector(".risk-panel");
  if (panel) {
    panel.dataset.riskTone = model.band.tone;
  }
  renderRiskGauge(model);
  renderActivityHeat(model);
  setText("#riskBand", model.band.label);
  setText("#riskHeadline", model.band.headline);
  setText("#riskNarrative", model.summary);
  setText(
    "#riskBurstWindow",
    model.burstScore > 0 ? summarizeRangeLabel(model.strongestBucket.start, model.strongestBucket.end) : "None"
  );
  setText("#riskBurstValue", `${Math.round(model.burstScore)} weighted events`);
  setText("#riskHotService", text(model.hottestService.name));
  setText("#riskHotServiceValue", `${Math.round(model.hottestService.value)} weighted events`);
  setText("#riskTypeCount", String(model.activeTypeCount));
  setText("#riskTypeLabel", model.activeTypeCount ? "Distinct event types seen" : "No suspicious event mix");
  setText("#activityHeatSubtitle", "Last 24 hours in four-hour slices.");
}

function renderDashboard(payload) {
  const stats = payload.stats || {};
  const profile = payload.profile || null;
  const services = payload.services || [];
  state.lastEvents = payload.events || [];
  renderServiceDonut(stats);
  renderRiskPanel(state.lastEvents);
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
