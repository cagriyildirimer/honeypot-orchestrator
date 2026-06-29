const h = React.createElement;
const { useEffect, useState, useRef, useMemo } = React;
import { NAV_ITEMS, SETTINGS_ITEMS, isSettingsPage } from '../utils.js';
export function Skeleton(props) {
  return h("div", { 
    className: `skeleton ${props.className || ""}`, 
    style: { width: "100%", height: "20px", ...props.style } 
  });
}

export function PageSkeleton() {
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

export function NavLink(props) {
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

export function AnimatedCounter(props) {
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

export function MetricCard(props) {
  return h(
    "article",
    { className: "metric-card" },
    h("span", null, props.label),
    h(AnimatedCounter, { value: props.value }),
    h("small", null, props.note)
  );
}

export function AppLayout(props) {
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
    h(
      "span",
      { className: "brand-mark" },
      h(
        "svg",
        {
          viewBox: "0 0 100 100",
          fill: "none",
          stroke: "currentColor",
          strokeWidth: "8px",
          style: { width: "18px", height: "18px", display: "block" }
        },
        h("polygon", { points: "50,14 65.6,23 65.6,41 50,50 34.4,41 34.4,23" }),
        h("polygon", { points: "34.4,41 50,50 50,68 34.4,77 18.8,68 18.8,50" }),
        h("polygon", { points: "65.6,41 81.2,50 81.2,68 65.6,77 50,68 50,50" })
      )
    ),
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
    h(
      "span",
      { className: "brand-mark" },
      h(
        "svg",
        {
          viewBox: "0 0 100 100",
          fill: "none",
          stroke: "currentColor",
          strokeWidth: "8px",
          style: { width: "18px", height: "18px", display: "block" }
        },
        h("polygon", { points: "50,14 65.6,23 65.6,41 50,50 34.4,41 34.4,23" }),
        h("polygon", { points: "34.4,41 50,50 50,68 34.4,77 18.8,68 18.8,50" }),
        h("polygon", { points: "65.6,41 81.2,50 81.2,68 65.6,77 50,68 50,50" })
      )
    ),
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
    ),
    h(NotificationBellPortal, { page: props.page })
  );
}

export function NotificationBellPortal(props) {
  const [portalTarget, setPortalTarget] = useState(null);

  useEffect(() => {
    let debounceTimer;
    const updateTarget = () => {
      const target = document.querySelector(".page-actions, .topbar-actions");
      setPortalTarget(target);
    };

    const debouncedUpdate = () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(updateTarget, 100);
    };

    updateTarget();
    const timer = setTimeout(updateTarget, 50);

    const observer = new MutationObserver(debouncedUpdate);
    observer.observe(document.body, { childList: true, subtree: true });

    return () => {
      clearTimeout(timer);
      clearTimeout(debounceTimer);
      observer.disconnect();
    };
  }, [props.page]);

  if (!portalTarget) return null;

  return ReactDOM.createPortal(h(NotificationBell, null), portalTarget);
}

export function NotificationBell() {
  const [alerts, setAlerts] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const es = new EventSource("/api/alerts/stream");
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.type === "ping") return;
        if (data.alerts && data.alerts.length > 0) {
          setAlerts(prev => {
            const newAlerts = [...data.alerts, ...prev].slice(0, 50); // keep last 50
            return newAlerts;
          });
          setUnreadCount(prev => prev + data.alerts.length);
          
          const latest = data.alerts[0];
          window.showToast(`🚨 ${latest.summary}`, "error");
        }
      } catch (err) {
        console.error("SSE parse error", err);
      }
    };
    return () => es.close();
  }, []);

  return h("div", { className: "notification-bell-container", style: { position: "relative", zIndex: 999, flexShrink: 0 } },
    h("button", { 
      className: "bell-btn", 
      onClick: () => { setOpen(!open); setUnreadCount(0); },
      style: { background: "transparent", border: "none", width: "38px", height: "38px", cursor: "pointer", position: "relative", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, color: "var(--accent, #0075ff)", padding: 0 }
    },
      h("svg", {
        width: "22",
        height: "22",
        viewBox: "0 0 24 24",
        fill: "none",
        stroke: "currentColor",
        strokeWidth: "2.2",
        strokeLinecap: "round",
        strokeLinejoin: "round",
        style: { display: "block" }
      },
        h("path", { d: "M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" }),
        h("path", { d: "M13.73 21a2 2 0 0 1-3.46 0" })
      ),
      unreadCount > 0 ? h("span", { 
        className: "badge", 
        style: { position: "absolute", top: "0px", right: "0px", background: "var(--danger)", color: "#ffffff", borderRadius: "10px", padding: "2px 6px", fontSize: "11px", fontWeight: "bold", border: "2px solid var(--surface-strong)" } 
      }, unreadCount > 99 ? "99+" : unreadCount) : null
    ),
    open ? h("div", { 
      className: "dropdown-menu", 
      style: { position: "absolute", top: "48px", right: "0", width: "320px", background: "var(--surface-strong, #131c44)", border: "1px solid var(--border)", borderRadius: "8px", padding: "0", boxShadow: "var(--shadow)", maxHeight: "400px", overflowY: "auto", overflowX: "hidden" } 
    },
      h("div", { style: { padding: "12px 16px", borderBottom: "1px solid var(--border)", background: "var(--glass-header-bg)", fontWeight: "600", fontSize: "14px" } }, "Notifications"),
      alerts.length === 0 ? h("p", { style: { textAlign: "center", color: "var(--muted)", margin: "20px 0" } }, "No recent alerts.") : null,
      alerts.map((a, i) => h("div", { key: i, style: { padding: "12px 16px", borderBottom: "1px solid var(--border)", fontSize: "13px", background: a.type === "aggregated" ? "var(--danger-soft, rgba(227, 26, 26, 0.16))" : "transparent" } },
        h("strong", { style: { color: "var(--danger)", display: "block", marginBottom: "4px" } }, a.type === "aggregated" ? "Aggregated Alert" : "Critical Alert"),
        h("div", { style: { color: "var(--muted-strong)", lineHeight: "1.4" } }, a.summary),
        h("div", { style: { color: "var(--muted)", marginTop: "6px", fontSize: "11px", display: "flex", justifyContent: "space-between" } }, 
          h("span", null, `IP: ${a.src_ip || "Unknown"}`),
          a.service ? h("span", { style: { background: "var(--tag-neutral-bg)", padding: "2px 6px", borderRadius: "4px" } }, a.service) : null
        )
      ))
    ) : null
  );
}

export function EventDrawer(props) {
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

export function GeoWorldMap(props) {
  const containerRef = React.useRef(null);
  const globeRef = React.useRef(null);
  const markers = props.markers || [];

  // Initialize the globe and window resize listener
  React.useEffect(() => {
    if (!containerRef.current) return;
    if (!globeRef.current && window.Globe) {
      const parent = containerRef.current.parentElement;
      const initialWidth = parent ? Math.min(800, parent.clientWidth) : 800;
      const initialHeight = Math.min(400, Math.max(250, initialWidth * 0.5));

      globeRef.current = window.Globe()(containerRef.current)
        .globeImageUrl('//unpkg.com/three-globe/example/img/earth-blue-marble.jpg')
        .bumpImageUrl('//unpkg.com/three-globe/example/img/earth-topology.png')
        .backgroundColor('rgba(0,0,0,0)')
        .width(initialWidth)
        .height(initialHeight)
        .pointOfView({ altitude: 2.0 });

      globeRef.current.controls().autoRotate = true;
      globeRef.current.controls().autoRotateSpeed = 1.0;
      globeRef.current.controls().enableZoom = false;
    }

    const handleResize = () => {
      if (containerRef.current && containerRef.current.parentElement && globeRef.current) {
        const w = Math.min(800, containerRef.current.parentElement.clientWidth);
        const h = Math.min(400, Math.max(250, w * 0.5));
        globeRef.current.width(w).height(h);
      }
    };

    window.addEventListener('resize', handleResize);
    // Ensure size is correct after layout settles
    const timer = setTimeout(handleResize, 100);

    return () => {
      window.removeEventListener('resize', handleResize);
      clearTimeout(timer);
    };
  }, []);

  // Update marker points when data changes
  React.useEffect(() => {
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

  return h("div", { className: "geo-map-container", style: { display: 'flex', justifyContent: 'center', minHeight: '400px', position: 'relative', width: '100%', overflow: 'hidden' } },
    h("div", { ref: containerRef, style: { width: '100%', overflow: 'hidden', display: 'flex', justifyContent: 'center' } }),
    markers.length === 0 ? h("div", { className: "geo-empty", style: { position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', pointerEvents: 'none' } }, "No external attacker IPs detected yet.") : null
  );
}

function abuseScoreLevel(score) {
  if (typeof score !== "number") return "low";
  if (score >= 80) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

export function ThreatIntelPanel(props) {
  const data = props.data;
  if (!data) {
    return h(
      "section",
      { className: "panel ti-panel", id: "ti-panel" },
      h(
        "div",
        { className: "section-heading" },
        h("div", null,
          h("h2", null, "Threat Intelligence"),
          h("p", null, "Enrichment data for top attacker IPs (last 24h).")
        ),
        h("span", { className: "status-counter" }, "Loading...")
      ),
      h("div", { className: "ti-empty" },
        h("div", { className: "ti-empty-icon" }, "\uD83D\uDD0D"),
        "Loading threat intelligence data..."
      )
    );
  }

  const attackers = data.attackers || [];
  const summary = data.summary || {};

  if (attackers.length === 0) {
    return h(
      "section",
      { className: "panel ti-panel", id: "ti-panel" },
      h(
        "div",
        { className: "section-heading" },
        h("div", null,
          h("h2", null, "Threat Intelligence"),
          h("p", null, "Enrichment data for top attacker IPs (last 24h).")
        )
      ),
      h("div", { className: "ti-empty" },
        h("div", { className: "ti-empty-icon" }, "\uD83D\uDEE1\uFE0F"),
        "No external attacker IPs detected in the last 24 hours."
      )
    );
  }

  return h(
    "section",
    { className: "panel ti-panel", id: "ti-panel" },
    h(
      "div",
      { className: "section-heading" },
      h("div", null,
        h("h2", null, "Threat Intelligence"),
        h("p", null, "Enrichment data for top attacker IPs (last 24h).")
      ),
      h("span", { className: "status-counter" }, `${attackers.length} IPs enriched`)
    ),
    // Summary pills
    h(
      "div",
      { className: "ti-summary-pills" },
      h(
        "div",
        { className: "ti-pill" },
        h("div", { className: "ti-pill-icon tor" }, "\uD83E\uDDC5"),
        h(
          "div",
          { className: "ti-pill-info" },
          h("span", { className: "ti-pill-label" }, "Tor Exit Nodes"),
          h("span", { className: "ti-pill-value" }, String(summary.tor_count || 0))
        )
      ),
      h(
        "div",
        { className: "ti-pill" },
        h("div", { className: "ti-pill-icon cloud" }, "\u2601\uFE0F"),
        h(
          "div",
          { className: "ti-pill-info" },
          h("span", { className: "ti-pill-label" }, "Cloud Providers"),
          h("span", { className: "ti-pill-value" }, String(summary.cloud_count || 0))
        )
      ),
      h(
        "div",
        { className: "ti-pill" },
        h("div", { className: "ti-pill-icon abuse" }, "\u26A0\uFE0F"),
        h(
          "div",
          { className: "ti-pill-info" },
          h("span", { className: "ti-pill-label" }, "Avg Abuse Score"),
          h("span", { className: "ti-pill-value" },
            typeof summary.avg_abuse_score === "number"
              ? String(summary.avg_abuse_score)
              : "N/A"
          )
        )
      )
    ),
    // Top 10 attacker table
    h(
      "div",
      { className: "table-shell ti-table-wrap" },
      h(
        "table",
        { className: "ti-table" },
        h(
          "thead",
          null,
          h(
            "tr",
            null,
            h("th", null, "IP"),
            h("th", null, "Location"),
            h("th", null, "rDNS"),
            h("th", null, "ASN"),
            h("th", null, "Tor"),
            h("th", null, "Cloud"),
            h("th", null, "Abuse Score"),
            h("th", null, "GreyNoise"),
            h("th", null, "Events")
          )
        ),
        h(
          "tbody",
          null,
          attackers.map(function (attacker, idx) {
            var abuseScore = attacker.abuse_score;
            var isNumericAbuse = typeof abuseScore === "number";
            var location = [attacker.city, attacker.country].filter(Boolean).join(", ") || "Unknown";
            var gnClass = String(attacker.greynoise_class || "n/a").toLowerCase();

            return h(
              "tr",
              { key: attacker.ip || idx },
              h("td", { className: "ti-ip-cell" }, attacker.ip),
              h("td", null, location),
              h("td", { className: "ti-rdns-cell", title: attacker.rdns || "" },
                attacker.rdns && attacker.rdns !== attacker.ip ? attacker.rdns : "\u2014"
              ),
              h("td", { className: "ti-asn-cell" },
                attacker.asn
                  ? [attacker.asn, attacker.org ? h("span", { key: "org", style: { color: "var(--muted)", marginLeft: "6px" } }, attacker.org) : null]
                  : "\u2014"
              ),
              h("td", null,
                h("span", { className: "tor-indicator" + (attacker.is_tor ? " active" : "") },
                  "\uD83E\uDDC5",
                  attacker.is_tor ? h("span", { className: "tor-label" }, "Yes") : null
                )
              ),
              h("td", null,
                h("span", { className: "cloud-cell" + (attacker.cloud_provider ? "" : " none") },
                  attacker.cloud_provider || "\u2014"
                )
              ),
              h("td", null,
                isNumericAbuse
                  ? h(
                      "div",
                      { className: "abuse-bar-wrap" },
                      h(
                        "div",
                        { className: "abuse-bar" },
                        h("div", {
                          className: "abuse-bar-fill",
                          "data-level": abuseScoreLevel(abuseScore),
                          style: { width: Math.min(100, abuseScore) + "%" },
                        })
                      ),
                      h("span", { className: "abuse-score-text" }, String(abuseScore))
                    )
                  : h("span", { className: "abuse-score-na" }, "N/A")
              ),
              h("td", null,
                h("span", { className: "greynoise-badge", "data-class": gnClass }, gnClass)
              ),
              h("td", null,
                h("span", { className: "event-count-badge" }, String(attacker.event_count || 0))
              )
            );
          })
        )
      )
    )
  );
}
