const h = React.createElement;
const { useEffect, useState, useRef, useMemo } = React;
import { target, rect, x, y, midX, midY, rotateX, rotateY, target, NAV_ITEMS, SETTINGS_ITEMS, STANDARD_PORTS, DONUT_COLORS, RISK_EVENT_WEIGHTS, RISK_IGNORED_EVENT_TYPES, ROLE_LABELS, TIMELINE_RANGES, APPEARANCE_THEMES, pathToPage, isSettingsPage, parseEventTime, normalized, date, classifyRisk, getRiskWeight, eventType, isRiskRelevantEvent, eventType, service, summarizeRangeLabel, buildSuspiciousOverview, now, windowMs, start, hourTotals, serviceTotals, ipTotals, date, time, hourStart, hourKey, service, ip, topHour, topService, topIp, buildRiskModel, now, windowMs, start, bucketCount, bucketSizeMs, buckets, serviceTotals, typeTotals, date, time, service, eventType, weight, recencyBoost, weightedValue, bucketIndex, bucket, sortedServices, topServices, strongestBucket, burstScore, diversityScore, concentrationScore, baseScore, score, band, hottestService, timelineRangeConfig, formatTimelineBucketLabel, alignTimelineWindowStart, base, bucketMs, bucketHours, aligned, aligned, buildTimelineBuckets, range, bucketCount, windowMs, bucketMs, now, start, buckets, date, time, index, smoothLinePath, slopes, path, current, next, dx, minY, maxY, controlOneY, controlTwoY, controlOne, controlTwo, buildTimelinePoints, width, height, padding, plotWidth, plotHeight, divisor, maxValue, buildTimelineAreaPath, baseline, timelineHitBox, start, end, formatBytes, value, standardPortNote, baseName, standardPort, servicePortTone, baseName, standardPort, filterLogEvents, search, copyText, textarea, copied, usePolling, run, timer } from '../utils.js';
import { DashboardPage } from './Dashboard.js';
import { LiveActivityPage } from './Live.js';
import { SettingsAppearance, SettingsWhitelist, SettingsBlocklist, SettingsUsers, SettingsSystem, SettingsRouter } from './Settings.js';
import { ProfilesPage } from './Profiles.js';
import { LogsPage } from './Logs.js';
import { AppRouter } from './AppRouter.js';

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

    return h("div", { className: "geo-map-container", style: { display: 'flex', justifyContent: 'center', minHeight: '400px', position: 'relative' } },
      h("div", { ref: containerRef }),
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


