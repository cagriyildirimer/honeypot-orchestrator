const h = React.createElement;
const { useEffect, useState, useRef, useMemo } = React;
import { target, rect, x, y, midX, midY, rotateX, rotateY, target, NAV_ITEMS, SETTINGS_ITEMS, STANDARD_PORTS, DONUT_COLORS, RISK_EVENT_WEIGHTS, RISK_IGNORED_EVENT_TYPES, ROLE_LABELS, TIMELINE_RANGES, APPEARANCE_THEMES, pathToPage, isSettingsPage, parseEventTime, normalized, date, classifyRisk, getRiskWeight, eventType, isRiskRelevantEvent, eventType, service, summarizeRangeLabel, buildSuspiciousOverview, now, windowMs, start, hourTotals, serviceTotals, ipTotals, date, time, hourStart, hourKey, service, ip, topHour, topService, topIp, buildRiskModel, now, windowMs, start, bucketCount, bucketSizeMs, buckets, serviceTotals, typeTotals, date, time, service, eventType, weight, recencyBoost, weightedValue, bucketIndex, bucket, sortedServices, topServices, strongestBucket, burstScore, diversityScore, concentrationScore, baseScore, score, band, hottestService, timelineRangeConfig, formatTimelineBucketLabel, alignTimelineWindowStart, base, bucketMs, bucketHours, aligned, aligned, buildTimelineBuckets, range, bucketCount, windowMs, bucketMs, now, start, buckets, date, time, index, smoothLinePath, slopes, path, current, next, dx, minY, maxY, controlOneY, controlTwoY, controlOne, controlTwo, buildTimelinePoints, width, height, padding, plotWidth, plotHeight, divisor, maxValue, buildTimelineAreaPath, baseline, timelineHitBox, start, end, formatBytes, value, standardPortNote, baseName, standardPort, servicePortTone, baseName, standardPort, filterLogEvents, search, copyText, textarea, copied, usePolling, run, timer } from '../utils.js';
import { Skeleton, PageSkeleton, NavLink, AnimatedCounter, MetricCard, AppLayout, EventDrawer, GeoWorldMap } from './Core.js';
import { DashboardPage } from './Dashboard.js';
import { LiveActivityPage } from './Live.js';
import { SettingsAppearance, SettingsWhitelist, SettingsBlocklist, SettingsUsers, SettingsSystem, SettingsRouter } from './Settings.js';
import { LogsPage } from './Logs.js';
import { AppRouter } from './AppRouter.js';

export function ProfilesPage(props) {
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


