const h = React.createElement;
const { useState, useEffect, useMemo } = React;
import { usePolling } from '../utils.js';
import { PageSkeleton, ThreatIntelPanel } from './Core.js';

function getFlagEmoji(countryCode) {
  const code = String(countryCode || "").toUpperCase();
  if (!code || code === "XX" || code === "PRIVATE" || code === "UNKNOWN") return "🌐";
  const codePoints = code
    .split("")
    .map(char => 127397 + char.charCodeAt(0));
  try {
    return String.fromCodePoint(...codePoints);
  } catch (e) {
    return "🌐";
  }
}

export function AnalyzePage(props) {
  const [activeTab, setActiveTab] = useState("analytics");
  const [tiData, setTiData] = useState(null);
  const [analyzeData, setAnalyzeData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeStage, setActiveStage] = useState(null);

  // Attack Timeline States
  const [selectedIp, setSelectedIp] = useState("");
  const [timelineEvents, setTimelineEvents] = useState([]);
  const [timelineLoading, setTimelineLoading] = useState(false);

  // Credential Harvest States
  const [harvestEvents, setHarvestEvents] = useState([]);
  const [harvestLoading, setHarvestLoading] = useState(false);

  // Captured Payloads States
  const [payloadEvents, setPayloadEvents] = useState([]);
  const [payloadsLoading, setPayloadsLoading] = useState(false);

  // Tarpit States
  const [tarpitEvents, setTarpitEvents] = useState([]);
  const [tarpitLoading, setTarpitLoading] = useState(false);

  async function loadData() {
    try {
      const [tiRes, analyzeRes] = await Promise.all([
        window.requestJson("/api/threat-intel").catch(() => null),
        window.requestJson("/api/analyze").catch(() => null)
      ]);
      if (tiRes) setTiData(tiRes);
      if (analyzeRes) setAnalyzeData(analyzeRes);
    } catch (e) {
      // silently ignore errors
    } finally {
      setLoading(false);
    }
  }

  usePolling(loadData, 30000, []);

  // Fetch timeline events when selected IP changes
  useEffect(() => {
    if (!selectedIp) {
      setTimelineEvents([]);
      return;
    }
    setTimelineLoading(true);
    window.requestJson(`/api/events?src_ip=${encodeURIComponent(selectedIp)}&limit=100`)
      .then(res => {
        if (res && Array.isArray(res.events)) {
          setTimelineEvents(res.events);
        }
      })
      .catch(e => {
        window.showToast("Failed to load timeline: " + e.message, "error");
      })
      .finally(() => {
        setTimelineLoading(false);
      });
  }, [selectedIp]);

  // Fetch harvest credentials when credentials tab is activated
  useEffect(() => {
    if (activeTab !== "credentials") return;
    setHarvestLoading(true);
    window.requestJson("/api/events?event_type=login_attempt&limit=200")
      .then(res => {
        if (res && Array.isArray(res.events)) {
          setHarvestEvents(res.events);
        }
      })
      .catch(e => {
        window.showToast("Failed to load credentials: " + e.message, "error");
      })
      .finally(() => {
        setHarvestLoading(false);
      });
  }, [activeTab]);

  // Fetch captured payloads when payloads tab is activated
  useEffect(() => {
    if (activeTab !== "payloads") return;
    setPayloadsLoading(true);
    window.requestJson("/api/events?event_type=captured_payload&limit=200")
      .then(res => {
        if (res && Array.isArray(res.events)) {
          setPayloadEvents(res.events);
        }
      })
      .catch(e => {
        window.showToast("Failed to load payloads: " + e.message, "error");
      })
      .finally(() => {
        setPayloadsLoading(false);
      });
  }, [activeTab]);

  // Fetch tarpit events when tarpit tab is activated
  useEffect(() => {
    if (activeTab !== "tarpit") return;
    setTarpitLoading(true);
    window.requestJson("/api/events?search=tarpit&limit=500")
      .then(res => {
        if (res && Array.isArray(res.events)) {
          setTarpitEvents(res.events);
        }
      })
      .catch(e => {
        window.showToast("Failed to load tarpit logs: " + e.message, "error");
      })
      .finally(() => {
        setTarpitLoading(false);
      });
  }, [activeTab]);

  // Extract techniques and calculate total counts
  const techniques = Array.isArray(analyzeData?.techniques) ? analyzeData.techniques : [];
  const countryBreakdown = Array.isArray(analyzeData?.country_breakdown) ? analyzeData.country_breakdown : [];
  const totalCountryHits = countryBreakdown.reduce((sum, c) => sum + c.count, 0) || 1;

  // Stages definition with dynamic counts aggregated from techniques
  const stages = [
    {
      name: "Initial Access",
      tactic: "Initial Access",
      icon: "🚪",
      description: "Adversaries attempt to gain an initial foothold by exploiting public-facing web or service applications.",
      mitigation: "Enforce web application firewalls (WAF), automatically blacklist aggressive web crawlers, and keep public-facing services patched.",
      techniques: ["T1190 - Exploit Public-Facing Application"],
      services: ["HTTP Exploit", "Vulnerability Scan", "HTTP Web Service"],
      count: techniques.filter(t => t.tactic === "Initial Access").reduce((sum, t) => sum + t.count, 0)
    },
    {
      name: "Execution",
      tactic: "Execution",
      icon: "⚡",
      description: "Adversaries attempt to execute unauthorized commands or scripts on the target host to run their payloads.",
      mitigation: "Restrict interactive shell commands, limit interpreter execution permissions, and maintain detailed session logs.",
      techniques: ["T1059 - Command and Scripting Interpreter"],
      services: ["SSH Shell Commands", "Telnet Shell", "SQL Query Injection"],
      count: techniques.filter(t => t.tactic === "Execution").reduce((sum, t) => sum + t.count, 0)
    },
    {
      name: "Credential Access",
      tactic: "Credential Access",
      icon: "🔑",
      description: "Adversaries attempt to steal credentials such as usernames and passwords through brute-force or credential guessing.",
      mitigation: "Implement strict rate limiting, enforce strong password policies, and enable automatic IP bans on successive authentication failures.",
      techniques: ["T1110 - Brute Force"],
      services: ["SSH Login Attempts", "FTP Brute Force", "Telnet Login", "HTTP Auth Guessing"],
      count: techniques.filter(t => t.tactic === "Credential Access").reduce((sum, t) => sum + t.count, 0)
    },
    {
      name: "Discovery",
      tactic: "Discovery",
      icon: "📡",
      description: "Adversaries attempt to gather system and network information to map out the environment for further attacks.",
      mitigation: "Disable legacy discovery protocols (e.g., LLMNR, NetBIOS), restrict active directory searches, and block port scanners.",
      techniques: ["T1046 - Network Service Discovery"],
      services: ["TCP/UDP Port Scans", "DNS Queries", "LDAP Directory Searches", "NetBIOS/LLMNR/RPC"],
      count: techniques.filter(t => t.tactic === "Discovery").reduce((sum, t) => sum + t.count, 0)
    },
    {
      name: "Lateral Movement",
      tactic: "Lateral Movement",
      icon: "🚀",
      description: "Adversaries attempt to navigate through the network to access and control remote systems.",
      mitigation: "Enforce network segmentation, restrict remote desktop protocol (RDP) access, and closely monitor Server Message Block (SMB) file transfers.",
      techniques: ["T1210 - Exploitation of Remote Services"],
      services: ["SMB Remote Exploits", "RDP Connection Attempts"],
      count: techniques.filter(t => t.tactic === "Lateral Movement").reduce((sum, t) => sum + t.count, 0)
    }
  ];

  // Calculate statistics
  const totalEvents = analyzeData?.total_events_analyzed || 0;
  const activeAlertsCount = techniques.filter(tech => tech.count > 0).length;
  const hasActiveThreats = activeAlertsCount > 0;

  // Selected stage details
  let selectedStageIdx = activeStage;
  if (selectedStageIdx === null && analyzeData) {
    const firstThreatIdx = stages.findIndex(s => s.count > 0);
    selectedStageIdx = firstThreatIdx !== -1 ? firstThreatIdx : 0;
  }
  if (selectedStageIdx === null) {
    selectedStageIdx = 0;
  }
  const selectedStage = stages[selectedStageIdx] || stages[0];

  // Filter top attackers for the selected stage's services (or show overall top if no matches)
  const topAttackers = Array.isArray(tiData?.attackers) ? tiData.attackers : [];

  // Extract all unique attacker IPs for timeline filter dropdown
  const allAttackerIps = useMemo(() => {
    const ips = new Set();
    topAttackers.forEach(a => { if (a.ip) ips.add(a.ip); });
    if (analyzeData?.tactic_attackers) {
      Object.values(analyzeData.tactic_attackers).forEach(arr => {
        if (Array.isArray(arr)) {
          arr.forEach(att => { if (att.ip) ips.add(att.ip); });
        }
      });
    }
    return Array.from(ips);
  }, [topAttackers, analyzeData]);

  // Aggregate and calculate Top Usernames/Passwords for Credential Harvest
  const harvestStats = useMemo(() => {
    const passwordCounts = {};
    const usernameCounts = {};
    
    harvestEvents.forEach(evt => {
      if (evt.password) {
        passwordCounts[evt.password] = (passwordCounts[evt.password] || 0) + 1;
      }
      if (evt.username) {
        usernameCounts[evt.username] = (usernameCounts[evt.username] || 0) + 1;
      }
    });

    const topPasswords = Object.entries(passwordCounts)
      .map(([p, count]) => ({ val: p, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    const topUsernames = Object.entries(usernameCounts)
      .map(([u, count]) => ({ val: u, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    return { topPasswords, topUsernames };
  }, [harvestEvents]);

  // Process tarpit active list and history
  const tarpitSummary = useMemo(() => {
    const activeTrapped = {};
    const history = [];

    // Tarpit events are processed in reverse chronological order
    tarpitEvents.forEach(evt => {
      const ip = evt.src_ip;
      if (!ip) return;

      history.push(evt);

      if (evt.event_type === "tarpit_hooked") {
        if (!activeTrapped[ip]) {
          activeTrapped[ip] = {
            ip: ip,
            port: evt.src_port,
            timestamp: evt.timestamp,
            summary: evt.summary
          };
        }
      } else if (evt.event_type === "tarpit_released") {
        if (!activeTrapped[ip]) {
          activeTrapped[ip] = "released";
        }
      }
    });

    const activeList = Object.values(activeTrapped).filter(v => v !== "released");
    return { activeList, history };
  }, [tarpitEvents]);

  // Client-side export helper
  function handleExportCredentials(format) {
    if (harvestEvents.length === 0) {
      window.showToast("No credentials to export.", "error");
      return;
    }
    
    let content = "";
    let filename = `credential_harvest_export_${Date.now()}`;
    let mimeType = "text/plain";
    
    if (format === "json") {
      content = JSON.stringify(harvestEvents, null, 2);
      filename += ".json";
      mimeType = "application/json";
    } else if (format === "csv") {
      const headers = ["Timestamp", "Source IP", "Service", "Username", "Password", "Summary"];
      const rows = harvestEvents.map(e => [
        e.timestamp || "",
        e.src_ip || "",
        e.service || "",
        e.username || "",
        e.password || "",
        e.summary || ""
      ]);
      content = [
        headers.join(","),
        ...rows.map(r => r.map(val => `"${String(val).replace(/"/g, '""')}"`).join(","))
      ].join("\n");
      filename += ".csv";
      mimeType = "text/csv";
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
    window.showToast(`Exported ${harvestEvents.length} records successfully.`, "success");
  }

  // Client-side timeline export helper
  function handleExportTimeline(format) {
    if (timelineEvents.length === 0) {
      window.showToast("No timeline events to export.", "error");
      return;
    }
    
    let content = "";
    let filename = `attacker_timeline_${selectedIp}_export_${Date.now()}`;
    let mimeType = "text/plain";
    
    if (format === "json") {
      content = JSON.stringify(timelineEvents, null, 2);
      filename += ".json";
      mimeType = "application/json";
    } else if (format === "csv") {
      const headers = ["Timestamp", "Event Type", "Service", "Summary", "Username", "Password", "Command"];
      const rows = timelineEvents.map(e => [
        e.timestamp || "",
        e.event_type || "",
        e.service || "",
        e.summary || "",
        e.username || "",
        e.password || "",
        e.command || ""
      ]);
      content = [
        headers.join(","),
        ...rows.map(r => r.map(val => `"${String(val).replace(/"/g, '""')}"`).join(","))
      ].join("\n");
      filename += ".csv";
      mimeType = "text/csv";
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
    window.showToast(`Exported ${timelineEvents.length} timeline events successfully.`, "success");
  }


  if (loading && !tiData && !analyzeData) {
    return h(PageSkeleton, null);
  }

  const isAdmin = props.session?.role === "admin";

  // Tab Content 1: Threat Analysis & Attack Timeline Panel
  const analyticsTabNode = h(
    React.Fragment,
    null,
    h(
      "div",
      { className: "analyze-grid-container" },
      h(
        "section",
        { className: "panel killchain-panel" },
        h(
          "div",
          { className: "section-heading" },
          h(
            "div",
            null,
            h("h2", null, "Adversary Cyber Kill Chain Pipeline"),
            h("p", null, "Interactive lifecycle of adversary threat progression across honeypot detection nodes.")
          )
        ),
        h(
          "div",
          { className: "mitre-stats-bar" },
          h(
            "div",
            { className: "mitre-stat-pill" },
            h("span", { className: "mitre-stat-label" }, "Total Events Analyzed"),
            h("span", { className: "mitre-stat-value" }, String(totalEvents))
          ),
          h(
            "div",
            { className: "mitre-stat-pill" },
            h("span", { className: "mitre-stat-label" }, "Compromise Stages"),
            h(
              "span",
              { className: `mitre-stat-value ${hasActiveThreats ? "text-danger" : "text-success"}` },
              `${activeAlertsCount} / 5 Alerting`
            )
          ),
          h(
            "div",
            { className: "mitre-stat-pill" },
            h("span", { className: "mitre-stat-label" }, "Perimeter Status"),
            h(
              "span",
              { className: `mitre-stat-value status-badge ${hasActiveThreats ? "badge-threat" : "badge-secure"}` },
              hasActiveThreats ? "ATTACK DETECTED" : "SECURE"
            )
          )
        ),
        h(
          "div",
          { className: "killchain-pipeline" },
          stages.map((stage, idx) => {
            const isActive = selectedStageIdx === idx;
            const isAlert = stage.count > 0;
            const radius = 22;
            const circumference = 2 * Math.PI * radius;
            const percent = totalEvents > 0 ? Math.min(100, Math.round((stage.count / totalEvents) * 100)) : 0;
            const strokeDashoffset = circumference - (percent / 100) * circumference;

            return h(
              React.Fragment,
              { key: stage.name },
              h(
                "div",
                {
                  className: `killchain-node ${isActive ? "active" : ""} ${isAlert ? "alert" : "secure"}`,
                  onClick: () => setActiveStage(idx),
                  title: `${stage.name}: Click to inspect threat details.`
                },
                h(
                  "div",
                  { className: "killchain-gauge-wrap" },
                  h(
                    "svg",
                    { className: "killchain-gauge", width: "56", height: "56" },
                    h("circle", {
                      className: "gauge-track",
                      cx: "28",
                      cy: "28",
                      r: String(radius)
                    }),
                    h("circle", {
                      className: "gauge-fill",
                      cx: "28",
                      cy: "28",
                      r: String(radius),
                      style: {
                        strokeDasharray: String(circumference),
                        strokeDashoffset: String(strokeDashoffset)
                      }
                    })
                  ),
                  h(
                    "span",
                    { className: "killchain-gauge-icon" },
                    isAlert ? String(stage.count) : "🛡️"
                  )
                ),
                h("span", { className: "killchain-node-name" }, stage.name),
                h(
                  "span",
                  { className: "killchain-node-status" },
                  isAlert ? "ALERTING" : "MONITORED"
                )
              ),
              idx < stages.length - 1
                ? h("div", {
                    className: `killchain-connector ${isAlert || stages[idx + 1].count > 0 ? "flowing" : ""}`
                  })
                : null
            );
          })
        ),
        h(
          "div",
          { className: "threat-inspector-panel" },
          h(
            "div",
            { className: "inspector-header" },
            h("span", { className: "inspector-icon" }, selectedStage.icon),
            h(
              "div",
              null,
              h("h3", null, `${selectedStage.name} Tactic Lifecycle Analysis`),
              h(
                "span",
                { className: `inspector-badge ${selectedStage.count > 0 ? "badge-threat" : "badge-secure"}` },
                selectedStage.count > 0 ? `${selectedStage.count} Active Incidents` : "0 Incidents (Secure)"
              )
            )
          ),
          h(
            "div",
            { className: "inspector-body" },
            h(
              "div",
              { className: "inspector-meta-col" },
              h("h4", null, "Tactic Description"),
              h("p", null, selectedStage.description),
              h("h4", { style: { marginTop: "14px" } }, "Honeypot Mitigation & Defenses"),
              h("p", null, selectedStage.mitigation)
            ),
            h(
              "div",
              { className: "inspector-spec-col" },
              h("h4", null, "Monitored ATT&CK Techniques"),
              h(
                "div",
                { className: "tech-tag-cloud" },
                selectedStage.techniques.map(tech => h("span", { key: tech, className: "tech-tag tech" }, tech))
              ),
              h("h4", { style: { marginTop: "14px" } }, "Active Sensor Ports & Targets"),
              h(
                "div",
                { className: "tech-tag-cloud" },
                selectedStage.services.map(svc => h("span", { key: svc, className: "tech-tag service" }, svc))
              )
            ),
            h(
              "div",
              { className: "inspector-attackers-col" },
              h("h4", null, "Top Phase Attacker IPs"),
              (() => {
                const stageAttackers = analyzeData?.tactic_attackers?.[selectedStage.tactic] || [];
                if (stageAttackers.length === 0) {
                  return h("div", { className: "no-attackers-placeholder" }, "No active IPs detected in this phase.");
                }
                return h(
                  "div",
                  { className: "inspector-attackers-list" },
                  stageAttackers.slice(0, 4).map((att, idx) => {
                    const matchingAttacker = Array.isArray(tiData?.attackers) ? tiData.attackers.find(a => a.ip === att.ip) : null;
                    const countryCode = matchingAttacker?.countryCode || matchingAttacker?.country_code || "XX";
                    return h(
                      "div",
                      { key: att.ip || idx, className: "inspector-attacker-item" },
                      h(
                        "span",
                        { className: "inspector-attacker-ip" },
                        h("span", { className: "country-flag", style: { marginRight: "6px" } }, getFlagEmoji(countryCode)),
                        att.ip
                      ),
                      h("span", { className: "inspector-attacker-count" }, `${att.count} hits`)
                    );
                  })
                );
              })()
            )
          )
        )
      )
    ),
    h(
      "div",
      { className: "analyze-dashboard-row" },
      h(
        "section",
        { className: "panel country-breakdown-panel" },
        h(
          "div",
          { className: "section-heading" },
          h(
            "div",
            null,
            h("h2", null, "Attacker Geo-Distribution Breakdown"),
            h("p", null, "Top threat source countries mapped from honeypot connection logs.")
          )
        ),
        h(
          "div",
          { className: "country-breakdown-list" },
          countryBreakdown.length === 0
            ? h("div", { className: "ti-empty" }, "No country data available.")
            : countryBreakdown.map((c, idx) => {
                const percentage = Math.round((c.count / totalCountryHits) * 100);
                return h(
                  "div",
                  { key: c.country_code || idx, className: "country-item" },
                  h(
                    "div",
                    { className: "country-item-header" },
                    h(
                      "span",
                      { className: "country-name" },
                      h("span", { className: "country-flag" }, getFlagEmoji(c.country_code)),
                      c.country
                    ),
                    h("span", { className: "country-count" }, `${c.count} (${percentage}%)`)
                  ),
                  h(
                    "div",
                    { className: "country-progress-bar" },
                    h("div", { className: "country-progress-fill", style: { width: `${percentage}%` } })
                  )
                );
              })
        )
      ),
      h(
        "section",
        { className: "panel active-attackers-panel" },
        h(
          "div",
          { className: "section-heading" },
          h(
            "div",
            null,
            h("h2", null, "Top Active Phase Attacker IPs"),
            h("p", null, "Active source hosts executing traffic associated with the selected stage.")
          )
        ),
        h(
          "div",
          { className: "country-breakdown-list" },
          topAttackers.length === 0
            ? h("div", { className: "ti-empty" }, "No active attacker data available.")
            : topAttackers.slice(0, 5).map((attacker, idx) => {
                const location = [attacker.city, attacker.country].filter(Boolean).join(", ") || "Unknown";
                return h(
                  "div",
                  { key: attacker.ip || idx, className: "attacker-lifecycle-item" },
                  h(
                    "div",
                    { className: "attacker-lifecycle-meta" },
                    h("span", { className: "attacker-lifecycle-ip" }, attacker.ip),
                    h("span", { className: "attacker-lifecycle-loc" }, 
                      h("span", { className: "country-flag", style: { marginRight: "6px" } }, getFlagEmoji(attacker.country_code)),
                      location
                    )
                  ),
                  h(
                    "div",
                    { className: "attacker-lifecycle-stats" },
                    h("span", { className: "attacker-lifecycle-badge badge-abuse" }, `Abuse: ${attacker.abuse_score || 0}%`),
                    h("span", { className: "attacker-lifecycle-badge badge-events" }, `${attacker.event_count || 0} hits`)
                  )
                );
              })
        )
      )
    ),

    h(ThreatIntelPanel, { data: tiData }),

    // Attack Timeline Panel
    h(
      "section",
      { className: "panel timeline-panel" },
      h(
        "div",
        { className: "section-heading" },
        h("div", null, h("h2", null, "Attacker Behavior Timeline"), h("p", null, "Replay the chronological sequence of actions executed by a specific source IP."))
      ),
      h(
        "div",
        { className: "timeline-search-row" },
        h("span", { className: "timeline-label" }, "Select Attacker IP:"),
        h(
          "select",
          {
            value: selectedIp,
            onChange: (e) => setSelectedIp(e.target.value),
            className: "select-input"
          },
          h("option", { value: "" }, "-- Select Attacker IP --"),
          allAttackerIps.map(ip => h("option", { key: ip, value: ip }, ip))
        ),
        selectedIp
          ? h(
              React.Fragment,
              null,
              h("button", {
                type: "button",
                className: "button secondary",
                onClick: () => {
                  const old = selectedIp;
                  setSelectedIp("");
                  setTimeout(() => setSelectedIp(old), 50);
                }
              }, "Refresh"),
              h("button", {
                type: "button",
                className: "button secondary",
                onClick: () => handleExportTimeline("csv")
              }, "Export Timeline (CSV)"),
              h("button", {
                type: "button",
                className: "button secondary",
                onClick: () => handleExportTimeline("json")
              }, "Export Timeline (JSON)")
            )
          : null
      ),
      timelineLoading
        ? h("div", { className: "timeline-loading" }, "Loading chronological actions...")
        : timelineEvents.length === 0
          ? h("div", { className: "timeline-empty" }, selectedIp ? "No events found for this IP." : "Select an attacker IP from the dropdown above to view their chronological timeline of activities.")
          : h(
              "div",
              { className: "attacker-timeline" },
              timelineEvents.map((evt, idx) => {
                let badgeColor = "var(--accent)";
                if (evt.event_type === "exploit_attempt" || evt.event_type === "login_attempt") {
                  badgeColor = "var(--warning)";
                } else if (evt.event_type === "command_execution" || evt.event_type === "ssh_command") {
                  badgeColor = "var(--danger)";
                } else if (evt.event_type === "connection") {
                  badgeColor = "var(--accent-focus)";
                }

                return h(
                  "div",
                  { key: evt.id || idx, className: "timeline-item" },
                  h("div", { className: "timeline-badge", style: { borderColor: badgeColor } }),
                  h(
                    "div",
                    { className: "timeline-item-card" },
                    h(
                      "div",
                      { className: "timeline-item-header" },
                      h("strong", { style: { color: badgeColor } }, String(evt.event_type || "EVENT").toUpperCase()),
                      h("span", null, evt.timestamp)
                    ),
                    h(
                      "div",
                      { className: "timeline-body-row" },
                      h("span", { className: "timeline-summary" }, evt.summary || "No description provided."),
                      h("span", { className: "timeline-service-tag" }, String(evt.service || "unknown").toUpperCase())
                    ),
                    evt.username || evt.password || evt.command
                      ? h(
                          "div",
                          { className: "timeline-details-row" },
                          evt.username ? h("span", null, "User: ", h("code", null, evt.username)) : null,
                          evt.password ? h("span", { style: { marginLeft: "12px" } }, "Pass: ", h("code", null, evt.password)) : null,
                          evt.command ? h("span", null, "Cmd: ", h("code", null, evt.command)) : null
                        )
                      : null
                  )
                );
              })
            )
    )
  );

  // Tab Content 2: Credential Harvest Report Tab
  const credentialsTabNode = h(
    "div",
    { className: "credential-harvest-view page-fade-in" },
    h(
      "div",
      { className: "harvest-stats-grid" },
      h(
        "section",
        { className: "panel" },
        h(
          "div",
          { className: "section-heading" },
          h("div", null, h("h2", null, "Most Attempted Passwords"), h("p", null, "The most common passwords targeted by brute-force attackers."))
        ),
        h(
          "div",
          { className: "country-breakdown-list" },
          harvestStats.topPasswords.length === 0
            ? h("div", { className: "ti-empty" }, "No password attempts logged yet.")
            : harvestStats.topPasswords.map((item, idx) => {
                const maxCount = harvestStats.topPasswords[0]?.count || 1;
                const percentage = Math.round((item.count / maxCount) * 100);
                return h(
                  "div",
                  { key: item.val || idx, className: "country-item" },
                  h(
                    "div",
                    { className: "country-item-header" },
                    h("span", { className: "country-name" }, h("code", null, item.val || "<empty>")),
                    h("span", { className: "country-count" }, `${item.count} times`)
                  ),
                  h(
                    "div",
                    { className: "country-progress-bar" },
                    h("div", { className: "country-progress-fill", style: { width: `${percentage}%` } })
                  )
                );
              })
        )
      ),
      h(
        "section",
        { className: "panel" },
        h(
          "div",
          { className: "section-heading" },
          h("div", null, h("h2", null, "Most Attempted Usernames"), h("p", null, "The most common usernames targeted by brute-force attackers."))
        ),
        h(
          "div",
          { className: "country-breakdown-list" },
          harvestStats.topUsernames.length === 0
            ? h("div", { className: "ti-empty" }, "No username attempts logged yet.")
            : harvestStats.topUsernames.map((item, idx) => {
                const maxCount = harvestStats.topUsernames[0]?.count || 1;
                const percentage = Math.round((item.count / maxCount) * 100);
                return h(
                  "div",
                  { key: item.val || idx, className: "country-item" },
                  h(
                    "div",
                    { className: "country-item-header" },
                    h("span", { className: "country-name" }, h("code", null, item.val || "<empty>")),
                    h("span", { className: "country-count" }, `${item.count} times`)
                  ),
                  h(
                    "div",
                    { className: "country-progress-bar" },
                    h("div", { className: "country-progress-fill", style: { width: `${percentage}%` } })
                  )
                );
              })
        )
      )
    ),
    h(
      "section",
      { className: "panel" },
      h(
        "div",
        { className: "section-heading", style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
        h("div", null, h("h2", null, "Captured Decoy Credentials"), h("p", null, "Real-time list of all username/password combinations entered in decoy portals.")),
        h(
          "div",
          { className: "button-row" },
          h("button", { type: "button", className: "button secondary", onClick: () => handleExportCredentials("csv") }, "Export CSV"),
          h("button", { type: "button", className: "button secondary", onClick: () => handleExportCredentials("json") }, "Export JSON")
        )
      ),
      h(
        "div",
        { className: "table-shell" },
        h(
          "table",
          null,
          h("thead", null, h("tr", null, h("th", null, "Timestamp"), h("th", null, "Source IP"), h("th", null, "Decoy Service"), h("th", null, "Username"), h("th", null, "Password"))),
          h(
            "tbody",
            null,
            harvestLoading
              ? h("tr", null, h("td", { colSpan: 5, className: "empty-row" }, "Loading captured credentials..."))
              : harvestEvents.length === 0
                ? h("tr", null, h("td", { colSpan: 5, className: "empty-row" }, "No credential logs captured yet."))
                : harvestEvents.map((evt, idx) =>
                    h(
                      "tr",
                      { key: evt.id || idx },
                      h("td", null, evt.timestamp),
                      h("td", null, h("span", { className: "table-strong" }, evt.src_ip)),
                      h("td", null, String(evt.service || "unknown").toUpperCase()),
                      h("td", null, h("code", null, evt.username || "<empty>")),
                      h("td", null, h("code", null, evt.password || "<empty>"))
                    )
                  )
          )
        )
      )
    )
  );

  const payloadsTabNode = h(
    "section",
    { className: "panel page-fade-in" },
    h(
      "div",
      { className: "section-heading" },
      h("div", null, h("h2", null, "Captured Decoy Payloads & Malware"), h("p", null, "Real-time list of all binaries, webshells, and scripts uploaded or downloaded in decoy services."))
    ),
    h(
      "div",
      { className: "table-shell" },
      h(
        "table",
        null,
        h("thead", null, h("tr", null, h("th", null, "Timestamp"), h("th", null, "Source IP"), h("th", null, "Filename"), h("th", null, "Size"), h("th", null, "Malware Tag"), h("th", null, "SHA-256"), h("th", null, "Source URL"))),
        h(
          "tbody",
          null,
          payloadsLoading
            ? h("tr", null, h("td", { colSpan: 7, className: "empty-row" }, "Loading captured payloads..."))
            : payloadEvents.length === 0
              ? h("tr", null, h("td", { colSpan: 7, className: "empty-row" }, "No malware payloads captured yet."))
              : payloadEvents.map((evt, idx) => {
                  const details = evt.details || {};
                  return h(
                    "tr",
                    { key: evt.id || idx },
                    h("td", null, evt.timestamp),
                    h("td", null, h("span", { className: "table-strong" }, evt.src_ip)),
                    h("td", null, details.filename || "unknown"),
                    h("td", null, details.file_size ? `${(details.file_size / 1024).toFixed(2)} KB` : "unknown"),
                    h("td", null, h("span", { className: "status-badge badge-threat" }, details.malware_type || "Generic Payload")),
                    h("td", null, h("code", { style: { fontSize: "0.85em" } }, details.sha256 || "N/A")),
                    h("td", null, details.download_url ? h("a", { href: details.download_url, target: "_blank", style: { color: "var(--neon-blue)" } }, "URL Link") : "Direct Upload (FTP)")
                  );
                })
        )
      )
    )
  );

  const tarpitTabNode = h(
    React.Fragment,
    null,
    h(
      "div",
      { className: "analyze-grid-container page-fade-in" },
      h(
        "section",
        { className: "panel" },
        h(
          "div",
          { className: "section-heading" },
          h("div", null, h("h2", null, "Active Attacker Traps (Currently Tarpitted)"), h("p", null, "Hostile IPs currently held in TCP Tarpit delays to waste scanner threads."))
        ),
        h(
          "div",
          { className: "country-breakdown-list" },
          tarpitSummary.activeList.length === 0
            ? h("div", { className: "ti-empty" }, "No attackers currently trapped in Tarpit.")
            : tarpitSummary.activeList.map((item, idx) => {
                return h(
                  "div",
                  { key: item.ip || idx, className: "country-item" },
                  h(
                    "div",
                    { className: "country-item-header" },
                    h("span", { className: "country-name", style: { color: "var(--neon-red)" } }, `⚠️ Attacker: ${item.ip}:${item.port}`),
                    h("span", { className: "country-count" }, `Trapped at: ${item.timestamp}`)
                  ),
                  h(
                    "div",
                    { className: "country-progress-bar", style: { height: "6px" } },
                    h("div", { className: "country-progress-fill", style: { width: "100%", background: "var(--neon-red)" } })
                  )
                );
              })
        )
      ),
      h(
        "section",
        { className: "panel" },
        h(
          "div",
          { className: "section-heading" },
          h("div", null, h("h2", null, "Tarpit Impact Statistics"), h("p", null, "Real-time active defense defensive value metrics."))
        ),
        h(
          "div",
          { className: "mitre-stats-bar", style: { flexDirection: "column", gap: "10px", padding: "10px 0" } },
          h(
            "div",
            { className: "mitre-stat-pill", style: { justifyContent: "space-between" } },
            h("span", { className: "mitre-stat-label" }, "Active Held Attackers"),
            h("span", { className: "mitre-stat-value text-danger" }, String(tarpitSummary.activeList.length))
          ),
          h(
            "div",
            { className: "mitre-stat-pill", style: { justifyContent: "space-between" } },
            h("span", { className: "mitre-stat-label" }, "Total Historical Tarpits"),
            h("span", { className: "mitre-stat-value text-success" }, String(tarpitSummary.history.filter(e => e.event_type === "tarpit_hooked").length))
          )
        )
      )
    ),
    h(
      "section",
      { className: "panel page-fade-in" },
      h(
        "div",
        { className: "section-heading" },
        h("div", null, h("h2", null, "Historical Tarpit Action Logs"), h("p", null, "Audit logs of all attacker trap/release operations."))
      ),
      h(
        "div",
        { className: "table-shell" },
        h(
          "table",
          null,
          h("thead", null, h("tr", null, h("th", null, "Timestamp"), h("th", null, "Action"), h("th", null, "Attacker IP"), h("th", null, "Summary"))),
          h(
            "tbody",
            null,
            tarpitLoading
              ? h("tr", null, h("td", { colSpan: 4, className: "empty-row" }, "Loading tarpit audit logs..."))
              : tarpitSummary.history.length === 0
                ? h("tr", null, h("td", { colSpan: 4, className: "empty-row" }, "No tarpit events logged yet."))
                : tarpitSummary.history.map((evt, idx) =>
                    h(
                      "tr",
                      { key: evt.id || idx },
                      h("td", null, evt.timestamp),
                      h("td", null, h("span", { className: `status-badge ${evt.event_type === "tarpit_hooked" ? "badge-threat" : "badge-secure"}` }, evt.event_type === "tarpit_hooked" ? "HOOKED" : "RELEASED")),
                      h("td", null, h("span", { className: "table-strong" }, evt.src_ip)),
                      h("td", null, evt.summary)
                    )
                  )
          )
        )
      )
    )
  );

  return h(
    "div",
    { className: "page-container page-fade-in" },
    h(
      "header",
      { className: "topbar" },
      h(
        "div",
        null,
        h("h1", null, "Threat Lifecycle & Security Analytics"),
        h("p", { className: "page-subtitle" }, "Interactive Cyber Kill Chain progression tracking and honeypot sensor analytics.")
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
          "a",
          {
            className: `button${isAdmin ? "" : " disabled"}`,
            href: "/api/ioc/csv",
            download: "ioc_export.csv",
            onClick: (event) => {
              if (!isAdmin) {
                event.preventDefault();
                window.showToast("Admin access required.", "error");
              }
            },
          },
          "Export IOC (CSV)"
        ),
        h(
          "a",
          {
            className: `button${isAdmin ? "" : " disabled"}`,
            href: "/api/ioc/stix",
            download: "ioc_export.stix.json",
            onClick: (event) => {
              if (!isAdmin) {
                event.preventDefault();
                window.showToast("Admin access required.", "error");
              }
            },
          },
          "Export IOC (STIX)"
        ),
        h(
          "button",
          { type: "button", className: "button", onClick: props.onLogout },
          "Log out"
        )
      )
    ),

    // Tabs Selector
    h(
      "div",
      { className: "analyze-tabs" },
      h(
        "button",
        {
          className: `analyze-tab-btn${activeTab === "analytics" ? " active" : ""}`,
          onClick: () => setActiveTab("analytics")
        },
        "🛡️ Threat Lifecycle & Attack Timeline"
      ),
      h(
        "button",
        {
          className: `analyze-tab-btn${activeTab === "credentials" ? " active" : ""}`,
          onClick: () => setActiveTab("credentials")
        },
        "🔑 Credential Harvest Report"
      ),
      h(
        "button",
        {
          className: `analyze-tab-btn${activeTab === "payloads" ? " active" : ""}`,
          onClick: () => setActiveTab("payloads")
        },
        "📦 Captured Payloads & Malware"
      ),
      h(
        "button",
        {
          className: `analyze-tab-btn${activeTab === "tarpit" ? " active" : ""}`,
          onClick: () => setActiveTab("tarpit")
        },
        "🍯 TCP Tarpit Activity"
      )
    ),

    activeTab === "analytics" ? analyticsTabNode : 
    activeTab === "credentials" ? credentialsTabNode : 
    activeTab === "payloads" ? payloadsTabNode : tarpitTabNode
  );
}
