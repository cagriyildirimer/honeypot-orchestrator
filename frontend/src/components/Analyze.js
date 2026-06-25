const h = React.createElement;
const { useState, useEffect } = React;
import { usePolling } from '../utils.js';
import { PageSkeleton, ThreatIntelPanel } from './Core.js';

function getFlagEmoji(countryCode) {
  if (!countryCode || countryCode === "XX" || countryCode === "Private" || countryCode === "Unknown") return "🌐";
  const codePoints = countryCode
    .toUpperCase()
    .split("")
    .map(char => 127397 + char.charCodeAt(0));
  try {
    return String.fromCodePoint(...codePoints);
  } catch (e) {
    return "🌐";
  }
}

export function AnalyzePage(props) {
  const [tiData, setTiData] = useState(null);
  const [analyzeData, setAnalyzeData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeStage, setActiveStage] = useState(null);

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

  // Extract techniques and calculate total counts
  const techniques = analyzeData?.techniques || [];
  const countryBreakdown = analyzeData?.country_breakdown || [];
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

  // Selected stage resolution (auto-selects first stage with threats on load, then respects user clicks)

  if (loading && !tiData && !analyzeData) {
    return h(PageSkeleton, null);
  }

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
  const topAttackers = tiData?.attackers || [];

  return h(
    "div",
    { className: "page-container page-fade-in" },
    h(
      "header",
      { className: "page-header" },
      h(
        "div",
        null,
        h("h1", null, "Threat Lifecycle & Security Analytics"),
        h("p", { className: "page-subtitle" }, "Interactive Cyber Kill Chain progression tracking and honeypot sensor analytics.")
      ),
      h(
        "div",
        { className: "page-actions" },
        h(
          "button",
          { type: "button", className: "button", onClick: props.onLogout },
          "Log out"
        )
      )
    ),

    h(
      "div",
      { className: "analyze-grid-container" },

      // 1. Cyber Kill Chain Pipeline Visualizer
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

        // Timeline Stats Bar
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

        // The Cyber Kill Chain Pipeline Row
        h(
          "div",
          { className: "killchain-pipeline" },
          stages.map((stage, idx) => {
            const isActive = selectedStageIdx === idx;
            const isAlert = stage.count > 0;
            
            // Circular SVG Progress Ring Math
            const radius = 22;
            const circumference = 2 * Math.PI * radius;
            // Percent of total events
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
                // Circular Gauge
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
              // Connector Line (except after the last node)
              idx < stages.length - 1
                ? h("div", {
                    className: `killchain-connector ${isAlert || stages[idx + 1].count > 0 ? "flowing" : ""}`
                  })
                : null
            );
          })
        ),

        // Interactive Threat Inspector Card
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
            // Stage-specific Attacker IPs
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
                    const matchingAttacker = tiData?.attackers?.find(a => a.ip === att.ip);
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
      ),

      // 2. Bottom Row: Country Breakdown & Threat Intel Table
      h(
        "div",
        { className: "analyze-dashboard-row" },
        
        // 2a. Geo-Distribution Breakdown Panel
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

        // 2b. Stage Specific Top Attackers List
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

      // 3. Threat Intelligence Panel (Full Details Table at bottom)
      h(ThreatIntelPanel, { data: tiData })
    )
  );
}
