const h = React.createElement;
const { useEffect, useState, useRef, useMemo } = React;
import { usePolling } from '../utils.js';
import { PageSkeleton, EventDrawer } from './Core.js';
export function LiveActivityPage(props) {
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
