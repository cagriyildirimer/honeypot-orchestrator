const h = React.createElement;
const { useState } = React;
import { usePolling } from '../utils.js';
import { PageSkeleton, ThreatIntelPanel } from './Core.js';

export function AnalyzePage(props) {
  const [tiData, setTiData] = useState(null);
  const [loading, setLoading] = useState(true);

  async function loadThreatIntel() {
    try {
      const data = await window.requestJson("/api/threat-intel");
      setTiData(data);
    } catch (e) {
      // silently ignore TI errors
    } finally {
      setLoading(false);
    }
  }

  usePolling(loadThreatIntel, 30000, []);

  if (loading && !tiData) {
    return h(PageSkeleton, null);
  }

  return h(
    "div",
    { className: "page-container page-fade-in" },
    h(
      "header",
      { className: "page-header" },
      h("h1", null, "Threat Intelligence Analyze"),
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
    h(ThreatIntelPanel, { data: tiData })
  );
}
