const h = React.createElement;
const { useEffect, useState, useRef, useMemo } = React;
import { pathToPage } from '../utils.js';
import { PageSkeleton, AppLayout } from './Core.js';
import { DashboardPage } from './Dashboard.js';
import { AnalyzePage } from './Analyze.js';
import { LiveActivityPage } from './Live.js';
import { LogsPage } from './Logs.js';
import { ProfilesPage } from './Profiles.js';
import { WhitelistPage, BlacklistPage, AppearancePage, SystemPage, UsersPage } from './Settings.js';
export function App() {
  const [page, setPage] = useState(pathToPage(window.location.pathname));
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const titles = {
      dashboard: "Honeypot Director Dashboard",
      analyze: "Honeypot Director Analyze",
      live: "Honeypot Director Live Monitor",
      whitelist: "Honeypot Director Whitelist",
      blacklist: "Honeypot Director Blacklist",
      blocklist: "Honeypot Director Blocklist",
      profiles: "Honeypot Director Profiles",
      logs: "Honeypot Director Logs",
      appearance: "Honeypot Director Appearance",
      system: "Honeypot Director System",
      users: "Honeypot Director Users",
    };
    document.title = titles[page] || "Honeypot Director";
  }, [page]);

  useEffect(() => {
    function handlePopState() {
      setPage(pathToPage(window.location.pathname));
    }
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  useEffect(() => {
    window.requestJson("/api/session")
      .then((payload) => {
        if (!payload.authenticated) {
          window.location.replace("/login");
          return;
        }
        setSession(payload);
        setLoading(false);
      })
      .catch(() => {
        window.location.replace("/login");
      });
  }, []);

  function navigate(path) {
    if (window.location.pathname === path) {
      return;
    }
    window.history.pushState({}, "", path);
    setPage(pathToPage(path));
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function navigateClick(path) {
    return function handleNavigate(event) {
      event.preventDefault();
      navigate(path);
    };
  }

  function handleLogout() {
    window.logoutAndRedirect();
  }

  if (loading || !session) {
    return h("div", { className: "app-frame" }, h("main", { className: "main-content" }, h(PageSkeleton, null)));
  }

  let pageNode = null;
  if (page === "dashboard") {
    pageNode = h(DashboardPage, { session, onLogout: handleLogout, navigateClick });
  } else if (page === "analyze") {
    pageNode = h(AnalyzePage, { session, onLogout: handleLogout });
  } else if (page === "live") {
    pageNode = h(LiveActivityPage, { session, onLogout: handleLogout });
  } else if (page === "whitelist") {
    pageNode = h(WhitelistPage, { session, onLogout: handleLogout });
  } else if (page === "blacklist" || page === "blocklist") {
    pageNode = h(BlacklistPage, { session, onLogout: handleLogout });
  } else if (page === "profiles") {
    pageNode = h(ProfilesPage, { session, onLogout: handleLogout });
  } else if (page === "logs") {
    pageNode = h(LogsPage, { session, onLogout: handleLogout });
  } else if (page === "appearance") {
    pageNode = h(AppearancePage, { session, onLogout: handleLogout });
  } else if (page === "system") {
    pageNode = h(SystemPage, { session, onLogout: handleLogout });
  } else if (page === "users") {
    pageNode = h(UsersPage, { session, onLogout: handleLogout });
  }

  return h(AppLayout, { page, navigateClick }, pageNode);
}
