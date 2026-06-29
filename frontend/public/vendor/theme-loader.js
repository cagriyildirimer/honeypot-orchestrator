try {
  var savedTheme = localStorage.getItem("honeypot-director-theme");
  var themes = ["vision", "nebula", "aurora", "emerald", "sunset", "slate"];
  document.documentElement.dataset.theme = themes.indexOf(savedTheme) >= 0 ? savedTheme : "vision";

  var savedScheme = localStorage.getItem("honeypot-director-scheme");
  var schemes = ["dark", "light"];
  document.documentElement.dataset.scheme = schemes.indexOf(savedScheme) >= 0 ? savedScheme : "dark";
} catch (error) {
  document.documentElement.dataset.theme = "vision";
  document.documentElement.dataset.scheme = "dark";
}
