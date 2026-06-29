try {
  var savedTheme = localStorage.getItem("honeypot-director-theme");
  var themes = ["vision", "nebula", "aurora", "emerald", "sunset", "slate"];
  document.documentElement.dataset.theme = themes.indexOf(savedTheme) >= 0 ? savedTheme : "vision";
} catch (error) {
  document.documentElement.dataset.theme = "vision";
}
