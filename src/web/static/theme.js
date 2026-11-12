// Runs in <head> before the page paints, so there is no flash of the wrong theme.
// The choice is a per-browser convenience: a saved choice wins, otherwise the OS setting.
(function () {
  var theme = null;
  try { theme = localStorage.getItem("cs-theme"); } catch (e) { /* storage blocked */ }
  if (theme !== "light" && theme !== "dark") {
    theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark" : "light";
  }
  document.documentElement.setAttribute("data-theme", theme);
})();
