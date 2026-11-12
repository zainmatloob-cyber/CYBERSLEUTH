// Page behaviour. Event delegation on document, so it keeps working after HTMX swaps.
(function () {
  "use strict";
  var root = document.documentElement;

  function setTheme(theme) {
    root.setAttribute("data-theme", theme);
    try { localStorage.setItem("cs-theme", theme); } catch (e) { /* storage blocked */ }
    document.dispatchEvent(new CustomEvent("cs:theme", { detail: theme }));
  }

  document.addEventListener("click", function (event) {
    var toggle = event.target.closest("#theme-toggle");
    if (toggle) {
      setTheme(root.getAttribute("data-theme") === "dark" ? "light" : "dark");
      return;
    }
    // Expand / collapse the evidence row under a table row.
    var rowToggle = event.target.closest(".row-toggle");
    if (rowToggle) {
      var detail = rowToggle.closest("tr").nextElementSibling;
      if (!detail || !detail.classList.contains("detail-row")) return;
      var open = rowToggle.getAttribute("aria-expanded") === "true";
      rowToggle.setAttribute("aria-expanded", String(!open));
      rowToggle.setAttribute("aria-label", open ? "Show evidence" : "Hide evidence");
      detail.hidden = open;
    }
  });

  // Upload drop zone: show the chosen file name; highlight while dragging.
  function chosenName(input) {
    var title = document.getElementById("dz-title");
    if (title && input.files && input.files.length) title.textContent = input.files[0].name;
  }
  document.addEventListener("change", function (event) {
    if (event.target.matches(".dropzone input[type=file]")) chosenName(event.target);
  });
  ["dragenter", "dragover"].forEach(function (type) {
    document.addEventListener(type, function (event) {
      var zone = event.target.closest && event.target.closest(".dropzone");
      if (zone) zone.classList.add("dragging");
    });
  });
  ["dragleave", "drop"].forEach(function (type) {
    document.addEventListener(type, function (event) {
      var zone = event.target.closest && event.target.closest(".dropzone");
      if (zone) zone.classList.remove("dragging");
    });
  });
})();
