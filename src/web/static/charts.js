// Draws Plotly charts from the JSON spec next to each .chart-plot and keeps them in step
// with the light/dark theme. The server builds the figures (src/visualization/dashboard.py);
// only colours are adapted here, read from the page's CSS tokens.
(function () {
  "use strict";
  if (!window.Plotly) return;

  var TRANSPARENT = "rgba(0,0,0,0)";
  // Single-hue sequential blue. Zero blends into the surface in both themes.
  var RAMPS = {
    dark: ["#111722", "#0d366b", "#1c5cab", "#3987e5", "#86b6ef", "#cde2fb"],
    light: ["#f3f6fb", "#cde2fb", "#86b6ef", "#3987e5", "#1c5cab", "#0d366b"]
  };

  function tokens() {
    var style = getComputedStyle(document.documentElement);
    var read = function (name) { return style.getPropertyValue(name).trim(); };
    return {
      theme: document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light",
      text: read("--text"), text2: read("--text-2"), muted: read("--muted"),
      grid: read("--border"), base: read("--border-strong"), series: read("--accent")
    };
  }

  function axis(original, t) {
    var a = Object.assign({}, original || {});
    if (a.gridcolor !== TRANSPARENT) a.gridcolor = t.grid;
    a.linecolor = t.base;
    a.zerolinecolor = t.base;
    a.tickfont = Object.assign({}, a.tickfont, { color: t.muted });
    return a;
  }

  function themed(spec, t) {
    var layout = Object.assign({}, spec.layout);
    layout.font = Object.assign({}, layout.font, { color: t.text2 });
    if (layout.title) {
      layout.title = Object.assign({}, layout.title);
      layout.title.font = Object.assign({}, layout.title.font, { color: t.text });
    }
    layout.xaxis = axis(layout.xaxis, t);
    layout.yaxis = axis(layout.yaxis, t);
    layout.hoverlabel = Object.assign({}, layout.hoverlabel, { bgcolor: t.theme === "dark" ? "#1d2635" : "#ffffff", bordercolor: t.base, font: Object.assign({}, (layout.hoverlabel || {}).font, { color: t.text }) });
    var ramp = RAMPS[t.theme];
    var data = (spec.data || []).map(function (trace) {
      var copy = Object.assign({}, trace);
      if (copy.type === "bar") copy.marker = Object.assign({}, copy.marker, { color: t.series });
      if (copy.type === "heatmap") {
        copy.colorscale = ramp.map(function (c, i) { return [i / (ramp.length - 1), c]; });
        copy.colorbar = Object.assign({}, copy.colorbar, {
          tickfont: { color: t.muted },
          title: Object.assign({}, (copy.colorbar || {}).title, { font: { color: t.text2 } })
        });
      }
      return copy;
    });
    return { data: data, layout: layout };
  }

  function draw(plot, t) {
    var holder = plot.parentElement.querySelector("script.chart-spec");
    if (!holder) return;
    var spec = plot._csSpec || (plot._csSpec = JSON.parse(holder.textContent));
    var figure = themed(spec, t);
    window.Plotly.react(plot, figure.data, figure.layout,
      { displaylogo: false, responsive: true, modeBarButtonsToRemove: ["lasso2d", "select2d"] });
  }

  function drawAll(root) {
    var t = tokens();
    (root || document).querySelectorAll(".chart-plot").forEach(function (plot) { draw(plot, t); });
  }

  drawAll();
  document.addEventListener("cs:theme", function () { drawAll(); });
  document.body.addEventListener("htmx:afterSettle", function (event) { drawAll(event.target); });
})();
