// Applied before first paint to avoid a theme flash.
(function () {
  var t = null;
  var q = /[?&]theme=(light|dark)/.exec(location.search);
  if (q) t = q[1];
  else try { t = localStorage.getItem("phishlens-theme"); } catch (e) { /* storage blocked */ }
  if (!t) t = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", t);
  if (/[?&]static\b/.test(location.search)) document.documentElement.classList.add("static");
  // Design variants: ?design=terminal|editorial|neon|bento (aurora = default stylesheet only)
  var DESIGNS = ["aurora", "terminal", "editorial", "neon", "bento"];
  var d = /[?&]design=(\w+)/.exec(location.search);
  d = d ? d[1] : null;
  if (!d) try { d = localStorage.getItem("phishlens-design"); } catch (e) { /* storage blocked */ }
  if (DESIGNS.indexOf(d) === -1) d = "aurora";
  // Editorial is designed light-first: use light unless the visitor explicitly chose a theme.
  if (d === "editorial" && !q) {
    var chosen = null;
    try { chosen = localStorage.getItem("phishlens-theme"); } catch (e) { /* storage blocked */ }
    if (!chosen) document.documentElement.setAttribute("data-theme", "light");
  }
  document.documentElement.setAttribute("data-design", d);
  if (d !== "aurora") document.write('<link rel="stylesheet" href="assets/designs/' + d + '.css">');
})();
