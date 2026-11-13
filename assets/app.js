// PhishLens web UI. Everything attacker-controlled is inserted with textContent / DOM APIs,
// never innerHTML, and the email preview runs in a sandboxed iframe with no scripts.
import { analyzeEmail } from "../src/analyze.js";
import { parseEmail } from "../src/mime.js";
import { toIocCsv, toJSON, toMarkdown, toStix } from "../src/report.js";
import { defangUrl } from "../src/urls.js";
import { defang } from "../src/domains.js";
import { TECHNIQUES, techniqueUrl } from "../src/mitre.js";
import { decodeQrBrowser } from "./qr.js";

const SAMPLES = [
  { file: "01-microsoft365-password-expiry.eml", icon: "🔑", title: "Microsoft 365 password expiry", desc: "Look-alike sender, DMARC fail and a button that lies about where it goes.", tags: ["Credential phishing", "Look-alike"] },
  { file: "02-ceo-urgent-wire-transfer.eml", icon: "💸", title: "CEO urgent wire transfer", desc: "Business email compromise from Gmail. It passes SPF, DKIM and DMARC.", tags: ["BEC", "No links"] },
  { file: "03-dhl-invoice-malware.eml", icon: "📦", title: "DHL customs invoice", desc: "A .pdf.js inside a ZIP and a macro document with remote template injection.", tags: ["Malware", "Macros"] },
  { file: "04-html-smuggling-secure-message.eml", icon: "🧨", title: "Payroll \"secure message\"", desc: "An HTML attachment that builds a file in the browser and fakes a login.", tags: ["HTML smuggling"] },
  { file: "05-qr-code-mfa-reenrollment.eml", icon: "🔳", title: "MFA re-enrollment QR code", desc: "Almost no text, just a QR code. PhishLens decodes it and checks the link.", tags: ["Quishing"] },
  { file: "06-paypal-homograph-refund.eml", icon: "🅿️", title: "PayPal refund", desc: "pаypal.com written with a Cyrillic \"а\", plus a short link posing as PayPal.", tags: ["Homograph", "Punycode"] },
  { file: "07-legit-github-notification.eml", icon: "✅", title: "Real GitHub notification", desc: "A legitimate, fully authenticated email: proof it doesn't cry wolf.", tags: ["Control sample"] },
];

const TACTIC_ORDER = ["Resource Development", "Reconnaissance", "Initial Access", "Execution", "Defense Evasion", "Credential Access", "Lateral Movement", "Impact"];
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const $ = (s, r = document) => r.querySelector(s);

const state = { items: [], index: -1, tab: "overview", iocRaw: false, contentMode: "preview" };

// ------------------------------------------------------------------ DOM helpers
function h(tag, props, ...children) {
  const el = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else if (k === "style") Object.assign(el.style, v);
      else if (k === "href") el.href = safeHref(v);
      else el.setAttribute(k, v === true ? "" : v);
    }
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const safeHref = (u) => (/^(https:\/\/|#|\.\/|mailto:)/i.test(u) ? u : "#");
const ext = (href, label, cls = "pivot") => h("a", { class: cls, href, target: "_blank", rel: "noopener noreferrer" }, label);

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.t);
  toast.t = setTimeout(() => t.classList.remove("show"), 1800);
}

async function copy(text, what = "Copied") {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = h("textarea", { style: { position: "fixed", opacity: "0" } });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  toast(`${what} ✓`);
}
const copyBtn = (text, label = "Copy") => h("button", { class: "copy", type: "button", onclick: (e) => { e.stopPropagation(); copy(text); } }, label);

function download(name, mime, text) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = h("a", { download: name });
  a.href = url;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage blocked */ } },
};

// ------------------------------------------------------------------ views
function show(view) {
  for (const id of ["landing", "results", "batch"]) $("#" + id).hidden = id !== view;
  window.scrollTo({ top: 0 });
}

function showLanding() {
  show("landing");
  state.index = -1;
  history.replaceState(null, "", location.pathname);
}

// ------------------------------------------------------------------ analysis
async function analyzeInputs(inputs) {
  if (!inputs.length) return;
  const scan = $("#scanning");
  scan.hidden = false;
  const live = $("#liveToggle").checked;
  const started = performance.now();
  state.items = [];
  try {
    for (let i = 0; i < inputs.length; i++) {
      $("#scanText").textContent = inputs.length > 1 ? `Analysing ${i + 1} / ${inputs.length}: ${inputs[i].name}` : live ? "Analysing + live intel lookups…" : "Analysing…";
      const report = await analyzeEmail(inputs[i].buffer, { filename: inputs[i].name, decodeQr: decodeQrBrowser, live });
      state.items.push({ name: inputs[i].name, buffer: inputs[i].buffer, report });
    }
  } catch (e) {
    console.error(e);
    toast("Could not analyse that file: " + (e.message || e));
  }
  const wait = 420 - (performance.now() - started);
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  scan.hidden = true;
  if (state.items.length === 1) openResult(0);
  else if (state.items.length > 1) renderBatch();
}

async function filesToInputs(fileList) {
  const files = [...fileList].slice(0, 50);
  const big = files.find((f) => f.size > 40 * 1024 * 1024);
  if (big) {
    toast(`${big.name} is larger than 40 MB`);
    return [];
  }
  return Promise.all(files.map(async (f) => ({ name: f.name, buffer: new Uint8Array(await f.arrayBuffer()) })));
}

async function loadAllSamples() {
  try {
    const inputs = await Promise.all(SAMPLES.map(async (s) => ({ name: s.file, buffer: new Uint8Array(await (await fetch(`samples/${s.file}`)).arrayBuffer()) })));
    await analyzeInputs(inputs);
    history.replaceState(null, "", "#batch=samples");
  } catch {
    toast("Couldn't load the samples");
  }
}

async function loadSample(file) {
  try {
    const r = await fetch(`samples/${file}`);
    if (!r.ok) throw new Error(r.status);
    await analyzeInputs([{ name: file, buffer: new Uint8Array(await r.arrayBuffer()) }]);
    if (!location.hash.startsWith(`#sample=${file.slice(0, 2)}`)) history.replaceState(null, "", `#sample=${file.slice(0, 2)}`);
  } catch {
    toast("Couldn't load the sample (open the page through a web server, not file://)");
  }
}

// ------------------------------------------------------------------ result page
function openResult(i) {
  state.index = i;
  state.tab = "overview";
  renderResult();
  show("results");
}

function verdictCard(r) {
  const m = r.message;
  const C = 2 * Math.PI * 64;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 156 156");
  svg.setAttribute("width", "156");
  svg.setAttribute("height", "156");
  const mk = (cls) => {
    const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    c.setAttribute("cx", "78"); c.setAttribute("cy", "78"); c.setAttribute("r", "64");
    c.setAttribute("fill", "none"); c.setAttribute("stroke-width", "12"); c.setAttribute("class", cls);
    return c;
  };
  svg.append(mk("track"));
  const arc = mk("bar");
  arc.setAttribute("stroke-dasharray", String(C));
  svg.append(arc);
  const final = String(C * (1 - r.score / 100));
  const num = h("b", { text: String(r.score) });
  // Animate only the first time a result is shown (not on every tab switch), and never in screenshot mode.
  if (!r._shown && !/[?&]static\b/.test(location.search)) {
    arc.setAttribute("stroke-dashoffset", String(C));
    requestAnimationFrame(() => requestAnimationFrame(() => arc.setAttribute("stroke-dashoffset", final)));
    num.textContent = "0";
    animateNumber(num, r.score);
  } else {
    arc.style.transition = "none";
    arc.setAttribute("stroke-dashoffset", final);
  }
  Object.defineProperty(r, "_shown", { value: true, enumerable: false, configurable: true });

  const a = r.auth;
  const dkim = a.dkim.find((d) => d.result === "pass") || a.dkim[0];
  const pill = (k, res, extra) => {
    const cls = res === "pass" ? "pass" : ["fail", "softfail", "permerror"].includes(res) ? "fail" : res ? "warn" : "";
    return h("span", { class: `auth-pill ${cls}`, title: `${k}: ${res || "no result"}` }, h("i"), k, h("small", { text: res || "none" }), extra);
  };
  const name = m.from.name || m.from.local || m.from.address || "?";
  return h("div", { class: `verdict v-${r.verdict.key} fade-in` },
    h("div", { class: "gauge" }, svg, h("div", { class: "num" }, num, h("span", { text: "RISK / 100" }))),
    h("div", null,
      h("div", { class: "v-label", text: r.verdict.label }),
      h("h2", { class: "v-subject", text: m.subject || "(no subject)" }),
      h("p", { class: "v-summary", text: r.summary }),
      h("div", { class: "sender-row" },
        h("div", { class: "avatar", text: name.trim().charAt(0).toUpperCase() || "?" }),
        h("div", { class: "who" }, h("div", { class: "name", text: m.from.name || "(no display name)" }), h("div", { class: "addr", text: m.from.address || "(no address)" })),
        h("div", { class: "auth-pills" }, pill("SPF", a.spf?.result), pill("DKIM", dkim?.result, r.dkimAligned ? h("small", { text: "· aligned" }) : null), pill("DMARC", a.dmarc?.result)),
      ),
      h("div", { class: "counts" },
        SEV_ORDER.filter((s) => s !== "info").map((s) => h("span", { class: "count" }, h("span", { class: `sev sev-${s}`, text: s }), h("b", { text: r.counts[s] }))),
        h("span", { class: "count muted", text: `· ${r.urls.length} link${r.urls.length === 1 ? "" : "s"} · ${r.attachments.length} attachment${r.attachments.length === 1 ? "" : "s"} · ${r.durationMs || "<1"} ms` }),
      ),
    ),
  );
}

function animateNumber(el, target) {
  const start = performance.now();
  const step = (t) => {
    const p = Math.min(1, Math.max(0, (t - start) / 1000));
    el.textContent = String(Math.round(target * (1 - Math.pow(1 - p, 3))));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function exportMenu(item) {
  const r = item.report;
  const base = (item.name || "email").replace(/\.[^.]+$/, "");
  const list = h("div", { class: "menu-list", hidden: true });
  const opt = (label, hint, fn) => h("button", { type: "button", onclick: () => { list.hidden = true; fn(); } }, label, h("small", { text: hint }));
  list.append(
    opt("Incident report", ".md", () => download(`${base}-report.md`, "text/markdown", toMarkdown(r))),
    opt("IOC list", ".csv", () => download(`${base}-iocs.csv`, "text/csv", toIocCsv(r))),
    opt("STIX 2.1 bundle", ".json", () => download(`${base}-stix.json`, "application/json", toStix(r))),
    opt("Full analysis", ".json", () => download(`${base}-phishlens.json`, "application/json", toJSON(r))),
    opt("Print / save as PDF", "⌘P", () => { state.tab = "overview"; renderResult(); setTimeout(() => window.print(), 150); }),
    opt("Copy summary", "", () => copy(`${r.verdict.label} (${r.score}/100): ${r.message.subject}\n${r.summary}`, "Summary copied")),
  );
  const btn = h("button", { class: "btn primary sm", type: "button", "aria-haspopup": "true", onclick: (e) => { e.stopPropagation(); list.hidden = !list.hidden; } }, "Export ▾");
  document.addEventListener("click", () => (list.hidden = true));
  return h("div", { class: "menu" }, btn, list);
}

function renderResult() {
  const item = state.items[state.index];
  const r = item.report;
  const root = $("#results");
  root.replaceChildren();
  const bar = h("div", { class: "results-bar" },
    h("button", { class: "btn sm ghost", type: "button", onclick: () => (state.items.length > 1 ? renderBatch() : showLanding()) }, state.items.length > 1 ? "← All emails" : "← New analysis"),
    h("span", { class: "file", text: item.name, title: item.name }),
    h("span", { class: "spacer" }),
    r.live ? h("span", { class: "tag", text: r.live.error ? "live intel failed" : "live intel ✓" }) : null,
    exportMenu(item),
  );
  const tabs = [
    ["overview", "Overview", r.findings.filter((f) => f.severity !== "info").length],
    ["sender", "Sender & headers", null],
    ["links", "Links", r.urls.length, r.urls.some((u) => u.flags.some((f) => ["critical", "high"].includes(f.severity)))],
    ["attachments", "Attachments", r.attachments.length, r.attachments.some((a) => a.flags.some((f) => ["critical", "high"].includes(f.severity)))],
    ["content", "Content", null],
    ["mitre", "MITRE ATT&CK", r.mitre.length],
    ["iocs", "IOCs", r.iocs.urls.length + r.iocs.domains.length + r.iocs.ips.length + r.iocs.files.length + r.iocs.emails.length],
    ["raw", "Raw headers", r.headers.length],
  ];
  const tabBar = h("div", { class: "tabs", role: "tablist" },
    tabs.map(([id, label, n, hot]) => h("button", { class: `tab${state.tab === id ? " active" : ""}`, role: "tab", "aria-selected": String(state.tab === id), type: "button", onclick: () => { state.tab = id; renderResult(); } }, label, n != null ? h("span", { class: `n${hot ? " hot" : ""}`, text: n }) : null)),
  );
  const panel = h("div", { class: "fade-in" });
  ({ overview, sender, links, attachments, content, mitre, iocs, raw })[state.tab](panel, r, item);
  root.append(bar, verdictCard(r), tabBar, panel);
}

// ------------------------------------------------------------------ tabs
function findingEl(f, open) {
  return h("details", { class: `finding ${f.severity}`, open },
    h("summary", null,
      h("span", { class: `sev sev-${f.severity}`, text: f.severity }),
      h("span", { class: "t", text: f.title }),
      h("span", { class: "tag", text: f.category }),
      h("span", { class: "chev", text: "›" }),
    ),
    h("div", { class: "body" },
      h("p", { text: f.detail }),
      f.evidence?.length ? h("pre", { class: "evidence", text: f.evidence.join("\n") }) : null,
      f.mitre?.length ? h("div", { class: "mitre-row" }, f.mitre.map((t) => ext(techniqueUrl(t), `${t} · ${TECHNIQUES[t]?.name || ""}`, "mitre-chip"))) : null,
    ),
  );
}

function overview(p, r) {
  const main = h("div");
  const real = r.findings.filter((f) => f.severity !== "info");
  const infos = r.findings.filter((f) => f.severity === "info");
  main.append(h("div", { class: "card" },
    h("h3", null, "Findings", h("span", { class: "muted", text: `${real.length} issue${real.length === 1 ? "" : "s"}, most severe first` })),
    real.length ? real.map((f, i) => findingEl(f, i < 3 && ["critical", "high"].includes(f.severity))) : h("div", { class: "empty", text: "No phishing indicators found." }),
    infos.length ? h("p", { class: "muted", style: { fontSize: "13px", margin: "12px 0 6px" }, text: "Context (not counted in the score):" }) : null,
    infos.map((f) => findingEl(f, false)),
  ));
  const side = h("div");
  side.append(h("div", { class: "card" }, h("h3", null, "What to do"), h("ul", { class: "list" }, r.recommendations.map((x) => h("li", null, h("span", { class: "do", text: "→" }), h("span", { text: x }))))));
  if (r.good.length) side.append(h("div", { class: "card" }, h("h3", null, "Good signs"), h("ul", { class: "list" }, r.good.map((g) => h("li", null, h("span", { class: "ok", text: "✓" }), h("span", { text: g })))), h("p", { class: "muted", style: { fontSize: "12.5px", margin: "10px 0 0" }, text: "Passing SPF/DKIM/DMARC only proves the mail came from the domain it claims, not that the domain is honest." })));
  if (r.mitre.length) side.append(h("div", { class: "card" }, h("h3", null, "ATT&CK techniques"), h("div", { class: "mitre-row" }, r.mitre.map((t) => ext(t.url, `${t.id} · ${t.name}`, "mitre-chip")))));
  if (r.message.warnings.length) side.append(h("div", { class: "card" }, h("h3", null, "Parser notes"), h("ul", { class: "list" }, r.message.warnings.map((w) => h("li", { text: w })))));
  p.append(h("div", { class: "grid2" }, main, side));
}

function sender(p, r) {
  const m = r.message;
  const fromReg = m.from.domain;
  const row = (k, v, warn) => h("tr", null, h("th", { text: k }), h("td", { class: warn ? "warn" : "" }, v || h("span", { class: "muted", text: "—" }), warn ? h("span", { class: "sev sev-high flag-inline", text: warn }) : null));
  const rt = m.replyTo.map((x) => x.address).join(", ");
  const rtWarn = m.replyTo.some((x) => x.domain && x.domain !== fromReg) ? "different domain" : "";
  const rpWarn = m.returnPath.domain && m.returnPath.domain !== fromReg && !r.dkimAligned ? "differs" : "";
  const id = h("div", { class: "card" }, h("h3", null, "Identity"),
    h("table", { class: "kv" },
      row("From", `${m.from.name ? m.from.name + " " : ""}<${m.from.address}>`),
      row("Reply-To", rt, rtWarn),
      row("Return-Path", m.returnPath.address, rpWarn),
      row("To", m.to.map((x) => x.address).join(", ")),
      m.cc.length ? row("Cc", m.cc.map((x) => x.address).join(", ")) : null,
      row("Date", m.date),
      row("Message-ID", m.messageId),
      row("Mailer", m.mailer),
      row("Origin IP", r.received.originIp),
      row("Size", `${(m.size / 1024).toFixed(1)} KB · ${m.parts} MIME part${m.parts === 1 ? "" : "s"}`),
    ),
  );
  const a = r.auth;
  const box = (k, res, detail) => {
    const cls = res === "pass" ? "pass" : ["fail", "softfail", "permerror"].includes(res) ? "fail" : res ? "warn" : "none";
    return h("div", { class: `auth-box ${cls}` }, h("div", { class: "k", text: k }), h("div", { class: "v", text: res || "none" }), h("div", { class: "d", text: detail || "no result in headers" }));
  };
  const dk = a.dkim.find((d) => d.result === "pass") || a.dkim[0];
  const auth = h("div", { class: "card" }, h("h3", null, "Authentication", h("span", { class: "muted", text: a.source || "" })),
    h("div", { class: "auth-grid" },
      box("SPF", a.spf?.result, a.spf ? `envelope: ${a.spf.domain || "?"}` : ""),
      box("DKIM", dk?.result, dk?.result === "none" ? "message not signed" : dk ? `d=${dk.domain || "?"}${dk.selector ? " s=" + dk.selector : ""}${r.dkimAligned ? " · aligned" : ""}` : r.dkimSignatures.length ? `signed by ${r.dkimSignatures.map((s) => s.domain).join(", ")} (not verified)` : ""),
      box("DMARC", a.dmarc?.result, a.dmarc ? `header.from=${a.dmarc.domain || "?"}${a.dmarc.policy ? " p=" + a.dmarc.policy : ""}` : ""),
    ),
    a.raw ? h("pre", { class: "evidence", style: { marginTop: "12px" }, text: a.raw }) : null,
  );

  const side = h("div");
  if (r.live) {
    side.append(h("div", { class: "card" }, h("h3", null, "Live intel"),
      r.live.error ? h("p", { class: "muted", text: `Lookups failed: ${r.live.error}` }) :
      r.live.domains.map((d) => h("div", { style: { marginBottom: "12px" } },
        h("div", { class: "mono", style: { fontWeight: 600 }, text: d.domain }),
        h("table", { class: "kv" },
          row("Registered", d.created ? `${d.created.slice(0, 10)} (${d.ageDays} days ago)` : d.rdapError ? `unknown (${d.rdapError})` : "unknown", d.ageDays != null && d.ageDays < 30 ? "brand new" : ""),
          d.registrar ? row("Registrar", d.registrar) : null,
          "spf" in d ? row("SPF record", d.spf || "none", d.spf ? "" : "missing") : null,
          "dmarc" in d ? row("DMARC", d.dmarc || "none", d.dmarc ? "" : "missing") : null,
          d.mx ? row("MX", d.mx.join(", ") || "none") : null,
        ),
      )),
    ));
  } else {
    side.append(h("div", { class: "card" }, h("h3", null, "Live intel"), h("p", { class: "muted", style: { margin: 0, fontSize: "13.5px" }, text: "Turn on \"Live intel\" on the start page to see domain age, SPF and DMARC records for the sender and link domains." })));
  }
  const hops = r.received.hops;
  side.append(h("div", { class: "card" }, h("h3", null, "Delivery path", h("span", { class: "muted", text: `${hops.length} hop${hops.length === 1 ? "" : "s"}, oldest first` })),
    hops.length ? h("ol", { class: "hops" }, hops.map((hp, i) => h("li", { class: `hop${hp.publicIp && hp.publicIp === r.received.originIp ? " origin" : ""}`, "data-n": String(i + 1) },
      h("div", { class: "route" }, h("b", { text: hp.from || "?" }), " → ", hp.by || "?"),
      h("div", { class: "meta" },
        hp.ip ? h("span", { class: "tag mono", text: hp.ip }) : null,
        hp.publicIp && hp.publicIp === r.received.originIp ? h("span", { class: "sev sev-high", text: "origin" }) : null,
        hp.delay != null ? h("span", { text: hp.delay < 0 ? `⚠ ${hp.delay}s (clock skew)` : `+${hp.delay}s` }) : null,
        hp.with ? h("span", { text: hp.with }) : null,
        hp.publicIp ? ext(`https://www.abuseipdb.com/check/${encodeURIComponent(hp.publicIp)}`, "AbuseIPDB ↗") : null,
      ),
    ))) : h("div", { class: "empty", text: "No Received headers." }),
  ));
  p.append(h("div", { class: "grid2" }, h("div", null, id, auth), side));
}

function urlCard(u) {
  const worst = u.flags.reduce((m, f) => Math.min(m, SEV_ORDER.indexOf(f.severity)), 9);
  const cls = worst <= 1 ? "bad" : worst <= 2 ? "warn" : "";
  const mm = /^([a-z]+:\/\/)([^/?#]*)(.*)$/i.exec(u.defanged);
  const uEl = mm ? h("div", { class: "u" }, h("span", { class: "rest", text: mm[1] }), h("span", { class: "host", text: mm[2] }), h("span", { class: "rest", text: mm[3] })) : h("div", { class: "u", text: u.defanged });
  const pivots = [];
  if (u.host && u.scheme.startsWith("http")) {
    pivots.push(ext(`https://www.virustotal.com/gui/search/${encodeURIComponent(u.url)}`, "VirusTotal ↗"));
    pivots.push(ext(`https://urlscan.io/search/#${encodeURIComponent("domain:" + u.host)}`, "urlscan ↗"));
    pivots.push(ext(`https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(u.host)}`, "URLhaus ↗"));
  }
  return h("div", { class: `url-card ${cls}` },
    h("div", { class: "url-top" }, uEl, copyBtn(u.url, "Copy")),
    u.hostUnicode && u.hostUnicode !== u.host ? h("p", { class: "url-shown" }, "Displays as ", h("b", { text: u.hostUnicode })) : null,
    u.texts.length ? h("p", { class: "url-shown" }, "Shown to the reader as ", h("b", { text: `"${u.texts[0].slice(0, 120)}"` })) : null,
    h("p", { class: "url-shown", text: `Found in: ${u.sources.join(", ")}${u.brand ? ` · belongs to ${u.brand}` : ""}` }),
    u.flags.length ? h("div", { class: "flags" }, u.flags.map((f) => h("div", { class: "flagline" }, h("span", { class: `sev sev-${f.severity}`, text: f.severity }), h("span", { text: f.text })))) : null,
    pivots.length ? h("div", { class: "pivots" }, pivots) : null,
  );
}

function links(p, r) {
  if (!r.urls.length) return p.append(h("div", { class: "card" }, h("div", { class: "empty", text: "No links in this email." })));
  const sorted = r.urls.slice().sort((a, b) => score(b) - score(a));
  function score(u) { return u.flags.reduce((s, f) => s + (5 - SEV_ORDER.indexOf(f.severity)) ** 2, 0); }
  p.append(h("div", { class: "card" }, h("h3", null, "Links", h("span", { class: "muted", text: "defanged, nothing was opened · riskiest first" })), sorted.map(urlCard)));
}

const FILE_COLORS = { pe: "#e11d48", elf: "#e11d48", lnk: "#e11d48", zip: "#d97706", rar: "#d97706", "7z": "#d97706", pdf: "#dc2626", ole: "#2563eb", html: "#7c3aed", svg: "#7c3aed", png: "#059669", jpeg: "#059669", gif: "#059669", iso: "#be123c" };

function attachments(p, r, item) {
  if (!r.attachments.length) return p.append(h("div", { class: "card" }, h("div", { class: "empty", text: "No attachments." })));
  let parsed = null;
  for (const a of r.attachments) {
    const card = h("div", { class: "card" });
    const label = (a.ext || a.magic.type || "bin").slice(0, 5);
    const color = a.office?.macros ? "#2563eb" : FILE_COLORS[a.magic.type] || "#475569";
    let preview = null;
    if (a.qr?.length || (a.isImage && a.size < 2e6)) {
      parsed ||= parseEmail(item.buffer);
      const src = parsed.attachments.find((x) => x.filename === a.filename || (a.contentId && x.contentId === a.contentId));
      if (src) {
        const img = h("img", { alt: "" });
        img.src = URL.createObjectURL(new Blob([src.bytes], { type: a.contentType }));
        preview = img;
      }
    }
    card.append(h("div", { class: "att" },
      h("div", { class: "file-ico", style: { "--fi": color }, text: label }),
      h("div", null,
        h("h3", { style: { marginBottom: "4px", wordBreak: "break-all" }, text: a.filename }),
        h("p", { class: "muted", style: { margin: "0 0 10px", fontSize: "13px" }, text: `${(a.size / 1024).toFixed(1)} KB · declared ${a.contentType} · really: ${a.magic.label}${a.disposition === "inline" ? " · inline" : ""}` }),
        ["sha256", "sha1", "md5"].map((k) => h("div", { class: "hash" }, h("b", { text: k.toUpperCase() }), h("span", { text: a.hashes[k] }), copyBtn(a.hashes[k]))),
        a.flags.length ? h("div", { class: "flags" }, a.flags.map((f) => h("div", { class: "flagline" }, h("span", { class: `sev sev-${f.severity}`, text: f.severity }), h("span", null, h("b", { style: { color: "var(--text)" }, text: f.title + ": " }), f.detail)))) : null,
        a.archive?.entries?.length ? h("div", { class: "entries" }, a.archive.entries.map((e) => h("div", { class: /\.(exe|js|vbs|scr|bat|cmd|lnk|hta|iso|ps1|bin)$/i.test(e.name) ? "bad" : "", text: `${e.encrypted ? "🔒 " : ""}${e.name}  (${e.size} B)` }))) : null,
        a.office?.externalRefs?.length ? h("pre", { class: "evidence", style: { marginTop: "10px" }, text: a.office.externalRefs.map((x) => `${x.type} → ${defangUrl(x.target)}`).join("\n") }) : null,
        a.qr?.length ? h("div", { class: "qr-box" }, preview, h("div", null, h("div", { style: { fontWeight: 700, marginBottom: "4px" }, text: "QR code decoded" }), h("div", { class: "mono", style: { wordBreak: "break-all", fontSize: "12.5px" }, text: defangUrl(a.qr[0]) }))) : preview ? h("div", { style: { marginTop: "12px" } }, preview) : null,
        h("div", { class: "pivots" },
          ext(`https://www.virustotal.com/gui/file/${a.hashes.sha256}`, "VirusTotal ↗"),
          ext(`https://bazaar.abuse.ch/browse.php?search=${encodeURIComponent("sha256:" + a.hashes.sha256)}`, "MalwareBazaar ↗"),
        ),
      ),
    ));
    if (preview && !a.qr?.length) { preview.style.maxWidth = "220px"; preview.style.borderRadius = "8px"; }
    p.append(card);
  }
}

function buildPreviewDoc(html, cidMap) {
  const doc = new DOMParser().parseFromString(html, "text/html"); // inert: nothing loads or runs
  doc.querySelectorAll("script,iframe,frame,frameset,object,embed,applet,base,link,meta,noscript,template,portal").forEach((n) => n.remove());
  for (const el of doc.querySelectorAll("*")) {
    for (const at of [...el.attributes]) {
      const n = at.name.toLowerCase();
      if (n.startsWith("on") || ["srcset", "background", "poster", "action", "formaction", "ping", "lowsrc", "dynsrc", "xlink:href"].includes(n)) el.removeAttribute(at.name);
      else if (n === "style" && /url\s*\(/i.test(at.value)) el.setAttribute("style", at.value.replace(/url\s*\(\s*(?!["']?data:image\/)[^)]*\)/gi, "none"));
      else if (n === "href" && el.tagName !== "A" && el.tagName !== "AREA") el.removeAttribute(at.name);
    }
  }
  doc.querySelectorAll("style").forEach((s) => { s.textContent = s.textContent.replace(/@import[^;]+;?/gi, "").replace(/url\s*\(\s*(?!["']?data:image\/)[^)]*\)/gi, "none"); });
  doc.querySelectorAll("a[href],area[href]").forEach((a) => {
    const real = a.getAttribute("href");
    a.removeAttribute("href");
    a.setAttribute("title", `Real destination: ${defangUrl(real)}`);
    a.style.cursor = "help";
    a.style.textDecoration = "underline";
  });
  doc.querySelectorAll("img").forEach((img) => {
    const s = img.getAttribute("src") || "";
    if (s.toLowerCase().startsWith("cid:") && cidMap[s.slice(4)]) img.setAttribute("src", cidMap[s.slice(4)]);
    else if (!/^data:image\//i.test(s)) {
      img.removeAttribute("src");
      img.setAttribute("alt", "[remote image blocked]");
      img.style.outline = "1px dashed #bbb";
      img.style.minWidth = "40px";
      img.style.minHeight = "20px";
    }
  });
  doc.querySelectorAll("input,button,select,textarea").forEach((n) => n.setAttribute("disabled", ""));
  const csp = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">`;
  return `<!doctype html><html><head><meta charset="utf-8">${csp}<style>body{font-family:Arial,sans-serif;margin:16px;color:#111;background:#fff}</style></head><body>${doc.body ? doc.body.innerHTML : ""}</body></html>`;
}

function bytesToDataUrl(bytes, type) {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return `data:${type};base64,${btoa(bin)}`;
}

function content(p, r, item) {
  const card = h("div", { class: "card" });
  const modes = [["preview", "Safe preview"], ["text", "Text (highlighted)"], ["source", "HTML source"]].filter(([m]) => m !== "preview" && m !== "source" || r.body.html);
  if (!modes.some(([m]) => m === state.contentMode)) state.contentMode = "text";
  const seg = h("div", { class: "seg" }, modes.map(([m, l]) => h("button", { type: "button", class: state.contentMode === m ? "on" : "", onclick: () => { state.contentMode = m; renderResult(); } }, l)));
  card.append(seg);
  if (state.contentMode === "preview") {
    const parsed = parseEmail(item.buffer);
    const cidMap = {};
    for (const a of parsed.attachments) if (a.contentId && /^image\//.test(a.contentType) && a.bytes.length < 3e6) cidMap[a.contentId] = bytesToDataUrl(a.bytes, a.contentType);
    const frame = h("iframe", { class: "preview-frame", sandbox: "", referrerpolicy: "no-referrer", title: "Sandboxed email preview" });
    frame.srcdoc = buildPreviewDoc(r.body.html, cidMap);
    card.append(h("p", { class: "preview-note", text: "Sandboxed: scripts removed, remote images blocked, links disabled. Hover a link to see where it really goes." }), frame);
  } else if (state.contentMode === "text") {
    const phrases = [...new Set(r.findings.flatMap((f) => f.phrases || []))].filter((x) => x.length > 2).sort((a, b) => b.length - a.length);
    const text = r.body.plain || "(empty body)";
    const pre = h("pre", { class: "plain" });
    if (phrases.length) {
      const re = new RegExp(`(${phrases.map((x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`, "gi");
      let last = 0;
      for (const m of text.matchAll(re)) {
        pre.append(text.slice(last, m.index), h("mark", { text: m[0] }));
        last = m.index + m[0].length;
      }
      pre.append(text.slice(last));
    } else pre.textContent = text;
    card.append(h("p", { class: "preview-note", text: phrases.length ? `${phrases.length} social-engineering phrase${phrases.length > 1 ? "s" : ""} highlighted · ${r.body.words} words` : `${r.body.words} words` }), pre);
  } else {
    card.append(h("pre", { class: "plain", text: r.body.html }));
  }
  p.append(card);
}

function mitre(p, r) {
  const active = new Map(r.mitre.map((t) => [t.id, t]));
  const byTactic = new Map(TACTIC_ORDER.map((t) => [t, []]));
  for (const [id, t] of Object.entries(TECHNIQUES)) byTactic.get(t.tactic)?.push({ id, ...t });
  p.append(h("div", { class: "card" },
    h("h3", null, "ATT&CK coverage", h("span", { class: "muted", text: `${active.size} of ${Object.keys(TECHNIQUES).length} phishing-related techniques seen in this email` })),
    h("div", { class: "matrix" }, [...byTactic].filter(([, list]) => list.length).map(([tactic, list]) => h("div", { class: "tactic" },
      h("h4", { text: tactic }),
      list.map((t) => {
        const on = active.get(t.id);
        return h(on ? "a" : "div", { class: `tech${on ? " on" : ""}`, href: on ? techniqueUrl(t.id) : null, target: on ? "_blank" : null, rel: on ? "noopener" : null, title: on ? `Seen: ${on.findings.join("; ")}` : "Not observed" }, h("code", { text: t.id }), t.name);
      }),
    ))),
  ));
}

function iocs(p, r) {
  const i = r.iocs;
  const fmt = (kind, v) => (state.iocRaw ? v : kind === "url" ? defangUrl(v) : defang(v));
  const group = (title, kind, values) => {
    if (!values.length) return null;
    const text = values.map((v) => fmt(kind, v)).join("\n");
    return h("div", { class: "ioc-group" }, h("h4", null, `${title} (${values.length})`, copyBtn(text, "Copy all")), h("pre", { class: "ioc-list", text }));
  };
  const hashText = i.files.map((f) => `${f.sha256}  ${f.name}${f.risky ? "  [risky]" : ""}`).join("\n");
  const total = i.urls.length + i.domains.length + i.ips.length + i.files.length + i.emails.length;
  p.append(h("div", { class: "grid2" },
    h("div", { class: "card" },
      h("div", { class: "seg" }, [["Defanged", false], ["Raw", true]].map(([l, v]) => h("button", { type: "button", class: state.iocRaw === v ? "on" : "", onclick: () => { state.iocRaw = v; renderResult(); } }, l))),
      total ? [
        group("Sender addresses", "email", i.emails),
        group("Domains", "domain", i.domains),
        group("IP addresses", "ip", i.ips),
        group("URLs", "url", i.urls),
        i.files.length ? h("div", { class: "ioc-group" }, h("h4", null, `File hashes, SHA-256 (${i.files.length})`, copyBtn(hashText, "Copy all")), h("pre", { class: "ioc-list", text: hashText })) : null,
      ] : h("div", { class: "empty", text: "No indicators worth blocking: this email looks legitimate." }),
    ),
    h("div", null, h("div", { class: "card" }, h("h3", null, "Export"),
      h("p", { class: "muted", style: { fontSize: "13.5px", marginTop: 0 }, text: "Hand-off formats for a ticket, a SIEM or a threat-intel platform." }),
      h("div", { style: { display: "grid", gap: "8px" } },
        h("button", { class: "btn", type: "button", onclick: () => download("phishlens-iocs.csv", "text/csv", toIocCsv(r)) }, "IOC list · CSV"),
        h("button", { class: "btn", type: "button", onclick: () => download("phishlens-stix.json", "application/json", toStix(r)) }, "STIX 2.1 bundle"),
        h("button", { class: "btn", type: "button", onclick: () => download("phishlens-report.md", "text/markdown", toMarkdown(r)) }, "Incident report · Markdown"),
      ),
    )),
  ));
}

function raw(p, r) {
  const input = h("input", { class: "raw-search", type: "search", placeholder: "Filter headers…  e.g. received, dkim, x-" });
  const tbody = h("tbody");
  const draw = () => {
    const q = input.value.trim().toLowerCase();
    tbody.replaceChildren(...r.headers.filter((x) => !q || x.name.toLowerCase().includes(q) || x.value.toLowerCase().includes(q)).map((x) => h("tr", null, h("td", { text: x.name }), h("td", { text: x.value }))));
  };
  input.addEventListener("input", draw);
  draw();
  p.append(h("div", { class: "card" }, input, h("table", { class: "raw-table" }, tbody)));
}

// ------------------------------------------------------------------ batch view
function renderBatch() {
  const root = $("#batch");
  const items = state.items.map((it, i) => ({ ...it, i })).sort((a, b) => b.report.score - a.report.score);
  const color = (k) => `var(--${{ malicious: "critical", phishing: "high", suspicious: "medium", clean: "safe" }[k]})`;
  const csv = () => {
    const rows = [["file", "verdict", "score", "subject", "from", "top_finding"]].concat(items.map((x) => [x.name, x.report.verdict.label, x.report.score, x.report.message.subject, x.report.message.from.address, x.report.findings[0]?.title || ""]));
    download("phishlens-batch.csv", "text/csv", rows.map((r) => r.map((c) => { let s = String(c ?? ""); if (/^[=+\-@]/.test(s)) s = "'" + s; return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; }).join(",")).join("\n"));
  };
  const counts = items.reduce((m, x) => ((m[x.report.verdict.key] = (m[x.report.verdict.key] || 0) + 1), m), {});
  root.replaceChildren(
    h("div", { class: "results-bar" },
      h("button", { class: "btn sm ghost", type: "button", onclick: showLanding }, "← New analysis"),
      h("span", { class: "file", text: `${items.length} emails triaged` }),
      h("span", { class: "spacer" }),
      h("button", { class: "btn primary sm", type: "button", onclick: csv }, "Export CSV"),
    ),
    h("div", { class: "card fade-in" },
      h("h3", null, "Batch triage", h("span", { class: "muted", text: ["malicious", "phishing", "suspicious", "clean"].filter((k) => counts[k]).map((k) => `${counts[k]} ${k}`).join(" · ") })),
      h("table", { class: "batch-table" },
        h("thead", null, h("tr", null, h("th", { text: "Verdict" }), h("th", { text: "Risk" }), h("th", { text: "Subject" }), h("th", { class: "hide-sm-col", text: "From" }), h("th", { class: "hide-sm-col", text: "Top finding" }))),
        h("tbody", null, items.map((x) => h("tr", { tabindex: "0", onclick: () => openResult(x.i), onkeydown: (e) => e.key === "Enter" && openResult(x.i) },
          h("td", null, h("span", { class: `vpill ${x.report.verdict.key}`, text: x.report.verdict.label })),
          h("td", { class: "mono" }, h("span", { class: "scorebar" }, h("i", { style: { width: `${x.report.score}%`, background: color(x.report.verdict.key) } })), String(x.report.score)),
          h("td", null, h("div", { style: { fontWeight: 600 }, text: x.report.message.subject || "(no subject)" }), h("div", { class: "muted mono", style: { fontSize: "12px" }, text: x.name })),
          h("td", { class: "hide-sm-col mono", style: { fontSize: "12.5px" }, text: x.report.message.from.address }),
          h("td", { class: "hide-sm-col muted", text: x.report.findings.find((f) => f.severity !== "info")?.title || "—" }),
        ))),
      ),
    ),
  );
  show("batch");
}

// ------------------------------------------------------------------ wiring
function init() {
  const grid = $("#samples");
  grid.replaceChildren(...SAMPLES.map((s) => h("button", { class: "sample", type: "button", onclick: () => loadSample(s.file) },
    h("span", { class: "s-ico", text: s.icon }),
    h("span", null, h("h3", { text: s.title }), h("p", { text: s.desc }), h("span", { style: { display: "flex", gap: "6px", flexWrap: "wrap" } }, s.tags.map((t) => h("span", { class: "tag", text: t })))),
  )));

  const input = $("#fileInput");
  $("#chooseBtn").addEventListener("click", (e) => { e.stopPropagation(); input.click(); });
  $("#dropzone").addEventListener("click", () => input.click());
  $("#dropzone").addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
  input.addEventListener("change", async () => { await analyzeInputs(await filesToInputs(input.files)); input.value = ""; });

  const overlay = $("#dropOverlay");
  let depth = 0;
  window.addEventListener("dragenter", (e) => { if (e.dataTransfer?.types?.includes("Files")) { depth++; overlay.hidden = false; $("#dropzone").classList.add("over"); } });
  window.addEventListener("dragleave", () => { if (--depth <= 0) { depth = 0; overlay.hidden = true; $("#dropzone").classList.remove("over"); } });
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", async (e) => {
    e.preventDefault();
    depth = 0;
    overlay.hidden = true;
    $("#dropzone").classList.remove("over");
    if (e.dataTransfer?.files?.length) await analyzeInputs(await filesToInputs(e.dataTransfer.files));
  });

  const dlg = $("#pasteDialog");
  const area = $("#pasteArea");
  $("#pasteBtn").addEventListener("click", (e) => { e.stopPropagation(); $("#pasteError").hidden = true; dlg.showModal(); area.focus(); });
  area.addEventListener("input", () => ($("#pasteError").hidden = true));
  $("#pasteAnalyze").addEventListener("click", async () => {
    const text = area.value.trim();
    if (!text) { $("#pasteError").hidden = false; return; }
    dlg.close();
    await analyzeInputs([{ name: "pasted-email.eml", buffer: text }]);
  });
  document.addEventListener("paste", async (e) => {
    if ($("#landing").hidden || dlg.open || /input|textarea/i.test(document.activeElement?.tagName || "")) return;
    const text = e.clipboardData?.getData("text") || "";
    if (/^(received|from|return-path|delivered-to|subject|message-id):/im.test(text) && text.length > 40) await analyzeInputs([{ name: "pasted-email.eml", buffer: text }]);
  });

  const live = $("#liveToggle");
  live.checked = store.get("phishlens-live") === "1";
  live.addEventListener("change", () => store.set("phishlens-live", live.checked ? "1" : "0"));

  $("#themeBtn").addEventListener("click", () => {
    const t = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", t);
    store.set("phishlens-theme", t);
  });
  $("#homeLink").addEventListener("click", (e) => { e.preventDefault(); showLanding(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") document.querySelectorAll(".menu-list").forEach((m) => (m.hidden = true)); });

  $("#allSamplesBtn").addEventListener("click", loadAllSamples);

  // Design switcher (pick a visual direction; remembered per browser)
  const DESIGNS = [["aurora", "Aurora"], ["terminal", "Terminal"], ["editorial", "Editorial"], ["neon", "Neon HUD"], ["bento", "Bento"]];
  const current = document.documentElement.getAttribute("data-design");
  document.body.append(h("div", { class: "design-switch", role: "group", "aria-label": "Design variant" },
    h("span", { class: "ds-label", text: "Design" }),
    DESIGNS.map(([id, label]) => h("button", { type: "button", class: id === current ? "on" : "", "aria-pressed": String(id === current), onclick: () => {
      store.set("phishlens-design", id);
      const q = new URLSearchParams(location.search);
      q.set("design", id);
      location.search = q.toString(); // keeps the #hash (sample + tab)
    } }, label)),
  ));

  const fromHash = async () => {
    if (location.hash === "#batch=samples" && $("#batch").hidden) return loadAllSamples();
    const m = /#sample=(\d{2})/.exec(location.hash);
    const tab = /[#&]tab=(\w+)/.exec(location.hash)?.[1];
    const s = m && SAMPLES.find((x) => x.file.startsWith(m[1]));
    if (s && state.items[state.index]?.name !== s.file) await loadSample(s.file);
    if (s && tab && ["overview", "sender", "links", "attachments", "content", "mitre", "iocs", "raw"].includes(tab) && state.index >= 0) {
      state.tab = tab;
      renderResult();
    }
  };
  window.addEventListener("hashchange", fromHash);
  fromHash();
}

init();
