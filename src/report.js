// Exports: Markdown incident report, IOC CSV, STIX 2.1 bundle, clean JSON.
import { defang } from "./domains.js";
import { defangUrl } from "./urls.js";

const SEV_ICON = { critical: "🟥", high: "🟧", medium: "🟨", low: "🟦", info: "⬜" };

export function toJSON(report) {
  return JSON.stringify(report, null, 2);
}

const md = (s) => String(s ?? "").replace(/([\\`*_[\]|<>])/g, "\\$1");

export function toMarkdown(r) {
  const m = r.message;
  const lines = [];
  lines.push(`# Phishing analysis report: ${md(m.subject || "(no subject)")}`);
  lines.push("");
  lines.push(`**Verdict:** ${r.verdict.label} · **Risk score:** ${r.score}/100 · Analysed ${r.analyzedAt} with ${r.tool.name} ${r.tool.version}`);
  lines.push("");
  lines.push(`> ${md(r.summary)}`);
  lines.push("");
  lines.push("## Message");
  lines.push("");
  lines.push("| Field | Value |", "|---|---|");
  lines.push(`| From | ${md(m.from.name)} \`${defang(m.from.address)}\` |`);
  if (m.replyTo.length) lines.push(`| Reply-To | ${m.replyTo.map((x) => `\`${defang(x.address)}\``).join(", ")} |`);
  if (m.returnPath.address) lines.push(`| Return-Path | \`${defang(m.returnPath.address)}\` |`);
  lines.push(`| To | ${m.to.map((x) => md(x.address)).join(", ")} |`);
  lines.push(`| Date | ${md(m.date)} |`);
  lines.push(`| Message-ID | \`${md(m.messageId)}\` |`);
  lines.push(`| Origin IP | ${r.received.originIp ? `\`${defang(r.received.originIp)}\`` : "unknown"} |`);
  const a = r.auth;
  lines.push(`| SPF / DKIM / DMARC | ${a.spf?.result || "none"} / ${a.dkim.map((d) => d.result).join(",") || "none"} / ${a.dmarc?.result || "none"} |`);
  lines.push("");
  lines.push("## Findings");
  lines.push("");
  for (const f of r.findings.filter((x) => x.severity !== "info")) {
    lines.push(`### ${SEV_ICON[f.severity]} ${f.severity.toUpperCase()}: ${md(f.title)}`);
    lines.push("");
    lines.push(md(f.detail));
    if (f.mitre?.length) lines.push("", `ATT&CK: ${f.mitre.map((t) => `[${t}](https://attack.mitre.org/techniques/${t.replace(".", "/")}/)`).join(", ")}`);
    if (f.evidence?.length) {
      lines.push("", "```");
      for (const e of f.evidence) lines.push(String(e).replace(/```/g, "'''"));
      lines.push("```");
    }
    lines.push("");
  }
  if (r.good.length) {
    lines.push("## Positive signals", "");
    for (const g of r.good) lines.push(`- ${md(g)}`);
    lines.push("");
  }
  if (r.mitre.length) {
    lines.push("## MITRE ATT&CK", "", "| Technique | Name | Tactic |", "|---|---|---|");
    for (const t of r.mitre) lines.push(`| [${t.id}](${t.url}) | ${md(t.name)} | ${md(t.tactic)} |`);
    lines.push("");
  }
  const i = r.iocs;
  if (i.urls.length || i.domains.length || i.ips.length || i.files.length || i.emails.length) {
    lines.push("## Indicators of compromise (defanged)", "", "```");
    for (const x of i.emails) lines.push(`email   ${defang(x)}`);
    for (const x of i.domains) lines.push(`domain  ${defang(x)}`);
    for (const x of i.ips) lines.push(`ip      ${defang(x)}`);
    for (const x of i.urls) lines.push(`url     ${defangUrl(x)}`);
    for (const x of i.files) lines.push(`sha256  ${x.sha256}  ${x.name}`);
    lines.push("```", "");
  }
  lines.push("## Recommended actions", "");
  for (const x of r.recommendations) lines.push(`- ${md(x)}`);
  lines.push("");
  return lines.join("\n");
}

const csvCell = (v) => {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // CSV/formula injection guard
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

export function toIocCsv(r) {
  const rows = [["type", "value", "context"]];
  for (const x of r.iocs.emails) rows.push(["email", x, "sender/reply-to/return-path"]);
  for (const x of r.iocs.domains) rows.push(["domain", x, ""]);
  for (const x of r.iocs.ips) rows.push(["ip", x, ""]);
  for (const x of r.iocs.urls) {
    const u = r.urls.find((y) => y.url === x);
    rows.push(["url", x, u ? u.flags.map((f) => f.code).join(" ") : ""]);
  }
  for (const x of r.iocs.files) {
    rows.push(["sha256", x.sha256, x.name]);
    rows.push(["md5", x.md5, x.name]);
  }
  return rows.map((row) => row.map(csvCell).join(",")).join("\n") + "\n";
}

function uuid() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const n = (Math.random() * 16) | 0;
    return (c === "x" ? n : (n & 3) | 8).toString(16);
  });
}

const stixStr = (s) => String(s).replace(/\\/g, "\\\\").replace(/'/g, "\\'");

export function toStix(r) {
  const now = new Date().toISOString();
  const objects = [];
  const report = { type: "report", spec_version: "2.1", id: `report--${uuid()}`, created: now, modified: now, name: `Phishing email: ${r.message.subject || "(no subject)"}`, description: r.summary, published: now, report_types: ["threat-report"], object_refs: [] };
  const ind = (name, pattern) => {
    const o = { type: "indicator", spec_version: "2.1", id: `indicator--${uuid()}`, created: now, modified: now, name, pattern, pattern_type: "stix", valid_from: now, indicator_types: ["malicious-activity"], labels: ["phishing"] };
    objects.push(o);
    report.object_refs.push(o.id);
  };
  for (const x of r.iocs.emails) ind(`Phishing sender ${x}`, `[email-addr:value = '${stixStr(x)}']`);
  for (const x of r.iocs.domains) ind(`Phishing domain ${x}`, `[domain-name:value = '${stixStr(x)}']`);
  for (const x of r.iocs.ips) ind(`Phishing IP ${x}`, `[${x.includes(":") ? "ipv6-addr" : "ipv4-addr"}:value = '${stixStr(x)}']`);
  for (const x of r.iocs.urls) ind(`Phishing URL`, `[url:value = '${stixStr(x)}']`);
  for (const x of r.iocs.files.filter((f) => f.risky)) ind(`Malicious attachment ${x.name}`, `[file:hashes.'SHA-256' = '${x.sha256}']`);
  for (const t of r.mitre) {
    const o = { type: "attack-pattern", spec_version: "2.1", id: `attack-pattern--${uuid()}`, created: now, modified: now, name: t.name, external_references: [{ source_name: "mitre-attack", external_id: t.id, url: t.url }] };
    objects.push(o);
    report.object_refs.push(o.id);
  }
  if (!report.object_refs.length) report.object_refs.push(report.id.replace("report--", "note--"));
  return JSON.stringify({ type: "bundle", id: `bundle--${uuid()}`, objects: [report, ...objects] }, null, 2);
}
