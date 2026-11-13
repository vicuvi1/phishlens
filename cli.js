#!/usr/bin/env node
// PhishLens CLI: analyze .eml files from the terminal or a CI pipeline.
//   node cli.js suspicious.eml
//   node cli.js samples/*.eml --json > report.json
//   node cli.js mail.eml --md > report.md
//   node cli.js mail.eml --fail-above 44      (exit code 2 when the score is higher)
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { analyzeEmail, VERSION } from "./src/analyze.js";
import { toIocCsv, toMarkdown, toStix } from "./src/report.js";

const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith("--")));
const files = args.filter((a, i) => !a.startsWith("--") && args[i - 1] !== "--fail-above");
const failIdx = args.indexOf("--fail-above");
const failAbove = failIdx !== -1 ? Number(args[failIdx + 1]) : null;

if (flags.has("--version")) {
  console.log(`phishlens ${VERSION}`);
  process.exit(0);
}
if (!files.length || flags.has("--help")) {
  console.log(`PhishLens ${VERSION} — phishing email analyzer

Usage: node cli.js <file.eml> [more.eml …] [options]

  --json            full JSON report
  --md              Markdown incident report
  --csv             IOC list as CSV
  --stix            STIX 2.1 bundle
  --fail-above N    exit with code 2 if any score is above N (CI / mail-flow gate)
`);
  process.exit(files.length ? 0 : 1);
}

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const SEV_COLOR = { critical: "1;31", high: "31", medium: "33", low: "36", info: "2" };
const VERDICT_COLOR = { malicious: "1;41;97", phishing: "1;31", suspicious: "1;33", clean: "1;32" };

let worst = 0;
const outputs = [];
for (const file of files) {
  const bytes = await readFile(file);
  const r = await analyzeEmail(new Uint8Array(bytes), { filename: basename(file) });
  worst = Math.max(worst, r.score);
  if (flags.has("--json")) outputs.push(r);
  else if (flags.has("--md")) console.log(toMarkdown(r));
  else if (flags.has("--csv")) process.stdout.write(toIocCsv(r));
  else if (flags.has("--stix")) console.log(toStix(r));
  else {
    const m = r.message;
    console.log(`\n${c("1", basename(file))}`);
    console.log(`  ${c(VERDICT_COLOR[r.verdict.key], ` ${r.verdict.label.toUpperCase()} `)}  risk ${c("1", r.score + "/100")}`);
    console.log(`  Subject: ${m.subject || "(none)"}`);
    console.log(`  From:    ${m.from.name ? m.from.name + " " : ""}<${m.from.address}>`);
    console.log(`  Auth:    SPF=${r.auth.spf?.result || "none"} DKIM=${r.auth.dkim.map((d) => d.result).join(",") || "none"} DMARC=${r.auth.dmarc?.result || "none"}`);
    console.log(`  ${c("2", r.summary)}\n`);
    for (const f of r.findings.filter((x) => x.severity !== "info")) {
      console.log(`  ${c(SEV_COLOR[f.severity], f.severity.toUpperCase().padEnd(8))} ${f.title}${f.mitre.length ? c("2", "  [" + f.mitre.join(", ") + "]") : ""}`);
    }
    if (r.iocs.urls.length || r.iocs.files.length) {
      console.log(`\n  ${c("1", "IOCs")}`);
      for (const u of r.iocs.urls.slice(0, 10)) console.log(`    url     ${r.urls.find((x) => x.url === u)?.defanged || u}`);
      for (const f of r.iocs.files) console.log(`    sha256  ${f.sha256}  ${f.name}`);
    }
  }
}
if (flags.has("--json")) console.log(JSON.stringify(outputs.length === 1 ? outputs[0] : outputs, null, 2));
if (failAbove != null && worst > failAbove) process.exit(2);
