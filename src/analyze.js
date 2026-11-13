// PhishLens analysis pipeline:
//   parse MIME → header forensics → attachments → links → language/HTML → score → IOCs
import { parseEmail } from "./mime.js";
import { analyzeHeaders } from "./headers.js";
import { analyzeAttachment } from "./attachments.js";
import { analyzeUrls } from "./urls.js";
import { analyzeLanguage, analyzeHtmlBody } from "./language.js";
import { computeScore, recommendations, sevRank, sortFindings, summarize } from "./score.js";
import { describe } from "./mitre.js";
import { brandForDomain, isIP } from "./domains.js";

export const VERSION = "1.0.0";

const LINK_FINDINGS = {
  homograph: { title: "Link uses look-alike letters from another alphabet", mitre: ["T1566.002", "T1036", "T1583.001"] },
  lookalike: { title: "Link to a look-alike domain", mitre: ["T1566.002", "T1583.001", "T1656"] },
  text_mismatch: { title: "Link text hides the real destination", mitre: ["T1566.002", "T1036"] },
  userinfo: { title: "\"@\" trick hides the real site in a link", mitre: ["T1566.002", "T1036"] },
  ip_host: { title: "Link to a raw IP address", mitre: ["T1566.002"] },
  download: { title: "Link downloads a risky file", mitre: ["T1566.002", "T1204.002"] },
  data_uri: { title: "Link carries an embedded page (data: URI)", mitre: ["T1027", "T1566.002"] },
  javascript_uri: { title: "Link runs JavaScript", mitre: ["T1059.007"] },
  shortener: { title: "Shortened link hides the destination", mitre: ["T1566.002"] },
  abused_hosting: { title: "Link to free hosting or a form builder", mitre: ["T1608.005", "T1566.002"] },
  redirect: { title: "Link bounces through a redirect", mitre: ["T1566.002"] },
  brand_in_path: { title: "Brand name used in a link to another site", mitre: ["T1656"] },
  punycode: { title: "Link to an international (punycode) domain", mitre: ["T1566.002"] },
  http_login: { title: "Login-style link without HTTPS", mitre: ["T1566.002"] },
  credential_path: { title: "Link to a login or verification page", mitre: ["T1598.003"] },
  suspicious_tld: { title: "Link to a high-abuse domain ending", mitre: ["T1583.001"] },
  many_subdomains: { title: "Link with a deep subdomain chain", mitre: [] },
  port: { title: "Link on a non-standard port", mitre: [] },
};

function maxSev(list) {
  return list.reduce((m, s) => (sevRank(s) > sevRank(m) ? s : m), "info");
}

function linkFindings(urls) {
  const groups = new Map();
  for (const u of urls) {
    for (const fl of u.flags) {
      if (!groups.has(fl.code)) groups.set(fl.code, []);
      groups.get(fl.code).push({ u, fl });
    }
  }
  const out = [];
  for (const [code, items] of groups) {
    const meta = LINK_FINDINGS[code] || { title: code, mitre: [] };
    out.push({
      id: `link_${code}`,
      severity: maxSev(items.map((i) => i.fl.severity)),
      category: "links",
      title: meta.title,
      detail: items[0].fl.text + (items.length > 1 ? ` (+${items.length - 1} more link${items.length > 2 ? "s" : ""})` : ""),
      evidence: items.slice(0, 8).map((i) => i.u.defanged + (i.u.texts[0] ? `  ← shown as "${i.u.texts[0].slice(0, 60)}"` : "")),
      mitre: meta.mitre,
    });
  }
  return out;
}

function attachmentFindings(atts) {
  const out = [];
  for (const a of atts) {
    for (const fl of a.flags) {
      out.push({ id: `att_${fl.code}`, severity: fl.severity, category: "attachments", title: fl.title, detail: fl.detail, evidence: [`${a.filename} (${a.magic.label}, ${a.size} bytes) sha256:${a.hashes.sha256}`], mitre: fl.mitre });
    }
  }
  return out;
}

function uniq(arr) {
  return [...new Set(arr.filter(Boolean))];
}

function buildIocs(hdr, urls, atts, verdict) {
  const suspiciousUrls = urls.filter((u) => !u.brand && u.scheme && !["mailto"].includes(u.scheme) && (u.flags.length || verdict.key !== "clean"));
  const senderLegit = !!brandForDomain(hdr.from.domain);
  const emails = uniq([hdr.from.address, ...hdr.replyTo.map((r) => r.address), hdr.returnPath.address, hdr.sender.address]);
  return {
    emails: verdict.key === "clean" ? [] : emails,
    domains: uniq([verdict.key !== "clean" && !senderLegit ? hdr.from.domain : "", ...suspiciousUrls.filter((u) => !isIP(u.host)).map((u) => u.host)]),
    urls: uniq(suspiciousUrls.map((u) => u.url)),
    ips: uniq([verdict.key !== "clean" ? hdr.received.originIp : "", ...suspiciousUrls.filter((u) => isIP(u.host)).map((u) => u.host)]),
    files: atts.map((a) => ({ name: a.filename, sha256: a.hashes.sha256, md5: a.hashes.md5, sha1: a.hashes.sha1, type: a.magic.label, risky: a.flags.some((f) => sevRank(f.severity) >= 2) })),
    subject: hdr.subject,
  };
}

/**
 * Analyze one raw email (.eml / RFC 822 source).
 * @param {string|ArrayBuffer|Uint8Array} input
 * @param {{ decodeQr?: (bytes: Uint8Array, type: string) => Promise<string[]>, filename?: string }} opts
 */
export async function analyzeEmail(input, opts = {}) {
  const started = Date.now();
  const parsed = parseEmail(input);
  const hdr = analyzeHeaders(parsed.headers);

  const atts = [];
  for (const a of parsed.attachments.slice(0, 60)) {
    const r = await analyzeAttachment(a);
    if (opts.decodeQr && r.isImage && a.bytes?.length) {
      try {
        r.qr = (await opts.decodeQr(a.bytes, a.contentType)) || [];
      } catch {
        r.qr = [];
      }
      for (const code of r.qr) if (/^https?:\/\//i.test(code)) r.urls.push({ url: code, source: `QR code in ${a.filename}`, text: "" });
    }
    atts.push(r);
  }
  // QR codes embedded as data: images inside the HTML body
  const inlineQr = [];
  if (opts.decodeQr && parsed.html) {
    for (const m of parsed.html.matchAll(/src\s*=\s*["']data:(image\/(?:png|jpe?g|gif|webp));base64,([A-Za-z0-9+/=\s]+)["']/gi)) {
      try {
        const bytes = Uint8Array.from(atob(m[2].replace(/\s+/g, "")), (c) => c.charCodeAt(0));
        const codes = (await opts.decodeQr(bytes, m[1])) || [];
        for (const c of codes) inlineQr.push(c);
      } catch {
        /* not an image we can read */
      }
    }
  }

  const extra = [...atts.flatMap((a) => a.urls), ...inlineQr.filter((c) => /^https?:\/\//i.test(c)).map((c) => ({ url: c, source: "QR code in email body", text: "" }))];
  const urls = analyzeUrls(parsed, extra);
  const lang = analyzeLanguage({ subject: hdr.subject, text: parsed.text, html: parsed.html });
  const htmlInfo = analyzeHtmlBody(parsed.html, atts);

  const findings = [...hdr.findings, ...attachmentFindings(atts), ...linkFindings(urls), ...lang.findings, ...htmlInfo.findings];

  const qrUrls = urls.filter((u) => u.sources.some((s) => s.startsWith("QR code")));
  if (qrUrls.length) {
    const risky = qrUrls.some((u) => u.flags.some((f) => sevRank(f.severity) >= 2));
    findings.push({ id: "qr_code", severity: risky ? "critical" : "high", category: "links", title: "QR code phishing (quishing)", detail: `A QR code in the email leads to ${qrUrls.map((u) => u.host).join(", ")}. QR codes move the click to a phone, out of reach of corporate link scanning.`, evidence: qrUrls.map((u) => u.defanged), mitre: ["T1566.002", "T1027"] });
  }
  // Sender pretends to be a brand and links point elsewhere
  const brandClaim = hdr.findings.find((f) => f.id === "display_name_brand" || f.id === "sender_lookalike");
  if (brandClaim && urls.some((u) => u.flags.some((fl) => ["lookalike", "text_mismatch", "credential_path"].includes(fl.code)))) {
    findings.push({ id: "brand_phish_combo", severity: "high", category: "content", title: "Brand impersonation with a login link", detail: "The email claims to be a well-known brand and sends you to a login page that brand doesn't own.", evidence: [], mitre: ["T1656", "T1598.003"] });
  }

  const ctx = { dmarcPass: hdr.auth.dmarc?.result === "pass", dkimAligned: hdr.dkimAligned };
  const { score, verdict } = computeScore(findings, ctx);
  const sorted = sortFindings(findings);

  const mitreMap = new Map();
  for (const f of sorted) {
    if (sevRank(f.severity) < 1) continue;
    for (const id of f.mitre || []) {
      if (!mitreMap.has(id)) mitreMap.set(id, { ...describe(id), findings: [] });
      mitreMap.get(id).findings.push(f.title);
    }
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;

  return {
    tool: { name: "PhishLens", version: VERSION },
    analyzedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    filename: opts.filename || "",
    score,
    verdict,
    summary: summarize(findings, verdict, score),
    recommendations: recommendations(findings, verdict),
    counts,
    findings: sorted,
    good: hdr.good,
    mitre: [...mitreMap.values()],
    message: {
      subject: hdr.subject,
      from: hdr.from,
      replyTo: hdr.replyTo,
      returnPath: hdr.returnPath,
      to: hdr.to,
      cc: hdr.cc,
      date: hdr.date,
      messageId: hdr.messageId,
      mailer: hdr.mailer,
      size: parsed.size,
      parts: parsed.partCount,
      warnings: parsed.warnings,
    },
    auth: hdr.auth,
    dkimSignatures: hdr.dkimSigs,
    dkimAligned: hdr.dkimAligned,
    received: hdr.received,
    headers: parsed.headers.list.map((h) => ({ name: h.name, value: h.value })),
    urls,
    attachments: atts,
    body: { text: parsed.text, html: parsed.html, plain: lang.bodyText, words: lang.wordCount, html_info: htmlInfo.info },
    iocs: buildIocs(hdr, urls, atts, verdict),
  };
}
