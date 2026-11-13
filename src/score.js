// Turns findings into a 0–100 risk score, a verdict and plain-English advice.

export const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"];
export const WEIGHTS = { info: 0, low: 6, medium: 14, high: 26, critical: 45 };

export const VERDICTS = [
  { key: "malicious", min: 75, label: "Dangerous", short: "This email is almost certainly an attack." },
  { key: "phishing", min: 45, label: "Likely phishing", short: "This email shows strong signs of phishing." },
  { key: "suspicious", min: 20, label: "Suspicious", short: "Some things about this email are off. Treat it with caution." },
  { key: "clean", min: 0, label: "Looks safe", short: "No significant phishing indicators were found." },
];

export const sevRank = (s) => SEVERITY_ORDER.indexOf(s);

export function sortFindings(findings) {
  return findings.slice().sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || a.category.localeCompare(b.category));
}

export function computeScore(findings, ctx = {}) {
  let keep = 1;
  for (const f of findings) keep *= 1 - (WEIGHTS[f.severity] || 0) / 100;
  let score = 100 * (1 - keep);
  const critical = findings.some((f) => f.severity === "critical");
  const highs = findings.filter((f) => f.severity === "high").length;
  if (critical) score = Math.max(score, 80);
  if (highs >= 2) score = Math.max(score, 55);
  // Fully authenticated mail with no serious finding gets the benefit of the doubt.
  if (ctx.dmarcPass && ctx.dkimAligned && !critical && !highs) score *= 0.6;
  score = Math.round(Math.min(100, score));
  const verdict = VERDICTS.find((v) => score >= v.min);
  return { score, verdict };
}

// Lower-case the first letter unless it starts an acronym (DMARC, HTML, SPF…)
const clean = (s) => (/^[A-Z][A-Z]/.test(s) ? s : s.charAt(0).toLowerCase() + s.slice(1));

export function summarize(findings, verdict, score) {
  const top = sortFindings(findings).filter((f) => sevRank(f.severity) >= 2).slice(0, 3);
  if (!top.length) {
    const minor = findings.filter((f) => f.severity === "low").length;
    return `${verdict.short}${minor ? ` ${minor} minor observation${minor > 1 ? "s were" : " was"} noted.` : ""}`;
  }
  const reasons = top.map((f) => clean(f.title));
  const list = reasons.length > 1 ? `${reasons.slice(0, -1).join(", ")} and ${reasons[reasons.length - 1]}` : reasons[0];
  return `${verdict.short} Main reasons: ${list}.`;
}

export function recommendations(findings, verdict) {
  const ids = new Set(findings.map((f) => f.id));
  const has = (re) => [...ids].some((id) => re.test(id));
  const out = [];
  if (verdict.key === "clean") {
    out.push("No action needed. If something still feels off, confirm with the sender through a channel you already trust.");
    return out;
  }
  out.push("Don't click any links, scan QR codes or open attachments from this email.");
  if (has(/^(lang_bec_payment|freemail_role|reply_to_other_freemail)$/)) out.push("Never pay or change bank details because of an email. Call the person on a phone number you already know, not one from this message.");
  if (has(/credential|link_|html_form|lookalike|display_name|qr/)) out.push("If you already typed your password on a linked page, change it now, sign out of all sessions and turn on multi-factor authentication.");
  if (has(/^att_/)) out.push("If an attachment was opened, disconnect the computer from the network and contact your IT/security team. Don't just delete the file.");
  out.push("Report it: use your mail client's \"Report phishing\" button or forward it as an attachment to your security team.");
  if (verdict.key !== "suspicious") out.push("SOC: block the sender domain and the IOCs below at the mail gateway, web proxy and EDR, then search mailboxes for the same subject and sender.");
  return out;
}
