// Header forensics: sender identity, SPF/DKIM/DMARC results, alignment, Received chain.
import { parseAddress, parseAddressList } from "./mime.js";
import { BRANDS, FREEMAIL, brandForDomain, impersonatedBrand, registrableDomain, toUnicode, scriptsIn } from "./domains.js";

export function isPrivateIP(ip) {
  if (!ip) return true;
  if (ip.includes(":")) {
    const l = ip.toLowerCase();
    return l === "::1" || l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe80") || l === "::";
  }
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !(n >= 0 && n <= 255))) return true;
  return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
}

export function parseAuthResults(headers) {
  const res = { spf: null, dkim: [], dmarc: null, arc: null, compauth: null, source: null, raw: "" };
  const ar = headers.getAll("authentication-results");
  const arcAr = headers.getAll("arc-authentication-results");
  const value = ar[0] || arcAr[0] || "";
  if (value) {
    res.raw = value;
    res.source = ar[0] ? "Authentication-Results" : "ARC-Authentication-Results";
    const segs = value.split(";").slice(1);
    for (const seg of segs) {
      const m = /^\s*(spf|dkim|dmarc|arc|compauth)\s*=\s*([a-z]+)/i.exec(seg);
      if (!m) continue;
      const method = m[1].toLowerCase();
      const result = m[2].toLowerCase();
      const prop = (k) => new RegExp(`${k.replace(".", "\\.")}\\s*=\\s*"?([^\\s;"]+)`, "i").exec(seg)?.[1]?.toLowerCase() || "";
      if (method === "spf") res.spf ??= { result, domain: prop("smtp.mailfrom").split("@").pop() || prop("smtp.helo"), detail: seg.trim() };
      else if (method === "dkim") res.dkim.push({ result, domain: prop("header.d") || prop("header.i").split("@").pop(), selector: prop("header.s"), detail: seg.trim() });
      else if (method === "dmarc") res.dmarc ??= { result, domain: prop("header.from"), policy: prop("p") || prop("policy.dmarc"), detail: seg.trim() };
      else if (method === "arc") res.arc ??= { result };
      else if (method === "compauth") res.compauth ??= { result, reason: prop("reason") };
    }
  }
  if (!res.spf) {
    const rs = headers.get("received-spf");
    const m = /^\s*(pass|fail|softfail|neutral|none|temperror|permerror)/i.exec(rs);
    if (m) res.spf = { result: m[1].toLowerCase(), domain: (/envelope-from=\"?([^\s;"]+)/i.exec(rs)?.[1] || "").split("@").pop(), detail: rs, source: "Received-SPF" };
  }
  return res;
}

export function parseDkimSignatures(headers) {
  return headers.getAll("dkim-signature").map((v) => {
    const tag = (t) => new RegExp(`(?:^|;)\\s*${t}\\s*=\\s*([^;]+)`, "i").exec(v)?.[1]?.replace(/\s+/g, "").toLowerCase() || "";
    return { domain: tag("d"), selector: tag("s"), algorithm: tag("a"), headers: tag("h") };
  });
}

export function parseReceived(headers) {
  const hops = headers.getAll("received").map((v) => {
    const semi = v.lastIndexOf(";");
    const dateStr = semi === -1 ? "" : v.slice(semi + 1).trim();
    const body = semi === -1 ? v : v.slice(0, semi);
    const from = /\bfrom\s+([^\s;()]+)/i.exec(body)?.[1] || "";
    const by = /\bby\s+([^\s;()]+)/i.exec(body)?.[1] || "";
    const withProto = /\bwith\s+([^\s;()]+)/i.exec(body)?.[1] || "";
    const fromPart = /\bby\s/i.test(body) ? body.slice(0, body.search(/\bby\s/i)) : body;
    const ips = [...fromPart.matchAll(/\[(?:IPv6:)?([0-9a-fA-F:.]{3,})\]|\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)].map((m) => m[1] || m[2]);
    const ts = Date.parse(dateStr.replace(/\s*\([^)]*\)\s*$/, ""));
    return { from, by, with: withProto, ip: ips[0] || "", date: dateStr, time: Number.isNaN(ts) ? null : ts, raw: v };
  });
  const chrono = hops.slice().reverse();
  chrono.forEach((h, i) => {
    const prev = chrono[i - 1];
    h.delay = prev && prev.time != null && h.time != null ? Math.round((h.time - prev.time) / 1000) : null;
    h.publicIp = h.ip && !isPrivateIP(h.ip) ? h.ip : "";
  });
  const origin = chrono.find((h) => h.publicIp);
  return { hops: chrono, originIp: origin?.publicIp || "", originHost: origin?.from || "" };
}

function f(id, severity, category, title, detail, evidence = [], mitre = []) {
  return { id, severity, category, title, detail, evidence, mitre };
}

const ROLE_WORDS = /\b(ceo|cfo|coo|cto|president|director|manager|hr|human resources|payroll|it (support|department|helpdesk|team)|helpdesk|help desk|admin(istrator)?|security( team)?|support|billing|accounts?( payable)?|finance|legal|compliance|mail(box)? (admin|server)|postmaster|webmaster)\b/i;

export function analyzeHeaders(headers) {
  const from = parseAddressList(headers.get("from"))[0] || parseAddress("");
  const replyTo = parseAddressList(headers.get("reply-to"));
  const returnPath = parseAddress(headers.get("return-path"));
  const sender = parseAddress(headers.get("sender"));
  const to = parseAddressList(headers.get("to"));
  const cc = parseAddressList(headers.get("cc"));
  const auth = parseAuthResults(headers);
  const dkimSigs = parseDkimSignatures(headers);
  const received = parseReceived(headers);
  const messageId = headers.get("message-id");
  const msgIdDomain = (/@([^>\s]+)>?\s*$/.exec(messageId)?.[1] || "").toLowerCase();
  const date = headers.get("date");
  const findings = [];
  const good = [];
  const fromReg = registrableDomain(from.domain);

  // --- authentication
  const spf = auth.spf?.result;
  const dmarc = auth.dmarc?.result;
  const dkimPass = auth.dkim.filter((d) => d.result === "pass");
  const dkimAligned = dkimPass.some((d) => registrableDomain(d.domain) === fromReg);
  if (!auth.raw && !auth.spf) {
    findings.push(f("auth_missing", "info", "auth", "No authentication results", "The message has no Authentication-Results header (it may be a draft, a sent-items copy or exported by a client that strips them). SPF/DKIM/DMARC can't be judged.", []));
  }
  if (spf === "fail") findings.push(f("spf_fail", "high", "auth", "SPF failed", `The server that sent this (${received.originIp || "unknown IP"}) is not allowed to send mail for ${auth.spf.domain || "the sender domain"}.`, [auth.spf.detail], ["T1656"]));
  else if (spf === "softfail") findings.push(f("spf_softfail", "medium", "auth", "SPF soft-failed", `${auth.spf.domain || "The sender domain"} says this server is probably not authorized to send for it.`, [auth.spf.detail], ["T1656"]));
  else if (spf === "pass") good.push(`SPF pass for ${auth.spf.domain || "envelope domain"}`);
  if (dmarc === "fail") findings.push(f("dmarc_fail", "high", "auth", "DMARC failed", `The visible From domain (${from.domain}) could not be verified by either SPF or DKIM — the From address is likely forged.`, [auth.dmarc.detail], ["T1656"]));
  else if (dmarc === "pass") good.push(`DMARC pass for ${auth.dmarc.domain || from.domain}`);
  const dkimFail = auth.dkim.filter((d) => d.result === "fail" || d.result === "permerror");
  if (dkimFail.length && !dkimPass.length) findings.push(f("dkim_fail", "medium", "auth", "DKIM signature failed", "The digital signature is invalid: the message was altered or forged.", dkimFail.map((d) => d.detail)));
  if (dkimPass.length) good.push(`DKIM pass (${dkimPass.map((d) => d.domain).join(", ")})${dkimAligned ? ", aligned with From" : ""}`);
  if (auth.raw && !dkimPass.length && !dkimFail.length && dkimSigs.length === 0) {
    findings.push(f("dkim_none", "low", "auth", "Not DKIM-signed", "Most legitimate bulk and corporate senders sign their mail with DKIM.", []));
  }
  if (auth.compauth?.result === "fail") findings.push(f("compauth_fail", "high", "auth", "Microsoft composite authentication failed", `compauth=fail${auth.compauth.reason ? ` reason=${auth.compauth.reason}` : ""}: Exchange Online judged the sender as spoofed.`, [], ["T1656"]));

  // --- sender identity
  const fromBrand = brandForDomain(from.domain);
  const imp = impersonatedBrand(from.domain);
  if (imp) {
    findings.push(f("sender_lookalike", "critical", "sender", `Sender domain imitates ${imp.brand}`, `${from.domain} is a look-alike (${imp.kind}) — it is not owned by ${imp.brand}.`, [from.address], ["T1583.001", "T1656"]));
  }
  if (from.domain.includes("xn--")) {
    const uni = toUnicode(from.domain);
    const scripts = scriptsIn(uni.replace(/\./g, ""));
    findings.push(f("sender_idn", scripts.length > 1 ? "critical" : "medium", "sender", "International (punycode) sender domain", `Displayed as ${uni}${scripts.length > 1 ? ` — mixes ${scripts.join(" + ")} letters` : ""}.`, [from.domain], ["T1656"]));
  }
  const nameEmail = /[\w.+-]+@[\w-]+(\.[\w-]+)+/.exec(from.name)?.[0]?.toLowerCase();
  if (nameEmail && nameEmail !== from.address) {
    findings.push(f("display_name_email", "high", "sender", "Display name contains a different email address", `The name shows "${nameEmail}", but the real address is ${from.address}.`, [`${from.name} <${from.address}>`], ["T1656", "T1036"]));
  }
  const nameBrand = BRANDS.find((b) => [b.name.toLowerCase(), ...b.keywords].some((k) => k.length >= 4 && new RegExp(`\\b${k.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}\\b`, "i").test(from.name)));
  const isFree = FREEMAIL.has(from.domain);
  if (nameBrand && !(fromBrand && fromBrand.name === nameBrand.name && !isFree) && !imp) {
    findings.push(f("display_name_brand", "high", "sender", `Display name claims to be ${nameBrand.name}`, `"${from.name}" — but the email comes from ${from.domain}, which is not a ${nameBrand.name} domain.`, [`${from.name} <${from.address}>`], ["T1656"]));
  }
  if (isFree && ROLE_WORDS.test(from.name + " " + from.local)) {
    findings.push(f("freemail_role", "medium", "sender", "Executive or department name on a free webmail account", `"${from.name || from.local}" is writing from ${from.domain}. Companies don't run their CEO, finance or IT desks from free mailboxes.`, [from.address], ["T1585.002", "T1656"]));
  }
  if (isFree) findings.push(f("freemail", "info", "sender", "Free webmail sender", `${from.domain} is a free email provider: anyone can register any name there.`, [from.address]));

  for (const r of replyTo) {
    if (r.address && registrableDomain(r.domain) !== fromReg) {
      const sev = isFree || FREEMAIL.has(r.domain) || imp ? "high" : "medium";
      findings.push(f("reply_to_mismatch", sev, "sender", "Replies go to a different domain", `You see ${from.address}, but hitting "Reply" sends your answer to ${r.address}.`, [`Reply-To: ${r.address}`], ["T1656"]));
    } else if (r.address && r.address !== from.address && isFree) {
      findings.push(f("reply_to_other_freemail", "high", "sender", "Replies go to a different free mailbox", `From ${from.address}, but Reply-To is ${r.address} — a classic business email compromise trick.`, [`Reply-To: ${r.address}`], ["T1656"]));
    }
  }
  if (returnPath.domain && fromReg && registrableDomain(returnPath.domain) !== fromReg && !dkimAligned) {
    findings.push(f("return_path_mismatch", dmarc === "fail" ? "medium" : "low", "sender", "Envelope sender differs from From", `Bounces go to ${returnPath.domain}, the visible sender is ${from.domain}. Normal for newsletters, suspicious otherwise.`, [`Return-Path: ${returnPath.address}`]));
  }
  if (msgIdDomain && fromReg && registrableDomain(msgIdDomain) !== fromReg && !dkimAligned && !/(google|outlook|prod\.outlook|amazonses|sendgrid|mailgun|mail\.gmail|mtasv|mcsv|exacttarget|sparkpost|mailchimp)/.test(msgIdDomain)) {
    findings.push(f("msgid_mismatch", "low", "sender", "Message-ID from another domain", `Message-ID was generated by ${msgIdDomain}, not ${from.domain}.`, [messageId]));
  }
  if (!messageId) findings.push(f("msgid_missing", "low", "sender", "No Message-ID", "Real mail servers always add a Message-ID; mass-mailing scripts often don't.", []));
  const mailer = headers.get("x-mailer") || headers.get("user-agent");
  if (/phpmailer|swiftmailer|python|curl|leaf|gammadyne|atomic mail|turbo-mailer|massmail|sendblaster/i.test(mailer)) {
    findings.push(f("mailer", "low", "sender", "Bulk-mailer or script client", `Sent with "${mailer}" — typical of mass phishing kits.`, [mailer]));
  }

  // --- Received chain sanity
  const negative = received.hops.filter((h) => h.delay != null && h.delay < -300);
  if (negative.length) findings.push(f("received_time_travel", "low", "headers", "Received timestamps go backwards", "One or more hops are dated before the previous hop: forged headers or a badly configured server.", negative.map((h) => h.raw.slice(0, 160))));
  if (received.hops.length > 15) findings.push(f("received_many", "low", "headers", "Unusually long relay chain", `${received.hops.length} Received hops.`, []));
  const dateTs = Date.parse(date);
  const lastHop = received.hops[received.hops.length - 1]?.time;
  if (date && !Number.isNaN(dateTs) && lastHop && dateTs - lastHop > 6 * 3600 * 1000) {
    findings.push(f("date_future", "low", "headers", "Date header is in the future", "The Date header is hours after the message was actually received.", [date]));
  }

  return {
    from,
    replyTo,
    returnPath,
    sender,
    to,
    cc,
    subject: headers.get("subject"),
    date,
    messageId,
    mailer,
    auth,
    dkimSigs,
    dkimAligned,
    received,
    fromBrand: fromBrand?.name || null,
    findings,
    good,
  };
}
