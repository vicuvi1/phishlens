// Optional live lookups (off by default): DNS-over-HTTPS for SPF / DMARC / MX and
// RDAP for domain age. Only domain names leave the machine — never the email itself.
import { brandForDomain, isIP, registrableDomain } from "./domains.js";

const DOH = "https://cloudflare-dns.com/dns-query";

async function withTimeout(promise, ms) {
  let t;
  const timeout = new Promise((_, rej) => (t = setTimeout(() => rej(new Error("timeout")), ms)));
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(t);
  }
}

async function doh(name, type, fetchImpl, ms) {
  const r = await withTimeout(fetchImpl(`${DOH}?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: "application/dns-json" } }), ms);
  if (!r.ok) throw new Error(`DoH ${r.status}`);
  const j = await r.json();
  return { status: j.Status, answers: (j.Answer || []).map((a) => String(a.data).replace(/^"|"$/g, "").replace(/"\s*"/g, "")) };
}

async function rdap(domain, fetchImpl, ms) {
  const tld = domain.split(".").pop();
  // .com/.net go straight to Verisign (CORS-enabled); everything else via the rdap.org bootstrap redirector.
  const url = ["com", "net"].includes(tld) ? `https://rdap.verisign.com/${tld}/v1/domain/${encodeURIComponent(domain)}` : `https://rdap.org/domain/${encodeURIComponent(domain)}`;
  const headers = { accept: "application/rdap+json" };
  if (typeof window === "undefined") headers["user-agent"] = "PhishLens (+https://github.com/vicuvi1/phishlens)"; // CLI only; rdap.org rejects Node's default UA
  const r = await withTimeout(fetchImpl(url, { headers }), ms);
  if (!r.ok) throw new Error(`RDAP ${r.status}`);
  const j = await r.json();
  const ev = (a) => (j.events || []).find((e) => e.eventAction === a)?.eventDate || null;
  const registrar = (j.entities || []).find((e) => (e.roles || []).includes("registrar"));
  const name = registrar?.vcardArray?.[1]?.find((v) => v[0] === "fn")?.[3] || "";
  return { created: ev("registration"), expires: ev("expiration"), registrar: name };
}

export async function lookupDomain(domain, { fetchImpl = globalThis.fetch, timeout = 5000, sender = false } = {}) {
  const out = { domain, ok: true };
  const tasks = [
    rdap(domain, fetchImpl, timeout).then((v) => Object.assign(out, v)).catch((e) => (out.rdapError = e.message)),
  ];
  if (sender) {
    tasks.push(
      doh(domain, "TXT", fetchImpl, timeout).then((v) => {
        out.nx = v.status === 3;
        out.spf = v.answers.find((a) => /^v=spf1/i.test(a)) || null;
      }).catch((e) => (out.dnsError = e.message)),
      doh(`_dmarc.${domain}`, "TXT", fetchImpl, timeout).then((v) => {
        out.dmarc = v.answers.find((a) => /^v=DMARC1/i.test(a)) || null;
        out.dmarcPolicy = /;\s*p\s*=\s*(\w+)/i.exec(out.dmarc || "")?.[1]?.toLowerCase() || null;
      }).catch(() => {}),
      doh(domain, "MX", fetchImpl, timeout).then((v) => (out.mx = v.answers.map((a) => a.split(" ").pop().replace(/\.$/, "")))).catch(() => {}),
    );
  }
  await Promise.all(tasks);
  if (out.created) out.ageDays = Math.floor((Date.now() - Date.parse(out.created)) / 86400000);
  return out;
}

function f(id, severity, title, detail, evidence, mitre = []) {
  return { id, severity, category: "intel", title, detail, evidence, mitre };
}

export async function liveChecks({ senderDomain, linkDomains = [] }, opts = {}) {
  const sender = senderDomain ? registrableDomain(senderDomain) : "";
  const links = [...new Set(linkDomains.map(registrableDomain))].filter((d) => d && d !== sender && !isIP(d) && !brandForDomain(d)).slice(0, 4);
  const results = await Promise.all([
    sender ? lookupDomain(sender, { ...opts, sender: true }) : null,
    ...links.map((d) => lookupDomain(d, opts)),
  ]);
  const findings = [];
  const domains = results.filter(Boolean);
  for (const d of domains) {
    const role = d.domain === sender ? "Sender domain" : "Link domain";
    if (d.ageDays != null && d.ageDays < 30) findings.push(f(`live_new_${d.domain}`, "high", `${role} registered ${d.ageDays} day${d.ageDays === 1 ? "" : "s"} ago`, `${d.domain} was created on ${d.created.slice(0, 10)}. Most phishing domains are used within days of registration.`, [`${d.domain} · registrar: ${d.registrar || "unknown"}`], ["T1583.001"]));
    else if (d.ageDays != null && d.ageDays < 180) findings.push(f(`live_young_${d.domain}`, "medium", `${role} is only ${Math.round(d.ageDays / 30)} months old`, `${d.domain} was registered on ${d.created.slice(0, 10)}.`, [d.domain], ["T1583.001"]));
  }
  const s = domains.find((d) => d.domain === sender);
  if (s) {
    if (s.nx) findings.push(f("live_nxdomain", "high", "Sender domain does not exist", `${sender} has no DNS records at all: the From address is fabricated.`, [sender], ["T1656"]));
    else if (!s.dnsError) {
      if (!s.dmarc) findings.push(f("live_no_dmarc", "low", "Sender domain has no DMARC policy", `Anyone can forge mail "from" ${sender} without it being rejected.`, [sender]));
      if (!s.spf) findings.push(f("live_no_spf", "low", "Sender domain has no SPF record", `${sender} doesn't publish which servers may send its mail.`, [sender]));
      if (s.mx && !s.mx.length) findings.push(f("live_no_mx", "low", "Sender domain can't receive email", `${sender} has no MX record, so nobody could ever reply to it.`, [sender]));
    }
  }
  return { domains, findings };
}
