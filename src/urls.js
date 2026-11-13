// Link extraction and per-URL risk analysis. Nothing here ever fetches a URL.
import { anchors, attr, decodeEntities, tags } from "./html.js";
import {
  ABUSED_HOSTING, SHORTENERS, SUSPICIOUS_TLDS, BRANDS, brandForDomain, defang, hostSuffixIn,
  impersonatedBrand, isIP, normalizeHost, registrableDomain, scriptsIn, skeleton, tld, toUnicode,
} from "./domains.js";

const TEXT_URL = /\b(?:https?:\/\/|www\.)[^\s<>"'`\])}]+/gi;
const DOMAIN_IN_TEXT = /\b((?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?\.)+[a-z¡-￿]{2,24})\b/i;
const RISKY_DOWNLOAD = /\.(exe|scr|msi|bat|cmd|js|jse|vbs|vbe|wsf|hta|ps1|lnk|iso|img|vhdx?|jar|apk|zip|rar|7z|docm|xlsm|pptm|one|svg)(?:$|[?#])/i;
const CREDENTIAL_PATH = /(log-?in|sign-?in|verify|verification|account|secure|update|password|passwd|auth|credential|wallet|banking|unlock|validate|confirm|webmail|owa|sso|mfa|2fa)/i;
const REDIRECT_PARAMS = ["url", "u", "q", "redirect", "redir", "target", "dest", "destination", "link", "goto", "next", "r", "return", "returnurl", "continue", "to"];
const KNOWN_WRAPPERS = /(^|\.)safelinks\.protection\.outlook\.com$|(^|\.)urldefense\.(proofpoint\.)?com$|^l\.facebook\.com$|^lm\.facebook\.com$|^(www\.)?google\.[a-z.]+$|(^|\.)mimecastprotect\.com$/;

export function defangUrl(u) {
  const m = /^([a-z][a-z0-9+.-]*:\/\/)([^/?#]*)(.*)$/i.exec(u);
  if (!m) return defang(u);
  return m[1].replace(/^http/i, "hxxp") + m[2].replace(/\./g, "[.]").replace(/@/g, "[@]") + m[3];
}

function trimTrailing(u) {
  let s = u.replace(/[.,;:!?'"]+$/, "");
  // balance a trailing ")" that isn't part of the URL
  if (s.endsWith(")") && (s.match(/\(/g) || []).length < (s.match(/\)/g) || []).length) s = s.slice(0, -1);
  return s;
}

function safeParse(raw) {
  let s = raw.trim();
  if (/^www\./i.test(s)) s = "http://" + s;
  try {
    return new URL(s);
  } catch {
    return null;
  }
}

export function unwrap(urlObj) {
  if (!urlObj) return null;
  const host = urlObj.hostname.toLowerCase();
  // Proofpoint v2: u=https-3A__evil.com_path
  if (/urldefense\.proofpoint\.com$/.test(host) && urlObj.searchParams.get("u")) {
    const v = urlObj.searchParams.get("u").replace(/_/g, "/").replace(/-([0-9A-F]{2})/g, "%$1");
    try {
      return decodeURIComponent(v);
    } catch {
      return null;
    }
  }
  // Proofpoint v3: /v3/__https://evil.com/path__;!!
  const v3 = /\/v3\/__(.+?)__;/.exec(urlObj.href);
  if (v3) return v3[1];
  for (const [k, v] of urlObj.searchParams) {
    if (!REDIRECT_PARAMS.includes(k.toLowerCase())) continue;
    const val = v.trim();
    if (/^(https?:)?\/\//i.test(val) || /^https?%3a/i.test(val)) {
      try {
        return decodeURIComponent(val).replace(/^\/\//, "https://");
      } catch {
        return val;
      }
    }
  }
  return null;
}

// Collect every link in the message: text, html anchors, forms, images, iframes, plus extras (attachments).
export function extractUrls({ text = "", html = "" }, extra = []) {
  const map = new Map();
  const add = (raw, source, anchorText) => {
    if (!raw) return;
    const href = decodeEntities(raw).trim();
    if (!href || href.startsWith("#") || /^(cid|tel|sms):/i.test(href)) return;
    const key = href;
    if (!map.has(key)) map.set(key, { raw: href, sources: new Set(), texts: new Set() });
    const e = map.get(key);
    e.sources.add(source);
    if (anchorText) e.texts.add(anchorText.slice(0, 200));
  };
  for (const m of text.matchAll(TEXT_URL)) add(trimTrailing(m[0]), "text body");
  if (html) {
    for (const a of anchors(html)) add(a.href, "html link", a.text || (a.hasImage ? "[image]" : ""));
    for (const t of tags(html, "form")) add(attr(t, "action"), "form action");
    for (const t of tags(html, "iframe")) add(attr(t, "src"), "iframe");
    for (const t of tags(html, "img")) {
      const src = attr(t, "src");
      if (src && /^https?:/i.test(src)) add(src, "remote image");
    }
    for (const t of tags(html, "meta")) {
      const c = attr(t, "content");
      if (/refresh/i.test(attr(t, "http-equiv") || "") && c) add(c.replace(/^.*?url\s*=\s*/i, ""), "meta refresh");
    }
    // bare URLs written as text inside the HTML
    for (const m of html.replace(/<[^>]+>/g, " ").matchAll(TEXT_URL)) add(trimTrailing(decodeEntities(m[0])), "html text");
  }
  for (const x of extra) add(x.url, x.source, x.text);
  return [...map.values()].map((e) => ({ raw: e.raw, sources: [...e.sources], texts: [...e.texts] }));
}

function flag(code, severity, text) {
  return { code, severity, text };
}

export function analyzeUrl(entry) {
  const out = {
    url: entry.raw,
    defanged: defangUrl(entry.raw),
    sources: entry.sources || [],
    texts: entry.texts || [],
    scheme: "",
    host: "",
    hostUnicode: "",
    domain: "",
    brand: null,
    flags: [],
    unwrapped: null,
  };
  const lower = entry.raw.toLowerCase();
  if (lower.startsWith("mailto:")) {
    out.scheme = "mailto";
    out.host = lower.slice(7).split("?")[0].split("@")[1] || "";
    out.domain = registrableDomain(out.host);
    return out;
  }
  if (lower.startsWith("javascript:")) {
    out.scheme = "javascript";
    out.flags.push(flag("javascript_uri", "high", "javascript: link runs code when clicked"));
    return out;
  }
  if (lower.startsWith("data:")) {
    out.scheme = "data";
    out.defanged = entry.raw.slice(0, 60) + (entry.raw.length > 60 ? "…" : "");
    out.flags.push(flag("data_uri", "high", "data: link embeds a whole page or file inside the link (used to bypass URL filters)"));
    return out;
  }
  const u = safeParse(entry.raw);
  if (!u) return out;
  out.scheme = u.protocol.replace(":", "");
  out.host = normalizeHost(u.hostname);
  out.hostUnicode = toUnicode(out.host);
  out.domain = registrableDomain(out.host);
  out.brand = brandForDomain(out.host)?.name || null;
  const fullHost = out.host;

  if (u.username || u.password || /^[a-z]+:\/\/[^/?#]*@/i.test(entry.raw)) {
    out.flags.push(flag("userinfo", "high", `"@" trick: everything before @ is ignored, the real site is ${out.host}`));
  }
  if (isIP(fullHost)) out.flags.push(flag("ip_host", "high", "points to a raw IP address instead of a domain name"));
  if (out.host.includes("xn--")) {
    const scripts = scriptsIn(out.hostUnicode.replace(/\./g, ""));
    if (scripts.length > 1 || (scripts.length === 1 && scripts[0] !== "Latin")) {
      out.flags.push(flag("homograph", "critical", `international domain ${out.hostUnicode} mixes ${scripts.join(" + ")} letters: it only looks like a familiar name`));
    } else {
      out.flags.push(flag("punycode", "medium", `international (punycode) domain, displayed as ${out.hostUnicode}`));
    }
  }
  const imp = impersonatedBrand(fullHost);
  if (imp) {
    const sev = imp.kind === "brand name in subdomain" ? "high" : "critical";
    out.flags.push(flag("lookalike", sev, `look-alike of ${imp.brand} (${imp.kind}: "${imp.keyword}"), but ${out.domain} is not a ${imp.brand} domain`));
  }
  const shortener = hostSuffixIn(fullHost, SHORTENERS) || (SHORTENERS.has(fullHost) ? fullHost : null);
  if (shortener) out.flags.push(flag("shortener", "medium", `URL shortener (${shortener}) hides the real destination`));
  const hosting = hostSuffixIn(fullHost, ABUSED_HOSTING) || (ABUSED_HOSTING.has(fullHost) ? fullHost : null);
  if (hosting && !shortener) out.flags.push(flag("abused_hosting", "medium", `free hosting / form service (${hosting}) often used for phishing pages`));
  if (SUSPICIOUS_TLDS.has(tld(fullHost))) out.flags.push(flag("suspicious_tld", "low", `.${tld(fullHost)} domains are cheap and heavily abused`));
  if (fullHost.split(".").length >= 5 && !isIP(fullHost)) out.flags.push(flag("many_subdomains", "low", "unusually deep subdomain chain"));
  if (u.port && !["80", "443"].includes(u.port)) out.flags.push(flag("port", "low", `non-standard port :${u.port}`));
  if (RISKY_DOWNLOAD.test(u.pathname)) out.flags.push(flag("download", "high", `downloads a risky file type (${u.pathname.split("/").pop()})`));

  if (!out.brand) {
    const pathSk = skeleton(decodeURIComponentSafe(u.pathname + u.search));
    const inPath = BRANDS.find((b) => b.keywords.some((k) => k.length >= 5 && pathSk.includes(skeleton(k))));
    if (inPath && !imp) out.flags.push(flag("brand_in_path", "medium", `mentions ${inPath.name} in the path, but the site is ${out.domain}`));
    if (CREDENTIAL_PATH.test(u.pathname + u.search) && !hosting) {
      out.flags.push(flag("credential_path", "low", "path looks like a login / verification page"));
      if (out.scheme === "http") out.flags.push(flag("http_login", "medium", "login-style page over plain http (no encryption)"));
    }
  }

  // Link text shows one domain, the link goes to another
  const target = out;
  for (const t of out.texts) {
    const m = DOMAIN_IN_TEXT.exec(t);
    if (!m || /\s/.test(t.trim()) && !/https?:\/\/|www\./i.test(t)) continue;
    const shownHost = normalizeHost(m[1]);
    if (!/\.[a-z]{2,}$/i.test(shownHost)) continue;
    const shownReg = registrableDomain(shownHost);
    const unwrappedHost = (() => {
      const w = unwrap(u);
      const p = w && safeParse(w);
      return p ? registrableDomain(p.hostname) : null;
    })();
    if (shownReg && shownReg !== target.domain && shownReg !== unwrappedHost) {
      out.flags.push(flag("text_mismatch", "high", `link text shows ${shownHost} but it really goes to ${target.host}`));
      break;
    }
  }

  const w = unwrap(u);
  if (w && w !== entry.raw) {
    out.unwrapped = w;
    if (!KNOWN_WRAPPERS.test(fullHost)) out.flags.push(flag("redirect", "medium", `redirects to another site: ${defangUrl(w)}`));
  }
  return out;
}

function decodeURIComponentSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

export function analyzeUrls(parsed, extra = []) {
  const entries = extractUrls(parsed, extra);
  const results = [];
  const seen = new Set();
  const queue = [...entries];
  while (queue.length && results.length < 400) {
    const e = queue.shift();
    if (seen.has(e.raw)) continue;
    seen.add(e.raw);
    const r = analyzeUrl(e);
    results.push(r);
    if (r.unwrapped && !seen.has(r.unwrapped)) {
      queue.push({ raw: r.unwrapped, sources: [`unwrapped from ${r.host}`], texts: r.texts });
    }
  }
  return results;
}
