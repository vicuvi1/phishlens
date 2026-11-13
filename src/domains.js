// Domain intelligence: registrable domains, punycode/homograph decoding,
// look-alike (typosquat / combosquat / homoglyph) brand detection.

// Multi-label public suffixes and shared-hosting suffixes (each customer is a separate site).
const MULTI_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz",
  "co.jp", "ne.jp", "or.jp", "com.br", "net.br", "com.mx", "com.ar", "com.co",
  "co.za", "co.in", "net.in", "org.in", "com.tr", "com.cn", "com.hk", "com.sg", "com.my",
  "com.ua", "org.ua", "com.ru", "com.pl", "co.kr", "co.id", "com.vn", "com.ph", "com.pk",
  "gov.md", "com.md", "co.il", "com.eg", "com.sa", "co.th",
  // shared hosting / developer platforms frequently abused for phishing pages
  "github.io", "gitlab.io", "herokuapp.com", "web.app", "firebaseapp.com", "pages.dev",
  "workers.dev", "netlify.app", "vercel.app", "blogspot.com", "azurewebsites.net",
  "r2.dev", "glitch.me", "ngrok-free.app", "ngrok.io", "ngrok.app", "duckdns.org",
  "000webhostapp.com", "weebly.com", "wixsite.com", "appspot.com", "s3.amazonaws.com",
  "onrender.com", "replit.app", "repl.co", "surge.sh", "framer.app", "webflow.io",
  "translate.goog", "trycloudflare.com", "ipfs.dweb.link", "myshopify.com", "square.site",
]);

export const ABUSED_HOSTING = new Set([
  "github.io", "gitlab.io", "herokuapp.com", "web.app", "firebaseapp.com", "pages.dev", "workers.dev",
  "netlify.app", "vercel.app", "blogspot.com", "azurewebsites.net", "r2.dev", "glitch.me",
  "ngrok-free.app", "ngrok.io", "ngrok.app", "duckdns.org", "000webhostapp.com", "weebly.com",
  "wixsite.com", "appspot.com", "s3.amazonaws.com", "onrender.com", "replit.app", "repl.co",
  "surge.sh", "framer.app", "webflow.io", "trycloudflare.com", "ipfs.dweb.link", "square.site",
  "storage.googleapis.com", "sites.google.com", "forms.gle", "docs.google.com", "1drv.ms",
  "dropboxusercontent.com", "jotform.com", "typeform.com", "forms.office.com", "notion.site",
]);

export const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
  "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "lnkd.in", "bl.ink", "short.io", "tr.ee",
  "qrco.de", "v.gd", "x.gd", "urlz.fr", "shorturl.ru", "clck.ru",
]);

export const FREEMAIL = new Set([
  "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com", "hotmail.com", "live.com",
  "msn.com", "aol.com", "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com", "pm.me",
  "gmx.com", "gmx.de", "gmx.net", "mail.ru", "bk.ru", "list.ru", "inbox.ru", "yandex.ru", "yandex.com",
  "zoho.com", "mail.com", "tutanota.com", "tuta.io", "hey.com", "web.de", "rambler.ru", "qq.com", "163.com",
]);

export const SUSPICIOUS_TLDS = new Set([
  "zip", "mov", "top", "xyz", "click", "link", "tk", "ml", "ga", "cf", "gq", "work", "rest", "cam",
  "icu", "buzz", "fit", "loan", "quest", "monster", "cfd", "sbs", "bond", "cyou", "shop", "online",
  "site", "live", "support", "lat", "beauty", "hair", "skin", "autos", "boats", "mom", "lol", "pw",
]);

// Brands most often impersonated in phishing. `keywords` are matched inside domains,
// `domains` are the brand's real (registrable) domains.
export const BRANDS = [
  { name: "Microsoft", keywords: ["microsoft", "office365", "outlook", "onedrive", "sharepoint", "microsoftonline", "m365"], domains: ["microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "hotmail.com", "microsoftonline.com", "sharepoint.com", "onedrive.com", "windows.net", "azure.com", "msn.com", "bing.com", "skype.com", "microsoft365.com", "msft.net", "msauth.net", "aka.ms"] },
  { name: "Google", keywords: ["google", "gmail", "googledocs", "gdrive"], domains: ["google.com", "gmail.com", "googlemail.com", "youtube.com", "googleusercontent.com", "gstatic.com", "goo.gl", "g.co"] },
  { name: "Apple", keywords: ["apple", "icloud", "appleid", "itunes"], domains: ["apple.com", "icloud.com", "me.com", "mac.com", "itunes.com"] },
  { name: "PayPal", keywords: ["paypal"], domains: ["paypal.com", "paypal.me", "paypalobjects.com"] },
  { name: "Amazon", keywords: ["amazon", "aws"], domains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazonaws.com", "amazonses.com", "aws.amazon.com", "primevideo.com"] },
  { name: "Netflix", keywords: ["netflix"], domains: ["netflix.com", "netflix.net"] },
  { name: "Meta / Facebook", keywords: ["facebook", "instagram", "whatsapp", "meta"], domains: ["facebook.com", "fb.com", "facebookmail.com", "instagram.com", "whatsapp.com", "meta.com"] },
  { name: "LinkedIn", keywords: ["linkedin"], domains: ["linkedin.com", "lnkd.in", "licdn.com"] },
  { name: "DHL", keywords: ["dhl"], domains: ["dhl.com", "dhl.de"] },
  { name: "FedEx", keywords: ["fedex"], domains: ["fedex.com"] },
  { name: "UPS", keywords: ["ups"], domains: ["ups.com"] },
  { name: "DocuSign", keywords: ["docusign"], domains: ["docusign.com", "docusign.net"] },
  { name: "Dropbox", keywords: ["dropbox"], domains: ["dropbox.com", "dropboxusercontent.com"] },
  { name: "Adobe", keywords: ["adobe"], domains: ["adobe.com", "adobesign.com", "adobelogin.com"] },
  { name: "Zoom", keywords: ["zoom"], domains: ["zoom.us", "zoom.com"] },
  { name: "Coinbase", keywords: ["coinbase"], domains: ["coinbase.com"] },
  { name: "Binance", keywords: ["binance"], domains: ["binance.com"] },
  { name: "Steam", keywords: ["steam", "steamcommunity", "steampowered"], domains: ["steampowered.com", "steamcommunity.com"] },
  { name: "GitHub", keywords: ["github"], domains: ["github.com", "githubusercontent.com", "github.io"] },
  { name: "Chase", keywords: ["chase"], domains: ["chase.com", "jpmorganchase.com"] },
  { name: "Bank of America", keywords: ["bankofamerica", "bofa"], domains: ["bankofamerica.com", "bofa.com"] },
  { name: "Wells Fargo", keywords: ["wellsfargo"], domains: ["wellsfargo.com"] },
  { name: "maib", keywords: ["maib"], domains: ["maib.md"] },
  { name: "Moldindconbank", keywords: ["micb", "moldindconbank"], domains: ["micb.md"] },
  { name: "Poșta Moldovei", keywords: ["postamoldovei", "posta"], domains: ["posta.md"] },
];

export function normalizeHost(host) {
  return (host || "").trim().toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
}

export function isIP(host) {
  const h = normalizeHost(host);
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || (h.includes(":") && /^[0-9a-f:.]+$/i.test(h));
}

export function registrableDomain(host) {
  const h = normalizeHost(host);
  if (!h || isIP(h)) return h;
  const labels = h.split(".");
  if (labels.length <= 2) return h;
  for (let n = Math.min(4, labels.length - 1); n >= 2; n--) {
    const suffix = labels.slice(-n).join(".");
    if (MULTI_SUFFIXES.has(suffix)) return labels.slice(-(n + 1)).join(".");
  }
  return labels.slice(-2).join(".");
}

export function tld(host) {
  const h = normalizeHost(host);
  return h.slice(h.lastIndexOf(".") + 1);
}

export function hostSuffixIn(host, set) {
  const labels = normalizeHost(host).split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    if (set.has(labels.slice(i).join("."))) return labels.slice(i).join(".");
  }
  return null;
}

// ---------------------------------------------------------------- punycode (RFC 3492)

function adapt(delta, numPoints, first) {
  delta = first ? Math.floor(delta / 700) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > 455) {
    delta = Math.floor(delta / 35);
    k += 36;
  }
  return k + Math.floor((36 * delta) / (delta + 38));
}

export function punycodeDecodeLabel(input) {
  const out = [];
  let n = 128;
  let i = 0;
  let bias = 72;
  let b = input.lastIndexOf("-");
  if (b < 0) b = 0;
  for (let j = 0; j < b; j++) out.push(input.charCodeAt(j));
  for (let idx = b > 0 ? b + 1 : 0; idx < input.length; ) {
    const oldi = i;
    let w = 1;
    for (let k = 36; ; k += 36) {
      if (idx >= input.length) throw new Error("bad punycode");
      const c = input.charCodeAt(idx++);
      const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : 36;
      if (digit >= 36) throw new Error("bad punycode");
      i += digit * w;
      const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < t) break;
      w *= 36 - t;
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

export function toUnicode(host) {
  return normalizeHost(host)
    .split(".")
    .map((l) => {
      if (!l.startsWith("xn--")) return l;
      try {
        return punycodeDecodeLabel(l.slice(4));
      } catch {
        return l;
      }
    })
    .join(".");
}

export function scriptsIn(str) {
  const s = new Set();
  for (const ch of str) {
    const cp = ch.codePointAt(0);
    if (/[a-z]/i.test(ch)) s.add("Latin");
    else if (cp >= 0x0400 && cp <= 0x052f) s.add("Cyrillic");
    else if (cp >= 0x0370 && cp <= 0x03ff) s.add("Greek");
    else if (cp >= 0x0530 && cp <= 0x058f) s.add("Armenian");
    else if (cp >= 0x0590 && cp <= 0x05ff) s.add("Hebrew");
    else if (cp >= 0x0600 && cp <= 0x06ff) s.add("Arabic");
    else if (cp >= 0x4e00 && cp <= 0x9fff) s.add("CJK");
    else if (cp > 0x7f && /\p{L}/u.test(ch)) s.add("Latin-ext");
  }
  return [...s];
}

// ---------------------------------------------------------------- look-alikes

const CONFUSABLE = {
  0: "o", 1: "l", 3: "e", 4: "a", 5: "s", 7: "t", 8: "b", 9: "g", $: "s", "@": "a", "|": "l", "!": "l", i: "l",
  а: "a", е: "e", о: "o", р: "p", с: "c", у: "y", х: "x", і: "l", ј: "j", ԁ: "d", ӏ: "l", ѕ: "s", һ: "h",
  ԛ: "q", ԝ: "w", ɡ: "g", ο: "o", α: "a", ν: "v", ρ: "p", τ: "t", ι: "l", κ: "k", ε: "e", ı: "l", ł: "l",
  ß: "ss", é: "e", è: "e", ê: "e", á: "a", à: "a", â: "a", ä: "a", í: "l", ì: "l", ó: "o", ò: "o",
  ö: "o", ô: "o", ü: "u", ú: "u", ç: "c", ñ: "n", ș: "s", ş: "s", ț: "t", ţ: "t", ă: "a",
};

export function skeleton(str) {
  return [...str.toLowerCase().normalize("NFKC")]
    .map((c) => CONFUSABLE[c] ?? c)
    .join("")
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/cl/g, "d");
}

export function editDistance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

export function brandForDomain(host) {
  const h = normalizeHost(host);
  return BRANDS.find((b) => b.domains.some((d) => h === d || h.endsWith("." + d))) || null;
}

const keywordCache = BRANDS.flatMap((b) => b.keywords.map((k) => ({ brand: b, raw: k, sk: skeleton(k) })));

// Returns { brand, kind, keyword, where } if the host imitates a brand it doesn't belong to.
export function impersonatedBrand(host) {
  const h = normalizeHost(host);
  if (!h || isIP(h) || brandForDomain(h)) return null;
  const reg = registrableDomain(h);
  const regLabel = reg.slice(0, reg.length - (reg.split(".").slice(1).join(".").length + 1)) || reg;
  const uni = toUnicode(regLabel);
  const sk = skeleton(uni);
  const tokens = sk.split(/[-_.]+/).filter(Boolean);
  const rawTokens = uni.toLowerCase().split(/[-_.]+/);
  const sub = h.slice(0, Math.max(0, h.length - reg.length - 1));
  const subTokens = skeleton(toUnicode(sub)).split(/[-_.]+/).filter(Boolean);

  for (const { brand, raw, sk: k } of keywordCache) {
    const long = k.length >= 6;
    const literal = rawTokens.includes(raw) || (long && uni.toLowerCase().includes(raw));
    if (tokens.includes(k) || (long && sk.includes(k))) {
      return { brand: brand.name, keyword: raw, kind: literal ? "brand name in domain" : "character substitution (homoglyph)", where: "domain" };
    }
  }
  for (const { brand, raw, sk: k } of keywordCache) {
    if (k.length < 6) continue;
    const max = k.length >= 8 ? 2 : 1;
    const hit = [...tokens, sk.replace(/[-_.]/g, "")].find((t) => Math.abs(t.length - k.length) <= max && editDistance(t, k) <= max);
    if (hit) return { brand: brand.name, keyword: raw, kind: "typosquat", where: "domain" };
  }
  for (const { brand, raw, sk: k } of keywordCache) {
    if (k.length >= 4 && subTokens.includes(k)) return { brand: brand.name, keyword: raw, kind: "brand name in subdomain", where: "subdomain" };
  }
  return null;
}

export function defang(s) {
  return String(s)
    .replace(/^http/i, "hxxp")
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");
}
