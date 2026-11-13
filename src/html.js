// Small, regex-based HTML helpers that work without a DOM (Node CLI + browser).

const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", copy: "©", reg: "®", hellip: "…", ndash: "–", mdash: "—", rsquo: "’", lsquo: "‘", rdquo: "”", ldquo: "“", zwnj: "", zwj: "" };

export function decodeEntities(s) {
  return String(s || "").replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);?/gi, (m, e) => {
    if (e[0] === "#") {
      const cp = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      try {
        return cp ? String.fromCodePoint(cp) : m;
      } catch {
        return m;
      }
    }
    const v = ENTITIES[e.toLowerCase()];
    return v === undefined ? m : v;
  });
}

export function stripTags(html) {
  return decodeEntities(
    String(html || "")
      .replace(/<!--[\s\S]*?-->/g, " ")
      .replace(/<(script|style|head|title)\b[\s\S]*?<\/\1>/gi, " ")
      .replace(/<br\s*\/?>/gi, "\n")
      .replace(/<\/(p|div|tr|li|h[1-6]|table)>/gi, "\n")
      .replace(/<[^>]+>/g, " "),
  )
    .replace(/[ \t ]+/g, " ")
    .replace(/\n\s*\n+/g, "\n")
    .trim();
}

export function attr(tag, name) {
  const re = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i");
  const m = re.exec(tag);
  return m ? decodeEntities(m[1] ?? m[2] ?? m[3] ?? "").trim() : null;
}

// Anchors with their visible text
export function anchors(html) {
  const out = [];
  const re = /<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi;
  let m;
  while ((m = re.exec(html))) {
    const href = attr(m[1], "href");
    if (href == null) continue;
    out.push({ href, text: stripTags(m[2]).replace(/\s+/g, " ").trim(), hasImage: /<img\b/i.test(m[2]) });
  }
  const area = /<area\b([^>]*)>/gi;
  while ((m = area.exec(html))) {
    const href = attr(m[1], "href");
    if (href) out.push({ href, text: attr(m[1], "alt") || "", hasImage: false });
  }
  return out;
}

export function tags(html, name) {
  const re = new RegExp(`<${name}\\b([^>]*)>`, "gi");
  const out = [];
  let m;
  while ((m = re.exec(html))) out.push(m[1]);
  return out;
}
