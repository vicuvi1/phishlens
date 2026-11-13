// Dependency-free RFC 5322 / MIME parser.
// Works on a "binary string" (one char per byte) so attachments survive byte-for-byte,
// and runs unchanged in the browser and in Node.

const MAX_DEPTH = 20;
const MAX_PARTS = 500;

export function toBinary(input) {
  if (typeof input === "string") {
    // Pasted text: re-encode as UTF-8 bytes so everything below works on bytes.
    return bytesToBinary(new TextEncoder().encode(input));
  }
  if (input instanceof ArrayBuffer) return bytesToBinary(new Uint8Array(input));
  if (ArrayBuffer.isView(input)) return bytesToBinary(new Uint8Array(input.buffer, input.byteOffset, input.byteLength));
  throw new TypeError("expected a string, ArrayBuffer or Uint8Array");
}

export function bytesToBinary(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return out;
}

export function binaryToBytes(bin) {
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
  return out;
}

export function decodeCharset(bytes, charset = "utf-8") {
  let label = (charset || "utf-8").trim().toLowerCase().replace(/^["']|["']$/g, "");
  if (label === "us-ascii" || label === "ascii") label = "utf-8";
  try {
    return new TextDecoder(label).decode(bytes);
  } catch {
    return new TextDecoder("utf-8").decode(bytes);
  }
}

// Header text may contain raw 8-bit bytes (often UTF-8). Prefer UTF-8, fall back to cp1252.
function decodeHeaderBytes(bin) {
  if (!/[\x80-\xff]/.test(bin)) return bin;
  const bytes = binaryToBytes(bin);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return new TextDecoder("windows-1252").decode(bytes);
  }
}

// RFC 2047 encoded words: =?charset?B|Q?text?=
export function decodeWords(value) {
  if (!value || value.indexOf("=?") === -1) return value;
  return value
    .replace(/(=\?[^?]+\?[BbQq]\?[^?]*\?=)\s+(?==\?[^?]+\?[BbQq]\?[^?]*\?=)/g, "$1")
    .replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_, charset, enc, text) => {
      const cs = charset.split("*")[0];
      let bytes;
      try {
        if (enc.toUpperCase() === "B") {
          bytes = binaryToBytes(atob(text.replace(/[^A-Za-z0-9+/=]/g, "")));
        } else {
          bytes = binaryToBytes(
            text.replace(/_/g, " ").replace(/=([0-9A-Fa-f]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16))),
          );
        }
      } catch {
        return text;
      }
      return decodeCharset(bytes, cs);
    });
}

export function splitHeadersBody(bin) {
  const crlf = bin.indexOf("\r\n\r\n");
  const lf = bin.indexOf("\n\n");
  let idx = -1;
  let sep = 0;
  if (crlf !== -1 && (lf === -1 || crlf <= lf)) {
    idx = crlf;
    sep = 4;
  } else if (lf !== -1) {
    idx = lf;
    sep = 2;
  }
  if (idx === -1) {
    // Headers only (or body only if it doesn't look like headers)
    return /^[\w-]+:/.test(bin) ? { head: bin, body: "" } : { head: "", body: bin };
  }
  return { head: bin.slice(0, idx), body: bin.slice(idx + sep) };
}

export class Headers {
  constructor(list = []) {
    this.list = list; // [{ name, raw, value }] in original order
  }
  static parse(headBin) {
    const text = decodeHeaderBytes(headBin);
    const lines = text.split(/\r?\n/);
    const list = [];
    for (const line of lines) {
      if (/^[ \t]/.test(line) && list.length) {
        list[list.length - 1].raw += "\r\n" + line;
      } else {
        const m = /^([^:\s]+)\s*:\s?(.*)$/.exec(line);
        if (m) list.push({ name: m[1], raw: m[2] });
      }
    }
    for (const h of list) {
      h.unfolded = h.raw.replace(/\r?\n[ \t]+/g, " ").trim();
      h.value = decodeWords(h.unfolded);
    }
    return new Headers(list);
  }
  get(name) {
    const n = name.toLowerCase();
    const h = this.list.find((x) => x.name.toLowerCase() === n);
    return h ? h.value : "";
  }
  getRaw(name) {
    const n = name.toLowerCase();
    const h = this.list.find((x) => x.name.toLowerCase() === n);
    return h ? h.unfolded : "";
  }
  getAll(name) {
    const n = name.toLowerCase();
    return this.list.filter((x) => x.name.toLowerCase() === n).map((x) => x.value);
  }
  has(name) {
    return this.list.some((x) => x.name.toLowerCase() === name.toLowerCase());
  }
}

// "text/html; charset=utf-8; name*=UTF-8''file%20name.pdf"
export function parseStructured(value) {
  const parts = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === "\\" && quoted && i + 1 < value.length) {
      cur += value[++i];
      continue;
    }
    if (c === '"') quoted = !quoted;
    if (c === ";" && !quoted) {
      parts.push(cur);
      cur = "";
    } else cur += c;
  }
  parts.push(cur);
  const main = (parts.shift() || "").trim().toLowerCase();
  const raw = {};
  for (const p of parts) {
    const eq = p.indexOf("=");
    if (eq === -1) continue;
    const key = p.slice(0, eq).trim().toLowerCase();
    let val = p.slice(eq + 1).trim();
    if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
    raw[key] = val;
  }
  // RFC 2231: key*=charset'lang'pct-encoded, and key*0, key*1 continuations
  const params = {};
  const continued = {};
  for (const [key, val] of Object.entries(raw)) {
    const m = /^([^*]+)\*(\d+)?(\*)?$/.exec(key);
    if (!m) {
      params[key] = decodeWords(val);
      continue;
    }
    const [, base, index, star] = m;
    (continued[base] ||= []).push({ index: index === undefined ? 0 : Number(index), val, encoded: star === "*" || index === undefined });
  }
  for (const [base, pieces] of Object.entries(continued)) {
    pieces.sort((a, b) => a.index - b.index);
    let charset = "utf-8";
    let bin = "";
    pieces.forEach((p, i) => {
      let v = p.val;
      if (p.encoded) {
        if (i === 0 && /^[^']*'[^']*'/.test(v)) {
          const q = v.split("'");
          charset = q[0] || "utf-8";
          v = q.slice(2).join("'");
        }
        bin += v.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
      } else {
        bin += v;
      }
    });
    params[base] = decodeCharset(binaryToBytes(bin), charset);
  }
  return { value: main, params };
}

export function decodeTransfer(bin, encoding) {
  const enc = (encoding || "").trim().toLowerCase();
  if (enc === "base64") {
    const clean = bin.replace(/[^A-Za-z0-9+/]/g, "");
    const padded = clean + "===".slice((clean.length + 3) % 4);
    try {
      return binaryToBytes(atob(padded.length % 4 === 1 ? padded.slice(0, -1) : padded));
    } catch {
      return binaryToBytes(bin);
    }
  }
  if (enc === "quoted-printable") {
    const s = bin.replace(/=\r?\n/g, "").replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    return binaryToBytes(s);
  }
  return binaryToBytes(bin);
}

function splitMultipart(body, boundary) {
  const delim = "--" + boundary;
  const text = "\r\n" + body;
  const positions = [];
  let from = 0;
  for (;;) {
    let i = text.indexOf("\n" + delim, from);
    if (i === -1) break;
    const after = i + 1 + delim.length;
    const isClose = text.startsWith("--", after);
    const lineEnd = text.indexOf("\n", after);
    const start = i > 0 && text[i - 1] === "\r" ? i - 1 : i;
    positions.push({ start, contentStart: lineEnd === -1 ? text.length : lineEnd + 1, isClose });
    if (isClose) break;
    from = after;
  }
  const parts = [];
  for (let k = 0; k < positions.length - 1; k++) {
    if (positions[k].isClose) break;
    parts.push(text.slice(positions[k].contentStart, positions[k + 1].start));
  }
  // Unterminated last part (truncated mail): keep what's there.
  const last = positions[positions.length - 1];
  if (last && !last.isClose) parts.push(text.slice(last.contentStart));
  return { parts, preamble: positions.length ? text.slice(2, positions[0].start) : text.slice(2) };
}

let partCounter = 0;

function parsePart(bin, depth, state, path) {
  const { head, body } = splitHeadersBody(bin);
  const headers = Headers.parse(head);
  const ct = parseStructured(headers.get("content-type") || "text/plain");
  const cd = parseStructured(headers.get("content-disposition") || "");
  const part = {
    id: ++partCounter,
    path,
    headers,
    contentType: ct.value || "text/plain",
    params: ct.params,
    disposition: cd.value,
    filename: cd.params.filename || ct.params.name || "",
    transferEncoding: (headers.get("content-transfer-encoding") || "7bit").toLowerCase(),
    contentId: headers.get("content-id").replace(/^<|>$/g, ""),
    children: [],
    size: body.length,
  };
  state.count++;
  if (part.contentType.startsWith("multipart/") && part.params.boundary && depth < MAX_DEPTH) {
    const { parts } = splitMultipart(body, part.params.boundary);
    parts.forEach((p, i) => {
      if (state.count < MAX_PARTS) part.children.push(parsePart(p, depth + 1, state, `${path}.${i + 1}`));
      else state.truncated = true;
    });
    if (!parts.length) state.warnings.push(`multipart boundary "${part.params.boundary}" not found`);
  } else {
    part.bytes = decodeTransfer(body, part.transferEncoding);
    part.size = part.bytes.length;
    if (part.contentType.startsWith("text/") && part.disposition !== "attachment") {
      part.text = decodeCharset(part.bytes, part.params.charset);
    }
  }
  return part;
}

function isAttachment(part) {
  if (part.children.length) return false;
  if (part.disposition === "attachment") return true;
  if (part.filename) return true;
  const t = part.contentType;
  if (t === "text/plain" || t === "text/html") return false;
  if (t.startsWith("text/") && !part.filename) return false;
  return true; // images, application/*, message/rfc822, …
}

export function parseEmail(input) {
  partCounter = 0;
  const bin = toBinary(input);
  const state = { count: 0, warnings: [], truncated: false };
  const root = parsePart(bin, 0, state, "1");
  const text = [];
  const html = [];
  const attachments = [];
  const walk = (p) => {
    if (p.children.length) {
      // multipart/alternative: prefer the richest version for display, keep all for analysis
      p.children.forEach(walk);
      return;
    }
    if (isAttachment(p)) {
      attachments.push({
        filename: p.filename || `unnamed-part-${p.path}${guessExt(p.contentType)}`,
        hasName: !!p.filename,
        contentType: p.contentType,
        disposition: p.disposition || (p.contentId ? "inline" : "attachment"),
        contentId: p.contentId,
        size: p.size,
        bytes: p.bytes,
      });
    } else if (p.contentType === "text/html") html.push(p.text || "");
    else text.push(p.text || "");
  };
  walk(root);
  if (state.truncated) state.warnings.push(`stopped after ${MAX_PARTS} MIME parts`);
  return {
    headers: root.headers,
    root,
    text: text.join("\n\n"),
    html: html.join("\n"),
    attachments,
    size: bin.length,
    partCount: state.count,
    warnings: state.warnings,
  };
}

function guessExt(type) {
  const map = { "image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif", "application/pdf": ".pdf", "message/rfc822": ".eml", "text/calendar": ".ics" };
  return map[type] || ".bin";
}

// ---------------------------------------------------------------- addresses

export function parseAddressList(value) {
  if (!value) return [];
  const items = [];
  let cur = "";
  let quoted = false;
  let angle = 0;
  let paren = 0;
  for (const c of value) {
    if (c === '"' && !paren) quoted = !quoted;
    else if (!quoted) {
      if (c === "<") angle++;
      else if (c === ">") angle = Math.max(0, angle - 1);
      else if (c === "(") paren++;
      else if (c === ")") paren = Math.max(0, paren - 1);
    }
    if (c === "," && !quoted && !angle && !paren) {
      items.push(cur);
      cur = "";
    } else cur += c;
  }
  items.push(cur);
  return items.map(parseAddress).filter((a) => a.address || a.name);
}

export function parseAddress(raw) {
  const s = (raw || "").trim();
  let name = "";
  let address = "";
  const m = /^(.*?)<([^<>]*)>\s*(\(.*\))?\s*$/.exec(s);
  if (m) {
    name = m[1].trim();
    address = m[2].trim();
  } else {
    const comment = /\(([^)]*)\)/.exec(s);
    address = s.replace(/\([^)]*\)/g, "").trim();
    if (comment) name = comment[1].trim();
  }
  name = name.replace(/^"(.*)"$/, "$1").replace(/\\(.)/g, "$1").trim();
  address = address.replace(/^mailto:/i, "");
  const at = address.lastIndexOf("@");
  const domain = at === -1 ? "" : address.slice(at + 1).toLowerCase().replace(/[>\]\s]+$/, "");
  const local = at === -1 ? address : address.slice(0, at);
  return { name, address: address.toLowerCase(), local, domain };
}
