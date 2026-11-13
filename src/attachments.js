// Static attachment analysis: hashes, real file type (magic bytes), risky extensions,
// archive listing, Office macros / template injection, PDF actions, HTML smuggling.
// Attachments are only read as bytes — never opened, rendered or executed.
import { md5 } from "./md5.js";
import { bytesToBinary } from "./mime.js";

const EXEC = ["exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "ps1", "psm1", "msi", "msp", "jar", "lnk", "reg", "cpl", "dll", "msc", "application", "gadget", "appx", "appxbundle", "msix", "xll", "chm", "iqy", "slk", "url", "scf", "sct", "inf", "apk"];
const DISK = ["iso", "img", "vhd", "vhdx"];
const MACRO = ["docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppsm", "sldm"];
const LEGACY_OFFICE = ["doc", "dot", "xls", "xlt", "ppt", "pps", "rtf"];
const ARCHIVE = ["zip", "rar", "7z", "gz", "tgz", "tar", "ace", "cab", "arj", "bz2", "xz", "r00", "z"];
const HTML_EXT = ["html", "htm", "shtml", "xhtml", "mht", "mhtml", "svg"];
const ONENOTE = ["one", "onepkg"];
const DOC_LIKE = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "csv", "rtf", "odt"];

const MAX_INFLATE = 5 * 1024 * 1024;

export async function hashes(bytes) {
  const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const subtle = globalThis.crypto?.subtle;
  const [sha1, sha256] = subtle
    ? await Promise.all([subtle.digest("SHA-1", bytes), subtle.digest("SHA-256", bytes)]).then((r) => r.map(hex))
    : ["", ""];
  return { md5: md5(bytes), sha1, sha256 };
}

const startsWith = (b, sig, off = 0) => sig.every((v, i) => b[off + i] === v);

export function sniffType(bytes) {
  const b = bytes;
  if (!b || !b.length) return { type: "empty", label: "Empty file" };
  if (startsWith(b, [0x4d, 0x5a])) return { type: "pe", label: "Windows executable (PE)" };
  if (startsWith(b, [0x7f, 0x45, 0x4c, 0x46])) return { type: "elf", label: "Linux executable (ELF)" };
  if (startsWith(b, [0x50, 0x4b, 0x03, 0x04]) || startsWith(b, [0x50, 0x4b, 0x05, 0x06])) return { type: "zip", label: "ZIP container" };
  if (startsWith(b, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return { type: "ole", label: "OLE2 (legacy Office / MSI)" };
  if (startsWith(b, [0x25, 0x50, 0x44, 0x46])) return { type: "pdf", label: "PDF document" };
  if (startsWith(b, [0x52, 0x61, 0x72, 0x21])) return { type: "rar", label: "RAR archive" };
  if (startsWith(b, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return { type: "7z", label: "7-Zip archive" };
  if (startsWith(b, [0x1f, 0x8b])) return { type: "gzip", label: "GZIP archive" };
  if (startsWith(b, [0x4d, 0x53, 0x43, 0x46])) return { type: "cab", label: "Cabinet archive" };
  if (startsWith(b, [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])) return { type: "lnk", label: "Windows shortcut (LNK)" };
  if (b.length > 0x8006 && startsWith(b, [0x43, 0x44, 0x30, 0x30, 0x31], 0x8001)) return { type: "iso", label: "ISO disk image" };
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47])) return { type: "png", label: "PNG image" };
  if (startsWith(b, [0xff, 0xd8, 0xff])) return { type: "jpeg", label: "JPEG image" };
  if (startsWith(b, [0x47, 0x49, 0x46, 0x38])) return { type: "gif", label: "GIF image" };
  if (startsWith(b, [0x7b, 0x5c, 0x72, 0x74, 0x66])) return { type: "rtf", label: "RTF document" };
  if (startsWith(b, [0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d])) return { type: "onenote", label: "OneNote section" };
  const head = bytesToBinary(b.subarray(0, 1024)).toLowerCase().replace(/^﻿|^\xef\xbb\xbf/, "").trimStart();
  if (head.startsWith("<svg") || (head.startsWith("<?xml") && head.includes("<svg"))) return { type: "svg", label: "SVG image (can contain script)" };
  if (/^<(!doctype html|html|head|body|script|meta|form|div|iframe)/.test(head)) return { type: "html", label: "HTML document" };
  if (head.startsWith("<?xml")) return { type: "xml", label: "XML document" };
  if (/^(from |received:|return-path:|mime-version:|message-id:)/.test(head)) return { type: "eml", label: "Email message" };
  if (/^[\x09\x0a\x0d\x20-\x7e]*$/.test(head)) return { type: "text", label: "Plain text" };
  return { type: "unknown", label: "Unknown binary" };
}

// ---------------------------------------------------------------- ZIP

export function listZip(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let eocd = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
    if (dv.getUint32(i, true) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd === -1) return null;
  const count = dv.getUint16(eocd + 10, true);
  let p = dv.getUint32(eocd + 16, true);
  const entries = [];
  const dec = new TextDecoder();
  for (let n = 0; n < count && n < 5000 && p + 46 <= bytes.length; n++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const flags = dv.getUint16(p + 8, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    entries.push({
      name: dec.decode(bytes.subarray(p + 46, p + 46 + nameLen)),
      encrypted: (flags & 1) === 1,
      method: dv.getUint16(p + 10, true),
      compSize: dv.getUint32(p + 20, true),
      size: dv.getUint32(p + 24, true),
      offset: dv.getUint32(p + 42, true),
    });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

async function inflateRaw(data) {
  const ds = new DecompressionStream("deflate-raw");
  const stream = new Blob([data]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export async function readZipEntry(bytes, entry) {
  if (entry.encrypted || entry.size > MAX_INFLATE) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const o = entry.offset;
  if (o + 30 > bytes.length || dv.getUint32(o, true) !== 0x04034b50) return null;
  const start = o + 30 + dv.getUint16(o + 26, true) + dv.getUint16(o + 28, true);
  const data = bytes.subarray(start, start + entry.compSize);
  try {
    if (entry.method === 0) return data;
    if (entry.method === 8) return await inflateRaw(data);
  } catch {
    return null;
  }
  return null;
}

// ---------------------------------------------------------------- helpers

function extOf(name) {
  const clean = name.replace(/[\s.]+$/, "");
  const i = clean.lastIndexOf(".");
  return i === -1 ? "" : clean.slice(i + 1).toLowerCase();
}

function prevExt(name) {
  const parts = name.replace(/[\s.]+$/, "").split(".");
  return parts.length >= 3 ? parts[parts.length - 2].toLowerCase() : "";
}

function f(code, severity, title, detail, mitre = []) {
  return { code, severity, title, detail, mitre };
}

const EXPECTED_MAGIC = {
  pdf: ["pdf"], docx: ["zip"], xlsx: ["zip"], pptx: ["zip"], docm: ["zip"], xlsm: ["zip"], zip: ["zip"], jar: ["zip"], apk: ["zip"],
  doc: ["ole", "rtf"], xls: ["ole"], ppt: ["ole"], msi: ["ole"], rtf: ["rtf", "ole"],
  png: ["png"], jpg: ["jpeg"], jpeg: ["jpeg"], gif: ["gif"], exe: ["pe"], dll: ["pe"], scr: ["pe"],
  iso: ["iso"], rar: ["rar"], "7z": ["7z"], gz: ["gzip"], lnk: ["lnk"], html: ["html", "text"], htm: ["html", "text"], svg: ["svg", "xml"],
};

// ---------------------------------------------------------------- analysis

export async function analyzeAttachment(att) {
  const bytes = att.bytes || new Uint8Array();
  const name = att.filename || "unnamed";
  const ext = extOf(name);
  const magic = sniffType(bytes);
  const result = {
    filename: name,
    contentType: att.contentType,
    disposition: att.disposition,
    contentId: att.contentId,
    size: bytes.length,
    ext,
    magic,
    hashes: await hashes(bytes),
    flags: [],
    urls: [],
    archive: null,
    office: null,
    isImage: ["png", "jpeg", "gif"].includes(magic.type) || /^image\/(png|jpe?g|gif|webp|bmp)$/.test(att.contentType || ""),
  };
  const flags = result.flags;

  if (/[‮‭‏⁦-⁩]/.test(name)) {
    flags.push(f("rtlo", "critical", "Right-to-left override in filename", `The filename contains invisible Unicode direction characters, so "${name.replace(/[‪-‮⁦-⁩]/g, "")}" is displayed in a misleading order.`, ["T1036.002"]));
  }
  if (prevExt(name) && DOC_LIKE.includes(prevExt(name)) && (EXEC.includes(ext) || DISK.includes(ext) || HTML_EXT.includes(ext) || ARCHIVE.includes(ext))) {
    flags.push(f("double_ext", "critical", "Double file extension", `"${name}" pretends to be a .${prevExt(name)} but is really a .${ext} file.`, ["T1036.007", "T1204.002"]));
  }
  if (/\s{4,}\.\w+$/.test(name)) flags.push(f("padded_name", "high", "Filename padded with spaces", "Many spaces before the extension push the real file type out of view.", ["T1036"]));

  if (EXEC.includes(ext) || magic.type === "pe" || magic.type === "elf" || magic.type === "lnk") {
    flags.push(f("executable", "critical", "Executable or script attachment", `${magic.type === "pe" ? "The file is a Windows program" : `.${ext} files run code`} when opened. Legitimate senders almost never email these.`, ["T1566.001", "T1204.002"]));
  }
  if (DISK.includes(ext) || magic.type === "iso") {
    flags.push(f("disk_image", "high", "Disk image attachment", "ISO/IMG/VHD files are used to smuggle malware past Mark-of-the-Web protections.", ["T1553.005", "T1566.001"]));
  }
  if (ONENOTE.includes(ext) || magic.type === "onenote") {
    flags.push(f("onenote", "high", "OneNote attachment", "OneNote files were widely abused in 2023+ to hide clickable malicious scripts behind fake buttons.", ["T1566.001", "T1204.002"]));
  }
  const expected = EXPECTED_MAGIC[ext];
  if (expected && !["empty", "unknown", "text"].includes(magic.type) && !expected.includes(magic.type)) {
    const sev = magic.type === "pe" || magic.type === "elf" ? "critical" : "high";
    flags.push(f("type_mismatch", sev, "File type does not match its extension", `Named .${ext}, but the content is really: ${magic.label}.`, ["T1036"]));
  }

  // archives
  if (magic.type === "zip") {
    const entries = listZip(bytes);
    if (entries) {
      const isOoxml = entries.some((e) => e.name === "[Content_Types].xml");
      result.archive = { kind: isOoxml ? "office" : "zip", entries: entries.slice(0, 200).map((e) => ({ name: e.name, size: e.size, encrypted: e.encrypted })) , count: entries.length };
      if (isOoxml) {
        result.office = await analyzeOoxml(bytes, entries, flags, result.urls);
      } else {
        if (entries.some((e) => e.encrypted)) {
          flags.push(f("encrypted_archive", "high", "Password-protected archive", "Encrypted archives cannot be scanned by email security gateways — a classic way to deliver malware.", ["T1027", "T1566.001"]));
        }
        const bad = entries.filter((e) => EXEC.includes(extOf(e.name)) || DISK.includes(extOf(e.name)) || HTML_EXT.includes(extOf(e.name)) || MACRO.includes(extOf(e.name)));
        if (bad.length) {
          flags.push(f("archive_payload", "critical", "Archive contains risky files", `Inside: ${bad.slice(0, 5).map((e) => e.name).join(", ")}${bad.length > 5 ? "…" : ""}`, ["T1566.001", "T1204.002"]));
        }
        const dbl = entries.filter((e) => DOC_LIKE.includes(prevExt(e.name)) && EXEC.includes(extOf(e.name)));
        if (dbl.length) flags.push(f("archive_double_ext", "critical", "Double extension inside archive", dbl.map((e) => e.name).join(", "), ["T1036.007"]));
      }
    }
  } else if (ARCHIVE.includes(ext) || ["rar", "7z", "gzip", "cab"].includes(magic.type)) {
    result.archive = { kind: magic.type, entries: [], count: null };
    flags.push(f("opaque_archive", "medium", "Compressed archive attachment", `${magic.label}: contents can't be inspected in the browser. Archives are a common malware wrapper.`, ["T1027"]));
  }

  if (MACRO.includes(ext) && !result.office?.macros) {
    flags.push(f("macro_ext", "high", "Macro-enabled Office file type", `.${ext} files are designed to carry VBA macros.`, ["T1059.005", "T1204.002"]));
  }

  if (magic.type === "ole") {
    const bin = bytesToBinary(bytes);
    const macros = bin.includes("_\x00V\x00B\x00A\x00_\x00P\x00R\x00O\x00J\x00E\x00C\x00T") || bin.includes("Attribute VB_") || bin.includes("VBA\x00");
    result.office = { macros, legacy: true };
    if (macros) flags.push(f("macros", "critical", "Document contains VBA macros", "Macros can download and run malware as soon as the user clicks \"Enable content\".", ["T1059.005", "T1204.002"]));
    else if (LEGACY_OFFICE.includes(ext)) flags.push(f("legacy_office", "low", "Legacy Office format", "Old .doc/.xls formats can carry macros and exploits; modern senders rarely use them.", ["T1566.001"]));
  }

  if (magic.type === "pdf") analyzePdf(bytes, flags, result.urls);
  if (magic.type === "html" || magic.type === "svg" || HTML_EXT.includes(ext)) analyzeHtmlAttachment(bytes, magic.type === "svg" || ext === "svg", flags, result.urls, name);
  if (magic.type === "eml" || att.contentType === "message/rfc822") {
    flags.push(f("attached_email", "low", "Email attached inside the email", "Forwarded .eml attachments are sometimes used to hide the real phishing message from filters.", ["T1027"]));
  }
  if (ext === "ics" || att.contentType === "text/calendar") {
    flags.push(f("calendar", "low", "Calendar invite attached", "Calendar invites can add phishing links straight into the victim's calendar.", ["T1566.002"]));
  }
  return result;
}

async function analyzeOoxml(bytes, entries, flags, urls) {
  const office = { macros: false, externalRefs: [], embedded: [] };
  if (entries.some((e) => /vbaProject\.bin$/i.test(e.name))) {
    office.macros = true;
    flags.push(f("macros", "critical", "Document contains VBA macros", "vbaProject.bin found: the document carries macros that can run code once enabled.", ["T1059.005", "T1204.002"]));
  }
  office.embedded = entries.filter((e) => /\/embeddings\//i.test(e.name)).map((e) => e.name);
  if (office.embedded.some((n) => /\.(bin|exe|js|vbs|lnk|bat|cmd)$/i.test(n) || /oleObject/i.test(n))) {
    flags.push(f("embedded_object", "high", "Embedded OLE object", `Embedded objects: ${office.embedded.slice(0, 4).join(", ")}`, ["T1204.002"]));
  }
  for (const e of entries.filter((x) => x.name.endsWith(".rels")).slice(0, 40)) {
    const data = await readZipEntry(bytes, e);
    if (!data) continue;
    const xml = new TextDecoder().decode(data);
    for (const m of xml.matchAll(/<Relationship\b[^>]*>/gi)) {
      const tag = m[0];
      if (!/TargetMode\s*=\s*"External"/i.test(tag)) continue;
      const target = /Target\s*=\s*"([^"]+)"/i.exec(tag)?.[1] || "";
      const type = (/Type\s*=\s*"([^"]+)"/i.exec(tag)?.[1] || "").split("/").pop();
      office.externalRefs.push({ type, target, part: e.name });
      if (/^https?:|^\\\\|^file:/i.test(target)) urls.push({ url: target.replace(/^\\\\/, "file://"), source: `office ${type}`, text: "" });
    }
  }
  const tpl = office.externalRefs.filter((r) => /attachedTemplate|oleObject|frame/i.test(r.type) && /^(https?:|\\\\|file:)/i.test(r.target));
  if (tpl.length) {
    flags.push(f("template_injection", "critical", "Remote template injection", `The document loads content from ${tpl[0].target} when opened (${tpl[0].type}).`, ["T1221", "T1204.002"]));
  }
  return office;
}

function analyzePdf(bytes, flags, urls) {
  const s = bytesToBinary(bytes.length > 8e6 ? bytes.subarray(0, 8e6) : bytes);
  const count = (re) => (s.match(re) || []).length;
  const js = count(/\/(JavaScript|JS)\b/g);
  const open = count(/\/(OpenAction|AA)\b/g);
  const launch = count(/\/Launch\b/g);
  const embedded = count(/\/EmbeddedFile\b/g);
  const submit = count(/\/SubmitForm\b/g);
  for (const m of s.matchAll(/\/URI\s*\(([^)]{4,2000})\)/g)) urls.push({ url: m[1].replace(/\\(.)/g, "$1"), source: "pdf link", text: "" });
  if (js) flags.push(f("pdf_js", open ? "critical" : "high", "PDF contains JavaScript", `${js} JavaScript reference(s)${open ? " and an automatic action on open" : ""}.`, ["T1059.007", "T1204.002"]));
  if (launch) flags.push(f("pdf_launch", "critical", "PDF can launch programs", "/Launch action found.", ["T1204.002"]));
  if (embedded) flags.push(f("pdf_embedded", "high", "PDF has embedded files", `${embedded} embedded file(s).`, ["T1027"]));
  if (submit) flags.push(f("pdf_form", "medium", "PDF submits form data", "/SubmitForm can send typed credentials to a remote server.", ["T1056.003"]));
  if (urls.length && !js && !launch) {
    flags.push(f("pdf_links", "low", "PDF contains links", `${urls.length} link(s) inside the PDF — a common way to move the phishing link out of the email body.`, ["T1566.002"]));
  }
}

function analyzeHtmlAttachment(bytes, isSvg, flags, urls, name) {
  const s = new TextDecoder().decode(bytes.length > 4e6 ? bytes.subarray(0, 4e6) : bytes);
  const has = (re) => re.test(s);
  const base64Blob = has(/[A-Za-z0-9+/]{3000,}={0,2}/);
  const decoder = has(/\batob\s*\(/) || has(/\bunescape\s*\(/) || has(/String\.fromCharCode\s*\(/) || has(/decodeURIComponent\s*\(\s*escape/);
  const blob = has(/new\s+Blob\s*\(/) || has(/createObjectURL/) || has(/msSaveOrOpenBlob/) || has(/\.download\s*=/) || has(/\bdownload\s*=\s*["']/i);
  const script = has(/<script\b/i) || has(/\bon(load|error|click|mouseover)\s*=/i);
  const password = has(/<input[^>]+type\s*=\s*["']?password/i);
  const form = has(/<form\b/i);
  const redirect = has(/(window|document|top)\.location(\.href)?\s*=|location\.replace\s*\(|<meta[^>]+http-equiv\s*=\s*["']?refresh/i);
  const exfil = has(/\b(fetch|XMLHttpRequest|\$\.ajax|\$\.post|sendBeacon)\b/) || has(/api\.telegram\.org\/bot/i);

  if (isSvg && script) flags.push(f("svg_script", "critical", "SVG image runs JavaScript", `${name} looks like an image but contains script that runs when opened in a browser.`, ["T1059.007", "T1027.006"]));
  if ((decoder || base64Blob) && blob) {
    flags.push(f("html_smuggling", "critical", "HTML smuggling", "The file decodes an embedded payload in the browser and saves it to disk, so the malware never crosses the email gateway as a file.", ["T1027.006", "T1204.002"]));
  }
  if (password) flags.push(f("html_credential_form", "critical", "Local fake login page", "The attachment is a self-contained login page with a password field — credentials typed in it go to the attacker.", ["T1056.003", "T1598.003"]));
  else if (form) flags.push(f("html_form", "high", "Attachment contains a form", "HTML forms in attachments are used to collect data offline, out of reach of URL scanners.", ["T1056.003"]));
  if (exfil && (password || form)) flags.push(f("html_exfil", "critical", "Sends form data to a server", "Script posts what the user types to a remote endpoint (fetch/XHR/Telegram bot).", ["T1056.003"]));
  if (redirect && !password) flags.push(f("html_redirect", "high", "Attachment redirects to a website", "Opening the file immediately sends the browser to a remote page.", ["T1204.001"]));
  if (script && decoder && !blob) flags.push(f("html_obfuscated", "high", "Obfuscated script in attachment", "The script decodes hidden content at runtime (atob / unescape / fromCharCode).", ["T1027"]));
  if (!flags.some((x) => x.code.startsWith("html_") || x.code === "svg_script") && !isSvg) {
    flags.push(f("html_attachment", "medium", "HTML attachment", "HTML files open in the browser with full control over what the user sees — a common phishing delivery method.", ["T1566.001"]));
  }
  for (const m of s.matchAll(/\b(?:action|href|src)\s*=\s*["'](https?:\/\/[^"']+)["']/gi)) urls.push({ url: m[1], source: `inside ${name}`, text: "" });
  for (const m of s.matchAll(/["'](https?:\/\/[^"'\s]{6,300})["']/g)) urls.push({ url: m[1], source: `script in ${name}`, text: "" });
}
