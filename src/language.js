// Social-engineering language and HTML trickery in the body.
import { attr, stripTags, tags } from "./html.js";

const RULES = [
  {
    id: "credential_request",
    title: "Asks you to log in or confirm credentials",
    base: "medium",
    many: "high",
    mitre: ["T1598.003", "T1566.002"],
    detail: "Real services rarely ask you to verify your account or password through an email link.",
    patterns: [
      /verify\s+(your\s+)?(account|identity|e-?mail|password|login)/i,
      /confirm\s+(your\s+)?(password|credentials|account|identity|details|e-?mail)/i,
      /(update|validate|re-?enter|re-?confirm)\s+(your\s+)?(payment|billing|card|password|credentials|account)/i,
      /unusual\s+(sign-?in|login|activity)/i,
      /(password|mailbox|account)\s+(will\s+|is\s+going\s+to\s+)?(expire|be\s+(closed|deleted|deactivated|suspended|disabled))/i,
      /sign\s+in\s+to\s+(keep|avoid|restore|continue|retain|view)/i,
      /\bre-?activate\b/i,
      /mailbox\s+(is\s+)?(almost\s+)?(full|over\s+quota|storage)/i,
      /(mfa|2fa|multi-?factor|two-?factor)\s+(re-?enrol+ment|re-?registration|update|expir|setup|required)/i,
      /scan\s+(the\s+)?qr\s*code/i,
      /(keep|retain)\s+(the\s+)?same\s+password/i,
      /verifica(ți|ti)\s+contul/i,
      /confirma(ți|ti)\s+parola/i,
    ],
  },
  {
    id: "bec_payment",
    title: "Money or payment request",
    base: "medium",
    many: "high",
    mitre: ["T1657", "T1656"],
    detail: "Requests for wire transfers, gift cards or changed bank details are the core of business email compromise (BEC) fraud.",
    patterns: [
      /wire\s+transfer/i,
      /bank\s+(details|account|information)\s+(have\s+|has\s+)?(changed|been\s+updated|updated)/i,
      /\bgift\s*cards?\b/i,
      /\b(iban|swift\s*code|routing\s+number|account\s+number)\b/i,
      /(process|make|send|approve)\s+(a|an|the)?\s*(urgent\s+)?(payment|transfer)/i,
      /are\s+you\s+(available|at\s+your\s+desk|in\s+the\s+office)/i,
      /quick\s+(favou?r|task|errand)/i,
      /(keep|remain)\s+(this\s+)?(strictly\s+)?(confidential|between\s+us|discreet|quiet)/i,
      /\bnew\s+(vendor|supplier|beneficiary)\b/i,
      /outstanding\s+(invoice|balance|payment)/i,
      /\bcrypto(currency)?\s+(wallet|payment)|\bbitcoin\b|\busdt\b/i,
      /transfer\s+bancar/i,
    ],
  },
  {
    id: "urgency",
    title: "Urgency and pressure",
    base: "low",
    many: "medium",
    mitre: ["T1566"],
    detail: "Artificial deadlines push people to act before they think — the #1 social-engineering lever.",
    patterns: [
      /\burgent(ly)?\b/i,
      /\bimmediate(ly)?\b/i,
      /within\s+(\d{1,2})\s*(hours?|hrs?|h)\b/i,
      /\b(final|last)\s+(notice|warning|reminder|attempt)\b/i,
      /\bact\s+now\b/i,
      /\b(expires?|expiring|expired)\b/i,
      /\bsuspend(ed|sion)?\b/i,
      /as\s+soon\s+as\s+possible|\basap\b/i,
      /\bdeadline\b/i,
      /\bby\s+end\s+of\s+(the\s+)?day\b|\bEOD\b/,
      /\bimediat\b|\burgen(t|ță)\b|în\s+24\s+de\s+ore/i,
    ],
  },
  {
    id: "threat",
    title: "Threats or consequences",
    base: "low",
    many: "medium",
    mitre: ["T1566"],
    detail: "Threatening account closure, fines or legal action is a pressure tactic.",
    patterns: [
      /legal\s+action/i,
      /(account|access|service)\s+will\s+be\s+(closed|terminated|blocked|locked|restricted|suspended)/i,
      /permanently\s+(deleted|lost|disabled|removed)/i,
      /\bpenalt(y|ies)\b|\bfine\s+of\b/i,
      /(lose|loss\s+of)\s+(access|your\s+(data|files|emails))/i,
      /contul\s+(dvs\.?|dumneavoastră|tău)\s+(va\s+fi\s+)?(suspendat|blocat|închis)/i,
    ],
  },
  {
    id: "lure",
    title: "Common phishing lure topic",
    base: "low",
    many: "low",
    mitre: ["T1566"],
    detail: "Package deliveries, shared documents, voicemails, invoices and refunds are the most-used phishing pretexts.",
    patterns: [
      /you('ve|\s+have)\s+(won|been\s+selected)/i,
      /\b(prize|lottery|winner)\b/i,
      /\brefund\b/i,
      /claim\s+(your|now|it)/i,
      /\b(voice\s*mail|voice\s+message)\b/i,
      /shared\s+(a\s+)?(document|file|folder)\s+with\s+you/i,
      /(pending|failed|held|undelivered)\s+(delivery|package|parcel|shipment)/i,
      /(customs|delivery|shipping)\s+fee/i,
      /document\s+(is\s+)?(ready|waiting)\s+(to|for)\s+(sign|review|signature)/i,
      /\bsalary\s+(increase|adjustment)|\bbonus\s+payment|\bpayroll\s+update/i,
      /colet(ul)?\s+(dvs|dumneavoastră)/i,
    ],
  },
  {
    id: "generic_greeting",
    title: "Generic greeting",
    base: "low",
    many: "low",
    mitre: [],
    detail: "Mass phishing doesn't know your name.",
    patterns: [/\bdear\s+(customer|user|client|member|account\s*holder|valued|sir|madam|employee|staff|colleague|recipient|beneficiary)\b/i, /\bhello\s+(user|customer|dear)\b/i, /\bstimate\s+client\b/i],
  },
  {
    id: "attachment_password",
    title: "Gives a password for an attachment",
    base: "medium",
    many: "high",
    mitre: ["T1027"],
    detail: "Sending the archive password in the same email is how attackers stop security scanners from opening the file.",
    patterns: [/\b(password|passcode|pass|pwd|parola)\s*(is|:|=)\s*["']?[\w!@#$%^&*-]{3,}/i, /\b(archive|zip|file|document|attachment)\s+is\s+(password[- ]protected|encrypted)/i],
  },
];

const SEV = ["info", "low", "medium", "high", "critical"];

function snippet(text, index, len) {
  const start = Math.max(0, index - 50);
  const end = Math.min(text.length, index + len + 50);
  return (start ? "…" : "") + text.slice(start, end).replace(/\s+/g, " ").trim() + (end < text.length ? "…" : "");
}

export function analyzeLanguage({ subject = "", text = "", html = "" }) {
  const bodyText = (text || "").trim() || stripTags(html);
  const corpus = `${subject}\n${bodyText}`;
  const findings = [];
  const stats = {};
  for (const rule of RULES) {
    const hits = [];
    for (const re of rule.patterns) {
      const m = re.exec(corpus);
      if (m) hits.push({ phrase: m[0], context: snippet(corpus, m.index, m[0].length) });
    }
    stats[rule.id] = hits.length;
    if (!hits.length) continue;
    const severity = hits.length >= 2 ? rule.many : rule.base;
    findings.push({
      id: `lang_${rule.id}`,
      severity,
      category: "content",
      title: rule.title,
      detail: `${rule.detail} Matched: ${hits.map((h) => `"${h.phrase}"`).join(", ")}.`,
      evidence: hits.slice(0, 5).map((h) => h.context),
      phrases: hits.map((h) => h.phrase),
      mitre: rule.mitre,
    });
  }
  // Pressure + action together is much stronger than either alone
  if ((stats.urgency || stats.threat) && (stats.credential_request || stats.bec_payment)) {
    findings.push({ id: "lang_combo", severity: "medium", category: "content", title: "Pressure combined with a request", detail: "The message both creates urgency/threat and asks for credentials or money — the textbook phishing formula.", evidence: [], mitre: ["T1566"] });
  }
  return { findings, stats, bodyText, wordCount: bodyText.split(/\s+/).filter(Boolean).length, severities: SEV };
}

export function analyzeHtmlBody(html, attachments = []) {
  const findings = [];
  const info = { forms: 0, scripts: 0, remoteImages: 0, trackingPixels: 0, hiddenBlocks: 0, iframes: 0, qrCandidates: 0 };
  if (!html) return { findings, info };
  const forms = tags(html, "form");
  info.forms = forms.length;
  info.scripts = tags(html, "script").length + (html.match(/\son(load|error|click|mouseover)\s*=/gi) || []).length;
  info.iframes = tags(html, "iframe").length;
  const imgs = tags(html, "img");
  for (const t of imgs) {
    const src = attr(t, "src") || "";
    if (/^https?:/i.test(src)) info.remoteImages++;
    const w = attr(t, "width");
    const h = attr(t, "height");
    if ((w === "1" || w === "0") && (h === "1" || h === "0")) info.trackingPixels++;
  }
  const hidden = html.match(/<[^>]+style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(px|pt|em)?\s*[;"']|opacity\s*:\s*0\s*[;"'])[^>]*>/gi) || [];
  info.hiddenBlocks = hidden.length;
  const visible = stripTags(html);
  const passwordField = /<input[^>]+type\s*=\s*["']?password/i.test(html);

  if (forms.length) {
    findings.push({ id: "html_form", severity: passwordField ? "critical" : "high", category: "html", title: passwordField ? "Login form inside the email" : "Form inside the email", detail: `The email itself contains ${forms.length} form(s)${passwordField ? " with a password field" : ""}. Legitimate companies never collect data this way.`, evidence: forms.map((t) => `<form${t.slice(0, 140)}>`), mitre: ["T1056.003", "T1598.003"] });
  }
  if (info.scripts) findings.push({ id: "html_script", severity: "medium", category: "html", title: "Script code in the email", detail: "Email clients block scripts, so their presence signals a phishing kit or a malformed template.", evidence: [], mitre: ["T1059.007"] });
  if (info.iframes) findings.push({ id: "html_iframe", severity: "medium", category: "html", title: "Embedded frame", detail: "Iframes can load a remote page inside the message.", evidence: [], mitre: ["T1566.002"] });
  if (/<meta[^>]+http-equiv\s*=\s*["']?refresh/i.test(html)) findings.push({ id: "html_refresh", severity: "medium", category: "html", title: "Automatic redirect", detail: "A meta refresh tag sends the reader to another page automatically.", evidence: [], mitre: ["T1204.001"] });
  const hiddenText = hidden.length >= 2 || /font-size\s*:\s*0/i.test(html) || /color\s*:\s*(#fff(fff)?|white)\s*;[^"']*background(-color)?\s*:\s*(#fff(fff)?|white)/i.test(html);
  if (hiddenText) findings.push({ id: "html_hidden", severity: "low", category: "html", title: "Hidden text", detail: `${hidden.length} hidden block(s). Invisible text is used to poison spam filters (also used by some newsletters for preview text).`, evidence: hidden.slice(0, 3).map((h) => h.slice(0, 160)), mitre: ["T1027"] });
  if (info.trackingPixels) findings.push({ id: "html_tracking", severity: "info", category: "html", title: "Tracking pixel", detail: `${info.trackingPixels} invisible 1×1 image(s) report back when the email is opened.`, evidence: [], mitre: [] });
  const inlineImages = attachments.filter((a) => a.isImage).length;
  if ((imgs.length || inlineImages) && visible.replace(/\s+/g, "").length < 60) {
    info.qrCandidates = imgs.length + inlineImages;
    findings.push({ id: "html_image_only", severity: "medium", category: "html", title: "Almost no text, mostly images", detail: "Image-only emails hide their message from text-based filters. This is how QR-code phishing (quishing) is delivered.", evidence: [], mitre: ["T1027", "T1566.002"] });
  }
  if (/href\s*=\s*["']?\s*data:/i.test(html)) findings.push({ id: "html_data_link", severity: "high", category: "html", title: "Link to an embedded data: page", detail: "data: links carry a whole web page inside the link itself.", evidence: [], mitre: ["T1027"] });
  return { findings, info };
}
