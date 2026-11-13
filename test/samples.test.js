// End-to-end: every bundled sample must get the expected verdict and key findings.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { analyzeEmail } from "../src/analyze.js";
import { toIocCsv, toMarkdown, toStix } from "../src/report.js";
import { decodeQrNode } from "../src/qr-node.js";

const load = async (name) => analyzeEmail(new Uint8Array(await readFile(new URL(`../samples/${name}`, import.meta.url))), { filename: name });
const ids = (r) => r.findings.map((f) => f.id);

test("Microsoft 365 credential phish", async () => {
  const r = await load("01-microsoft365-password-expiry.eml");
  assert.equal(r.verdict.key, "malicious");
  for (const id of ["sender_lookalike", "dmarc_fail", "link_text_mismatch", "link_lookalike", "reply_to_mismatch", "lang_credential_request"]) assert.ok(ids(r).includes(id), id);
  assert.ok(r.mitre.some((t) => t.id === "T1566.002"));
  assert.equal(r.received.originIp, "203.0.113.77");
});

test("CEO wire-transfer fraud passes SPF/DKIM/DMARC but is still caught", async () => {
  const r = await load("02-ceo-urgent-wire-transfer.eml");
  assert.equal(r.auth.dmarc.result, "pass");
  assert.ok(["phishing", "malicious"].includes(r.verdict.key));
  for (const id of ["lang_bec_payment", "freemail_role", "reply_to_mismatch"]) assert.ok(ids(r).includes(id), id);
});

test("DHL invoice: double extension in archive, macros, template injection", async () => {
  const r = await load("03-dhl-invoice-malware.eml");
  assert.equal(r.verdict.key, "malicious");
  for (const id of ["att_archive_double_ext", "att_macros", "att_template_injection", "lang_attachment_password", "sender_lookalike"]) assert.ok(ids(r).includes(id), id);
  const docm = r.attachments.find((a) => a.filename.endsWith(".docm"));
  assert.equal(docm.office.externalRefs[0].target, "http://198.51.100.66/templates/invoice.dotm");
  assert.match(docm.hashes.sha256, /^[0-9a-f]{64}$/);
});

test("HTML smuggling attachment", async () => {
  const r = await load("04-html-smuggling-secure-message.eml");
  assert.equal(r.verdict.key, "malicious");
  assert.ok(ids(r).includes("att_html_smuggling"));
  assert.ok(ids(r).includes("att_html_credential_form"));
  assert.ok(r.urls.some((u) => u.host === "payroll-portal-docs.web.app"));
});

test("QR code phishing: the real PNG is decoded and its link analysed", async () => {
  const bytes = new Uint8Array(await readFile(new URL("../samples/05-qr-code-mfa-reenrollment.eml", import.meta.url)));
  const r = await analyzeEmail(bytes, { decodeQr: decodeQrNode });
  const png = r.attachments.find((a) => a.isImage);
  assert.deepEqual(png.qr, ["https://mfa-reset.sharepoint-docs.xyz/enroll?tenant=example&id=55102"]);
  assert.ok(ids(r).includes("qr_code"));
  assert.ok(ids(r).includes("html_image_only"));
  assert.equal(r.verdict.key, "malicious");
});

test("live intel: a 3-day-old sender domain with no DMARC is flagged (mocked network)", async () => {
  const created = new Date(Date.now() - 3 * 86400000).toISOString();
  const fetchImpl = async (url) => {
    const body = url.includes("rdap") ? { events: [{ eventAction: "registration", eventDate: created }] }
      : url.includes("_dmarc") ? { Status: 3 } : url.includes("type=MX") ? { Status: 0, Answer: [] } : { Status: 0, Answer: [{ data: '"v=spf1 -all"' }] };
    return { ok: true, json: async () => body };
  };
  const r = await analyzeEmail(new Uint8Array(await readFile(new URL("../samples/02-ceo-urgent-wire-transfer.eml", import.meta.url))), { live: true, fetchImpl });
  assert.ok(r.live.domains.length >= 1);
  const raw = "From: Billing <billing@fresh-invoices.example>\r\nTo: a@example.com\r\nSubject: hi\r\n\r\nhello";
  const r2 = await analyzeEmail(raw, { live: true, fetchImpl });
  assert.ok(ids(r2).includes("live_new_fresh-invoices.example"));
  assert.ok(ids(r2).includes("live_no_dmarc"));
});

test("PayPal homograph link", async () => {
  const r = await load("06-paypal-homograph-refund.eml");
  assert.equal(r.verdict.key, "malicious");
  assert.ok(ids(r).includes("link_homograph"));
  assert.ok(r.urls.some((u) => u.hostUnicode === "pаypal.com"));
});

test("legitimate GitHub notification stays clean", async () => {
  const r = await load("07-legit-github-notification.eml");
  assert.equal(r.verdict.key, "clean");
  assert.ok(r.score < 20, `score ${r.score}`);
  assert.ok(r.dkimAligned);
  assert.deepEqual(r.iocs.urls, []);
});

test("exports: markdown, CSV (formula-injection safe) and STIX 2.1", async () => {
  const r = await load("01-microsoft365-password-expiry.eml");
  const mdText = toMarkdown(r);
  assert.match(mdText, /# Phishing analysis report/);
  assert.ok(!mdText.includes("https://micros0ft"), "URLs in the report must be defanged");
  r.iocs.domains.push("=HYPERLINK(\"x\")");
  assert.match(toIocCsv(r), /'=HYPERLINK/);
  const stix = JSON.parse(toStix(r));
  assert.equal(stix.type, "bundle");
  assert.ok(stix.objects.some((o) => o.type === "indicator" && o.pattern.startsWith("[url:value")));
});
