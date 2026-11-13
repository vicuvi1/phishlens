import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeWords, parseAddress, parseAddressList, parseEmail, parseStructured, decodeTransfer } from "../src/mime.js";
import { editDistance, impersonatedBrand, punycodeDecodeLabel, registrableDomain, skeleton, toUnicode } from "../src/domains.js";
import { md5 } from "../src/md5.js";
import { analyzeUrl, defangUrl, unwrap } from "../src/urls.js";
import { parseAuthResults, parseReceived, isPrivateIP } from "../src/headers.js";
import { Headers } from "../src/mime.js";
import { sniffType } from "../src/attachments.js";
import { computeScore } from "../src/score.js";
import { analyzeLanguage } from "../src/language.js";

const enc = (s) => new TextEncoder().encode(s);

test("RFC 2047 encoded words (B and Q, adjacent words joined)", () => {
  assert.equal(decodeWords("=?UTF-8?B?UGxhdGEgcmVzcGluc8SD?="), "Plata respinsă");
  assert.equal(decodeWords("=?iso-8859-1?Q?Caf=E9_cr=E8me?="), "Café crème");
  assert.equal(decodeWords("=?UTF-8?Q?a?= =?UTF-8?Q?b?="), "ab");
});

test("structured headers with RFC 2231 filenames", () => {
  const ct = parseStructured("application/pdf; name*=UTF-8''factur%C4%83%201.pdf");
  assert.equal(ct.value, "application/pdf");
  assert.equal(ct.params.name, "factură 1.pdf");
  const cd = parseStructured('attachment; filename*0="very_long_"; filename*1="name.zip"');
  assert.equal(cd.params.filename, "very_long_name.zip");
});

test("transfer encodings", () => {
  assert.deepEqual([...decodeTransfer("aGk=", "base64")], [104, 105]);
  assert.equal(new TextDecoder().decode(decodeTransfer("a=3Db=\r\nc", "quoted-printable")), "a=bc");
});

test("address parsing handles quotes, commas and comments", () => {
  const list = parseAddressList('"Doe, John" <John.Doe@Example.com>, plain@example.org, x@y.com (Support)');
  assert.equal(list.length, 3);
  assert.equal(list[0].name, "Doe, John");
  assert.equal(list[0].address, "john.doe@example.com");
  assert.equal(list[0].domain, "example.com");
  assert.equal(list[2].name, "Support");
  assert.equal(parseAddress("<a@b.co>").domain, "b.co");
});

test("multipart parsing keeps attachments byte-exact", () => {
  const raw = [
    "From: a@example.com", "To: b@example.com", "Subject: t", "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="XYZ"', "", "preamble", "--XYZ",
    "Content-Type: text/plain; charset=utf-8", "", "Hello ă", "--XYZ",
    'Content-Type: application/octet-stream; name="f.bin"', "Content-Transfer-Encoding: base64", "", "AAEC/w==", "--XYZ--", "",
  ].join("\r\n");
  const p = parseEmail(enc(raw));
  assert.equal(p.text.trim(), "Hello ă");
  assert.equal(p.attachments.length, 1);
  assert.equal(p.attachments[0].filename, "f.bin");
  assert.deepEqual([...p.attachments[0].bytes], [0, 1, 2, 255]);
});

test("md5 matches RFC 1321 test vectors", () => {
  assert.equal(md5(enc("")), "d41d8cd98f00b204e9800998ecf8427e");
  assert.equal(md5(enc("abc")), "900150983cd24fb0d6963f7d28e17f72");
  assert.equal(md5(enc("a".repeat(1000))), "cabe45dcc9ae5b66ba86600cca6b8ba8");
});

test("punycode and homographs", () => {
  assert.equal(punycodeDecodeLabel("pypal-4ve"), "pаypal");
  assert.equal(toUnicode("xn--pypal-4ve.com"), "pаypal.com");
  assert.equal(skeleton("pаypal"), skeleton("paypal"));
});

test("registrable domains", () => {
  assert.equal(registrableDomain("a.b.example.co.uk"), "example.co.uk");
  assert.equal(registrableDomain("login.evil.github.io"), "evil.github.io");
  assert.equal(registrableDomain("mail.google.com"), "google.com");
});

test("look-alike brand detection, without flagging the real brands", () => {
  assert.equal(impersonatedBrand("micros0ft-secure-login.com")?.brand, "Microsoft");
  assert.equal(impersonatedBrand("paypa1.com")?.brand, "PayPal");
  assert.equal(impersonatedBrand("xn--pypal-4ve.com")?.brand, "PayPal");
  assert.equal(impersonatedBrand("paypal.com.account-check.xyz")?.where, "subdomain");
  assert.equal(impersonatedBrand("dhl-shipment-notice.top")?.brand, "DHL");
  for (const ok of ["login.microsoftonline.com", "www.paypal.com", "github.com", "accounts.google.com", "example.com", "applebees.com", "upstream.org"]) {
    assert.equal(impersonatedBrand(ok), null, ok);
  }
  assert.equal(editDistance("paypal", "paypla"), 1);
});

test("URL analysis flags", () => {
  const codes = (u, texts = []) => analyzeUrl({ raw: u, sources: ["t"], texts }).flags.map((f) => f.code);
  assert.ok(codes("http://192.0.2.5/login").includes("ip_host"));
  assert.ok(codes("https://www.paypal.com@evil.example/").includes("userinfo"));
  assert.ok(codes("https://bit.ly/abc").includes("shortener"));
  assert.ok(codes("https://evil.example/a", ["https://www.paypal.com"]).includes("text_mismatch"));
  assert.ok(!codes("https://github.com/settings", ["github.com/settings"]).includes("text_mismatch"));
  assert.ok(codes("https://cdn.example.net/invoice.iso").includes("download"));
  assert.deepEqual(codes("https://github.com/settings/keys"), []);
  assert.equal(defangUrl("https://evil.example.com/a.b"), "hxxps://evil[.]example[.]com/a.b");
});

test("redirect and Safe Links unwrapping", () => {
  const sl = new URL("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Fx&data=1");
  assert.equal(unwrap(sl), "https://evil.example/x");
  const pp = new URL("https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_path&d=1");
  assert.equal(unwrap(pp), "https://evil.example/path");
});

test("Authentication-Results and Received parsing", () => {
  const h = Headers.parse(
    [
      "Received: from mx.example.com (mx.example.com [10.0.0.2]) by store.example.com; Tue, 10 Nov 2026 08:12:33 +0000",
      "Received: from evil.example (evil.example [203.0.113.9]) by mx.example.com; Tue, 10 Nov 2026 08:12:31 +0000",
      "Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=evil.example; dkim=pass header.d=evil.example; dmarc=fail header.from=bank.example",
    ].join("\r\n"),
  );
  const a = parseAuthResults(h);
  assert.equal(a.spf.result, "fail");
  assert.equal(a.dkim[0].domain, "evil.example");
  assert.equal(a.dmarc.result, "fail");
  const r = parseReceived(h);
  assert.equal(r.originIp, "203.0.113.9");
  assert.equal(r.hops[1].delay, 2);
  assert.ok(isPrivateIP("10.1.2.3") && isPrivateIP("192.168.1.1") && !isPrivateIP("8.8.8.8"));
});

test("magic byte sniffing", () => {
  assert.equal(sniffType(new Uint8Array([0x4d, 0x5a, 0x90, 0])).type, "pe");
  assert.equal(sniffType(enc("%PDF-1.7")).type, "pdf");
  assert.equal(sniffType(enc("<!DOCTYPE html><html>")).type, "html");
  assert.equal(sniffType(enc('<svg xmlns="http://www.w3.org/2000/svg">')).type, "svg");
});

test("language rules: BEC wording is detected, a normal email is not", () => {
  const bec = analyzeLanguage({ subject: "Quick favour", text: "Are you at your desk? Process an urgent wire transfer and keep this confidential." });
  assert.ok(bec.findings.some((f) => f.id === "lang_bec_payment" && f.severity === "high"));
  const normal = analyzeLanguage({ subject: "Lunch", text: "Hi Ana, shall we grab lunch on Friday? Cheers, Mihai" });
  assert.equal(normal.findings.length, 0);
});

test("score combines findings with diminishing returns", () => {
  assert.equal(computeScore([]).score, 0);
  const one = computeScore([{ severity: "medium", category: "x" }]).score;
  const two = computeScore([{ severity: "medium", category: "x" }, { severity: "medium", category: "x" }]).score;
  assert.ok(two > one && two < 2 * one);
  assert.ok(computeScore([{ severity: "critical", category: "x" }]).score >= 80);
});
