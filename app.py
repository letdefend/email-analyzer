# -*- coding: utf-8 -*-
"""
Email Analyzer Web - Flask Backend
"""

from flask import Flask, request, jsonify, render_template, send_file
import email, email.policy, re, json, csv, os, hashlib, base64, io
from datetime import datetime
from email import message_from_string
from email.header import decode_header, make_header

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB max upload

# =============================================================
#  IOC & ANALYSIS PATTERNS
# =============================================================
IP_RE     = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
URL_RE    = re.compile(r"https?://[^\s\"'<>\x00-\x1f]{6,}", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|gov|edu|io|co|uk|de|ru|cn|fr|jp|au|us|info|biz|xyz|online|site|tech|app|dev|cloud|mil|me|cc|tv)\b", re.I)
EMAIL_RE  = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
MD5_RE    = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE   = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
CVE_RE    = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
B64_RE    = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
PRIVATE_IPS = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.)")

PHISHING_KEYWORDS = [
    "verify your account","confirm your identity","account suspended",
    "urgent action required","click here to","login to your account",
    "update your payment","your account will be","security alert",
    "you have won","claim your prize","act now","limited time offer",
    "verify now","unusual activity","reset your password",
    "billing information","update required","dear customer",
    "invoice attached","track your package","delivery failed",
]

SUSPICIOUS_EXTENSIONS = {
    ".exe",".bat",".cmd",".vbs",".js",".jse",".wsf",".ps1",
    ".scr",".pif",".com",".hta",".jar",".lnk",".reg",".dll",
}

# =============================================================
#  EMAIL PARSER ENGINE
# =============================================================
def decode_mime_words(s):
    if not s:
        return ""
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return str(s)

def parse_email(raw):
    try:
        msg = message_from_string(raw, policy=email.policy.compat32)
    except Exception:
        msg = message_from_string(raw)

    r = {}
    r["from"]       = decode_mime_words(msg.get("From", ""))
    r["to"]         = decode_mime_words(msg.get("To", ""))
    r["cc"]         = decode_mime_words(msg.get("Cc", ""))
    r["reply_to"]   = decode_mime_words(msg.get("Reply-To", ""))
    r["subject"]    = decode_mime_words(msg.get("Subject", ""))
    r["date"]       = msg.get("Date", "")
    r["message_id"] = msg.get("Message-ID", "")
    r["x_mailer"]   = msg.get("X-Mailer", msg.get("User-Agent", ""))
    r["x_orig_ip"]  = msg.get("X-Originating-IP", msg.get("X-Original-IP", ""))
    r["mime_ver"]   = msg.get("MIME-Version", "")

    # Authentication
    r["received_spf"]   = msg.get("Received-SPF", "")
    r["auth_results"]   = msg.get("Authentication-Results", "")
    r["dkim_signature"] = "Present" if msg.get("DKIM-Signature") else "Missing"

    spf_raw = (r["received_spf"] + r["auth_results"]).lower()
    if "pass" in spf_raw:        r["spf_status"] = "PASS"
    elif "fail" in spf_raw:      r["spf_status"] = "FAIL"
    elif "softfail" in spf_raw:  r["spf_status"] = "SOFTFAIL"
    elif "neutral" in spf_raw:   r["spf_status"] = "NEUTRAL"
    else:                         r["spf_status"] = "UNKNOWN"

    dkim_raw = r["auth_results"].lower()
    r["dkim_status"]  = "PASS" if "dkim=pass" in dkim_raw else "FAIL" if "dkim=fail" in dkim_raw else "UNKNOWN"
    r["dmarc_status"] = "PASS" if "dmarc=pass" in dkim_raw else "FAIL" if "dmarc=fail" in dkim_raw else "UNKNOWN"

    # Received hops
    received_list = msg.get_all("Received") or []
    hops = []
    for rec in received_list:
        hop = {"raw": rec.strip()}
        ips = [ip for ip in IP_RE.findall(rec) if not PRIVATE_IPS.match(ip)]
        hop["ips"]  = ips
        hop["by"]   = (re.search(r"by\s+([\w\.\-]+)", rec, re.I) or type("", (), {"group": lambda s,n: ""})()).group(1)
        hop["from"] = (re.search(r"from\s+([\w\.\-]+)", rec, re.I) or type("", (), {"group": lambda s,n: ""})()).group(1)
        hop["with"] = (re.search(r"with\s+([\w]+)", rec, re.I) or type("", (), {"group": lambda s,n: ""})()).group(1)
        m = re.search(r";\s*(.+)$", rec.strip())
        hop["date"] = m.group(1).strip() if m else ""
        hops.append(hop)
    r["received_hops"] = hops

    all_header_text = "\n".join(str(v) for v in msg.values())
    r["header_ips"] = list(set(ip for ip in IP_RE.findall(all_header_text) if not PRIVATE_IPS.match(ip)))

    # Body extraction
    body_plain = ""
    body_html  = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            ct   = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            fname = part.get_filename()
            if "attachment" in disp or fname:
                payload = part.get_payload(decode=True) or b""
                ext = os.path.splitext(fname or "")[1].lower()
                attachments.append({
                    "filename": fname or "unnamed",
                    "type": ct,
                    "size": len(payload),
                    "md5": hashlib.md5(payload).hexdigest() if payload else "",
                    "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
                    "suspicious": ext in SUSPICIOUS_EXTENSIONS,
                    "extension": ext,
                })
            elif ct == "text/plain" and not body_plain:
                try:
                    body_plain = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    body_plain = str(part.get_payload())
            elif ct == "text/html" and not body_html:
                try:
                    body_html = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    body_html = str(part.get_payload())
    else:
        try:
            payload = msg.get_payload(decode=True)
            body_plain = payload.decode(msg.get_content_charset() or "utf-8", errors="replace") if payload else str(msg.get_payload() or "")
        except Exception:
            body_plain = str(msg.get_payload() or "")

    r["body_plain"]  = body_plain
    r["body_html"]   = body_html
    r["attachments"] = attachments

    # IOC extraction
    combined = body_plain + " " + body_html
    r["body_urls"]    = list(set(URL_RE.findall(combined)))[:50]
    r["body_ips"]     = list(set(ip for ip in IP_RE.findall(combined) if not PRIVATE_IPS.match(ip)))
    r["body_domains"] = list(set(d for d in DOMAIN_RE.findall(combined) if len(d) > 5))[:50]
    r["body_emails"]  = list(set(EMAIL_RE.findall(combined)))
    r["body_md5"]     = list(set(MD5_RE.findall(combined)))
    r["body_sha1"]    = list(set(SHA1_RE.findall(combined)))
    r["body_sha256"]  = list(set(SHA256_RE.findall(combined)))
    r["body_cve"]     = list(set(CVE_RE.findall(combined)))

    # Base64
    decoded_b64 = []
    for blob in B64_RE.findall(combined)[:5]:
        try:
            dec = base64.b64decode(blob + "==").decode("utf-8", errors="replace")
            if sum(c.isprintable() for c in dec[:20]) > 10:
                decoded_b64.append({"encoded": blob[:60]+"...", "decoded": dec[:200]})
        except Exception:
            pass
    r["base64_blobs"] = decoded_b64

    # Phishing detection
    body_lower    = combined.lower()
    subject_lower = r["subject"].lower()
    r["phishing_keywords"] = [kw for kw in PHISHING_KEYWORDS if kw in body_lower or kw in subject_lower]

    from_domain    = re.search(r"@([\w\.\-]+)", r["from"] or "")
    replyto_domain = re.search(r"@([\w\.\-]+)", r["reply_to"] or "")
    r["replyto_mismatch"] = bool(
        from_domain and replyto_domain and
        from_domain.group(1).lower() != replyto_domain.group(1).lower()
    )
    r["suspicious_urls"]  = re.findall(r"https?://[^\s/]+\.(?:tk|ml|ga|cf|gq|xyz|top|pw)", body_lower)
    r["shortened_urls"]   = re.findall(r"https?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd)[^\s\"]*", combined, re.I)
    r["punycode_domains"] = re.findall(r"xn--[a-z0-9\-]+", body_lower)

    # Threat score
    score   = 0
    reasons = []
    if r["spf_status"]   in ("FAIL","SOFTFAIL"): score += 25; reasons.append(f"SPF {r['spf_status']} (+25)")
    if r["dkim_status"]  == "FAIL":              score += 20; reasons.append("DKIM FAIL (+20)")
    if r["dmarc_status"] == "FAIL":              score += 20; reasons.append("DMARC FAIL (+20)")
    if r["replyto_mismatch"]:                    score += 20; reasons.append("Reply-To domain mismatch (+20)")
    if r["phishing_keywords"]:
        pts = min(len(r["phishing_keywords"])*5, 25)
        score += pts; reasons.append(f"Phishing keywords x{len(r['phishing_keywords'])} (+{pts})")
    if r["suspicious_urls"]:  score += 15; reasons.append("Suspicious TLD URLs (+15)")
    if r["shortened_urls"]:   score += 10; reasons.append("URL shorteners (+10)")
    if r["punycode_domains"]: score += 15; reasons.append("Punycode domains (+15)")
    if any(a["suspicious"] for a in attachments): score += 30; reasons.append("Suspicious attachments (+30)")
    if r["body_ips"]:         score += 5;  reasons.append("IPs in body (+5)")

    score = min(score, 100)
    if score >= 70:   verdict = "HIGH RISK"
    elif score >= 40: verdict = "MEDIUM RISK"
    elif score >= 15: verdict = "LOW RISK"
    else:             verdict = "CLEAN"

    r["threat_score"]   = score
    r["threat_verdict"] = verdict
    r["threat_reasons"] = reasons
    r["analyzed_at"]    = datetime.utcnow().isoformat() + "Z"

    # Don't send full raw back (too large); send first 3000 chars
    r["raw_preview"] = raw[:3000]
    return r

# =============================================================
#  ROUTES
# =============================================================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    raw = ""
    if "file" in request.files:
        f = request.files["file"]
        raw = f.read().decode("utf-8", errors="replace")
    elif request.json and "raw" in request.json:
        raw = request.json["raw"]
    else:
        return jsonify({"error": "No email content provided"}), 400

    if not raw.strip():
        return jsonify({"error": "Empty email content"}), 400

    try:
        result = parse_email(raw)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/export/<fmt>", methods=["POST"])
def export(fmt):
    data = request.json
    if not data:
        return jsonify({"error": "No data"}), 400

    ts  = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    buf = io.StringIO()

    if fmt == "json":
        json.dump(data, buf, indent=2, ensure_ascii=False)
        buf.seek(0)
        return send_file(
            io.BytesIO(buf.getvalue().encode()),
            mimetype="application/json",
            as_attachment=True,
            download_name=f"email_analysis_{ts}.json"
        )
    elif fmt == "csv":
        w = csv.writer(buf)
        w.writerow(["type","value"])
        for url in data.get("body_urls",[]): w.writerow(["URL", url])
        for ip  in data.get("body_ips",[]): w.writerow(["IP", ip])
        for dom in data.get("body_domains",[]): w.writerow(["Domain", dom])
        for em  in data.get("body_emails",[]): w.writerow(["Email", em])
        for h   in data.get("body_md5",[]): w.writerow(["MD5", h])
        for h   in data.get("body_sha256",[]): w.writerow(["SHA256", h])
        buf.seek(0)
        return send_file(
            io.BytesIO(buf.getvalue().encode()),
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"email_iocs_{ts}.csv"
        )
    elif fmt == "txt":
        lines = [
            "EMAIL ANALYSIS REPORT",
            f"Tool    : Email Analyzer Web v1.0",
            f"Date    : {datetime.utcnow().isoformat()}Z",
            f"Score   : {data.get('threat_score',0)}/100  -  {data.get('threat_verdict','')}",
            "="*60,
            f"From    : {data.get('from','')}",
            f"To      : {data.get('to','')}",
            f"Subject : {data.get('subject','')}",
            f"Date    : {data.get('date','')}",
            "",
            f"SPF     : {data.get('spf_status','')}",
            f"DKIM    : {data.get('dkim_status','')}",
            f"DMARC   : {data.get('dmarc_status','')}",
            "",
        ]
        for label, key in [("URLs",data.get("body_urls",[])),("IPs",data.get("body_ips",[])),
                           ("Domains",data.get("body_domains",[])),("SHA256",data.get("body_sha256",[]))]:
            if key:
                lines.append(f"[{label}]")
                lines.extend(f"  {v}" for v in key)
                lines.append("")
        buf.write("\n".join(lines))
        buf.seek(0)
        return send_file(
            io.BytesIO(buf.getvalue().encode()),
            mimetype="text/plain",
            as_attachment=True,
            download_name=f"email_analysis_{ts}.txt"
        )
    return jsonify({"error": "Unknown format"}), 400

@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "1.0"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
