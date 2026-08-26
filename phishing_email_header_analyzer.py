#!/usr/bin/env python3
import argparse
import json
import re
import sys
from email import message_from_file
from email.utils import parseaddr

URGENCY_KEYWORDS = [
    "urgent", "verify your account", "click here", "suspended", "act now",
    "confirm your identity", "unusual activity", "limited time",
    "acil", "hesabınız askıya alınacak", "şifrenizi güncelleyin",
    "hemen doğrulayın", "hesabınızı doğrulayın",
]

AUTH_RESULT_RE = re.compile(r"(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)


def domain_of(address: str) -> str:
    addr = parseaddr(address)[1]
    return addr.split("@")[-1].lower() if "@" in addr else ""


def check_auth_results(headers: str):
    findings = []
    score = 0
    results = {m.group(1).lower(): m.group(2).lower() for m in AUTH_RESULT_RE.finditer(headers)}
    if not results:
        findings.append(("Authentication-Results", "MISSING", "No Authentication-Results header found — cannot verify SPF/DKIM/DMARC.", 15))
        score += 15
        return findings, score
    for mech in ("spf", "dkim", "dmarc"):
        value = results.get(mech)
        if value is None:
            findings.append((mech.upper(), "UNKNOWN", "No result reported.", 5))
            score += 5
        elif value in ("fail", "softfail"):
            pts = 25 if mech == "dmarc" else 20
            findings.append((mech.upper(), "FAIL", f"{mech.upper()} check failed ({value}).", pts))
            score += pts
        elif value == "pass":
            findings.append((mech.upper(), "PASS", "Passed.", 0))
        else:
            findings.append((mech.upper(), value.upper(), "Non-pass result.", 10))
            score += 10
    return findings, score


def check_sender_consistency(msg):
    findings = []
    score = 0
    from_domain = domain_of(msg.get("From", ""))
    reply_to = msg.get("Reply-To")
    return_path = msg.get("Return-Path")

    if reply_to:
        reply_domain = domain_of(reply_to)
        if reply_domain and reply_domain != from_domain:
            findings.append(("Reply-To vs From", "MISMATCH", f"From domain '{from_domain}' != Reply-To domain '{reply_domain}'.", 20))
            score += 20
        else:
            findings.append(("Reply-To vs From", "OK", "Domains match.", 0))
    else:
        findings.append(("Reply-To vs From", "N/A", "No Reply-To header present.", 0))

    if return_path:
        rp_domain = domain_of(return_path)
        if rp_domain and rp_domain != from_domain:
            findings.append(("Return-Path vs From", "MISMATCH", f"From domain '{from_domain}' != Return-Path domain '{rp_domain}'.", 15))
            score += 15
        else:
            findings.append(("Return-Path vs From", "OK", "Domains match.", 0))
    else:
        findings.append(("Return-Path vs From", "N/A", "No Return-Path header present.", 0))

    return findings, score


def check_display_name_spoofing(msg):
    display_name, _addr = parseaddr(msg.get("From", ""))
    domain = domain_of(msg.get("From", ""))
    if not display_name:
        return [("Display Name", "N/A", "No display name set.", 0)], 0

    generic_terms = ["support", "security", "team", "service", "official", "account", "billing"]
    looks_official = any(term in display_name.lower() for term in generic_terms)
    looks_generic_domain = bool(re.search(r"(secure|verify|confirm|update|alert)", domain))

    if looks_official and looks_generic_domain:
        return [("Display Name", "SUSPICIOUS", f"Display name '{display_name}' sounds official but domain '{domain}' contains suspicious keywords.", 20)], 20
    return [("Display Name", "OK", f"Display name '{display_name}' does not indicate spoofing.", 0)], 0


def check_urgency_keywords(msg):
    subject = (msg.get("Subject") or "").lower()
    hits = [kw for kw in URGENCY_KEYWORDS if kw in subject]
    if hits:
        pts = min(20, 8 * len(hits))
        return [("Subject Urgency", "FLAGGED", f"Urgency keywords found: {', '.join(hits)}", pts)], pts
    return [("Subject Urgency", "OK", "No urgency/threat keywords detected in subject.", 0)], 0


def verdict_for(score: int) -> str:
    if score >= 60:
        return "High Risk"
    if score >= 30:
        return "Medium Risk"
    return "Low Risk"


def analyze(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        msg = message_from_file(f)
        f.seek(0)
        raw_headers = f.read()

    all_findings = []
    total_score = 0

    for findings, score in (
        check_auth_results(raw_headers),
        check_sender_consistency(msg),
        check_display_name_spoofing(msg),
        check_urgency_keywords(msg),
    ):
        all_findings.extend(findings)
        total_score += score

    total_score = min(total_score, 100)
    return {
        "file": path,
        "from": msg.get("From", ""),
        "subject": msg.get("Subject", ""),
        "findings": all_findings,
        "score": total_score,
        "verdict": verdict_for(total_score),
    }


def render_markdown(result: dict) -> str:
    lines = [
        f"## {result['file']}",
        "",
        f"- **From:** {result['from']}",
        f"- **Subject:** {result['subject']}",
        f"- **Risk Score:** {result['score']}/100",
        f"- **Verdict:** {result['verdict']}",
        "",
        "| Check | Result | Detail | Points |",
        "|---|---|---|---|",
    ]
    for name, status, detail, pts in result["findings"]:
        lines.append(f"| {name} | {status} | {detail} | {pts} |")
    lines.append("")
    return "\n".join(lines)


def render_json(result: dict) -> str:
    payload = {
        "file": result["file"],
        "from": result["from"],
        "subject": result["subject"],
        "score": result["score"],
        "verdict": result["verdict"],
        "findings": [
            {"check": name, "status": status, "detail": detail, "points": pts}
            for name, status, detail, pts in result["findings"]
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(description="Analyze a .eml file for phishing indicators.")
    parser.add_argument("--eml", required=True, help="Path to the .eml file to analyze")
    parser.add_argument("--output", default="sample_report.md", help="Path to write the report")
    parser.add_argument("--append", action="store_true", help="Append to the output file instead of overwriting")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Report output format"
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "medium", "high"],
        default="none",
        help="Exit with code 1 if the verdict is at/above this risk level (for CI gating).",
    )
    args = parser.parse_args()

    result = analyze(args.eml)
    report = render_json(result) if args.format == "json" else render_markdown(result)

    mode = "a" if args.append else "w"
    with open(args.output, mode, encoding="utf-8") as f:
        f.write(report)

    print(f"[{result['verdict']}] score={result['score']} file={args.eml}")

    if args.fail_on == "high" and result["verdict"] == "High Risk":
        return 1
    if args.fail_on == "medium" and result["verdict"] in ("Medium Risk", "High Risk"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
